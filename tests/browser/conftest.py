"""Infrastructure for the browser suites: a real server, a real browser.

The Python suites call the API directly and cover it thoroughly. That is not
the same thing as covering the app, and the gap is not theoretical -- every one
of these shipped while the API suite was green:

  * Enter did nothing in the server form. There is no <form> on the page, so
    the browser's own submit behaviour never applied, and the keydown handler
    named five element ids that did not include any field of that form. The
    API was fine; the form had no way to submit it.
  * The inline theme script is pinned in the CSP by content hash. Editing the
    script without recomputing the hash makes the browser drop it silently --
    no error, no failed request, just the wrong theme on first paint.
  * The filter library was a tab; choosing a filter filled a field on a
    different tab.

None of those produce a bad HTTP response, so none of them can be seen from a
test that only speaks HTTP. These suites drive the page the way a person does.

These suites use playwright's async API, not its sync one. The sync API drives
the driver through an event loop it installs on the main thread and keeps for
as long as it is open; the rest of this repo's tests are async and run under
pytest-asyncio, which then finds a loop it did not make and cannot tear down.
Each suite passes on its own either way -- the two only collide in a full run,
which is the run that matters.

Skipping: if playwright or a chromium binary is missing the tests report as
SKIPPED with the remedy in the reason, the same way the tshark-dependent tests
do -- scripts/check.sh runs pytest with -r s so a skipped browser suite is
printed, not silently dropped.
"""

from __future__ import annotations

import base64
import importlib.util
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.browser.browser_binary import launch_kwargs

REPO_ROOT = Path(__file__).resolve().parents[2]

HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None

needs_browser = pytest.mark.skipif(
    not HAS_PLAYWRIGHT,
    reason="playwright is not installed -- pip install -r backend/requirements-dev.txt",
)

# The admin account every suite signs in as. Created through the real
# registration and TOTP-enrolment endpoints, not by writing rows. These are not
# credentials to anything: the account exists inside a throwaway database, on a
# server bound to loopback, for the length of one test run.
ADMIN_USERNAME = "browser-admin"
ADMIN_PASSWORD = "browser-admin-passphrase"

_STARTUP_TIMEOUT = 60.0


@dataclass(frozen=True)
class LiveServer:
    """A uvicorn process serving the real app out of throwaway directories."""

    url: str
    root: Path
    totp_secret: str = ""

    @property
    def ssh_keys_dir(self) -> Path:
        return self.root / "ssh-keys"


def _free_port() -> int:
    """Ask the kernel for a port, then hand it to uvicorn.

    There is a window between closing this socket and uvicorn binding it. It is
    the standard approach and the alternative -- passing an inherited socket
    through uvicorn -- buys very little for a test fixture.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_serving(url: str, proc: subprocess.Popen, log: Path) -> None:
    deadline = time.monotonic() + _STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"the test server exited with {proc.returncode} before serving:\n"
                f"{log.read_text(errors='replace')}"
            )
        try:
            with urllib.request.urlopen(f"{url}/api/auth/status", timeout=2) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError, TimeoutError):
            time.sleep(0.1)
    raise RuntimeError(
        f"the test server did not answer within {_STARTUP_TIMEOUT:.0f}s:\n"
        f"{log.read_text(errors='replace')}"
    )


def _start_server(root: Path) -> tuple[LiveServer, subprocess.Popen]:
    """Launch the app on loopback with its own data, captures and key dirs.

    Loopback matters beyond isolation: the app is deliberately read-only over
    plain HTTP, and it treats a loopback client as secure transport (nothing
    crosses a wire to be read). Served on 127.0.0.1 the whole UI works over
    http:// without a certificate.
    """
    for name in ("data", "captures", "ssh-keys"):
        (root / name).mkdir(parents=True, exist_ok=True)

    port = _free_port()
    env = {
        **os.environ,
        "DATA_DIR": str(root / "data"),
        "CAPTURES_DIR": str(root / "captures"),
        "SSH_KEYS_DIR": str(root / "ssh-keys"),
        "PCAP_MASTER_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
        "COOKIE_SECURE": "false",
    }
    log = root / "server.log"
    # To a file rather than a pipe nobody reads: a pipe fills and blocks the
    # server mid-test, and the log is what explains a startup failure.
    handle = log.open("w")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "backend.main:app",
            "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning",
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_serving(url, proc, log)
    except Exception:
        _stop_server(proc)
        handle.close()
        raise
    handle.close()
    return LiveServer(url=url, root=root), proc


def _stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def _seed_admin(url: str) -> str:
    """Register the admin and finish TOTP enrolment through the public API.

    Enrolment is compulsory -- an account that skips it cannot reach the app --
    so every suite that is not specifically testing first-run setup needs it
    done already. Returns the TOTP secret so tests can produce valid codes.
    """
    import httpx
    import pyotp

    with httpx.Client(base_url=url, timeout=30) as client:
        client.post(
            "/api/auth/register",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        ).raise_for_status()
        secret = client.get("/api/auth/totp/setup").raise_for_status().json()["secret"]
        client.post(
            "/api/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()}
        ).raise_for_status()
    return secret


@pytest.fixture(scope="session")
def live_server():
    """One server for the whole session, with the admin already enrolled.

    Shared deliberately: booting uvicorn per test would dominate the runtime.
    Tests that need a server with no users take `fresh_server` instead.
    """
    root = Path(tempfile.mkdtemp(prefix="pcap-browser-"))
    try:
        server, proc = _start_server(root)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise
    # add_server refuses a key name that is not present in SSH_KEYS_DIR. The
    # contents are never read by the endpoint under test -- only the presence
    # of the file is checked -- so this is a placeholder, not a key.
    (server.ssh_keys_dir / "browser-test-key").write_text(
        "# placeholder for tests; not a key\n"
    )
    try:
        yield LiveServer(url=server.url, root=root, totp_secret=_seed_admin(server.url))
    finally:
        _stop_server(proc)
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def fresh_server():
    """A server with an empty database, for the first-run screens."""
    root = Path(tempfile.mkdtemp(prefix="pcap-browser-fresh-"))
    try:
        server, proc = _start_server(root)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise
    try:
        yield server
    finally:
        _stop_server(proc)
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
async def browser():
    """A headless chromium, for one test.

    Per test rather than per session because an async fixture outliving the
    test's event loop has to be pinned to a loop of its own, and every test
    using it pinned to the same one. Chromium starts in a fraction of a second;
    that is the cheaper side of the trade.
    """
    if not HAS_PLAYWRIGHT:
        pytest.skip("playwright is not installed")
    from playwright.async_api import async_playwright

    async with async_playwright() as play:
        kwargs = launch_kwargs(play)
        if kwargs is None:
            pytest.skip(
                "no chromium for playwright -- run: "
                f"{sys.executable} -m playwright install chromium"
            )
        if getattr(os, "geteuid", lambda: 1)() == 0:
            # Chromium's setuid sandbox refuses to start as root, which is how
            # CI images and dev containers usually run. The pages loaded here
            # are this repo's own, served from loopback, so the sandbox is not
            # what stands between these tests and anything.
            kwargs["args"] = ["--no-sandbox"]
        instance = await play.chromium.launch(**kwargs)
        try:
            yield instance
        finally:
            await instance.close()


async def _open_page(browser, url: str):
    """A fresh context (so: no cookies, no storage) pointed at `url`.

    Console errors and uncaught exceptions are collected onto the page as
    `console_errors`. A page that throws still renders, so without this a
    broken handler looks exactly like a working one until the assertion that
    happens to touch it.
    """
    context = await browser.new_context(base_url=url)
    page = await context.new_page()
    errors: list[str] = []
    page.console_errors = errors

    def on_console(msg) -> None:
        if msg.type != "error":
            return
        # With the URL, because the text of a failed load does not carry one:
        # "Failed to load resource: ... 404" says nothing about what failed.
        where = (msg.location or {}).get("url", "")
        errors.append(f"{msg.text} ({where})" if where else msg.text)

    page.on("console", on_console)
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    return context, page


@pytest.fixture
async def page(browser, live_server):
    context, page = await _open_page(browser, live_server.url)
    try:
        yield page
    finally:
        await context.close()


@pytest.fixture
async def fresh_page(browser, fresh_server):
    context, page = await _open_page(browser, fresh_server.url)
    try:
        yield page
    finally:
        await context.close()


def totp_now(secret: str) -> str:
    import pyotp

    return pyotp.TOTP(secret).now()


async def sign_in(page, live_server) -> None:
    """Sign in through the login screen, TOTP and all, and land in the app."""
    await page.goto("/")
    await page.fill("#login-username", ADMIN_USERNAME)
    await page.fill("#login-password", ADMIN_PASSWORD)
    await page.click("#btn-login")
    await page.wait_for_selector("#totp-group:not([hidden])")
    await page.fill("#login-totp", totp_now(live_server.totp_secret))
    await page.click("#btn-login")
    await page.wait_for_selector("#app-screen:not([hidden])")


@pytest.fixture
async def app_page(page, live_server):
    """A page signed in and sitting on the Servers tab."""
    await sign_in(page, live_server)
    return page


@pytest.fixture(scope="session")
def api_client(live_server):
    """A signed-in HTTP client, for arranging and tearing down state.

    Setting up a test's preconditions through the UI would make every test a
    test of the setup as well; this does it over the same API the UI calls.
    """
    import httpx

    with httpx.Client(base_url=live_server.url, timeout=30) as client:
        client.post(
            "/api/auth/login",
            json={
                "username": ADMIN_USERNAME,
                "password": ADMIN_PASSWORD,
                "totp_code": totp_now(live_server.totp_secret),
                "trust_device": False,
            },
        ).raise_for_status()
        yield client
