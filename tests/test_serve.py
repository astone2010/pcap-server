"""backend.serve end to end, as a real process: it starts on plain HTTP, an
admin switches it to HTTPS, and the same process -- same PID, never exiting --
comes back serving the stored certificate.

Loopback counts as secure transport, so the restart route is reachable without
TLS here; that is what lets the test drive the switch the way an admin would.
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pyotp
import pytest

from backend.crypto import Cryptor
from backend.tls import store
from tests.tls_helpers import make_pair

REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "pcap.example.com"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(check, proc, log: Path, timeout: float = 60.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.fail(f"server exited {proc.returncode}:\n{log.read_text()}")
        try:
            return check()
        except Exception as exc:  # not up yet
            last = exc
            time.sleep(0.2)
    pytest.fail(f"timed out ({last}):\n{log.read_text()}")


def _served_cert_der(port: int) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw) as s:
        return s.getpeercert(binary_form=True)


def _start(root: Path, kek: bytes, port: int, log: Path) -> subprocess.Popen:
    env = {
        **os.environ,
        "DATA_DIR": str(root / "data"),
        "CAPTURES_DIR": str(root / "captures"),
        "SSH_KEYS_DIR": str(root / "ssh-keys"),
        "PCAP_MASTER_KEY": kek.hex(),
        "COOKIE_SECURE": "false",
    }
    with log.open("a") as handle:
        return subprocess.Popen(
            [sys.executable, "-m", "backend.serve", "--host", "127.0.0.1", "--port", str(port)],
            cwd=REPO_ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT,
        )


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def _store(root: Path, cryptor: Cryptor) -> bytes:
    cert, key = make_pair(domain=DOMAIN)
    tls_dir = root / "data" / "tls"
    store.ensure_tls_dir(tls_dir)
    (tls_dir / store.CERT_FILE).write_bytes(cert)
    (tls_dir / store.KEY_FILE).write_bytes(cryptor.seal_bytes(key))
    return ssl.PEM_cert_to_DER_cert(cert.decode())


@pytest.fixture()
def root(tmp_path):
    for name in ("data", "captures", "ssh-keys"):
        (tmp_path / name).mkdir(mode=0o700)
    return tmp_path


def test_switching_to_https_replaces_the_process_in_place(root):
    kek, port, log = os.urandom(32), _free_port(), root / "server.log"
    proc = _start(root, kek, port, log)
    try:
        http = f"http://127.0.0.1:{port}"
        _wait_for(lambda: httpx.get(f"{http}/api/auth/status", timeout=2).raise_for_status(), proc, log)

        with httpx.Client(base_url=http, timeout=30) as client:
            client.post("/api/auth/register",
                        json={"username": "admin", "password": "a-long-admin-passphrase"}).raise_for_status()
            secret = client.get("/api/auth/totp/setup").raise_for_status().json()["secret"]
            client.post("/api/auth/totp/confirm",
                        json={"code": pyotp.TOTP(secret).now()}).raise_for_status()

            expected = _store(root, Cryptor(kek))
            status = client.get("/api/admin/tls").raise_for_status().json()
            assert status["serving_https"] is False
            assert status["restart_needed"] is True
            assert client.post("/api/admin/tls/restart").raise_for_status().json()["restarting"] is True

        assert _wait_for(lambda: _served_cert_der(port), proc, log) == expected
        assert proc.poll() is None, "the process exited instead of re-executing"

        resp = _wait_for(
            lambda: httpx.get(f"https://127.0.0.1:{port}/api/auth/status", verify=False, timeout=2),
            proc, log,
        )
        assert resp.status_code == 200
        assert "Strict-Transport-Security" in resp.headers
        with pytest.raises(httpx.HTTPError):
            httpx.get(f"{http}/api/auth/status", timeout=2)

        text = log.read_text()
        assert "restarting to switch to HTTPS" in text
        assert f"serving HTTPS for {DOMAIN}" in text
        assert "PRIVATE KEY" not in text
    finally:
        _stop(proc)


def test_a_stored_certificate_is_served_from_the_first_start(root):
    kek, port, log = os.urandom(32), _free_port(), root / "server.log"
    expected = _store(root, Cryptor(kek))
    proc = _start(root, kek, port, log)
    try:
        assert _wait_for(lambda: _served_cert_der(port), proc, log) == expected
        for path in (root / "data").rglob("*"):
            if path.is_file():
                assert b"PRIVATE KEY" not in path.read_bytes(), path
    finally:
        _stop(proc)


def test_passphrase_mode_with_a_stored_certificate_refuses_to_start(root):
    port, log = _free_port(), root / "server.log"
    _store(root, Cryptor(os.urandom(32)))
    env = {**os.environ, "DATA_DIR": str(root / "data"), "CAPTURES_DIR": str(root / "captures"),
           "SSH_KEYS_DIR": str(root / "ssh-keys"), "ENCRYPTION_MODE": "passphrase"}
    env.pop("PCAP_MASTER_KEY", None)
    result = subprocess.run(
        [sys.executable, "-m", "backend.serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 1
    assert "REFUSING TO START" in result.stdout + result.stderr
    assert "ENCRYPTION_MODE=passphrase" in result.stdout + result.stderr
