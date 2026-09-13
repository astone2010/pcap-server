"""Run lego once, in RAM, and hand back what it issued.

This is the only module that runs lego.

Nothing lego writes survives
----------------------------
Each run gets a fresh directory under /dev/shm -- memory, not disk -- as its
working directory, its HOME and its --path. lego's ACME account key, the
issued private key, and any credential file the provider needed all live there,
and the directory is removed before this returns, success or failure. So every
issuance registers a new ACME account, which Let's Encrypt allows and which
renewal every ~60 days does not come close to rate-limiting.

The working directory matters for a second reason: lego loads a .lego.yml from
it if one exists. A fresh empty directory has none.

What lego is given
------------------
- argv: our own flags, with the two user-supplied values (domain, email)
  validated as a hostname and an address and passed as --flag=value, so neither
  can stand as a flag of its own. The finished argv is checked once more.
- environment: PATH, HOME, and the provider variables validated against
  lego_providers.json -- never the app's own environment, which holds the
  master key in some configurations, and never a LEGO_* or NAME_FILE variable.
- "file" variables point at files written here, never at a path an admin chose.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from backend.crypto import Cryptor
from backend.tls import providers, store
from backend.tls.errors import AcmeBusy, AcmeError
from backend.tls.store import AcmeConfig, CertInfo

LEGO_BIN = os.environ.get("LEGO_BIN", "/usr/local/bin/lego")
CERT_NAME = "pcap-server"
LEGO_TIMEOUT_SECONDS = 900
STAGING_SERVER = "letsencrypt-staging"

# RAM-backed in every Docker container. Deliberately not configurable: if it is
# missing, issuance is refused rather than quietly falling back to disk.
SCRATCH_ROOT = Path("/dev/shm")


def build_argv(config: AcmeConfig, lego_path: Path, lego_bin: str | None = None) -> list[str]:
    """The complete lego command. Re-validates, so no caller can skip it."""
    domain = store.validate_domain(config.domain)
    email = store.validate_email(config.email)
    provider = providers.get(config.provider).code
    delay = store.validate_validation_delay(config.validation_delay)
    argv = [
        lego_bin or LEGO_BIN,
        "--log.format=text",
        "run",
        "--accept-tos",
        f"--email={email}",
        f"--domains={domain}",
        f"--dns={provider}",
        # Wait, then let Let's Encrypt check -- no polling of local DNS.
        # See DEFAULT_VALIDATION_DELAY in store.py for why.
        f"--dns.propagation.wait={delay}s",
        f"--path={lego_path}",
        "--key-type=EC256",
        f"--cert.name={CERT_NAME}",
    ]
    if config.staging:
        argv.append(f"--server={STAGING_SERVER}")
    _assert_argv_shape(argv)
    return argv


def _assert_argv_shape(argv: list[str]) -> None:
    """Every element but the binary and the subcommand is one of our own flags.

    Unreachable while the validators hold -- which is why it is checked rather
    than assumed.
    """
    for arg in argv[1:]:
        if arg == "run":
            continue
        if not arg.startswith("--") or arg.startswith("---") or "\n" in arg or "\x00" in arg:
            raise AcmeError(f"refusing to run lego with an unexpected argument: {arg!r}")


@contextlib.contextmanager
def issuance_lock(tls_dir: Path):
    """One issuance at a time, across the app and the CLI."""
    store.ensure_tls_dir(tls_dir)
    fd = os.open(tls_dir / store.LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AcmeBusy("a certificate request is already running") from None
        yield
    finally:
        os.close(fd)


@contextlib.contextmanager
def _scratch_dir():
    if not SCRATCH_ROOT.is_dir():
        raise AcmeError(
            f"{SCRATCH_ROOT} does not exist, so there is no RAM-backed place for "
            "lego to work in. Refusing rather than putting the key on disk."
        )
    path = Path(tempfile.mkdtemp(prefix="pcap-acme-", dir=SCRATCH_ROOT))
    try:
        os.chmod(path, 0o700)
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _environment(scratch: Path, provider_code: str, values: dict[str, str]) -> dict[str, str]:
    provider = providers.get(provider_code)
    try:
        clean = providers.validate_credentials(provider_code, values, resolve=True)
    except ValueError as exc:
        # An AcmeError, so a stored setting that has started resolving
        # somewhere refused is a failed renewal -- logged and backed off --
        # rather than an exception housekeeping was not expecting.
        raise AcmeError(str(exc)) from exc
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(scratch), "LANG": "C.UTF-8"}
    files = scratch / "credentials"
    for name, value in clean.items():
        if provider.variable(name).kind == "file":
            files.mkdir(mode=0o700, exist_ok=True)
            path = files / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(value)
            env[name] = str(path)
        else:
            env[name] = value
    return env


# lego logs in logfmt: time=... level=... msg="..." error="...". What an
# operator needs is the error="..." of the ERROR line; the rest is either
# progress (INFO) or lego's advice to back up an account directory that is
# deleted the moment it exits (the WARN "HEADS UP").
_ERROR_FIELD = re.compile(r'level=ERROR\b.*?\berror="((?:[^"\\]|\\.)*)"')

# Known failures, and what to do about them, matched on lego's own wording.
_HINTS = (
    ("NXDOMAIN looking up TXT",
     "Let's Encrypt could not see the challenge record yet. Raise \"Wait before "
     "validation\" and try again."),
    ("Incorrect TXT record",
     "Let's Encrypt found an old or different challenge record. Wait a minute for it "
     "to expire, or raise \"Wait before validation\"."),
    ("invalidContact",
     "Let's Encrypt refused the contact email address."),
    ("rateLimited",
     "A Let's Encrypt rate limit. Tick Staging while testing."),
    ("Authentication error", "The provider refused the credentials."),
)


def _unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")


def _failure(proc: subprocess.CompletedProcess, secrets: list[str]) -> str:
    text = (proc.stderr or "") + (proc.stdout or "")
    errors = [_unescape(m) for m in _ERROR_FIELD.findall(text)]
    if errors:
        detail = "\n".join(errors[-3:])
    else:
        lines = [ln for ln in text.strip().splitlines()
                 if ln.strip() and "level=INFO" not in ln and "level=WARN" not in ln][-12:]
        detail = "\n".join(lines) if lines else "no output"
    for secret in sorted(secrets, key=len, reverse=True):
        if len(secret) >= 4:
            detail = detail.replace(secret, "[redacted]")
    # The first match only, from a list ordered most specific first: one
    # failure can contain more than one of the phrases.
    hint = next((h for needle, h in _HINTS if needle.lower() in detail.lower()), "")
    return f"lego exited {proc.returncode}: {detail}" + (f"\n\n{hint}" if hint else "")


def issue(
    tls_dir: Path, cryptor: Cryptor, config: AcmeConfig, credentials: dict[str, str], *,
    lego_bin: str | None = None,
) -> CertInfo:
    """Run lego once and replace the stored certificate and sealed key.

    Nothing already stored is touched unless lego succeeds and its output checks
    out, so a failed renewal leaves the working certificate in place.
    """
    lego_bin = lego_bin or LEGO_BIN
    with issuance_lock(tls_dir), _scratch_dir() as scratch:
        env = _environment(scratch, config.provider, credentials)
        lego_path = scratch / "lego"
        argv = build_argv(config, lego_path, lego_bin)
        try:
            proc = subprocess.run(
                argv, env=env, cwd=scratch, capture_output=True, text=True,
                timeout=LEGO_TIMEOUT_SECONDS, check=False, stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            raise AcmeError(f"lego is not installed at {lego_bin}") from None
        except subprocess.TimeoutExpired:
            raise AcmeError(f"lego did not finish within {LEGO_TIMEOUT_SECONDS}s") from None
        if proc.returncode != 0:
            raise AcmeError(_failure(proc, list(credentials.values())))

        certs = lego_path / "certificates"
        try:
            cert_pem = (certs / f"{CERT_NAME}.crt").read_bytes()
            key_pem = (certs / f"{CERT_NAME}.key").read_bytes()
        except OSError as exc:
            raise AcmeError(f"lego reported success but wrote no certificate: {exc}") from exc
        return store.store_issued(tls_dir, cryptor, cert_pem, key_pem, config.domain)
