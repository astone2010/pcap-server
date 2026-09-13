"""Shared fixtures-by-function for the built-in HTTPS tests."""

from __future__ import annotations

import os
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from backend.crypto import Cryptor
from backend.tls import store

TOKEN = "cf_TestToken_0123456789abcdefghijklmnop"
DOMAIN = "pcap.example.com"
EMAIL = "admin@example.com"
CREDS = {"CF_DNS_API_TOKEN": TOKEN}


class FakeVault:
    def __init__(self, mode: str, cryptor: Cryptor | None = None):
        self.mode = mode
        self.enabled = mode != "disabled"
        self.cryptor = cryptor


def make_pair(domain: str = DOMAIN, days: int = 90) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()),
    )


def store_pair(tls_dir: Path, cryptor: Cryptor, cert: bytes, key: bytes) -> None:
    store.ensure_tls_dir(tls_dir)
    (tls_dir / store.CERT_FILE).write_bytes(cert)
    (tls_dir / store.KEY_FILE).write_bytes(cryptor.seal_bytes(key))


def write_stub_lego(tmp_path: Path, *, exit_code: int = 0, cert: bytes = b"", key: bytes = b"",
                    stderr: str = "") -> tuple[Path, Path]:
    """A lego stand-in. Records argv, env, cwd, and any credential files it was pointed at."""
    record = tmp_path / "record.json"
    (tmp_path / "stub-cert.pem").write_bytes(cert)
    (tmp_path / "stub-key.pem").write_bytes(key)
    stub = tmp_path / "lego"
    stub.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import json, os, sys
        from pathlib import Path
        args = sys.argv[1:]
        opts = dict(a[2:].split("=", 1) for a in args if a.startswith("--") and "=" in a)
        files = {{}}
        for k, v in os.environ.items():
            if v.startswith("/") and Path(v).is_file() and "credentials" in v:
                files[k] = {{"content": Path(v).read_text(), "mode": oct(Path(v).stat().st_mode & 0o777)}}
        Path({str(record)!r}).write_text(json.dumps({{
            "argv": args, "env": dict(os.environ), "cwd": os.getcwd(), "files": files,
            "stdin_tty": sys.stdin.isatty(),
        }}))
        sys.stderr.write({stderr!r})
        if {exit_code}:
            sys.exit({exit_code})
        certs = Path(opts["path"]) / "certificates"
        certs.mkdir(parents=True)
        (certs / "pcap-server.crt").write_bytes(Path({str(tmp_path / "stub-cert.pem")!r}).read_bytes())
        (certs / "pcap-server.key").write_bytes(Path({str(tmp_path / "stub-key.pem")!r}).read_bytes())
        """))
    stub.chmod(0o755)
    return stub, record
