"""What built-in HTTPS keeps on the data volume, and the only code that writes it.

Everything lives in DATA_DIR/tls (mode 0700):

    fullchain.pem          the certificate chain. Public by nature; not sealed.
    privkey.pem.enc        the private key, sealed under the master key with the
                           same envelope as captures and SSH keys.
    dns-credentials.enc    the DNS provider's settings as JSON, sealed the same
                           way. A token that can edit a DNS zone is
                           master-key-class material.
    acme.json              domain, email, provider code, staging flag.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID

from backend.crypto import CryptoError, Cryptor
from backend.tls import providers
from backend.tls.errors import AcmeError

CERT_FILE = "fullchain.pem"
KEY_FILE = "privkey.pem.enc"
CREDENTIALS_FILE = "dns-credentials.enc"
CONFIG_FILE = "acme.json"
LOCK_FILE = ".lock"

RENEW_WITHIN_DAYS = 30


# --- validation -------------------------------------------------------------

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"(?:{_LABEL}\.)+[a-z][a-z0-9-]{{0,61}}[a-z0-9]")
_EMAIL_LOCAL_RE = re.compile(r"[a-z0-9_+][a-z0-9._+%-]{0,63}")


def validate_domain(value: str) -> str:
    """A fully qualified hostname: dot-separated labels, nothing else.

    No wildcard, no port, no trailing dot, no IP address (Let's Encrypt will not
    issue for one), and nothing that can start with a hyphen -- a value that
    reaches lego's argv must never be readable as a flag.
    """
    v = (value or "").strip().lower() if isinstance(value, str) else ""
    if len(v) > 253 or not _DOMAIN_RE.fullmatch(v):
        raise ValueError(
            "domain must be a fully qualified hostname such as pcap.example.com -- "
            "letters, digits, hyphens and dots only, no wildcard, no port"
        )
    return v


def validate_email(value: str) -> str:
    v = (value or "").strip().lower() if isinstance(value, str) else ""
    local, sep, domain = v.partition("@")
    if not sep or len(v) > 254 or not _EMAIL_LOCAL_RE.fullmatch(local):
        raise ValueError("email must be a plain address such as you@example.com")
    try:
        validate_domain(domain)
    except ValueError:
        raise ValueError("email must be a plain address such as you@example.com") from None
    return v


# --- stored settings --------------------------------------------------------

@dataclass(frozen=True)
class AcmeConfig:
    domain: str
    email: str
    provider: str
    staging: bool = False

    @classmethod
    def validated(cls, domain: str, email: str, provider: str, staging: bool = False) -> "AcmeConfig":
        return cls(
            domain=validate_domain(domain),
            email=validate_email(email),
            provider=providers.get(provider).code,
            staging=bool(staging),
        )


def ensure_tls_dir(tls_dir: Path) -> Path:
    tls_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    tls_dir.chmod(0o700)
    return tls_dir


def write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".partial")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def load_config(tls_dir: Path) -> AcmeConfig | None:
    try:
        raw = json.loads((tls_dir / CONFIG_FILE).read_text())
        return AcmeConfig.validated(raw["domain"], raw["email"], raw["provider"], raw.get("staging", False))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise AcmeError(f"{tls_dir / CONFIG_FILE} is unreadable: {exc}") from exc


def save_config(tls_dir: Path, config: AcmeConfig) -> None:
    ensure_tls_dir(tls_dir)
    body = {"domain": config.domain, "email": config.email,
            "provider": config.provider, "staging": config.staging}
    write_atomic(tls_dir / CONFIG_FILE, json.dumps(body, indent=2).encode())


def has_credentials(tls_dir: Path) -> bool:
    return (tls_dir / CREDENTIALS_FILE).is_file()


def save_credentials(tls_dir: Path, cryptor: Cryptor, provider: str, values: dict[str, str]) -> None:
    clean = providers.validate_credentials(provider, values)
    ensure_tls_dir(tls_dir)
    body = json.dumps({"provider": provider, "values": clean}).encode()
    write_atomic(tls_dir / CREDENTIALS_FILE, cryptor.seal_bytes(body))


def load_credentials(tls_dir: Path, cryptor: Cryptor) -> tuple[str, dict[str, str]]:
    path = tls_dir / CREDENTIALS_FILE
    if not path.is_file():
        return "", {}
    try:
        raw = json.loads(cryptor.open_bytes(path))
        provider = raw["provider"]
        return provider, providers.validate_credentials(provider, raw["values"])
    except (CryptoError, ValueError, KeyError, TypeError) as exc:
        raise AcmeError(f"the stored DNS credentials could not be opened: {exc}") from exc


# --- certificate ------------------------------------------------------------

@dataclass(frozen=True)
class CertInfo:
    names: tuple[str, ...]
    not_after: datetime
    issuer: str
    fingerprint: str

    @property
    def days_left(self) -> int:
        return int((self.not_after - datetime.now(timezone.utc)).total_seconds() // 86400)

    @property
    def staging(self) -> bool:
        return "staging" in self.issuer.lower()

    def as_dict(self) -> dict:
        return {
            "names": list(self.names),
            "not_after": self.not_after.isoformat(),
            "days_left": self.days_left,
            "issuer": self.issuer,
            "staging": self.staging,
            "fingerprint": self.fingerprint,
        }


def cert_info(pem: bytes) -> CertInfo:
    cert = x509.load_pem_x509_certificates(pem)[0]
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names = tuple(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = ()
    issuer = ", ".join(a.value for a in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                       + cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))
    return CertInfo(
        names=names,
        not_after=cert.not_valid_after_utc,
        issuer=issuer or cert.issuer.rfc4514_string(),
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
    )


def stored_cert_info(tls_dir: Path) -> CertInfo | None:
    try:
        return cert_info((tls_dir / CERT_FILE).read_bytes())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise AcmeError(f"{tls_dir / CERT_FILE} is not a readable certificate: {exc}") from exc


def has_material(tls_dir: Path) -> bool:
    return (tls_dir / CERT_FILE).is_file() and (tls_dir / KEY_FILE).is_file()


def open_key(tls_dir: Path, cryptor: Cryptor) -> bytes:
    """The private key's PEM, in memory. Callers must not write it to disk."""
    return cryptor.open_bytes(tls_dir / KEY_FILE)


def store_issued(tls_dir: Path, cryptor: Cryptor, cert_pem: bytes, key_pem: bytes, domain: str) -> CertInfo:
    """Check the pair, then replace what is stored. Nothing changes on a bad pair."""
    try:
        cert = x509.load_pem_x509_certificates(cert_pem)[0]
        key = serialization.load_pem_private_key(key_pem, password=None)
    except ValueError as exc:
        raise AcmeError(f"lego produced unreadable material: {exc}") from exc
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    if cert.public_key().public_bytes(der, pub) != key.public_key().public_bytes(der, pub):
        raise AcmeError("the issued certificate does not match its private key")
    info = cert_info(cert_pem)
    if domain not in info.names:
        raise AcmeError(f"the issued certificate does not name {domain} (it names {info.names})")
    ensure_tls_dir(tls_dir)
    write_atomic(tls_dir / KEY_FILE, cryptor.seal_bytes(key_pem))
    write_atomic(tls_dir / CERT_FILE, cert_pem)
    return info


def renewal_due(info: CertInfo, *, within_days: int = RENEW_WITHIN_DAYS) -> bool:
    return info.days_left < within_days


def remove_all(tls_dir: Path) -> list[str]:
    removed = []
    for name in (CERT_FILE, KEY_FILE, CREDENTIALS_FILE, CONFIG_FILE):
        path = tls_dir / name
        if path.exists():
            path.unlink()
            removed.append(name)
    return removed
