from __future__ import annotations

import hashlib
import hmac
import io
import secrets
import time
import uuid
from base64 import b64encode
from datetime import datetime, timedelta, timezone

import pyotp
import qrcode
import qrcode.image.svg

from backend.database import Database


class RateLimiter:
    def __init__(self, max_attempts: int = 5, lockout_minutes: int = 15) -> None:
        self.max_attempts = max_attempts
        self.lockout_minutes = lockout_minutes
        self._attempts: dict[str, list[float]] = {}

    def is_locked(self, key: str) -> bool:
        attempts = self._attempts.get(key, [])
        cutoff = time.monotonic() - (self.lockout_minutes * 60)
        recent = [t for t in attempts if t > cutoff]
        if recent:
            self._attempts[key] = recent
        else:
            self._attempts.pop(key, None)
        return len(recent) >= self.max_attempts

    def record_failure(self, key: str) -> None:
        if key not in self._attempts:
            self._attempts[key] = []
        self._attempts[key].append(time.monotonic())

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)

    def update_config(self, max_attempts: int, lockout_minutes: int) -> None:
        self.max_attempts = max_attempts
        self.lockout_minutes = lockout_minutes


# scrypt cost. The old format stored only salt$hash, so the parameters were
# implicit and could never be raised without invalidating every existing
# password. They are recorded in the hash now, so cost can follow the hardware.
#
# N = 2**17 is the current OWASP guidance for scrypt with r=8, p=1 -- roughly
# 128 MB and ~100 ms per verification, which is a cost an attacker pays per
# guess and a user pays once per sign-in.
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64

# What the implicit parameters used to be, for hashes written before this change.
_LEGACY_SCRYPT = (1 << 14, 8, 1, 64)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    # maxmem must be raised explicitly: hashlib's default is too small for N=2**17.
    return hashlib.scrypt(
        password.encode(), salt=salt, n=n, r=r, p=p, dklen=dklen,
        maxmem=(128 * n * r * 2),
    )


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = _scrypt(password, salt.encode(), SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verifies both the current parameterised format and the original one."""
    if stored.startswith("scrypt$"):
        try:
            _, n_s, r_s, p_s, salt, expected_hex = stored.split("$", 5)
            n, r, p = int(n_s), int(r_s), int(p_s)
        except (ValueError, TypeError):
            return False
        dklen = len(expected_hex) // 2
    else:
        parts = stored.split("$", 1)
        if len(parts) != 2:
            return False
        salt, expected_hex = parts
        n, r, p, dklen = _LEGACY_SCRYPT

    try:
        h = _scrypt(password, salt.encode(), n, r, p, dklen)
    except ValueError:
        return False
    return hmac.compare_digest(h.hex(), expected_hex)


def needs_rehash(stored: str) -> bool:
    """True when a stored hash was written with weaker parameters than current."""
    if not stored.startswith("scrypt$"):
        return True
    try:
        _, n_s, r_s, p_s, _salt, _hash = stored.split("$", 5)
        return (int(n_s), int(r_s), int(p_s)) != (SCRYPT_N, SCRYPT_R, SCRYPT_P)
    except (ValueError, TypeError):
        return True


def hash_token(token: str) -> str:
    """Sessions are looked up by digest, so the database never holds the bearer."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_session_token(db: Database, user_id: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    duration_hours = db.get_setting_int("session_duration_hours")
    expires = now + timedelta(hours=duration_hours)
    db.create_session(hash_token(token), user_id, expires.isoformat())
    return token, expires.isoformat()


def validate_session(db: Database, token: str) -> dict | None:
    """Absolute expiry is enforced in SQL; idle expiry is enforced here.

    An idle session is deleted rather than merely rejected, so it cannot be
    revived by a later request that happens to arrive inside the window.
    """
    token_hash = hash_token(token)
    session = db.get_valid_session(token_hash)
    if not session:
        return None

    idle_minutes = db.get_setting_int("session_idle_timeout_minutes")
    if idle_minutes > 0 and session.get("last_seen"):
        try:
            last_seen = datetime.fromisoformat(session["last_seen"])
        except ValueError:
            last_seen = None
        if last_seen is not None:
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - last_seen > timedelta(minutes=idle_minutes):
                db.delete_session(token_hash)
                return None

    # Only write when the stamp is actually stale. Touching on every request
    # turns each authenticated API call into a SQLite write, which on a
    # single-writer database is both wasteful and a lock-contention risk.
    _refresh_last_seen(db, token_hash, session.get("last_seen"))
    return db.get_user(session["user_id"])


# Coarser than the idle window by a wide margin, so throttling can never cause
# a session to outlive its timeout by a meaningful amount.
_LAST_SEEN_WRITE_INTERVAL = timedelta(seconds=60)


def _refresh_last_seen(db: Database, token_hash: str, last_seen: str | None) -> None:
    if last_seen:
        try:
            stamp = datetime.fromisoformat(last_seen)
        except ValueError:
            stamp = None
        if stamp is not None:
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - stamp < _LAST_SEEN_WRITE_INTERVAL:
                return
    db.touch_session(token_hash)


def delete_session(db: Database, token: str) -> None:
    db.delete_session(hash_token(token))


def cleanup_expired_sessions(db: Database) -> int:
    return db.cleanup_expired_sessions()


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "pcap-server") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.totp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def create_device_trust(db: Database, user_id: str, device_name: str = "Browser") -> str:
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    device_id = str(uuid.uuid4())
    trust_days = db.get_setting_int("device_trust_days")
    expires = (datetime.now(timezone.utc) + timedelta(days=trust_days)).isoformat()
    db.add_trusted_device(device_id, user_id, token_hash, device_name, expires)
    return token


def check_device_trust(db: Database, user_id: str, token: str) -> bool:
    if not token:
        return False
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return db.get_trusted_device_by_hash(user_id, token_hash) is not None


def generate_qr_data_uri(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    svg_bytes = buf.getvalue()
    return "data:image/svg+xml;base64," + b64encode(svg_bytes).decode()
