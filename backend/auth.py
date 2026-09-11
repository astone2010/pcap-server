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


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=64)
    return f"{salt}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    parts = stored.split("$", 1)
    if len(parts) != 2:
        return False
    salt, expected_hex = parts
    h = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=64)
    return hmac.compare_digest(h.hex(), expected_hex)


def create_session_token(db: Database, user_id: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    duration_hours = db.get_setting_int("session_duration_hours")
    expires = now + timedelta(hours=duration_hours)
    db.create_session(token, user_id, expires.isoformat())
    return token, expires.isoformat()


def validate_session(db: Database, token: str) -> dict | None:
    session = db.get_valid_session(token)
    if not session:
        return None
    return db.get_user(session["user_id"])


def delete_session(db: Database, token: str) -> None:
    db.delete_session(token)


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
