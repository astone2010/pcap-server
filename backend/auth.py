from __future__ import annotations

import hashlib
import hmac
import io
import secrets
import uuid
from base64 import b64encode
from datetime import datetime, timedelta

import pyotp
import qrcode
import qrcode.image.svg

from backend.database import Database

SESSION_DURATION_HOURS = 8
TRUST_DURATION_DAYS = 30


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
    now = datetime.utcnow()
    expires = now + timedelta(hours=SESSION_DURATION_HOURS)
    db._conn().execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user_id, now.isoformat(), expires.isoformat()),
    )
    db._conn().commit()
    return token, expires.isoformat()


def validate_session(db: Database, token: str) -> dict | None:
    row = db._conn().execute(
        "SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
        (token, datetime.utcnow().isoformat()),
    ).fetchone()
    if not row:
        return None
    return db.get_user(row["user_id"])


def delete_session(db: Database, token: str) -> None:
    db._conn().execute("DELETE FROM sessions WHERE token = ?", (token,))
    db._conn().commit()


def cleanup_expired_sessions(db: Database) -> int:
    cur = db._conn().execute("DELETE FROM sessions WHERE expires_at <= ?", (datetime.utcnow().isoformat(),))
    db._conn().commit()
    return cur.rowcount


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
    device_id = str(uuid.uuid4())[:8]
    expires = (datetime.utcnow() + timedelta(days=TRUST_DURATION_DAYS)).isoformat()
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
