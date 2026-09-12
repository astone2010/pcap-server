"""Tests for backend.auth -- password hashing/migration, the bearer-token
digest boundary, idle-session deletion, the last-seen write throttle, and
RateLimiter lockout behavior."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone

import pytest

from backend import auth


# --- hash_password / verify_password ----------------------------------------


def test_hash_password_verify_round_trip():
    stored = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("correct horse battery staple", stored) is True


def test_verify_password_rejects_wrong_password():
    stored = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("wrong password", stored) is False


def test_hash_password_uses_unique_salt_each_time():
    a = auth.hash_password("same password")
    b = auth.hash_password("same password")
    assert a != b
    assert auth.verify_password("same password", a) is True
    assert auth.verify_password("same password", b) is True


def test_hash_password_stores_current_scrypt_parameters():
    stored = auth.hash_password("pw")
    prefix, n, r, p, _salt, _hash = stored.split("$", 5)
    assert prefix == "scrypt"
    assert (int(n), int(r), int(p)) == (auth.SCRYPT_N, auth.SCRYPT_R, auth.SCRYPT_P)


def _legacy_hash(password: str, salt: str) -> str:
    n, r, p, dklen = auth._LEGACY_SCRYPT
    h = hashlib.scrypt(
        password.encode(), salt=salt.encode(), n=n, r=r, p=p, dklen=dklen,
        maxmem=(128 * n * r * 2),
    )
    return f"{salt}${h.hex()}"


def test_verify_password_accepts_legacy_salt_dollar_hash_format():
    stored = _legacy_hash("legacy password", "abc123salt")
    assert auth.verify_password("legacy password", stored) is True


def test_verify_password_rejects_wrong_password_in_legacy_format():
    stored = _legacy_hash("legacy password", "abc123salt")
    assert auth.verify_password("wrong", stored) is False


@pytest.mark.parametrize(
    "garbage",
    ["", "not-a-hash", "scrypt$notanumber$8$1$salt$hash", "onlyonepart"],
)
def test_verify_password_rejects_malformed_stored_value(garbage):
    assert auth.verify_password("anything", garbage) is False


# --- needs_rehash ------------------------------------------------------------


def test_needs_rehash_false_for_current_hash():
    stored = auth.hash_password("pw")
    assert auth.needs_rehash(stored) is False


def test_needs_rehash_true_for_legacy_format():
    stored = _legacy_hash("pw", "salt")
    assert auth.needs_rehash(stored) is True


def test_needs_rehash_true_for_weaker_scrypt_parameters():
    stored = f"scrypt${1 << 10}$8$1$salt$" + "aa" * 64
    assert auth.needs_rehash(stored) is True


def test_needs_rehash_true_for_malformed_value():
    assert auth.needs_rehash("scrypt$not$valid$ints$salt$hash") is True


# --- hash_token: the DB never holds the bearer ------------------------------


def test_hash_token_is_sha256_digest_not_the_token():
    token = "super-secret-bearer-token"
    digest = auth.hash_token(token)
    assert digest == hashlib.sha256(token.encode()).hexdigest()
    assert digest != token


def test_hash_token_deterministic():
    token = "same-token"
    assert auth.hash_token(token) == auth.hash_token(token)


def test_hash_token_differs_for_different_tokens():
    assert auth.hash_token("token-a") != auth.hash_token("token-b")


# --- validate_session: idle timeout deletes the session ---------------------


class FakeSessionDB:
    def __init__(self, session: dict | None, idle_timeout_minutes: int) -> None:
        self._session = session
        self._idle_timeout_minutes = idle_timeout_minutes
        self.deleted: list[str] = []
        self.touched: list[str] = []

    def get_valid_session(self, token_hash: str) -> dict | None:
        return self._session

    def get_setting_int(self, key: str) -> int:
        assert key == "session_idle_timeout_minutes"
        return self._idle_timeout_minutes

    def delete_session(self, token_hash: str) -> None:
        self.deleted.append(token_hash)
        self._session = None

    def touch_session(self, token_hash: str) -> None:
        self.touched.append(token_hash)

    def get_user(self, user_id: str) -> dict:
        return {"id": user_id, "username": "someone"}


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def test_validate_session_returns_none_when_no_session():
    db = FakeSessionDB(session=None, idle_timeout_minutes=30)
    assert auth.validate_session(db, "any-token") is None


def test_validate_session_deletes_and_returns_none_past_idle_timeout():
    stale = datetime.now(timezone.utc) - timedelta(minutes=31)
    session = {"user_id": "u1", "last_seen": _iso(stale)}
    db = FakeSessionDB(session=session, idle_timeout_minutes=30)

    result = auth.validate_session(db, "some-token")

    assert result is None
    assert db.deleted == [auth.hash_token("some-token")]
    assert db.touched == []  # deleted, never touched


def test_validate_session_succeeds_within_idle_window():
    recent = datetime.now(timezone.utc) - timedelta(minutes=5)
    session = {"user_id": "u1", "last_seen": _iso(recent)}
    db = FakeSessionDB(session=session, idle_timeout_minutes=30)

    result = auth.validate_session(db, "some-token")

    assert result == {"id": "u1", "username": "someone"}
    assert db.deleted == []


def test_validate_session_idle_timeout_disabled_when_zero():
    ancient = datetime.now(timezone.utc) - timedelta(days=365)
    session = {"user_id": "u1", "last_seen": _iso(ancient)}
    db = FakeSessionDB(session=session, idle_timeout_minutes=0)

    result = auth.validate_session(db, "some-token")

    assert result == {"id": "u1", "username": "someone"}
    assert db.deleted == []


def test_validate_session_handles_naive_last_seen_as_utc():
    # last_seen without tzinfo, as sqlite's isoformat storage can produce
    stale_naive = (datetime.now(timezone.utc) - timedelta(minutes=31)).replace(tzinfo=None)
    session = {"user_id": "u1", "last_seen": stale_naive.isoformat()}
    db = FakeSessionDB(session=session, idle_timeout_minutes=30)

    result = auth.validate_session(db, "some-token")

    assert result is None
    assert db.deleted


# --- _LAST_SEEN_WRITE_INTERVAL throttle --------------------------------------


def test_validate_session_does_not_touch_when_last_seen_is_fresh():
    fresh = datetime.now(timezone.utc) - timedelta(seconds=5)
    session = {"user_id": "u1", "last_seen": _iso(fresh)}
    db = FakeSessionDB(session=session, idle_timeout_minutes=30)

    auth.validate_session(db, "some-token")

    assert db.touched == []


def test_validate_session_touches_when_last_seen_exceeds_write_interval():
    stale_enough = datetime.now(timezone.utc) - timedelta(
        seconds=auth._LAST_SEEN_WRITE_INTERVAL.total_seconds() + 5
    )
    session = {"user_id": "u1", "last_seen": _iso(stale_enough)}
    db = FakeSessionDB(session=session, idle_timeout_minutes=30)

    auth.validate_session(db, "some-token")

    assert db.touched == [auth.hash_token("some-token")]


def test_validate_session_touches_when_last_seen_missing():
    session = {"user_id": "u1", "last_seen": None}
    db = FakeSessionDB(session=session, idle_timeout_minutes=30)

    auth.validate_session(db, "some-token")

    assert db.touched == [auth.hash_token("some-token")]


# --- RateLimiter: lockout and window expiry ---------------------------------


def test_rate_limiter_not_locked_before_max_attempts():
    limiter = auth.RateLimiter(max_attempts=3, lockout_minutes=15)
    limiter.record_failure("1.2.3.4")
    limiter.record_failure("1.2.3.4")
    assert limiter.is_locked("1.2.3.4") is False


def test_rate_limiter_locks_at_max_attempts():
    limiter = auth.RateLimiter(max_attempts=3, lockout_minutes=15)
    for _ in range(3):
        limiter.record_failure("1.2.3.4")
    assert limiter.is_locked("1.2.3.4") is True


def test_rate_limiter_is_keyed_independently():
    limiter = auth.RateLimiter(max_attempts=2, lockout_minutes=15)
    limiter.record_failure("attacker")
    limiter.record_failure("attacker")
    assert limiter.is_locked("attacker") is True
    assert limiter.is_locked("someone-else") is False


def test_rate_limiter_reset_clears_attempts():
    limiter = auth.RateLimiter(max_attempts=2, lockout_minutes=15)
    limiter.record_failure("1.2.3.4")
    limiter.record_failure("1.2.3.4")
    assert limiter.is_locked("1.2.3.4") is True

    limiter.reset("1.2.3.4")

    assert limiter.is_locked("1.2.3.4") is False


def test_rate_limiter_window_expiry_via_monkeypatched_clock(monkeypatch):
    limiter = auth.RateLimiter(max_attempts=2, lockout_minutes=15)
    fake_now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: fake_now[0])

    limiter.record_failure("1.2.3.4")
    limiter.record_failure("1.2.3.4")
    assert limiter.is_locked("1.2.3.4") is True

    # advance past the lockout window
    fake_now[0] += 15 * 60 + 1
    assert limiter.is_locked("1.2.3.4") is False


def test_rate_limiter_update_config_changes_thresholds():
    limiter = auth.RateLimiter(max_attempts=5, lockout_minutes=15)
    limiter.update_config(max_attempts=1, lockout_minutes=1)
    limiter.record_failure("1.2.3.4")
    assert limiter.is_locked("1.2.3.4") is True
