"""Tests for backend.auth -- password hashing/migration, the bearer-token
digest boundary, idle-session deletion, the last-seen write throttle,
RateLimiter lockout behavior, and SlidingWindowLimiter's per-minute cap."""

from __future__ import annotations

import asyncio
import hashlib
import threading
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


# --- SlidingWindowLimiter: per-minute cap, no lockout ------------------------


def test_sliding_window_allows_up_to_the_limit():
    limiter = auth.SlidingWindowLimiter(max_per_minute=3)
    assert limiter.allow("user-1") is True
    assert limiter.allow("user-1") is True
    assert limiter.allow("user-1") is True


def test_sliding_window_refuses_the_call_over_the_limit():
    limiter = auth.SlidingWindowLimiter(max_per_minute=2)
    assert limiter.allow("user-1") is True
    assert limiter.allow("user-1") is True
    assert limiter.allow("user-1") is False


def test_sliding_window_does_not_lock_out_on_success():
    """Unlike RateLimiter, there is no failure/reset distinction -- every
    allowed call counts, and there is nothing to reset. A refused call must
    not itself count twice against the window."""
    limiter = auth.SlidingWindowLimiter(max_per_minute=1)
    assert limiter.allow("user-1") is True
    assert limiter.allow("user-1") is False
    assert limiter.allow("user-1") is False


def test_sliding_window_is_keyed_independently():
    limiter = auth.SlidingWindowLimiter(max_per_minute=1)
    assert limiter.allow("user-1") is True
    assert limiter.allow("user-1") is False
    assert limiter.allow("user-2") is True


def test_sliding_window_expiry_via_monkeypatched_clock(monkeypatch):
    limiter = auth.SlidingWindowLimiter(max_per_minute=1)
    fake_now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: fake_now[0])

    assert limiter.allow("user-1") is True
    assert limiter.allow("user-1") is False

    # advance past the 60-second window
    fake_now[0] += 61
    assert limiter.allow("user-1") is True


def test_sliding_window_update_config_changes_threshold():
    limiter = auth.SlidingWindowLimiter(max_per_minute=5)
    limiter.update_config(max_per_minute=1)
    assert limiter.allow("user-1") is True
    assert limiter.allow("user-1") is False


# --- constant-cost verification for an unknown username ----------------------
#
# login() used to short-circuit: `bool(user) and verify_password(...)`. A
# username that does not exist skipped scrypt entirely and answered in
# microseconds, where a real one took ~100ms. That difference is a username
# oracle anyone who can reach the login endpoint can measure.


def test_verify_absent_user_is_always_false():
    assert auth.verify_absent_user("anything at all") is False
    assert auth.verify_absent_user("") is False


def test_absent_user_hash_is_in_the_current_format():
    """It has to go down verify_password's current-format path, or it would not
    cost what a real verification costs."""
    prefix, n, r, p, salt, digest = auth._ABSENT_USER_HASH.split("$", 5)
    assert prefix == "scrypt"
    assert (int(n), int(r), int(p)) == (auth.SCRYPT_N, auth.SCRYPT_R, auth.SCRYPT_P)
    assert len(digest) == auth.SCRYPT_DKLEN * 2
    assert len(salt) == 32  # what secrets.token_hex(16) produces


def test_absent_user_costs_the_same_scrypt_work_as_a_real_account(monkeypatch):
    """Asserted on the parameters, not the clock: a wall-clock comparison is a
    flaky test on shared CI, and the parameters are what actually decide the
    cost."""
    calls: list[tuple] = []
    real = auth._scrypt

    def spy(password, salt, n, r, p, dklen):
        calls.append((n, r, p, dklen))
        return real(password, salt, n, r, p, dklen)

    monkeypatch.setattr(auth, "_scrypt", spy)

    auth.verify_password("pw", auth.hash_password("pw"))
    auth.verify_absent_user("pw")

    # hash_password, then the real verify, then the absent-user verify.
    assert calls[-1] == calls[-2]


# --- limiter state is bounded ------------------------------------------------


def test_rate_limiter_prune_drops_keys_whose_attempts_aged_out():
    limiter = auth.RateLimiter(max_attempts=5, lockout_minutes=15)
    limiter.record_failure("198.51.100.1")
    limiter.record_failure("198.51.100.2")
    assert len(limiter._attempts) == 2

    # An hour later, nothing recorded is still inside a 15-minute window.
    limiter.prune(now=time.monotonic() + 3600)
    assert limiter._attempts == {}


def test_rate_limiter_prune_keeps_keys_still_inside_the_window():
    limiter = auth.RateLimiter(max_attempts=5, lockout_minutes=15)
    limiter.record_failure("198.51.100.1")
    limiter.prune()
    assert "198.51.100.1" in limiter._attempts


def test_sliding_window_limiter_prune_drops_stale_keys():
    limiter = auth.SlidingWindowLimiter(max_per_minute=5)
    limiter.allow("user-a")
    limiter.allow("user-b")
    assert len(limiter._hits) == 2

    limiter.prune(now=time.monotonic() + 120)
    assert limiter._hits == {}


def test_sliding_window_limiter_prune_keeps_keys_inside_the_window():
    limiter = auth.SlidingWindowLimiter(max_per_minute=5)
    limiter.allow("user-a")
    limiter.prune()
    assert "user-a" in limiter._hits


# --- scrypt concurrency gate (H1: unauthenticated login memory exhaustion) ----


def _make_concurrency_tracker():
    """A drop-in for a scrypt call that records peak concurrent entries.

    Runs in a worker thread (asyncio.to_thread), so the counter is guarded by a
    lock; the sleep forces overlap so the peak is meaningful.
    """
    lock = threading.Lock()
    state = {"current": 0, "peak": 0}

    def enter():
        with lock:
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
        time.sleep(0.05)
        with lock:
            state["current"] -= 1

    return state, enter


async def test_scrypt_gate_bounds_concurrent_verifications(monkeypatch):
    """The semaphore caps how many scrypt verifications run at once, however many
    are requested. This is the bound the login rate limiter is not: it counts
    failures, and a failure is only recorded after the hash -- so a flood of
    simultaneous logins would otherwise allocate ~256 MB each in parallel."""
    limit = 3
    monkeypatch.setattr(auth, "_scrypt_gate", asyncio.Semaphore(limit))
    state, enter = _make_concurrency_tracker()

    def fake_verify(password, stored):
        enter()
        return False

    monkeypatch.setattr(auth, "verify_password", fake_verify)

    await asyncio.gather(
        *(auth.verify_password_async("pw", "stored") for _ in range(15))
    )

    # Never exceeded the cap, and with 15 requests against a cap of 3 it actually
    # reached it -- so the bound is real, not an artifact of too little load.
    assert state["peak"] == limit


async def test_scrypt_gate_is_shared_across_present_and_absent_paths(monkeypatch):
    """Both login branches -- real user (verify_password) and unknown user
    (verify_absent_user) -- go through the one gate, so neither can starve the
    other and the constant-time login property holds under load."""
    limit = 2
    monkeypatch.setattr(auth, "_scrypt_gate", asyncio.Semaphore(limit))
    state, enter = _make_concurrency_tracker()

    def fake_verify(password, stored):
        enter()
        return False

    def fake_absent(password):
        enter()
        return False

    monkeypatch.setattr(auth, "verify_password", fake_verify)
    monkeypatch.setattr(auth, "verify_absent_user", fake_absent)

    mixed = []
    for i in range(12):
        if i % 2:
            mixed.append(auth.verify_password_async("pw", "stored"))
        else:
            mixed.append(auth.verify_absent_user_async("pw"))
    await asyncio.gather(*mixed)

    assert state["peak"] == limit


def test_scrypt_concurrency_env_override(monkeypatch):
    monkeypatch.setenv("PCAP_SCRYPT_CONCURRENCY", "7")
    assert auth._scrypt_concurrency() == 7
    monkeypatch.setenv("PCAP_SCRYPT_CONCURRENCY", "0")
    assert auth._scrypt_concurrency() == 4  # non-positive falls back to the default
    monkeypatch.setenv("PCAP_SCRYPT_CONCURRENCY", "nonsense")
    assert auth._scrypt_concurrency() == 4  # unparseable falls back too
