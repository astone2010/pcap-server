"""Tests for backend.main's transport-security surface: the _client_ip
regression (this exact bug was a live rate-limiter bypass -- unlimited
password guessing), the read-only-over-HTTP middleware, and the security
headers including CSP and HSTS.

conftest.py sets DATA_DIR/CAPTURES_DIR/SSH_KEYS_DIR and a master key before
this module (or anything importing backend.main) is collected, since
backend.main runs Database()/CaptureVault() at module scope and can
SystemExit(1) on a refused vault.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
import pyotp
from fastapi.testclient import TestClient

from backend.auth import create_session_token

from backend import main


def fake_request(headers: dict | None = None, client_host: str | None = "1.2.3.4", scheme: str = "http"):
    """A minimal stand-in for fastapi.Request -- _client_ip and
    _is_secure_transport only read .headers, .client.host and .url.scheme,
    so a full ASGI request is unnecessary overhead for testing them directly."""
    return SimpleNamespace(
        headers={k.lower(): v for k, v in (headers or {}).items()},
        client=SimpleNamespace(host=client_host) if client_host is not None else None,
        url=SimpleNamespace(scheme=scheme),
    )


# --- _client_ip: the rate-limiter-bypass regression -------------------------


def test_client_ip_ignores_x_forwarded_for_by_default(monkeypatch):
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", False)
    request = fake_request(headers={"x-forwarded-for": "9.9.9.9"}, client_host="1.2.3.4")
    assert main._client_ip(request) == "1.2.3.4"


def test_client_ip_falls_back_to_unknown_with_no_client(monkeypatch):
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", False)
    request = fake_request(client_host=None)
    assert main._client_ip(request) == "unknown"


def test_client_ip_uses_rightmost_forwarded_entry_when_trusted(monkeypatch):
    """The regression: trusting the LEFTMOST entry (or the header
    unconditionally) let any caller invent a fresh address per request and
    never trip the login rate limiter -- unlimited password guessing. The
    rightmost entry is the one the trusted proxy itself appended; anything
    to its left may have been supplied by the client."""
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", True)
    request = fake_request(
        headers={"x-forwarded-for": "client-supplied-garbage, 203.0.113.7"},
        client_host="10.0.0.1",  # the proxy's own address
    )
    assert main._client_ip(request) == "203.0.113.7"


def test_client_ip_a_spoofed_leftmost_entry_does_not_win(monkeypatch):
    """Same regression, phrased as the attack directly: an attacker who
    controls the leftmost X-Forwarded-For entry must not be able to make
    every request appear to come from a different address."""
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", True)
    real_client_ip = "203.0.113.7"
    for spoofed in ("1.1.1.1", "2.2.2.2", "attacker-controlled"):
        request = fake_request(
            headers={"x-forwarded-for": f"{spoofed}, {real_client_ip}"},
            client_host="10.0.0.1",
        )
        assert main._client_ip(request) == real_client_ip


def test_client_ip_skips_unparseable_entries_from_the_right(monkeypatch):
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", True)
    request = fake_request(
        headers={"x-forwarded-for": "203.0.113.7, not-an-ip"},
        client_host="10.0.0.1",
    )
    assert main._client_ip(request) == "203.0.113.7"


def test_client_ip_falls_back_to_client_host_when_header_entirely_unparseable(monkeypatch):
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", True)
    request = fake_request(
        headers={"x-forwarded-for": "not-an-ip, also-not-an-ip"},
        client_host="10.0.0.1",
    )
    assert main._client_ip(request) == "10.0.0.1"


def test_client_ip_ignores_forwarded_for_when_header_absent_even_if_trusted(monkeypatch):
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", True)
    request = fake_request(headers={}, client_host="10.0.0.1")
    assert main._client_ip(request) == "10.0.0.1"


# --- _is_secure_transport -----------------------------------------------------


def test_is_secure_transport_true_for_https_scheme(monkeypatch):
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", False)
    request = fake_request(scheme="https", client_host="1.2.3.4")
    assert main._is_secure_transport(request) is True


def test_is_secure_transport_false_for_plain_http_remote_client(monkeypatch):
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", False)
    request = fake_request(scheme="http", client_host="1.2.3.4")
    assert main._is_secure_transport(request) is False


@pytest.mark.parametrize("loopback", ["127.0.0.1", "::1", "localhost"])
def test_is_secure_transport_true_for_loopback_over_http(monkeypatch, loopback):
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", False)
    request = fake_request(scheme="http", client_host=loopback)
    assert main._is_secure_transport(request) is True


def test_is_secure_transport_trusts_forwarded_proto_only_when_configured(monkeypatch):
    request = fake_request(
        scheme="http", client_host="1.2.3.4", headers={"x-forwarded-proto": "https"}
    )
    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", False)
    assert main._is_secure_transport(request) is False

    monkeypatch.setattr(main, "_TRUST_PROXY_HEADERS", True)
    assert main._is_secure_transport(request) is True


# --- middleware: security headers, CSP, HSTS --------------------------------


@pytest.fixture()
def client():
    with TestClient(main.app) as c:
        yield c


def test_security_headers_present_on_every_response(client):
    resp = client.get("/api/auth/status")
    assert resp.status_code == 200
    for header in main._SECURITY_HEADERS:
        assert header in resp.headers

    assert resp.headers["Content-Security-Policy"] == main._CSP
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_hsts_absent_over_plain_http(client):
    resp = client.get("/api/auth/status")
    assert "Strict-Transport-Security" not in resp.headers


def test_hsts_present_over_https():
    with TestClient(main.app, base_url="https://testserver") as https_client:
        resp = https_client.get("/api/auth/status")
    assert resp.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains"


# --- middleware: read-only over plain HTTP ----------------------------------


def test_mutating_request_over_http_is_refused(client):
    """/api/servers is a POST endpoint that is not in _INSECURE_ALLOWED_PATHS,
    so this must be blocked by the middleware before it ever reaches auth --
    the 403 should come back even fully unauthenticated."""
    resp = client.post("/api/servers", json={})
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "https_required"


def test_mutating_request_over_https_is_not_blocked_by_this_middleware():
    """Still unauthenticated, so this should fail auth (401/422), not the
    read-only-over-HTTP check -- proving HTTPS lets mutating requests past
    this particular middleware."""
    with TestClient(main.app, base_url="https://testserver") as https_client:
        resp = https_client.post("/api/servers", json={})
    assert resp.status_code != 403 or resp.json().get("detail", {}).get("code") != "https_required"


@pytest.mark.parametrize(
    "path", ["/api/auth/login", "/api/auth/logout", "/api/auth/register", "/api/auth/totp/confirm"]
)
def test_insecure_allowed_paths_are_not_blocked_over_http(client, path):
    resp = client.post(path, json={})
    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    assert not (resp.status_code == 403 and body.get("detail", {}).get("code") == "https_required")


def test_get_requests_are_never_blocked_by_read_only_middleware(client):
    resp = client.get("/api/auth/status")
    assert resp.status_code == 200


# --- TOTP is enforced by the API, not just by the UI ---------------------------
#
# A first login returns needs_totp_setup and the frontend acts on it, but for a
# long time nothing on this side looked at totp_confirmed. Any client that
# ignored the flag -- curl, a script, a stale tab -- held a session backed by a
# password and nothing else, with the whole API behind it. The check lives on
# get_current_user now, so a new route cannot forget it, and the two enrolment
# endpoints opt out visibly by depending on get_session_user instead.


@pytest.fixture()
def half_enrolled(client):
    """Signed in, second factor not yet set up."""
    user_id = str(uuid.uuid4())
    main.db.create_user(user_id, f"pending-{user_id[:8]}", "scrypt$1$1$1$00$00", is_admin=True)
    token, _ = create_session_token(main.db, user_id)
    client.cookies.set("session", token)
    try:
        yield user_id
    finally:
        main.db.delete_user(user_id)


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/servers"),
        ("get", "/api/captures"),
        ("get", "/api/usernames"),
        ("get", "/api/ssh-keys"),
    ],
)
def test_a_session_without_totp_is_refused(client, half_enrolled, method, path):
    resp = getattr(client, method)(path)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "totp_setup_required"


def test_admin_routes_are_refused_before_totp_as_well(client, half_enrolled):
    """require_admin depends on get_current_user, so it inherits the gate. An
    admin account with one factor must be less reachable than a user's, not more."""
    resp = client.get("/api/admin/users")
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "totp_setup_required"


def test_enrolment_itself_stays_reachable(client, half_enrolled):
    """The one thing a half-enrolled account must be able to do."""
    resp = client.get("/api/auth/totp/setup")
    assert resp.status_code == 200
    assert resp.json()["secret"]


def test_auth_status_still_answers_for_a_half_enrolled_session(client, half_enrolled):
    """The UI bootstraps off this and routes to enrolment when it sees
    totp_confirmed false. Gating it would lock the user out of the screen that
    finishes enrolment."""
    body = client.get("/api/auth/status").json()
    assert body["authenticated"] is True
    assert body["user"]["totp_confirmed"] is False


def test_confirming_totp_opens_the_rest_of_the_api(client, half_enrolled):
    secret = client.get("/api/auth/totp/setup").json()["secret"]

    confirmed = client.post("/api/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()})
    assert confirmed.status_code == 200
    assert client.get("/api/servers").status_code == 200


def test_no_session_is_still_a_401_not_a_403(client):
    """The two refusals mean different things: 401 is "sign in", 403 here is
    "you are signed in but only halfway"."""
    client.cookies.clear()
    assert client.get("/api/servers").status_code == 401


# --- the per-interface refusal reaches the client as a 409 -------------------
#
# The manager's rule is covered in test_capture.py. What that cannot show is the
# status code: InterfaceAlreadyCapturing is a different exception from
# CaptureLimitExceeded, so if the route ever stops naming it the refusal turns
# into a blanket 500 "failed to start capture" and the reason is lost.


@pytest.fixture()
def secure_client():
    """Starting a capture changes state, and over plain HTTP that is refused
    outright (403) before the route is ever reached -- so a test about the
    route's own status code has to arrive over TLS or it only ever sees the
    transport gate."""
    with TestClient(main.app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def enrolled(secure_client):
    """Signed in with the second factor confirmed -- a usable session."""
    user_id = str(uuid.uuid4())
    main.db.create_user(user_id, f"user-{user_id[:8]}", "scrypt$1$1$1$00$00", is_admin=True)
    main.db.set_totp_secret(user_id, "A" * 32)
    main.db.confirm_totp(user_id)
    token, _ = create_session_token(main.db, user_id)
    secure_client.cookies.set("session", token)
    try:
        yield user_id
    finally:
        main.db.delete_user(user_id)


def _a_server(user_id: str) -> str:
    server_id = str(uuid.uuid4())
    main.db.add_active_server(
        server_id, user_id, "target", "target.example", 22, "alice", "alice-key", False
    )
    return server_id


def test_interface_conflict_is_a_409_naming_the_interface(secure_client, enrolled, monkeypatch):
    server_id = _a_server(enrolled)

    async def refuse(req, server, user_id):
        raise main.InterfaceAlreadyCapturing(
            "a capture is already running on eth0 on this server (friday-debug) -- "
            "stop it first, or capture a different interface"
        )

    monkeypatch.setattr(main.capture_manager, "start", refuse)
    resp = secure_client.post("/api/captures", json={"server_id": server_id, "interface": "eth0"})

    assert resp.status_code == 409
    assert "eth0" in resp.json()["detail"]
    assert "friday-debug" in resp.json()["detail"]


def test_the_concurrency_limit_is_still_a_429(secure_client, enrolled, monkeypatch):
    """The two refusals must not collapse into one status: waiting clears a
    429 and does nothing for a 409."""
    server_id = _a_server(enrolled)

    async def refuse(req, server, user_id):
        raise main.CaptureLimitExceeded("5 capture(s) already running or finishing up")

    monkeypatch.setattr(main.capture_manager, "start", refuse)
    resp = secure_client.post("/api/captures", json={"server_id": server_id, "interface": "eth0"})
    assert resp.status_code == 429
