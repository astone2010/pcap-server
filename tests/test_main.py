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

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import pyotp
from fastapi.testclient import TestClient

from backend.auth import SlidingWindowLimiter, create_session_token

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


def test_api_responses_are_not_cached(client):
    """API responses carry per-user state and must not sit in a shared or disk
    cache. The middleware sets no-store for every /api/ path."""
    resp = client.get("/api/auth/status")
    assert resp.headers.get("Cache-Control") == "no-store"


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


def test_version_is_withheld_from_a_password_only_session(client, half_enrolled):
    """The running version tells whoever holds it which build to match advisories
    against, so it is gated behind both factors -- not just the password. A
    half-enrolled session is authenticated but has not proved TOTP, exactly the
    threshold the gate sits above."""
    body = client.get("/api/auth/status").json()
    assert body["authenticated"] is True
    assert body["version"] == ""
    assert body["release_notes_url"] == ""


def test_version_is_shown_once_totp_is_confirmed(client, half_enrolled):
    secret = client.get("/api/auth/totp/setup").json()["secret"]
    client.post("/api/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()})
    body = client.get("/api/auth/status").json()
    assert body["version"] == main.APP_VERSION
    assert body["version"] != ""


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


def _a_server(user_id: str, *, verified: bool = True) -> str:
    """An ordinary, usable server.

    Verified by default because that is what the add flow now produces: it
    probes the host and records the self-target check before creating the row.
    Pass verified=False for the other case the flow can produce -- a server
    pre-staged while its host was unreachable, which nothing has ever connected
    to and which the capture gate refuses.
    """
    server_id = str(uuid.uuid4())
    main.db.add_active_server(
        server_id, user_id, "target", "target.example", 22, "alice", "alice-key", False,
        kernel_verified_at=(
            datetime.now(timezone.utc).isoformat() if verified else ""
        ),
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


# --- per-user rate limits on capture start and packet listing ---------------
#
# Both endpoints do real work per call -- capture start opens an SSH
# connection, packet listing spawns tshark -- so each gets its own
# SlidingWindowLimiter (backend/auth.py), keyed on the caller's user id. These
# tests prove the limiter trips *before* that work happens, not just that a
# 429 eventually comes back.


def test_capture_start_rate_limit_returns_429_before_opening_ssh(secure_client, enrolled, monkeypatch):
    server_id = _a_server(enrolled)
    called = False

    async def should_not_run(req, server, user_id):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(main.capture_manager, "start", should_not_run)
    monkeypatch.setattr(main, "capture_start_rate_limiter", SlidingWindowLimiter(max_per_minute=0))

    resp = secure_client.post("/api/captures", json={"server_id": server_id, "interface": "eth0"})

    assert resp.status_code == 429
    assert called is False


def test_packet_list_rate_limit_returns_429_before_spawning_tshark(secure_client, enrolled, monkeypatch):
    called = False

    def should_not_run(capture_id):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(main.capture_manager, "get", should_not_run)
    monkeypatch.setattr(main, "packet_rate_limiter", SlidingWindowLimiter(max_per_minute=0))

    resp = secure_client.get("/api/captures/some-capture-id/packets")

    assert resp.status_code == 429
    assert called is False


def test_a_column_field_shaped_like_a_flag_never_reaches_the_capture(
    secure_client, enrolled, monkeypatch
):
    """The packet list re-checks the field names on every call rather than
    trusting that they were checked when the layout was saved: this query
    string is the caller's, not the layout's, and `-r` as a `-e` argument is
    the flag that chooses which file tshark opens."""
    called = False

    def should_not_run(capture_id):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(main.capture_manager, "get", should_not_run)

    resp = secure_client.get("/api/captures/some-capture-id/packets?columns=-r")

    assert resp.status_code == 400
    assert "-r" in resp.json()["detail"]
    assert called is False, "the capture was looked up before the field names were checked"


def test_protocol_hierarchy_rate_limit_returns_429_before_spawning_tshark(
    secure_client, enrolled, monkeypatch
):
    called = False

    def should_not_run(capture_id):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(main.capture_manager, "get", should_not_run)
    monkeypatch.setattr(main, "packet_rate_limiter", SlidingWindowLimiter(max_per_minute=0))

    resp = secure_client.get("/api/captures/some-capture-id/protocol-hierarchy")

    assert resp.status_code == 429
    assert called is False


def test_conversations_rate_limit_returns_429_before_spawning_tshark(
    secure_client, enrolled, monkeypatch
):
    called = False

    def should_not_run(capture_id):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(main.capture_manager, "get", should_not_run)
    monkeypatch.setattr(main, "packet_rate_limiter", SlidingWindowLimiter(max_per_minute=0))

    resp = secure_client.get("/api/captures/some-capture-id/conversations")

    assert resp.status_code == 429
    assert called is False


def test_follow_stream_rate_limit_returns_429_before_spawning_tshark(
    secure_client, enrolled, monkeypatch
):
    called = False

    def should_not_run(capture_id):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(main.capture_manager, "get", should_not_run)
    monkeypatch.setattr(main, "packet_rate_limiter", SlidingWindowLimiter(max_per_minute=0))

    resp = secure_client.get("/api/captures/some-capture-id/stream/tcp/0")

    assert resp.status_code == 429
    assert called is False


def test_follow_stream_refuses_an_unknown_protocol(secure_client, enrolled):
    """Checked before the rate limiter or the capture lookup: a bogus
    protocol is never going to be accepted, whatever else is true of the
    request, and get_follow_stream itself only asserts tcp/udp rather than
    reporting a clean 400 -- the route is where that has to be caught."""
    resp = secure_client.get("/api/captures/some-capture-id/stream/sctp/0")
    assert resp.status_code == 400


def test_admin_settings_update_propagates_to_new_rate_limiters(secure_client, enrolled):
    """admin_update_setting must route these two keys to the new limiters, the
    same way it already routes rate_limit_max_attempts/lockout_minutes to
    RateLimiter -- a typo in that if/elif silently leaves a limiter frozen at
    its default forever, since these singletons are built once at import."""
    original_packets = main.packet_rate_limiter.max_per_minute
    original_captures = main.capture_start_rate_limiter.max_per_minute
    try:
        resp = secure_client.put(
            "/api/admin/settings", json={"key": "rate_limit_packets_per_min", "value": "7"}
        )
        assert resp.status_code == 200
        assert main.packet_rate_limiter.max_per_minute == 7

        resp = secure_client.put(
            "/api/admin/settings", json={"key": "rate_limit_captures_per_min", "value": "3"}
        )
        assert resp.status_code == 200
        assert main.capture_start_rate_limiter.max_per_minute == 3
    finally:
        main.db.set_setting("rate_limit_packets_per_min", str(original_packets))
        main.db.set_setting("rate_limit_captures_per_min", str(original_captures))
        main.packet_rate_limiter.update_config(original_packets)
        main.capture_start_rate_limiter.update_config(original_captures)


def test_csp_hash_matches_the_inline_script():
    """The pinned hash must be the hash of the script actually in the page.

    script-src carries no 'unsafe-inline', so the pre-paint theme script runs
    only if its hash is listed exactly. A drift between the two is invisible
    server-side and nearly invisible client-side -- the browser drops the script
    without failing anything, and the page just flashes the wrong theme on every
    load. Nothing else in the suite would notice, which is how it would ship.

    Comments are stripped before extracting, because the comment above the
    script contains the literal tags a naive split would land on.
    """
    import re
    from pathlib import Path

    html = (Path(__file__).parent.parent / "frontend" / "index.html").read_text(encoding="utf-8")
    body = re.search(r"<script>(.*?)</script>", re.sub(r"<!--.*?-->", "", html, flags=re.S), re.S)
    assert body, "no inline <script> found in index.html"

    digest = base64.b64encode(hashlib.sha256(body.group(1).encode()).digest()).decode()
    expected = f"'sha256-{digest}'"
    assert expected in main._CSP, (
        f"CSP does not list the inline script's hash.\n"
        f"  script-src expects: {expected}\n"
        f"  update _CSP in backend/main.py to match"
    )


# --- host-key endpoints: a model, not a hand-parsed dict --------------------


@pytest.mark.parametrize(
    "kwargs, label",
    [
        ({"json": []}, "a JSON array"),
        ({"json": "nope"}, "a bare JSON string"),
        ({"json": 5}, "a bare JSON number"),
        ({"content": b"{not json", "headers": {"Content-Type": "application/json"}}, "not JSON"),
        ({"content": b"", "headers": {"Content-Type": "application/json"}}, "an empty body"),
    ],
)
def test_a_malformed_host_key_body_is_a_422_not_a_500(secure_client, enrolled, kwargs, label):
    """These two routes read their body as a raw dict and answered 500.

    `await request.json()` raises on anything that is not JSON, and `.get` on
    anything that is JSON but not an object -- neither was caught, so four
    different shapes of bad input came back as server errors. A 500 says the
    server is broken; every one of these is the caller's mistake.
    """
    resp = secure_client.post("/api/admin/known-hosts/forget", **kwargs)
    assert resp.status_code == 422, f"{label} produced {resp.status_code}"


def test_the_model_rules_are_actually_wired_to_the_route(secure_client, enrolled):
    """One case each, to prove the model is on the route.

    The exhaustive table of hostnames and ports is checked against the model
    itself in test_servers.py; repeating it over HTTP would test pydantic
    twice and the wiring once.
    """
    assert secure_client.post(
        "/api/admin/known-hosts/forget", json={"hostname": "a;rm -rf /", "port": 22}
    ).status_code == 422
    assert secure_client.post(
        "/api/admin/known-hosts/forget", json={"hostname": "ok.example", "port": 70000}
    ).status_code == 422


def test_a_well_formed_host_key_body_still_reaches_the_endpoint(secure_client, enrolled):
    """The model must not have narrowed the happy path.

    404 is the endpoint answering: nothing is stored for that host. Anything
    else would mean validation is now refusing input it used to accept.
    """
    resp = secure_client.post(
        "/api/admin/known-hosts/forget", json={"hostname": "nothing.example", "port": 22}
    )
    assert resp.status_code == 404


# --- middleware: a body is refused on its headers ---------------------------


def test_an_oversized_body_is_refused_before_it_is_parsed(secure_client, enrolled):
    resp = secure_client.post(
        "/api/admin/known-hosts/forget",
        content=b"x" * (main._MAX_BODY_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert "too large" in resp.json()["detail"]


def test_the_upload_route_has_its_own_larger_limit(secure_client, enrolled):
    """A private key is bigger than any JSON this API takes, so one cap cannot
    serve both. The upload's own 64 KB check still applies after this one."""
    assert main._body_limit("/api/admin/ssh-keys") == main._MAX_UPLOAD_BYTES
    assert main._body_limit("/api/servers") == main._MAX_BODY_BYTES

    resp = secure_client.post(
        "/api/admin/ssh-keys",
        content=b"x" * (main._MAX_UPLOAD_BYTES + 1),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert resp.status_code == 413


def test_a_body_within_the_upload_limit_gets_past_the_middleware(secure_client, enrolled):
    """Between the two caps: refused by the route, not by the middleware.

    422 is FastAPI reporting a missing multipart file field -- which means the
    request reached the endpoint, which is the point of the assertion.
    """
    resp = secure_client.post(
        "/api/admin/ssh-keys",
        content=b"x" * (main._MAX_BODY_BYTES + 1),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert resp.status_code != 413


def test_an_unparseable_content_length_is_refused(secure_client, enrolled):
    resp = secure_client.post(
        "/api/admin/known-hosts/forget",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": "not-a-number"},
    )
    assert resp.status_code == 400


# --- static assets must be revalidated ----------------------------------------
#
# StaticFiles sends ETag and Last-Modified and no Cache-Control. With no
# Cache-Control a browser falls back to heuristic freshness and serves app.js
# from its own cache without asking, so a released frontend fix reaches the
# server and not the person using it. dev.18 shipped a fix for a dead button
# and the button stayed dead for exactly that reason.


@pytest.mark.parametrize("path", ["/js/app.js", "/css/style.css", "/"])
def test_frontend_assets_must_be_revalidated(client, path):
    resp = client.get(path)
    assert resp.status_code == 200
    assert resp.headers.get("cache-control") == "no-cache"


@pytest.mark.parametrize("path", ["/js/app.js", "/"])
def test_revalidation_is_still_cheap(client, path):
    """no-cache means revalidate, not re-download. The ETag has to survive, or
    every page load pays for the whole file again."""
    assert client.get(path).headers.get("etag")



# --- capture start: the guard that used to run only at add time ---------------
#
# _reject_self_target was wired into adding and editing a server, which left
# every row already in the database outside it -- rows added before the guard
# existed, and rows whose hostname has since come to resolve to this machine.
# A capture is the thing that actually records the password, so the check
# belongs on the path that starts one.


_SELF_FINDING = ("the target reports the same kernel boot id as pcap-server "
                 "itself, so it is the machine this container is running on")


def test_capture_start_refuses_a_server_already_known_to_be_this_machine(
        secure_client, enrolled, monkeypatch):
    server_id = _a_server(enrolled)
    main.db.set_active_server_self_target(server_id, enrolled, _SELF_FINDING)
    started = False

    async def should_not_run(req, server, user_id):
        nonlocal started
        started = True
        return {}

    monkeypatch.setattr(main.capture_manager, "start", should_not_run)
    resp = secure_client.post("/api/captures", json={"server_id": server_id, "interface": "eth0"})

    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "self_capture"
    assert started is False, "nothing should connect to a target already known to be us"


def test_capture_start_refuses_a_hostname_that_now_resolves_to_this_machine(
        secure_client, enrolled, monkeypatch):
    """The stored row was fine when it was added. DNS moved under it."""
    server_id = str(uuid.uuid4())
    main.db.add_active_server(
        server_id, enrolled, "target", "localhost", 22, "alice", "alice-key", False
    )
    started = False

    async def should_not_run(req, server, user_id):
        nonlocal started
        started = True
        return {}

    monkeypatch.setattr(main.capture_manager, "start", should_not_run)
    resp = secure_client.post("/api/captures", json={"server_id": server_id, "interface": "eth0"})

    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "self_capture"
    assert started is False
    assert main.db.get_active_server(server_id, enrolled)["self_target_reason"] != "", (
        "an address that has moved to this machine is the case nobody would "
        "think to look for -- the list has to say so"
    )


def test_capture_start_surfaces_a_refusal_raised_on_the_captures_own_connection(
        secure_client, enrolled, monkeypatch):
    """The host LAN address case: nothing before the connection can see it, so
    run_tcpdump refuses on the connection tcpdump was about to run on."""
    server_id = _a_server(enrolled)

    async def refuse(req, server, user_id):
        raise main.SelfCaptureRefused(_SELF_FINDING)

    monkeypatch.setattr(main.capture_manager, "start", refuse)
    resp = secure_client.post("/api/captures", json={"server_id": server_id, "interface": "eth0"})

    assert resp.status_code == 400, "a self-capture refusal must not read as a 500"
    detail = resp.json()["detail"]
    assert detail["code"] == "self_capture"
    assert "same kernel boot id" in detail["reason"]


def test_a_refusal_on_the_captures_connection_is_recorded_against_the_server(
        secure_client, enrolled, monkeypatch):
    """So the second attempt is refused before connecting, and the server list
    can say why rather than leaving a dead entry behind."""
    server_id = _a_server(enrolled)

    async def refuse(req, server, user_id):
        raise main.SelfCaptureRefused(_SELF_FINDING)

    monkeypatch.setattr(main.capture_manager, "start", refuse)
    secure_client.post("/api/captures", json={"server_id": server_id, "interface": "eth0"})

    assert main.db.get_active_server(server_id, enrolled)["self_target_reason"] == _SELF_FINDING


def test_an_ordinary_capture_still_starts(secure_client, enrolled, monkeypatch):
    """The guard must not become a wall: a normal target is unaffected."""
    async def start(req, server, user_id):
        return {"id": "cap-1", "status": "running"}

    monkeypatch.setattr(main.capture_manager, "start", start)
    server_id = _a_server(enrolled)
    resp = secure_client.post("/api/captures", json={"server_id": server_id, "interface": "eth0"})

    assert resp.status_code == 200


# --- H2: bootstrap registration cannot create two admins in a race -----------


def test_create_first_user_is_atomic(tmp_path):
    """Two bootstrap registrations racing must not both become admin. The
    check-and-insert is one statement, so exactly one call inserts a row; the
    rest report False and write nothing. (The route hashes the password before
    this, a ~100 ms window that made the old count()-then-insert race real.)"""
    from backend.database import Database

    db = Database(tmp_path / "bootstrap.db")
    first = db.create_first_user("id-1", "alice", "scrypt$1$1$1$00$00")
    second = db.create_first_user("id-2", "mallory", "scrypt$1$1$1$00$00")

    assert first is True
    assert second is False
    assert db.user_count() == 1
    only = db.get_user_by_username("alice")
    assert only is not None and bool(only["is_admin"]) is True
    assert db.get_user_by_username("mallory") is None
