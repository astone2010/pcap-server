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


# --- the live streaming routes ----------------------------------------------
#
# Same two reads as the stored viewer -- a packet list and one packet's detail
# -- against a capture that has not finished. The tests below are about the
# gates around them and about the one behaviour that is genuinely new: a live
# view has to be able to tell "the capture ended between two polls" apart from
# "something went wrong", because the first happens to every live stream and is
# not an error.


def _a_capture(user_id: str, *, live_stream: bool, status) -> str:
    """Register a capture with the manager directly, no SSH involved."""
    from backend.models import CaptureInfo

    info = CaptureInfo(
        id=str(uuid.uuid4()),
        server_id="some-server",
        user_id=user_id,
        live_stream=live_stream,
        status=status,
    )
    main.capture_manager._captures[info.id] = info
    return info.id


def test_live_packets_refuses_a_capture_that_is_not_live_streamed(secure_client, enrolled):
    """400 and not 404: the capture is real and the caller owns it. Hiding that
    would send someone hunting for a capture that is sitting in front of them."""
    from backend.models import CaptureStatus

    capture_id = _a_capture(enrolled, live_stream=False, status=CaptureStatus.RUNNING)
    resp = secure_client.get(f"/api/captures/{capture_id}/live/packets")
    assert resp.status_code == 400
    assert "not started with live streaming" in resp.json()["detail"]


def test_live_packets_on_someone_elses_capture_is_a_404(secure_client, enrolled):
    """404, not 403, for the same reason _require_own_capture gives: a 403
    confirms the id exists."""
    from backend.models import CaptureStatus

    capture_id = _a_capture("another-user", live_stream=True, status=CaptureStatus.RUNNING)
    resp = secure_client.get(f"/api/captures/{capture_id}/live/packets")
    assert resp.status_code == 404


def test_a_finished_live_capture_reports_finished_rather_than_erroring(secure_client, enrolled):
    """The end of every live stream, not an error.

    The viewer reads `finished` and moves to the saved capture. Returning a 400
    here would make the normal completion of a capture look like a fault.
    """
    from backend.models import CaptureStatus

    capture_id = _a_capture(enrolled, live_stream=True, status=CaptureStatus.COMPLETED)
    resp = secure_client.get(f"/api/captures/{capture_id}/live/packets")
    assert resp.status_code == 200
    body = resp.json()
    assert body["finished"] is True
    assert body["live"] is False
    assert body["packets"] == []
    assert body["status"] == "completed"


def test_a_live_capture_with_nothing_captured_yet_is_not_an_error(secure_client, enrolled, monkeypatch):
    """What the first second of every capture on a quiet link looks like."""
    from backend.livestream import LiveBuffer
    from backend.models import CaptureStatus

    capture_id = _a_capture(enrolled, live_stream=True, status=CaptureStatus.RUNNING)

    async def empty_poll(cid):
        return LiveBuffer(1024 * 1024)

    monkeypatch.setattr(main.capture_manager, "live_poll", empty_poll)
    resp = secure_client.get(f"/api/captures/{capture_id}/live/packets")

    assert resp.status_code == 200
    body = resp.json()
    assert body["packets"] == []
    assert body["finished"] is False
    assert body["live"] is True
    assert body["buffered_packets"] == 0


def test_live_packets_reports_a_frozen_preview_alongside_the_running_capture(
    secure_client, enrolled, monkeypatch
):
    """Both numbers, deliberately.

    A frozen preview with no sign that the capture is still going reads as the
    capture having died -- which is exactly the wrong conclusion, since the
    saved pcap will be complete.
    """
    from backend.livestream import LiveBuffer
    from backend.models import CaptureStatus
    from tests.test_livestream import build_pcap

    capture_id = _a_capture(enrolled, live_stream=True, status=CaptureStatus.RUNNING)
    main.capture_manager._captures[capture_id].packet_count = 9999

    full = build_pcap(50)
    buffer = LiveBuffer(len(full) // 2)
    buffer.feed(full)
    assert buffer.frozen

    async def frozen_poll(cid):
        return buffer

    monkeypatch.setattr(main.capture_manager, "live_poll", frozen_poll)
    resp = secure_client.get(f"/api/captures/{capture_id}/live/packets")

    body = resp.json()
    assert body["frozen"] is True
    assert body["live"] is True, "the capture has not stopped"
    assert body["captured_packets"] == 9999
    assert body["buffered_packets"] < 9999


def test_live_packets_rejects_unknown_view_flags(secure_client, enrolled):
    from backend.models import CaptureStatus

    capture_id = _a_capture(enrolled, live_stream=True, status=CaptureStatus.RUNNING)
    resp = secure_client.get(f"/api/captures/{capture_id}/live/packets?flags=-rm-rf")
    assert resp.status_code == 400
    assert "unknown view flags" in resp.json()["detail"]


def test_live_packets_has_its_own_rate_limit_budget(secure_client, enrolled, monkeypatch):
    """A live view polls on a timer. Sharing the stored viewer's budget would
    mean two streams left clicking a packet permanently rate-limited."""
    from backend.models import CaptureStatus

    capture_id = _a_capture(enrolled, live_stream=True, status=CaptureStatus.RUNNING)
    called = False

    async def should_not_run(cid):
        nonlocal called
        called = True

    monkeypatch.setattr(main.capture_manager, "live_poll", should_not_run)
    monkeypatch.setattr(main, "live_poll_rate_limiter", SlidingWindowLimiter(max_per_minute=0))

    resp = secure_client.get(f"/api/captures/{capture_id}/live/packets")
    assert resp.status_code == 429
    assert called is False


def test_the_stored_packet_route_is_not_throttled_by_live_polling(secure_client, enrolled, monkeypatch):
    """The other half of the separation above."""
    monkeypatch.setattr(main, "live_poll_rate_limiter", SlidingWindowLimiter(max_per_minute=0))
    resp = secure_client.get("/api/captures/no-such-capture/packets")
    assert resp.status_code != 429


def test_live_packet_detail_before_anything_has_arrived_is_a_404(secure_client, enrolled):
    from backend.models import CaptureStatus

    capture_id = _a_capture(enrolled, live_stream=True, status=CaptureStatus.RUNNING)
    resp = secure_client.get(f"/api/captures/{capture_id}/live/packets/1")
    assert resp.status_code == 404
    assert "not in the live stream yet" in resp.json()["detail"]


def test_the_live_stream_limit_is_a_429_naming_live_streaming(secure_client, enrolled, monkeypatch):
    """429 and not 409: the slot clears by waiting, so the same request will
    succeed unchanged -- which is exactly what distinguishes it from the
    per-interface conflict next door."""
    server_id = _a_server(enrolled)

    async def refuse(req, server, user_id):
        raise main.LiveStreamLimitExceeded(
            "2 live stream(s) already running -- stop one before starting another, "
            "or start this capture without live streaming"
        )

    monkeypatch.setattr(main.capture_manager, "start", refuse)
    resp = secure_client.post(
        "/api/captures",
        json={"server_id": server_id, "interface": "eth0", "live_stream": True},
    )
    assert resp.status_code == 429
    assert "live stream" in resp.json()["detail"]


def test_an_untargeted_live_stream_is_a_400(secure_client, enrolled):
    """400, not 429 or 409: nothing is busy and nothing clears by waiting. The
    request as sent would be refused on a completely idle server.

    Not monkeypatched -- this one goes through the real manager, because the
    point is that the request never reaches a target host at all.
    """
    server_id = _a_server(enrolled)
    resp = secure_client.post(
        "/api/captures",
        json={"server_id": server_id, "interface": "any", "live_stream": True},
    )
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "interface" in detail and "BPF filter" in detail


def test_the_live_poll_limiter_is_reconfigured_from_the_admin_panel(secure_client, enrolled):
    """A limiter the panel writes to but never reloads is frozen at boot."""
    original = main.live_poll_rate_limiter.max_per_minute
    try:
        resp = secure_client.put(
            "/api/admin/settings",
            json={"key": "rate_limit_live_polls_per_min", "value": "7"},
        )
        assert resp.status_code == 200
        assert main.live_poll_rate_limiter.max_per_minute == 7
    finally:
        main.live_poll_rate_limiter.update_config(original)
        main.db.set_setting("rate_limit_live_polls_per_min", str(original))
