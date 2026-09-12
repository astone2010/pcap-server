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

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

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
