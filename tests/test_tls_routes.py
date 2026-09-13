"""The built-in HTTPS admin routes, the plain-HTTP exception they carry, the
DATA_DIR permission warning, and rekey reaching the TLS material.

conftest.py sets the environment backend.main needs before it is imported.
"""

from __future__ import annotations

import logging
import os
import uuid

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.auth import create_session_token
from backend.crypto import Cryptor, WrongKey
from backend.rekey import rekey_all
from backend.tls import store
from backend.tls.errors import AcmeBusy
from tests.tls_helpers import CREDS, DOMAIN, EMAIL, TOKEN, make_pair

TLS_POSTS = ["/api/admin/tls/acme", "/api/admin/tls/renew", "/api/admin/tls/restart"]


@pytest.fixture()
def http_client(tmp_path, monkeypatch):
    """Plain HTTP from a non-loopback client: the read-only configuration."""
    monkeypatch.setattr(main.tls_manager, "tls_dir", tmp_path / "tls")
    with TestClient(main.app) as c:
        yield c


def _sign_in(client, *, admin: bool) -> str:
    user_id = str(uuid.uuid4())
    main.db.create_user(user_id, f"u-{user_id[:8]}", "scrypt$1$1$1$00$00", is_admin=admin)
    main.db.set_totp_secret(user_id, "A" * 32)
    main.db.confirm_totp(user_id)
    token, _ = create_session_token(main.db, user_id)
    client.cookies.set("session", token)
    return user_id


@pytest.fixture()
def admin(http_client):
    user_id = _sign_in(http_client, admin=True)
    yield user_id
    main.db.delete_user(user_id)


@pytest.fixture()
def non_admin(http_client):
    user_id = _sign_in(http_client, admin=False)
    yield user_id
    main.db.delete_user(user_id)


# --- the plain-HTTP exception -----------------------------------------------

@pytest.mark.parametrize("path", TLS_POSTS)
def test_certificate_routes_are_reachable_over_plain_http(http_client, path):
    resp = http_client.post(path, json={})
    body = resp.json()
    assert not (resp.status_code == 403 and isinstance(body.get("detail"), dict)
                and body["detail"].get("code") == "https_required")


def test_the_exception_covers_nothing_else(http_client):
    """A neighbouring admin route is still refused over HTTP."""
    resp = http_client.put("/api/admin/settings", json={"key": "x", "value": "1"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "https_required"


@pytest.mark.parametrize("method,path", [("get", "/api/admin/tls"), ("delete", "/api/admin/tls"),
                                         ("get", "/api/admin/tls/providers")]
                         + [("post", p) for p in TLS_POSTS])
def test_certificate_routes_are_admin_only(http_client, non_admin, method, path):
    resp = getattr(http_client, method)(path, **({"json": {}} if method == "post" else {}))
    assert resp.status_code == 403


@pytest.mark.parametrize("method,path", [("get", "/api/admin/tls"), ("delete", "/api/admin/tls"),
                                         ("get", "/api/admin/tls/providers")]
                         + [("post", p) for p in TLS_POSTS])
def test_certificate_routes_need_a_session(http_client, method, path):
    resp = getattr(http_client, method)(path, **({"json": {}} if method == "post" else {}))
    assert resp.status_code == 401


# --- the routes -------------------------------------------------------------

def test_status_over_http(http_client, admin):
    resp = http_client.get("/api/admin/tls")
    assert resp.status_code == 200
    assert resp.json()["serving_https"] is False
    assert resp.json()["available"] is True


@pytest.mark.parametrize("field,value", [
    ("domain", "--path=/app/data"), ("email", "-x@example.com"), ("provider", "exec"),
])
def test_bad_input_is_a_400_that_does_not_echo_the_value(http_client, admin, field, value):
    body = {"domain": DOMAIN, "email": EMAIL, "provider": "cloudflare", "credentials": CREDS, field: value}
    resp = http_client.post("/api/admin/tls/acme", json=body)
    assert resp.status_code == 400
    assert value not in resp.text
    assert TOKEN not in resp.text


def test_a_credential_the_provider_does_not_list_is_refused(http_client, admin):
    resp = http_client.post("/api/admin/tls/acme", json={
        "domain": DOMAIN, "email": EMAIL, "provider": "cloudflare",
        "credentials": {"LEGO_DEPLOY_HOOK": "touch /tmp/pwned"}})
    assert resp.status_code == 400
    assert "not a setting" in resp.json()["detail"]


def test_issue_route_hands_the_request_to_the_manager(http_client, admin, monkeypatch):
    seen = []

    def fake_issue(domain, email, provider, credentials, staging):
        seen.append((domain, email, provider, credentials, staging))
        return store.cert_info(make_pair()[0])

    monkeypatch.setattr(main.tls_manager, "issue", fake_issue)
    resp = http_client.post("/api/admin/tls/acme", json={
        "domain": DOMAIN, "email": EMAIL, "provider": "cloudflare", "credentials": CREDS, "staging": True})
    assert resp.status_code == 200, resp.text
    assert seen == [(DOMAIN, EMAIL, "cloudflare", CREDS, True)]
    assert TOKEN not in resp.text


def test_the_provider_catalog_is_served(http_client, admin):
    body = http_client.get("/api/admin/tls/providers").json()
    assert body["lego_version"]
    assert any(p["code"] == "cloudflare" for p in body["providers"])


def test_a_second_request_while_one_runs_is_a_409(http_client, admin, monkeypatch):
    def busy(*a, **k):
        raise AcmeBusy("a certificate request is already running")

    monkeypatch.setattr(main.tls_manager, "issue", busy)
    resp = http_client.post("/api/admin/tls/acme", json={"domain": DOMAIN, "email": EMAIL,
                                                         "provider": "cloudflare"})
    assert resp.status_code == 409


def test_restart_is_refused_while_captures_run(http_client, admin, monkeypatch):
    monkeypatch.setattr(main.capture_manager, "active_count", lambda: 2)
    called = []
    monkeypatch.setattr(main.tls_manager, "request_restart", lambda: called.append(1))
    resp = http_client.post("/api/admin/tls/restart")
    assert resp.status_code == 409
    assert "2 capture(s)" in resp.json()["detail"]
    assert called == []


def test_restart_without_a_certificate_is_a_400(http_client, admin, monkeypatch):
    monkeypatch.setattr(main.capture_manager, "active_count", lambda: 0)
    resp = http_client.post("/api/admin/tls/restart")
    assert resp.status_code == 400
    assert "no certificate" in resp.json()["detail"]


def test_delete_forgets_the_material(http_client, admin):
    tls_dir = main.tls_manager.tls_dir
    cert, key = make_pair()
    store.ensure_tls_dir(tls_dir)
    (tls_dir / store.CERT_FILE).write_bytes(cert)
    (tls_dir / store.KEY_FILE).write_bytes(main.vault.cryptor.seal_bytes(key))
    resp = http_client.delete("/api/admin/tls")
    assert resp.status_code == 200
    assert resp.json()["certificate"] is None
    assert not store.has_material(tls_dir)


# --- cookies ----------------------------------------------------------------

def test_cookies_are_secure_whenever_https_is_built_in(monkeypatch):
    monkeypatch.setattr(main, "_COOKIE_SECURE", False)
    assert main._cookie_secure() is False
    monkeypatch.setattr(main.tls_manager, "_context", object())
    assert main._cookie_secure() is True


# --- DATA_DIR permissions -----------------------------------------------------

@pytest.mark.parametrize("mode,warns", [(0o700, False), (0o750, True), (0o755, True), (0o701, True)])
def test_data_dir_warning(tmp_path, caplog, mode, warns):
    d = tmp_path / "data"
    d.mkdir()
    d.chmod(mode)
    with caplog.at_level(logging.WARNING, logger="backend.main"):
        assert main.warn_if_data_dir_exposed(d) is warns
    assert ("chmod 0700 data" in caplog.text) is warns


def test_data_dir_warning_is_quiet_about_a_missing_directory(tmp_path):
    assert main.warn_if_data_dir_exposed(tmp_path / "absent") is False


# --- rekey --------------------------------------------------------------------

def test_rekey_moves_the_tls_key_and_credentials_too(tmp_path):
    old, new = Cryptor(os.urandom(32)), Cryptor(os.urandom(32))
    tls_dir = tmp_path / "data" / "tls"
    cert, key = make_pair()
    store.ensure_tls_dir(tls_dir)
    (tls_dir / store.CERT_FILE).write_bytes(cert)
    (tls_dir / store.KEY_FILE).write_bytes(old.seal_bytes(key))
    store.save_credentials(tls_dir, old, "cloudflare", CREDS)
    past = os.stat(tls_dir).st_mtime - 3600
    for p in tls_dir.iterdir():
        os.utime(p, (past, past))

    out = rekey_all(old, new, captures_dir=None, ssh_keys_dir=None, tls_dir=tls_dir, apply=True)

    assert out.ok and len(out.rekeyed) == 2
    assert new.open_bytes(tls_dir / store.KEY_FILE) == key
    assert store.load_credentials(tls_dir, new) == ("cloudflare", CREDS)
    with pytest.raises(WrongKey):
        old.open_bytes(tls_dir / store.KEY_FILE)
    assert (tls_dir / store.CERT_FILE).read_bytes() == cert
