"""backend.tls.manager and backend.tls.serving: the key reaches OpenSSL without
touching a filesystem, a renewed certificate is served without a restart,
credentials merge the way the form promises, and passphrase mode is refused."""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import threading
import time

import pytest

from backend import serve
from backend.crypto import Cryptor
from backend.tls import lego, store
from backend.tls.errors import AcmeBusy, AcmeError
from backend.tls.manager import TlsManager
from backend.tls.serving import key_path_in_memory
from backend.tls.store import AcmeConfig
from backend.vault import StartupRefused
from tests.tls_helpers import CREDS, DOMAIN, EMAIL, TOKEN, FakeVault, make_pair, store_pair


@pytest.fixture()
def cryptor():
    return Cryptor(os.urandom(32))


@pytest.fixture()
def tls_dir(tmp_path):
    return tmp_path / "tls"


@pytest.fixture()
def configured(tls_dir, cryptor):
    def _configure(days: int = 80) -> TlsManager:
        cert, key = make_pair(days=days)
        store_pair(tls_dir, cryptor, cert, key)
        store.save_config(tls_dir, AcmeConfig(DOMAIN, EMAIL, "cloudflare"))
        store.save_credentials(tls_dir, cryptor, "cloudflare", CREDS)
        return TlsManager(tls_dir, FakeVault("file", cryptor))
    return _configure


@pytest.fixture()
def fake_lego(monkeypatch):
    calls = []

    def fake_issue(tls_dir_, cryptor_, config, credentials, **kw):
        calls.append((config, dict(credentials)))
        cert, key = make_pair(domain=config.domain)
        return store.store_issued(tls_dir_, cryptor_, cert, key, config.domain)

    monkeypatch.setattr(lego, "issue", fake_issue)
    return calls


# --- memfd ------------------------------------------------------------------

def test_the_key_path_is_memory_and_closes_after_use():
    secret = b"-----BEGIN PRIVATE KEY-----\nnot really\n-----END PRIVATE KEY-----\n"
    with key_path_in_memory(secret) as path:
        assert path.startswith("/proc/self/fd/")
        assert "memfd:" in os.readlink(path)
        with open(path, "rb") as fh:
            assert fh.read() == secret
    with pytest.raises(OSError):
        open(path, "rb")


# --- startup ----------------------------------------------------------------

def test_passphrase_mode_with_a_stored_certificate_refuses_to_start(tls_dir, cryptor):
    store_pair(tls_dir, cryptor, *make_pair())
    with pytest.raises(StartupRefused, match="passphrase"):
        TlsManager(tls_dir, FakeVault("passphrase")).startup_check()


def test_passphrase_mode_without_a_certificate_starts(tls_dir):
    TlsManager(tls_dir, FakeVault("passphrase")).startup_check()


def test_a_key_sealed_under_another_master_key_is_an_error_not_a_crash(tls_dir, cryptor):
    store_pair(tls_dir, Cryptor(os.urandom(32)), *make_pair())
    with pytest.raises(AcmeError, match="could not be opened"):
        TlsManager(tls_dir, FakeVault("file", cryptor)).serving_material()


@pytest.mark.parametrize("mode,match", [("passphrase", "passphrase mode"), ("disabled", "without one")])
def test_issuing_needs_a_key_the_app_can_read_unattended(tls_dir, cryptor, mode, match):
    with pytest.raises(AcmeError, match=match):
        TlsManager(tls_dir, FakeVault(mode, cryptor)).issue(DOMAIN, EMAIL, "cloudflare", CREDS, False)


# --- serving and reloading, over a real socket -------------------------------

async def _app(scope, receive, send):
    if scope["type"] != "http":
        return
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _served_der(port: int) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw) as s:
        return s.getpeercert(binary_form=True)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_https_is_served_and_a_renewal_is_picked_up_without_a_restart(tls_dir, cryptor):
    import uvicorn

    cert, key = make_pair()
    store_pair(tls_dir, cryptor, cert, key)
    manager = TlsManager(tls_dir, FakeVault("file", cryptor))
    port = _free_port()
    config, info = serve.build_config(_app, manager, "127.0.0.1", port, "warning")
    assert config.ssl.minimum_version == ssl.TLSVersion.TLSv1_2
    server = uvicorn.Server(config)
    manager.attach(server, config.ssl, info)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _served_der(port) == ssl.PEM_cert_to_DER_cert(cert.decode())
        assert manager.reload_if_changed() is False

        cert2, key2 = make_pair()
        store_pair(tls_dir, cryptor, cert2, key2)
        assert manager.reload_if_changed() is True
        assert _served_der(port) == ssl.PEM_cert_to_DER_cert(cert2.decode())
    finally:
        server.should_exit = True
        thread.join(10)


def test_an_unopenable_key_falls_back_to_plain_http(tls_dir, cryptor, caplog):
    store_pair(tls_dir, Cryptor(os.urandom(32)), *make_pair())
    manager = TlsManager(tls_dir, FakeVault("file", cryptor))
    config, info = serve.build_config(_app, manager, "127.0.0.1", _free_port(), "warning")
    assert info is None and not config.is_ssl
    assert "HTTPS NOT ENABLED" in caplog.text


# --- issuance and credentials -----------------------------------------------

def test_issue_saves_settings_only_after_success(tls_dir, cryptor, monkeypatch):
    manager = TlsManager(tls_dir, FakeVault("file", cryptor))
    monkeypatch.setattr(lego, "issue", lambda *a, **k: (_ for _ in ()).throw(AcmeError("nope")))
    with pytest.raises(AcmeError):
        manager.issue(DOMAIN, EMAIL, "cloudflare", CREDS, staging=False)
    assert store.load_config(tls_dir) is None
    assert not store.has_credentials(tls_dir)


def test_blank_fields_keep_what_is_stored_for_the_same_provider(configured, fake_lego):
    manager = configured()
    manager.issue("new.example.com", EMAIL, "cloudflare", {"CF_DNS_API_TOKEN": "", "CF_ZONE_API_TOKEN": "zone-tok"},
                  staging=True)
    assert fake_lego[-1][1] == {"CF_DNS_API_TOKEN": TOKEN, "CF_ZONE_API_TOKEN": "zone-tok"}
    assert store.load_config(manager.tls_dir) == AcmeConfig("new.example.com", EMAIL, "cloudflare", True)


def test_a_different_provider_starts_from_nothing(configured, fake_lego):
    manager = configured()
    manager.issue(DOMAIN, EMAIL, "hetzner", {"HETZNER_API_TOKEN": "h-token"}, staging=False)
    assert fake_lego[-1][1] == {"HETZNER_API_TOKEN": "h-token"}
    assert store.load_credentials(manager.tls_dir, manager._vault.cryptor) == (
        "hetzner", {"HETZNER_API_TOKEN": "h-token"})


def test_no_credentials_at_all_is_refused_before_lego_runs(tls_dir, cryptor, fake_lego):
    manager = TlsManager(tls_dir, FakeVault("file", cryptor))
    with pytest.raises(AcmeError, match="credentials"):
        manager.issue(DOMAIN, EMAIL, "cloudflare", {}, staging=False)
    assert fake_lego == []


# --- renewal ----------------------------------------------------------------

def test_housekeeping_leaves_a_fresh_certificate_alone(configured, fake_lego):
    configured(days=80).maybe_renew()
    assert fake_lego == []


def test_housekeeping_renews_inside_thirty_days(configured, fake_lego):
    configured(days=10).maybe_renew()
    assert fake_lego == [(AcmeConfig(DOMAIN, EMAIL, "cloudflare"), CREDS)]


def test_a_failed_renewal_is_not_retried_every_hour(configured, monkeypatch, caplog):
    manager = configured(days=10)
    calls = []
    monkeypatch.setattr(lego, "issue", lambda *a, **k: calls.append(1) or (_ for _ in ()).throw(AcmeError("DNS said no")))
    manager.maybe_renew()
    manager.maybe_renew()
    assert calls == [1]
    assert manager.last_error == "DNS said no"
    assert "renewal failed" in caplog.text


def test_the_cli_holding_the_lock_is_not_a_failed_renewal(configured, monkeypatch):
    manager = configured(days=10)
    monkeypatch.setattr(lego, "issue", lambda *a, **k: (_ for _ in ()).throw(AcmeBusy("busy")))
    manager.maybe_renew()
    assert manager._last_failure is None and manager.last_error is None


def test_a_reload_failure_does_not_discard_a_good_issuance(configured, monkeypatch):
    manager = configured()
    manager.attach(object(), ssl.create_default_context(ssl.Purpose.CLIENT_AUTH), None)
    cert, key = make_pair(domain="other.example.com")

    def issue_with_unloadable_key(tls_dir_, cryptor_, config, credentials, **k):
        (tls_dir_ / store.CERT_FILE).write_bytes(cert)
        (tls_dir_ / store.KEY_FILE).write_bytes(Cryptor(os.urandom(32)).seal_bytes(key))
        return store.stored_cert_info(tls_dir_)

    monkeypatch.setattr(lego, "issue", issue_with_unloadable_key)
    manager.issue("other.example.com", EMAIL, "cloudflare", CREDS, staging=False)
    assert store.load_config(manager.tls_dir).domain == "other.example.com"
    assert "could not be loaded" in manager.last_error


# --- restart ----------------------------------------------------------------

def test_restart_needs_a_certificate(tls_dir, cryptor):
    with pytest.raises(AcmeError, match="no certificate"):
        TlsManager(tls_dir, FakeVault("file", cryptor)).request_restart()


def test_restart_needs_the_launcher(configured):
    with pytest.raises(AcmeError, match="backend.serve"):
        configured().request_restart()


def test_restart_stops_the_server_after_the_response_has_gone(configured):
    manager = configured()

    class FakeServer:
        should_exit = False

    server = FakeServer()
    manager.attach(server, None, None)

    async def run():
        manager.request_restart(delay=0.05)
        assert server.should_exit is False
        await asyncio.sleep(0.15)

    asyncio.run(run())
    assert server.should_exit is True and manager.restart_requested is True


# --- status -----------------------------------------------------------------

def test_status_names_stored_settings_but_never_their_values(configured):
    st = configured().status()
    assert st["available"] is True
    assert st["config"]["provider_name"] == "Cloudflare"
    assert st["stored_provider"] == "cloudflare"
    assert st["stored_credentials"] == ["CF_DNS_API_TOKEN"]
    assert st["certificate"]["names"] == [DOMAIN]
    assert st["restart_needed"] is True
    assert TOKEN not in repr(st)


def test_status_explains_passphrase_mode(tls_dir):
    st = TlsManager(tls_dir, FakeVault("passphrase")).status()
    assert st["available"] is False and "passphrase" in st["unavailable_reason"]
