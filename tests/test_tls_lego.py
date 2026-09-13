"""backend.tls.lego and backend.tls.store: the validators and argv between admin
input and lego, and the issuance path that must leave no plaintext behind.

lego itself is never run; a stub stands in, writing a certificate and key where
lego would and recording what it was handed.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from backend.crypto import MAGIC, Cryptor
from backend.tls import lego, store
from backend.tls.errors import AcmeBusy, AcmeError
from backend.tls.store import AcmeConfig
from tests.tls_helpers import CREDS, DOMAIN, EMAIL, TOKEN, make_pair, write_stub_lego

CONFIG = AcmeConfig(DOMAIN, EMAIL, "cloudflare")


@pytest.fixture()
def cryptor():
    return Cryptor(os.urandom(32))


@pytest.fixture()
def scratch_root(tmp_path, monkeypatch):
    root = tmp_path / "shm"
    root.mkdir()
    monkeypatch.setattr(lego, "SCRATCH_ROOT", root)
    return root


@pytest.fixture()
def tls_dir(tmp_path):
    return tmp_path / "data" / "tls"


# --- validators -------------------------------------------------------------

@pytest.mark.parametrize("value", ["pcap.example.com", "a.co", "PCAP.Example.COM", "x-1.y-2.example.org"])
def test_domain_accepts_plain_hostnames(value):
    assert store.validate_domain(value) == value.lower()


@pytest.mark.parametrize("value", [
    "", "-d", "--path=/app/data", "-pcap.example.com", "pcap-.example.com", "localhost",
    "*.example.com", "1.2.3.4", "example.com.", "exa_mple.com", "a..example.com",
    "pcap.example.com\n--server=x", "pcap example.com", "pcap.example.com:8443", "pcap.exämple.com",
    None, 5,
])
def test_domain_refuses_everything_else(value):
    with pytest.raises(ValueError):
        store.validate_domain(value)


@pytest.mark.parametrize("value", [
    "", "-x@example.com", "--email=a@b.com", "a@-b.com", "admin", "admin@localhost",
    "a b@example.com", "admin@example.com\n--server=x", "admin@@example.com",
])
def test_email_refuses_everything_else(value):
    with pytest.raises(ValueError):
        store.validate_email(value)


def test_config_refuses_an_unknown_provider():
    with pytest.raises(ValueError):
        AcmeConfig.validated(DOMAIN, EMAIL, "exec")


# --- argv -------------------------------------------------------------------

def test_argv_carries_every_user_value_inside_its_own_flag(tmp_path):
    argv = lego.build_argv(CONFIG, tmp_path / "lego", "/usr/local/bin/lego")
    assert argv[0] == "/usr/local/bin/lego"
    assert "run" in argv
    assert f"--domains={DOMAIN}" in argv and f"--email={EMAIL}" in argv
    assert "--dns=cloudflare" in argv
    assert not any(a.startswith("--server") for a in argv)
    assert all(a.startswith("--") for a in argv[1:] if a != "run")


def test_staging_selects_the_staging_directory(tmp_path):
    argv = lego.build_argv(AcmeConfig(DOMAIN, EMAIL, "cloudflare", staging=True), tmp_path)
    assert "--server=letsencrypt-staging" in argv


def test_argv_builder_revalidates_so_no_caller_can_skip_it(tmp_path):
    for bad in (AcmeConfig("--path=/app", EMAIL, "cloudflare"),
                AcmeConfig(DOMAIN, "--server=https://evil/", "cloudflare"),
                AcmeConfig(DOMAIN, EMAIL, "exec")):
        with pytest.raises(ValueError):
            lego.build_argv(bad, tmp_path)


@pytest.mark.parametrize("bad", ["bare", "-x", "---weird", "--ok\n--server=x"])
def test_argv_shape_check_is_the_last_line(bad):
    with pytest.raises(AcmeError):
        lego._assert_argv_shape(["lego", "run", "--accept-tos", bad])


# --- issuance ---------------------------------------------------------------

def test_issue_stores_a_sealed_key_and_leaves_no_plaintext(tmp_path, tls_dir, cryptor, scratch_root):
    cert, key = make_pair()
    stub, record = write_stub_lego(tmp_path, cert=cert, key=key)

    info = lego.issue(tls_dir, cryptor, CONFIG, CREDS, lego_bin=str(stub))

    assert info.names == (DOMAIN,)
    assert (tls_dir / store.KEY_FILE).read_bytes().startswith(MAGIC)
    assert cryptor.open_bytes(tls_dir / store.KEY_FILE) == key
    assert (tls_dir / store.CERT_FILE).read_bytes() == cert
    for path in tls_dir.parent.rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes(), path
    assert list(scratch_root.iterdir()) == []
    assert stat.S_IMODE(tls_dir.stat().st_mode) == 0o700


def test_lego_gets_only_the_provider_settings_and_an_empty_working_directory(
        tmp_path, tls_dir, cryptor, scratch_root, monkeypatch):
    monkeypatch.setenv("LEGO_DEPLOY_HOOK", "touch /tmp/pwned")
    monkeypatch.setenv("PCAP_MASTER_KEY", "should-not-leak")
    cert, key = make_pair()
    stub, record = write_stub_lego(tmp_path, cert=cert, key=key)
    lego.issue(tls_dir, cryptor, CONFIG, CREDS, lego_bin=str(stub))

    seen = json.loads(record.read_text())
    assert set(seen["env"]) - {"PWD", "LC_CTYPE", "SHLVL", "_"} == {"PATH", "HOME", "LANG", "CF_DNS_API_TOKEN"}
    assert seen["env"]["CF_DNS_API_TOKEN"] == TOKEN
    assert Path(seen["cwd"]).is_relative_to(scratch_root)
    assert seen["env"]["HOME"] == seen["cwd"]
    assert TOKEN not in " ".join(seen["argv"])
    assert seen["stdin_tty"] is False


def test_a_file_setting_is_written_by_the_app_not_pointed_at_by_the_admin(
        tmp_path, tls_dir, cryptor, scratch_root):
    cert, key = make_pair()
    stub, record = write_stub_lego(tmp_path, cert=cert, key=key)
    pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
    lego.issue(tls_dir, cryptor, AcmeConfig(DOMAIN, EMAIL, "transip"),
               {"TRANSIP_ACCOUNT_NAME": "me", "TRANSIP_PRIVATE_KEY_PATH": pem}, lego_bin=str(stub))

    seen = json.loads(record.read_text())
    path = seen["env"]["TRANSIP_PRIVATE_KEY_PATH"]
    assert Path(path).is_relative_to(scratch_root)
    assert seen["files"]["TRANSIP_PRIVATE_KEY_PATH"] == {"content": pem, "mode": "0o600"}
    assert not Path(path).exists()


def test_a_failed_run_keeps_the_existing_certificate_and_hides_the_credentials(
        tmp_path, tls_dir, cryptor, scratch_root):
    cert, key = make_pair()
    good, _ = write_stub_lego(tmp_path, cert=cert, key=key)
    lego.issue(tls_dir, cryptor, CONFIG, CREDS, lego_bin=str(good))
    before = {p.name: p.read_bytes() for p in tls_dir.iterdir() if p.is_file()}

    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    bad, _ = write_stub_lego(bad_dir, exit_code=1, stderr=(
        "time=2026 level=INFO msg=noise\n"
        f"time=2026 level=ERROR msg=Error error=\"cloudflare: bad token {TOKEN}\"\n"))
    with pytest.raises(AcmeError) as exc:
        lego.issue(tls_dir, cryptor, CONFIG, CREDS, lego_bin=str(bad))

    assert TOKEN not in str(exc.value)
    assert "[redacted]" in str(exc.value)
    assert "noise" not in str(exc.value)
    assert {p.name: p.read_bytes() for p in tls_dir.iterdir() if p.is_file()} == before
    assert list(scratch_root.iterdir()) == []


def test_a_certificate_that_does_not_match_its_key_is_refused(tmp_path, tls_dir, cryptor, scratch_root):
    cert, _ = make_pair()
    _, other = make_pair()
    stub, _ = write_stub_lego(tmp_path, cert=cert, key=other)
    with pytest.raises(AcmeError, match="does not match"):
        lego.issue(tls_dir, cryptor, CONFIG, CREDS, lego_bin=str(stub))
    assert not (tls_dir / store.KEY_FILE).exists()


def test_a_certificate_for_another_name_is_refused(tmp_path, tls_dir, cryptor, scratch_root):
    cert, key = make_pair(domain="other.example.com")
    stub, _ = write_stub_lego(tmp_path, cert=cert, key=key)
    with pytest.raises(AcmeError, match="does not name"):
        lego.issue(tls_dir, cryptor, CONFIG, CREDS, lego_bin=str(stub))


def test_no_ram_backed_scratch_means_no_issuance(tmp_path, tls_dir, cryptor, monkeypatch):
    monkeypatch.setattr(lego, "SCRATCH_ROOT", tmp_path / "missing")
    with pytest.raises(AcmeError, match="RAM-backed"):
        lego.issue(tls_dir, cryptor, CONFIG, CREDS, lego_bin="/bin/true")


def test_missing_lego_is_reported_plainly(tls_dir, cryptor, scratch_root, tmp_path):
    with pytest.raises(AcmeError, match="not installed"):
        lego.issue(tls_dir, cryptor, CONFIG, CREDS, lego_bin=str(tmp_path / "nope"))


def test_only_one_issuance_runs_at_a_time(tls_dir, cryptor, scratch_root):
    with lego.issuance_lock(tls_dir):
        with pytest.raises(AcmeBusy):
            lego.issue(tls_dir, cryptor, CONFIG, CREDS, lego_bin="/bin/true")


def test_disallowed_credentials_never_reach_lego(tls_dir, cryptor, scratch_root):
    with pytest.raises(AcmeError, match="not a setting"):
        lego.issue(tls_dir, cryptor, CONFIG, {"LEGO_DEPLOY_HOOK": "id"}, lego_bin="/bin/true")


# --- stored state -----------------------------------------------------------

def test_credentials_are_sealed_at_rest(tls_dir, cryptor):
    store.save_credentials(tls_dir, cryptor, "cloudflare", CREDS)
    assert TOKEN.encode() not in (tls_dir / store.CREDENTIALS_FILE).read_bytes()
    assert store.load_credentials(tls_dir, cryptor) == ("cloudflare", CREDS)


def test_config_round_trips_and_is_revalidated_on_load(tls_dir):
    store.save_config(tls_dir, AcmeConfig(DOMAIN, EMAIL, "cloudflare", staging=True))
    assert store.load_config(tls_dir) == AcmeConfig(DOMAIN, EMAIL, "cloudflare", staging=True)
    (tls_dir / store.CONFIG_FILE).write_text(json.dumps(
        {"domain": DOMAIN, "email": EMAIL, "provider": "exec"}))
    with pytest.raises(AcmeError):
        store.load_config(tls_dir)


def test_renewal_is_due_inside_thirty_days():
    assert store.renewal_due(store.cert_info(make_pair(days=20)[0]))
    assert not store.renewal_due(store.cert_info(make_pair(days=80)[0]))


def test_remove_all_forgets_everything(tls_dir, cryptor):
    cert, key = make_pair()
    store.ensure_tls_dir(tls_dir)
    (tls_dir / store.CERT_FILE).write_bytes(cert)
    (tls_dir / store.KEY_FILE).write_bytes(cryptor.seal_bytes(key))
    store.save_credentials(tls_dir, cryptor, "cloudflare", CREDS)
    store.save_config(tls_dir, CONFIG)
    assert len(store.remove_all(tls_dir)) == 4
    assert not store.has_material(tls_dir) and not store.has_credentials(tls_dir)
