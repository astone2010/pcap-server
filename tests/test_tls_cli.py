"""`python -m backend.tls`: credentials come from a prompt or stdin, never argv."""

from __future__ import annotations

import io
import os
import sys

import pytest

from backend.crypto import Cryptor
from backend.tls import cli, lego, store
from backend.tls.manager import TlsManager
from backend.tls.store import AcmeConfig
from tests.tls_helpers import DOMAIN, EMAIL, TOKEN, FakeVault, make_pair


@pytest.fixture()
def manager(tmp_path, monkeypatch):
    m = TlsManager(tmp_path / "tls", FakeVault("file", Cryptor(os.urandom(32))))
    monkeypatch.setattr(cli, "_manager", lambda: m)
    seen = []

    def fake_issue(tls_dir, cryptor, config, credentials, **kw):
        seen.append((config, dict(credentials)))
        cert, key = make_pair(domain=config.domain)
        return store.store_issued(tls_dir, cryptor, cert, key, config.domain)

    monkeypatch.setattr(lego, "issue", fake_issue)
    m.seen = seen
    return m


def test_piped_credentials_are_read_as_name_value_lines(manager, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"# comment\nCF_DNS_API_TOKEN={TOKEN}\n"))
    assert cli.main(["issue", "--domain", DOMAIN, "--email", EMAIL, "--provider", "cloudflare"]) == 0
    assert manager.seen == [(AcmeConfig(DOMAIN, EMAIL, "cloudflare"), {"CF_DNS_API_TOKEN": TOKEN})]
    assert "docker compose restart" in capsys.readouterr().out


def test_a_file_setting_can_be_read_from_a_path_inside_the_container(manager, monkeypatch, tmp_path):
    keyfile = tmp_path / "transip.key"
    keyfile.write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n")
    monkeypatch.setattr(sys, "stdin", io.StringIO(
        f"TRANSIP_ACCOUNT_NAME=me\nTRANSIP_PRIVATE_KEY_PATH=@{keyfile}\n"))
    assert cli.main(["issue", "--domain", DOMAIN, "--email", EMAIL, "--provider", "transip"]) == 0
    assert manager.seen[0][1]["TRANSIP_PRIVATE_KEY_PATH"] == keyfile.read_text()


def test_there_is_no_argument_that_takes_a_credential():
    with pytest.raises(SystemExit):
        cli._parse_args(["issue", "--domain", DOMAIN, "--email", EMAIL, "--provider", "cloudflare",
                         "--token", TOKEN])


def test_a_variable_the_provider_does_not_list_is_refused(manager, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("LEGO_DEPLOY_HOOK=id\n"))
    assert cli.main(["issue", "--domain", DOMAIN, "--email", EMAIL, "--provider", "cloudflare"]) == 2
    assert "not a setting" in capsys.readouterr().err
    assert manager.seen == []


def test_bad_domain_is_refused_before_anything_is_read(manager, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"CF_DNS_API_TOKEN={TOKEN}\n"))
    assert cli.main(["issue", "--domain=--path=/tmp", "--email", EMAIL, "--provider", "cloudflare"]) == 2
    assert manager.seen == []


def test_providers_lists_and_describes(capsys):
    assert cli.main(["providers"]) == 0
    assert "cloudflare" in capsys.readouterr().out
    assert cli.main(["providers", "cloudflare"]) == 0
    assert "CF_DNS_API_TOKEN" in capsys.readouterr().out


def test_status_prints_names_not_values(manager, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"CF_DNS_API_TOKEN={TOKEN}\n"))
    cli.main(["issue", "--domain", DOMAIN, "--email", EMAIL, "--provider", "cloudflare"])
    capsys.readouterr()
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "CF_DNS_API_TOKEN" in out and TOKEN not in out
