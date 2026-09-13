"""The DNS provider catalog is an allowlist of environment variables handed to
lego. These check the list itself: that it is the one the image installs, and
that nothing on it could make lego do more than set a TXT record."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from backend.tls import providers

REPO = Path(__file__).resolve().parents[1]
CATALOG = json.loads((REPO / "backend" / "tls" / "lego_providers.json").read_text())


def test_catalog_matches_the_lego_the_image_installs():
    dockerfile = (REPO / "Dockerfile").read_text()
    pinned = re.search(r"^ARG LEGO_VERSION=(\S+)$", dockerfile, re.M).group(1)
    assert CATALOG["lego_version"] == pinned == providers.lego_version()


def test_catalog_was_actually_loaded():
    assert len(providers.all_providers()) > 150
    cf = providers.get("cloudflare")
    assert cf.variable("CF_DNS_API_TOKEN").kind == "secret"


@pytest.mark.parametrize("code", ["exec", "manual", "acmedns"])
def test_providers_that_run_programs_or_need_a_terminal_are_absent(code):
    with pytest.raises(ValueError):
        providers.get(code)


ALL_VARIABLES = [(p.code, v) for p in providers.all_providers() for v in p.variables]


@pytest.mark.parametrize("name", ["AWS_SHARED_CREDENTIALS_FILE", "OCI_CONFIG_FILE",
                                  "DNSUPDATE_TSIG_GSS_KEYTAB_FILE"])
def test_files_that_reach_further_than_a_credential_are_not_offered(name):
    """An AWS credentials file can run a command (credential_process); an OCI
    config names a key_file path lego would read."""
    assert all(v.name != name for _, v in ALL_VARIABLES)
    assert name in CATALOG["excluded_variables"]


def test_route53_still_works_without_the_credentials_file():
    names = {v.name for v in providers.get("route53").variables}
    assert {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} <= names


def test_no_variable_can_reconfigure_lego_itself():
    """LEGO_* includes hooks that run commands."""
    assert not [n for _, v in ALL_VARIABLES if (n := v.name).upper().startswith("LEGO_")]


def test_no_variable_is_a_path_the_admin_could_choose():
    """lego reads NAME_FILE, and path-like settings, as files. Every one of
    those must be 'file' kind, which the app fills with a path of its own."""
    offenders = [
        (code, v.name) for code, v in ALL_VARIABLES
        if re.search(r"(_FILE|_PATH|_LOCATION|_EDGERC)$", v.name) and v.kind != "file"
    ]
    assert offenders == []


def test_every_name_is_a_plain_environment_variable():
    assert all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v.name) for _, v in ALL_VARIABLES)


def test_aliases_are_not_offered_twice():
    assert providers.get("cloudflare").variable("CLOUDFLARE_DNS_API_TOKEN") is None


# --- credential validation ---------------------------------------------------

def test_known_values_pass_and_blanks_are_dropped():
    assert providers.validate_credentials(
        "cloudflare", {"CF_DNS_API_TOKEN": "abc", "CF_ZONE_API_TOKEN": ""}
    ) == {"CF_DNS_API_TOKEN": "abc"}


@pytest.mark.parametrize("name", [
    "LEGO_DEPLOY_HOOK", "CF_DNS_API_TOKEN_FILE", "LD_PRELOAD", "PATH", "HOME",
    "PCAP_MASTER_KEY", "AWS_ACCESS_KEY_ID",  # a real variable, but not Cloudflare's
])
def test_a_name_the_provider_does_not_list_is_refused(name):
    with pytest.raises(ValueError, match="not a setting"):
        providers.validate_credentials("cloudflare", {name: "x"})


def test_values_are_bounded():
    with pytest.raises(ValueError, match="longer"):
        providers.validate_credentials("cloudflare", {"CF_DNS_API_TOKEN": "a" * 5000})
    with pytest.raises(ValueError, match="NUL"):
        providers.validate_credentials("cloudflare", {"CF_DNS_API_TOKEN": "a\x00b"})
    with pytest.raises(ValueError, match="text"):
        providers.validate_credentials("cloudflare", {"CF_DNS_API_TOKEN": 5})


def test_a_file_setting_takes_contents_up_to_its_own_limit():
    pem = "-----BEGIN PRIVATE KEY-----\n" + "A" * 6000 + "\n-----END PRIVATE KEY-----\n"
    assert providers.validate_credentials("transip", {"TRANSIP_PRIVATE_KEY_PATH": pem})


def test_unknown_provider_is_refused():
    with pytest.raises(ValueError, match="unknown"):
        providers.validate_credentials("../../etc", {})


def test_ui_catalog_carries_no_values():
    ui = providers.catalog_for_ui()
    assert {"code", "name", "docs", "primary", "variables"} == set(ui[0])
    assert all(set(v) == {"name", "description", "kind", "group"} for p in ui for v in p["variables"])


def test_every_recommended_setting_exists_for_its_provider():
    for code, names in providers.PRIMARY.items():
        available = {v.name for v in providers.get(code).variables}
        assert set(names) <= available, (code, set(names) - available)


def test_cloudflare_leads_with_just_the_api_token():
    ui = {p["code"]: p for p in providers.catalog_for_ui()}
    assert ui["cloudflare"]["primary"] == ["CF_DNS_API_TOKEN"]
    assert ui["hetzner"]["primary"] == []
