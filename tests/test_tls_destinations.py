"""URL and address settings cannot point lego at the container itself, at
link-local space (cloud metadata lives there), or at nothing-in-particular --
but a self-hosted DNS server on the LAN is the ordinary case and stays allowed."""

from __future__ import annotations

import socket

import pytest

from backend.tls import destinations, providers


@pytest.mark.parametrize("value", [
    "http://127.0.0.1:8080/api", "https://localhost/", "http://[::1]:8081/",
    "http://169.254.169.254/latest/meta-data/", "http://[fe80::1]/", "http://0.0.0.0/",
    "http://[::ffff:127.0.0.1]/", "http://metadata.google.internal/", "http://app.localhost/",
])
def test_urls_at_the_container_or_metadata_are_refused(value):
    with pytest.raises(ValueError):
        destinations.check("PDNS_API_URL", value, resolve=False)


@pytest.mark.parametrize("value", ["127.0.0.1:53", "[::1]:53", "169.254.1.1", "localhost"])
def test_bare_addresses_in_host_settings_are_refused(value):
    with pytest.raises(ValueError):
        destinations.check("DNSUPDATE_NAMESERVER", value, resolve=False)


@pytest.mark.parametrize("value", [
    "https://10.0.0.5:8081/api/v1", "http://192.168.1.10/", "https://pdns.internal.example.com/",
    "https://[fd00::5]/",
])
def test_lan_and_public_servers_are_allowed(value):
    destinations.check("PDNS_API_URL", value, resolve=False)


@pytest.mark.parametrize("value", ["file:///etc/passwd", "gopher://10.0.0.1/", "ftp://x.example.com/"])
def test_only_http_urls_are_accepted(value):
    with pytest.raises(ValueError, match="http"):
        destinations.check("PDNS_API_URL", value, resolve=False)


def test_non_address_settings_are_not_treated_as_hosts():
    destinations.check("CF_DNS_API_TOKEN", "127.0.0.1", resolve=False)
    destinations.check("OVH_ENDPOINT", "ovh-eu", resolve=False)


def test_a_hostname_that_resolves_to_loopback_is_caught_before_lego_runs(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, port: [(socket.AF_INET, 0, 0, "", ("127.0.0.1", 0))])
    destinations.check("PDNS_API_URL", "https://sneaky.example.com/", resolve=False)
    with pytest.raises(ValueError, match="resolves to 127.0.0.1"):
        destinations.check("PDNS_API_URL", "https://sneaky.example.com/", resolve=True)


def test_a_name_that_does_not_resolve_is_left_to_lego(monkeypatch):
    def fail(host, port):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    destinations.check("PDNS_API_URL", "https://does-not-exist.example/", resolve=True)


def test_credential_validation_applies_it():
    with pytest.raises(ValueError, match="loopback"):
        providers.validate_credentials("pdns", {"PDNS_API_URL": "http://127.0.0.1:8080/", "PDNS_API_KEY": "k"})
    assert providers.validate_credentials(
        "pdns", {"PDNS_API_URL": "http://10.0.0.53:8081/", "PDNS_API_KEY": "k"})


def test_settings_that_turn_off_certificate_checks_are_not_offered():
    names = {v.name for p in providers.all_providers() for v in p.variables}
    for gone in ("ISPCONFIG_INSECURE_SKIP_VERIFY", "EFFICIENTIP_INSECURE_SKIP_VERIFY",
                 "NAMESURFER_INSECURE_SKIP_VERIFY", "INFOBLOX_SSL_VERIFY"):
        assert gone not in names
