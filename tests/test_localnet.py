"""Tests for backend.localnet.describe_if_local -- table-driven across the
three ways a target can be recognised as "this machine" (HOST_ALIASES,
an address the container itself holds, the default gateway), plus an
explicit test of the case the module's own docstring says it cannot catch.

resolve()/_own_addresses()/_default_gateways() touch real DNS, sockets and
/proc -- monkeypatched here so describe_if_local's branching logic runs
anywhere, deterministically, with no dependency on the container's actual
network state.
"""

from __future__ import annotations

import pytest

from backend import localnet


def _stub(monkeypatch, *, resolves_to: set[str], own: set[str] = frozenset(), gateways: set[str] = frozenset()):
    monkeypatch.setattr(localnet, "resolve", lambda hostname: set(resolves_to))
    monkeypatch.setattr(localnet, "_own_addresses", lambda: set(own))
    monkeypatch.setattr(localnet, "_default_gateways", lambda: set(gateways))


# --- HOST_ALIASES: short-circuits before resolve() is ever called ----------


@pytest.mark.parametrize("alias", sorted(localnet.HOST_ALIASES))
def test_host_aliases_are_recognised_as_local(monkeypatch, alias):
    monkeypatch.setattr(localnet, "resolve", _resolve_should_not_be_called)
    result = localnet.describe_if_local(alias)
    assert result != ""
    assert alias in result


def _resolve_should_not_be_called(hostname):
    raise AssertionError("resolve() should not be called for a HOST_ALIASES hit")


def test_host_alias_match_is_case_insensitive(monkeypatch):
    monkeypatch.setattr(localnet, "resolve", _resolve_should_not_be_called)
    assert localnet.describe_if_local("Host.Docker.Internal") != ""


def test_host_alias_match_ignores_trailing_dot(monkeypatch):
    monkeypatch.setattr(localnet, "resolve", _resolve_should_not_be_called)
    assert localnet.describe_if_local("localhost.") != ""


def test_non_alias_hostname_falls_through_to_resolve(monkeypatch):
    _stub(monkeypatch, resolves_to=set())
    assert localnet.describe_if_local("example.com") == ""


# --- loopback ----------------------------------------------------------------


@pytest.mark.parametrize("loopback_addr", ["127.0.0.1", "127.5.5.5", "::1"])
def test_resolves_to_loopback_is_local(monkeypatch, loopback_addr):
    _stub(monkeypatch, resolves_to={loopback_addr})
    result = localnet.describe_if_local("some-target")
    assert result != ""
    assert loopback_addr in result


# --- own address ---------------------------------------------------------------


def test_resolves_to_own_address_is_local(monkeypatch):
    _stub(monkeypatch, resolves_to={"10.0.0.5"}, own={"10.0.0.5", "127.0.0.1"})
    result = localnet.describe_if_local("this-container")
    assert result != ""
    assert "10.0.0.5" in result
    assert "itself answers on" in result


# --- default gateway -----------------------------------------------------------


def test_resolves_to_default_gateway_is_local(monkeypatch):
    _stub(monkeypatch, resolves_to={"172.17.0.1"}, own={"172.17.0.5"}, gateways={"172.17.0.1"})
    result = localnet.describe_if_local("docker-host")
    assert result != ""
    assert "172.17.0.1" in result
    assert "gateway" in result


# --- not local (or genuinely unknown) -------------------------------------------


def test_unresolvable_hostname_is_not_flagged(monkeypatch):
    _stub(monkeypatch, resolves_to=set())
    assert localnet.describe_if_local("does-not-resolve.invalid") == ""


def test_resolves_to_unrelated_address_is_not_flagged(monkeypatch):
    _stub(monkeypatch, resolves_to={"93.184.216.34"}, own={"10.0.0.5"}, gateways={"172.17.0.1"})
    assert localnet.describe_if_local("clearly-remote-host") == ""


def test_the_case_this_guard_cannot_catch(monkeypatch):
    """Documented in the module's own docstring: the host's real LAN address,
    reached from a bridged container that was never told what the host is
    called, resolves to neither an address the container holds nor its
    gateway -- so it looks exactly like a genuinely remote target. This
    pins the guard's actual limit rather than assuming it is caught."""
    host_lan_address = "192.168.1.50"
    _stub(
        monkeypatch,
        resolves_to={host_lan_address},
        own={"172.17.0.5"},        # the container's own bridge address
        gateways={"172.17.0.1"},   # the bridge gateway, not the host's LAN IP
    )
    assert localnet.describe_if_local(host_lan_address) == ""


# --- resolve(): IP literals and failure handling --------------------------------


def test_resolve_ip_literal_short_circuits_without_dns(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("getaddrinfo should not be called for an IP literal")

    monkeypatch.setattr(localnet.socket, "getaddrinfo", boom)
    assert localnet.resolve("203.0.113.9") == {"203.0.113.9"}


def test_resolve_empty_hostname_returns_empty_set():
    assert localnet.resolve("") == set()
    assert localnet.resolve("   ") == set()


def test_resolve_returns_empty_set_when_dns_fails(monkeypatch):
    def boom(*a, **k):
        raise OSError("simulated DNS failure")

    monkeypatch.setattr(localnet.socket, "getaddrinfo", boom)
    assert localnet.resolve("some-hostname-that-fails") == set()


def test_resolve_strips_ipv6_zone_id(monkeypatch):
    monkeypatch.setattr(
        localnet.socket, "getaddrinfo",
        lambda *a, **k: [(None, None, None, None, ("fe80::1%eth0", 0))],
    )
    assert localnet.resolve("some-hostname") == {"fe80::1"}


def test_resolve_restores_default_timeout_even_on_failure(monkeypatch):
    original = localnet.socket.getdefaulttimeout()

    def boom(*a, **k):
        raise OSError("simulated failure")

    monkeypatch.setattr(localnet.socket, "getaddrinfo", boom)
    localnet.resolve("whatever")
    assert localnet.socket.getdefaulttimeout() == original


# --- local_addresses(): union of own + gateway ----------------------------------


def test_local_addresses_is_the_union(monkeypatch):
    monkeypatch.setattr(localnet, "_own_addresses", lambda: {"127.0.0.1", "10.0.0.5"})
    monkeypatch.setattr(localnet, "_default_gateways", lambda: {"10.0.0.1"})
    assert localnet.local_addresses() == {"127.0.0.1", "10.0.0.5", "10.0.0.1"}


def test_a_docker_hosts_lan_address_is_not_detected():
    """The limit of what detection can see, asserted rather than assumed.

    describe_if_local knows this container's own addresses and its default
    gateway. A bridged container knows nothing about the host's LAN address, so
    pointing pcap-server at the very machine it runs on -- by the address an
    operator would actually type -- is invisible from in here. That is not a bug
    to fix at this layer; it is why the Add server form carries a standing
    warning as well as this check. If this ever starts returning a finding, the
    warning can be reconsidered.
    """
    assert localnet.describe_if_local("192.168.1.10") == ""
    assert localnet.describe_if_local("10.0.0.5") == ""


def test_the_obvious_self_targets_are_still_caught():
    """The other half: what detection does cover is not weakened by the above."""
    assert localnet.describe_if_local("localhost") != ""
    assert localnet.describe_if_local("127.0.0.1") != ""
