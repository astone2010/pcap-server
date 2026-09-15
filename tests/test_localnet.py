"""Tests for backend.localnet -- the address layer (describe_if_local) and the
kernel layer (describe_if_same_kernel).

The address layer is table-driven across the three ways a target can be
recognised as "this machine" (HOST_ALIASES, an address the container itself
holds, the default gateway), plus an explicit test of the case addresses cannot
catch: a Docker host reached by its own LAN address. The kernel layer is what
catches that one, by comparing the target's boot id with ours -- so its tests
cover the comparison, the normalising that keeps a remote value in shape, and
both directions of "unknown", which must never refuse.

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


def test_the_case_address_checks_cannot_catch(monkeypatch):
    """The host's real LAN address, reached from a bridged container that was
    never told what the host is called, resolves to neither an address the
    container holds nor its gateway -- so it looks exactly like a genuinely
    remote target. This pins the address layer's actual limit rather than
    assuming it is caught. describe_if_same_kernel is what covers this case,
    and it needs a connection to the target to do it."""
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


def test_a_docker_hosts_lan_address_is_not_detected_by_address():
    """The limit of the ADDRESS layer, asserted rather than assumed.

    describe_if_local knows this container's own addresses and its default
    gateway. A bridged container knows nothing about the host's LAN address, so
    pointing pcap-server at the very machine it runs on -- by the address an
    operator would actually type -- is invisible to resolving. That is why
    describe_if_same_kernel exists: it answers the same question from the
    target's own kernel identity, where topology does not come into it.
    """
    assert localnet.describe_if_local("192.168.1.10") == ""
    assert localnet.describe_if_local("10.0.0.5") == ""


def test_the_obvious_self_targets_are_still_caught():
    """The other half: what detection does cover is not weakened by the above."""
    assert localnet.describe_if_local("localhost") != ""
    assert localnet.describe_if_local("127.0.0.1") != ""


# --- boot id: the check that does not depend on addressing at all ---------------


_A_BOOT_ID = "70612579-dfd6-4521-a99b-5959f2ba5760"
_ANOTHER_BOOT_ID = "0f9c1a2b-3d4e-4f50-8a6b-7c8d9e0f1a2b"


@pytest.mark.parametrize("raw,expected", [
    (_A_BOOT_ID, _A_BOOT_ID),
    (f"{_A_BOOT_ID}\n", _A_BOOT_ID),
    (f"  {_A_BOOT_ID}  ", _A_BOOT_ID),
    (_A_BOOT_ID.upper(), _A_BOOT_ID),
    ("", ""),
    ("not-a-uuid", ""),
    ("70612579dfd645219a995959f2ba5760", ""),          # no dashes
    (f"{_A_BOOT_ID} rm -rf /", ""),                    # trailing junk
    (f"{_A_BOOT_ID}{_A_BOOT_ID}", ""),                 # two concatenated
    ("../../etc/passwd", ""),
])
def test_normalise_boot_id(raw, expected):
    assert localnet.normalise_boot_id(raw) == expected


def test_normalise_boot_id_bounds_what_it_will_even_look_at():
    """A target answering with a flood of bytes cannot make us hold any of it."""
    flood = "a" * 10_000_000
    assert localnet.normalise_boot_id(flood) == ""


def test_normalise_boot_id_ignores_a_valid_id_buried_past_the_bound():
    padded = " " * (localnet.BOOT_ID_MAX_CHARS + 1) + _A_BOOT_ID
    assert localnet.normalise_boot_id(padded) == ""


def test_same_boot_id_is_this_machine(monkeypatch):
    monkeypatch.setattr(localnet, "own_boot_id", lambda: _A_BOOT_ID)
    result = localnet.describe_if_same_kernel(_A_BOOT_ID)
    assert result != ""
    assert "same kernel boot id" in result


def test_same_boot_id_in_a_different_case_still_matches(monkeypatch):
    monkeypatch.setattr(localnet, "own_boot_id", lambda: _A_BOOT_ID)
    assert localnet.describe_if_same_kernel(f"{_A_BOOT_ID.upper()}\n") != ""


def test_different_boot_id_is_not_this_machine(monkeypatch):
    monkeypatch.setattr(localnet, "own_boot_id", lambda: _A_BOOT_ID)
    assert localnet.describe_if_same_kernel(_ANOTHER_BOOT_ID) == ""


def test_unreadable_remote_boot_id_proves_nothing(monkeypatch):
    """A BSD target, or one with a masked /proc, has told us nothing. Refusing
    it would break legitimate targets for no security gain -- absence of proof
    is not proof of locality, and the address checks still apply underneath."""
    monkeypatch.setattr(localnet, "own_boot_id", lambda: _A_BOOT_ID)
    assert localnet.describe_if_same_kernel("") == ""
    assert localnet.describe_if_same_kernel("unknown") == ""


def test_unreadable_own_boot_id_never_matches_everything(monkeypatch):
    """If our own /proc gives nothing, two empty strings must not compare equal
    and refuse every target in existence. Fails open, loudly documented."""
    monkeypatch.setattr(localnet, "own_boot_id", lambda: "")
    assert localnet.describe_if_same_kernel("") == ""
    assert localnet.describe_if_same_kernel(_A_BOOT_ID) == ""


def test_own_boot_id_reads_the_kernels_value(tmp_path, monkeypatch):
    path = tmp_path / "boot_id"
    path.write_text(f"{_A_BOOT_ID}\n")
    monkeypatch.setattr(localnet, "BOOT_ID_PATH", path)
    assert localnet.own_boot_id() == _A_BOOT_ID


def test_own_boot_id_survives_a_missing_proc(tmp_path, monkeypatch):
    monkeypatch.setattr(localnet, "BOOT_ID_PATH", tmp_path / "definitely-absent")
    assert localnet.own_boot_id() == ""


def test_own_boot_id_is_not_cached_across_calls(tmp_path, monkeypatch):
    """A cached empty string from an early call would disable the check for the
    life of the process -- the failure mode would be silent and total."""
    path = tmp_path / "boot_id"
    monkeypatch.setattr(localnet, "BOOT_ID_PATH", path)
    assert localnet.own_boot_id() == ""
    path.write_text(_A_BOOT_ID)
    assert localnet.own_boot_id() == _A_BOOT_ID


def test_this_container_reports_some_boot_id():
    """Not a unit test of our code: a check that the environment this ships into
    actually exposes /proc/sys/kernel/random/boot_id. If a runtime ever stops
    exposing it, the kernel check degrades to doing nothing at all, and that
    should fail here rather than in production silence.
    """
    assert localnet.own_boot_id() != "", (
        "no readable boot id -- the shared-kernel self-capture check cannot fire"
    )
