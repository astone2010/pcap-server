"""The keyed stand-ins a sanitized capture is built from.

What has to hold for the sanitizer to be worth using:

  * **The IPv4 map is Crypto-PAn, not something like it.** Checked against the
    known-answer vectors published with the reference implementation.
  * **Prefixes are preserved** -- for IPv6 as well as IPv4 -- so subnets are
    still visible in a sanitized capture.
  * **The same key gives the same stand-in, and a different key does not.**
  * **What identifies nothing is left alone**: loopback, multicast, broadcast,
    group MACs; and private ranges only when the operator asks.
  * **Names keep their length and shape**, so every length field in the
    packet stays true.
"""

from __future__ import annotations

import ipaddress
import os
import random

import pytest

from backend.anonymize import AddressMapper, PrefixPreservingMap, Pseudonyms, derive_key

KEY = bytes(range(64))

# The sample key and trace from the Crypto-PAn reference distribution.
_REFERENCE_KEY = bytes([
    21, 34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16,
    216, 152, 143, 131, 121, 121, 101, 39, 98, 87, 76, 45, 42, 132, 34, 2,
])
_REFERENCE_VECTORS = [
    ("128.11.68.132", "135.242.180.132"),
    ("129.118.74.4", "134.136.186.123"),
    ("130.132.252.244", "133.68.164.234"),
    ("141.223.7.43", "141.167.8.160"),
    ("141.233.145.108", "141.129.237.235"),
    ("152.163.225.39", "151.140.114.167"),
    ("156.29.3.236", "147.225.12.42"),
    ("165.247.96.84", "162.9.99.234"),
    ("166.107.77.190", "160.132.178.185"),
    ("192.102.249.13", "252.138.62.131"),
]


@pytest.mark.parametrize("original, expected", _REFERENCE_VECTORS)
def test_ipv4_matches_the_crypto_pan_reference_vectors(original, expected):
    mapped = PrefixPreservingMap(_REFERENCE_KEY).map(int(ipaddress.IPv4Address(original)), 32)
    assert str(ipaddress.IPv4Address(mapped)) == expected


def _common_prefix(a: int, b: int, bits: int) -> int:
    diff = a ^ b
    return bits if diff == 0 else bits - diff.bit_length()


@pytest.mark.parametrize("bits", [32, 128])
def test_shared_prefixes_survive_mapping(bits):
    prefix_map = PrefixPreservingMap(os.urandom(32))
    rng = random.Random(7)
    for _ in range(200):
        a = rng.getrandbits(bits)
        b = a ^ rng.getrandbits(rng.randint(0, bits))
        assert _common_prefix(prefix_map.map(a, bits), prefix_map.map(b, bits), bits) == \
            _common_prefix(a, b, bits)


def test_the_same_key_gives_the_same_stand_in_and_another_key_does_not():
    address = ipaddress.IPv4Address("203.0.113.9").packed
    assert AddressMapper(KEY).ipv4(address) == AddressMapper(KEY).ipv4(address)
    other = bytes(reversed(KEY))
    assert AddressMapper(other).ipv4(address) != AddressMapper(KEY).ipv4(address)


@pytest.mark.parametrize("address", ["127.0.0.1", "224.0.0.251", "255.255.255.255", "0.0.0.0"])
def test_ipv4_addresses_that_identify_nothing_are_kept(address):
    raw = ipaddress.IPv4Address(address).packed
    assert AddressMapper(KEY).ipv4(raw) == raw


@pytest.mark.parametrize("address", ["::", "::1", "ff02::1"])
def test_ipv6_addresses_that_identify_nothing_are_kept(address):
    raw = ipaddress.IPv6Address(address).packed
    assert AddressMapper(KEY).ipv6(raw) == raw


@pytest.mark.parametrize("address", ["10.1.2.3", "172.20.0.5", "192.168.1.10", "169.254.3.3", "100.64.8.8"])
def test_private_ipv4_is_replaced_unless_asked_to_keep_it(address):
    raw = ipaddress.IPv4Address(address).packed
    assert AddressMapper(KEY).ipv4(raw) != raw
    assert AddressMapper(KEY, keep_private=True).ipv4(raw) == raw


@pytest.mark.parametrize("address", ["fe80::1", "fd00::5"])
def test_private_ipv6_is_replaced_unless_asked_to_keep_it(address):
    raw = ipaddress.IPv6Address(address).packed
    assert AddressMapper(KEY).ipv6(raw) != raw
    assert AddressMapper(KEY, keep_private=True).ipv6(raw) == raw


def test_keep_private_does_not_keep_public_addresses():
    raw = ipaddress.IPv4Address("8.8.8.8").packed
    assert AddressMapper(KEY, keep_private=True).ipv4(raw) != raw


def test_an_ipv4_mapped_ipv6_address_gets_the_ipv4_stand_in():
    mapper = AddressMapper(KEY)
    v4 = ipaddress.IPv4Address("198.51.100.7").packed
    v6 = ipaddress.IPv6Address("::ffff:198.51.100.7").packed
    assert mapper.ipv6(v6)[12:] == mapper.ipv4(v4)
    assert mapper.ipv6(v6)[:12] == v6[:12]


def test_group_and_empty_macs_are_kept():
    mapper = AddressMapper(KEY)
    for raw in (b"\xff" * 6, bytes.fromhex("01005e0000fb"), bytes.fromhex("333300000001"), b"\x00" * 6):
        assert mapper.mac(raw) == raw


def test_a_replaced_mac_is_unicast_and_locally_administered():
    stand_in = AddressMapper(KEY).mac(bytes.fromhex("a4bb6d010203"))
    assert stand_in != bytes.fromhex("a4bb6d010203")
    assert stand_in[0] & 0x01 == 0
    assert stand_in[0] & 0x02 == 0x02


def test_keep_oui_replaces_only_the_device_half():
    original = bytes.fromhex("a4bb6d010203")
    stand_in = AddressMapper(KEY, keep_oui=True).mac(original)
    assert stand_in[:3] == original[:3]
    assert stand_in[3:] != original[3:]


def test_counts_only_count_what_was_actually_replaced():
    mapper = AddressMapper(KEY)
    mapper.ipv4(ipaddress.IPv4Address("8.8.8.8").packed)
    mapper.ipv4(ipaddress.IPv4Address("8.8.8.8").packed)
    mapper.ipv4(ipaddress.IPv4Address("127.0.0.1").packed)
    mapper.mac(b"\xff" * 6)
    assert mapper.counts == {"ipv4": 1, "ipv6": 0, "mac": 0}


def test_derived_keys_depend_on_the_context():
    secret = os.urandom(32)
    assert derive_key(secret, b"a") == derive_key(secret, b"a")
    assert derive_key(secret, b"a") != derive_key(secret, b"b")
    assert len(derive_key(secret)) == 64


# --- names ---------------------------------------------------------------------


def test_a_pseudonym_keeps_length_character_classes_and_punctuation():
    names = Pseudonyms(KEY)
    original = b"Alice.Smith-99@corp"
    stand_in = names.text(b"user", "Alice.Smith-99@corp", original)
    assert len(stand_in) == len(original)
    assert stand_in != original
    for a, b in zip(original, stand_in):
        a, b = chr(a), chr(b)
        assert a.isdigit() == b.isdigit()
        assert a.islower() == b.islower()
        assert a.isupper() == b.isupper()
        if not a.isalnum():
            assert a == b


def test_a_pseudonym_replaces_non_ascii_bytes_one_for_one():
    original = "zoë".encode()
    stand_in = Pseudonyms(KEY).text(b"user", "zoë", original)
    assert len(stand_in) == len(original)
    assert all(b < 0x80 for b in stand_in)


def test_hostnames_keep_their_last_label_and_share_suffix_mappings():
    names = Pseudonyms(KEY)
    a = names.hostname(b"www.corp.example.com")
    b = names.hostname(b"mail.corp.example.com")
    assert a.endswith(b".com") and b.endswith(b".com")
    assert a.split(b".")[1:] == b.split(b".")[1:]
    assert a.split(b".")[0] != b"www"
    assert len(a) == len(b"www.corp.example.com")


def test_a_label_maps_the_same_in_a_dotted_name_and_on_its_own():
    names = Pseudonyms(KEY)
    assert names.hostname(b"printer.local").split(b".")[0] == names.label(b"printer")


def test_a_single_label_name_is_replaced():
    assert Pseudonyms(KEY).hostname(b"fileserver") != b"fileserver"


def test_reverse_lookup_structure_is_kept():
    stand_in = Pseudonyms(KEY).hostname(b"9.113.0.203.in-addr.arpa")
    assert stand_in.endswith(b".in-addr.arpa")
    labels = stand_in.split(b".")[:4]
    assert labels != [b"9", b"113", b"0", b"203"]
    assert all(label.isdigit() for label in labels)


def test_the_caches_stop_growing_but_the_answers_do_not_change(monkeypatch):
    from backend import anonymize

    monkeypatch.setattr(anonymize, "CACHE_LIMIT", 3)
    mapper = AddressMapper(KEY)
    addresses = [ipaddress.IPv4Address(f"203.0.113.{i}").packed for i in range(10)]
    first = [mapper.ipv4(a) for a in addresses]
    assert len(mapper._ipv4) == 3
    assert [mapper.ipv4(a) for a in addresses] == first
    assert [AddressMapper(KEY).ipv4(a) for a in addresses] == first
