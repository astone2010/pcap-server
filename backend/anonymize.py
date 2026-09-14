"""Stable, keyed stand-ins for the addresses and names in a sanitized capture.

Everything here is a pure function of a per-capture key and the original value,
which is what makes the user's requirement hold: sanitizing the same capture
twice gives the same mapping, so two downloads a week apart can be compared
side by side, and nothing about the mapping has to be stored anywhere.

The key is the part that must stay secret. Anyone holding it and a sanitized
file can recompute the mapping for every address they care to guess, so it is
derived from something that already guards the capture itself (see
CaptureVault.derived_key) and never leaves this process.

Three kinds of stand-in, each chosen so the sanitized capture is still worth
opening:

* **IP addresses** are prefix-preserving (Crypto-PAn, Xu et al. 2002): two
  addresses sharing an n-bit prefix map to two addresses sharing an n-bit
  prefix. Subnets stay subnets, so "these hosts are on the same /24" survives
  sanitizing even though the /24 itself does not.
* **MAC addresses** are keyed hashes, marked locally administered so a stand-in
  can never be mistaken for a real vendor's address -- unless the operator asks
  to keep the vendor prefix, in which case only the device half is replaced.
* **Names** (hostnames, usernames) are keyed pseudonyms of the same length and
  the same character classes, so a sanitized capture is byte-for-byte the same
  size and every length field in it stays true.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from backend.crypto import derive_subkey

# The label every sanitize key is derived under. Versioned so a future change to
# the mapping can take a new label rather than silently changing old mappings.
KEY_INFO = b"pcap-server sanitize v1"

_MASK128 = (1 << 128) - 1

# Kept as they are whatever is ticked. None of these identify a host or a
# network: they are the same on every network in the world.
_IPV4_ALWAYS_KEPT = (
    (0x00000000, 32),  # 0.0.0.0, "this host" in DHCP and friends
    (0x7F000000, 8),   # 127.0.0.0/8 loopback
    (0xE0000000, 4),   # 224.0.0.0/4 multicast
    (0xF0000000, 4),   # 240.0.0.0/4 reserved, and 255.255.255.255 broadcast
)
_IPV4_PRIVATE = (
    (0x0A000000, 8),   # 10.0.0.0/8
    (0xAC100000, 12),  # 172.16.0.0/12
    (0xC0A80000, 16),  # 192.168.0.0/16
    (0xA9FE0000, 16),  # 169.254.0.0/16 link-local
    (0x64400000, 10),  # 100.64.0.0/10 carrier-grade NAT
)
_IPV6_ALWAYS_KEPT = (
    (0, 128),                    # ::
    (1, 128),                    # ::1
    (0xFF << 120, 8),            # ff00::/8 multicast
)
_IPV6_PRIVATE = (
    (0xFE80 << 112, 10),         # fe80::/10 link-local
    (0xFC << 120, 7),            # fc00::/7 unique local
)
_IPV4_MAPPED_PREFIX = b"\x00" * 10 + b"\xff\xff"

# Distinct values remembered per kind. Packet contents are whatever the network
# sent, so a capture of an address sweep could otherwise grow these without
# limit. Past the cap a stand-in is recomputed each time -- the same answer,
# more slowly -- and the summary's counts become a lower bound.
CACHE_LIMIT = 200_000


def derive_key(secret: bytes, context: bytes = b"") -> bytes:
    """64 bytes of key material for one capture, from a secret and a context.

    The first 32 feed the prefix-preserving map; the second 32 key every hash.
    HKDF rather than slicing the secret itself, so the secret is never used
    directly as a cipher key and neither half says anything about the other.
    """
    return derive_subkey(secret, KEY_INFO + context, 64)


def _in_ranges(value: int, bits: int, ranges) -> bool:
    for base, prefix in ranges:
        shift = bits - prefix
        if (value >> shift) == (base >> shift):
            return True
    return False


class PrefixPreservingMap:
    """Crypto-PAn over 32- and 128-bit addresses.

    For bit i of the address, AES encrypts a block made of the address's first
    i bits followed by the pad's remaining bits; the top bit of the result is
    XORed into bit i. Bit i therefore depends only on the bits before it, which
    is exactly the prefix-preserving property. IPv4 is the published algorithm
    unchanged; IPv6 is the same construction carried on to 128 bits.
    """

    def __init__(self, key32: bytes) -> None:
        if len(key32) != 32:
            raise ValueError("prefix-preserving map needs a 32-byte key")
        # ECB is correct here, not a shortcut: every block is a distinct
        # single-block PRF evaluation, and the construction is defined on AES
        # itself. Nothing is ever encrypted for confidentiality with this.
        self._encryptor = Cipher(algorithms.AES(key32[:16]), modes.ECB()).encryptor()
        self._pad = int.from_bytes(self._encryptor.update(key32[16:]), "big")

    def map(self, address: int, bits: int) -> int:
        aligned = address << (128 - bits)
        blocks = bytearray()
        for position in range(bits):
            keep = (((1 << position) - 1) << (128 - position)) if position else 0
            block = (aligned & keep) | (self._pad & ~keep & _MASK128)
            blocks += block.to_bytes(16, "big")
        # One call for all of them: the per-block cost is AES, not Python.
        out = self._encryptor.update(bytes(blocks))
        flips = 0
        for position in range(bits):
            flips = (flips << 1) | (out[position * 16] >> 7)
        return address ^ flips


class AddressMapper:
    """The IPv4, IPv6 and MAC stand-ins for one capture, cached as it goes.

    The caches double as the summary's counts: every distinct address that was
    replaced is in exactly one of them.
    """

    def __init__(self, key: bytes, *, keep_private: bool = False, keep_oui: bool = False) -> None:
        if len(key) != 64:
            raise ValueError("address mapper needs 64 bytes of key material")
        self._prefix_map = PrefixPreservingMap(key[:32])
        self._hash_key = key[32:]
        self.keep_private = keep_private
        self.keep_oui = keep_oui
        self._ipv4: dict[bytes, bytes] = {}
        self._ipv6: dict[bytes, bytes] = {}
        self._mac: dict[bytes, bytes] = {}

    @property
    def counts(self) -> dict[str, int]:
        return {
            "ipv4": sum(1 for k, v in self._ipv4.items() if k != v),
            "ipv6": sum(1 for k, v in self._ipv6.items() if k != v),
            "mac": sum(1 for k, v in self._mac.items() if k != v),
        }

    @staticmethod
    def _remember(cache: dict[bytes, bytes], raw: bytes, stand_in: bytes) -> bytes:
        if len(cache) < CACHE_LIMIT:
            cache[raw] = stand_in
        return stand_in

    def ipv4(self, raw: bytes) -> bytes:
        cached = self._ipv4.get(raw)
        return cached if cached is not None else self._remember(self._ipv4, raw, self._map_ipv4(raw))

    def _map_ipv4(self, raw: bytes) -> bytes:
        value = int.from_bytes(raw, "big")
        if _in_ranges(value, 32, _IPV4_ALWAYS_KEPT):
            return raw
        if self.keep_private and _in_ranges(value, 32, _IPV4_PRIVATE):
            return raw
        return self._prefix_map.map(value, 32).to_bytes(4, "big")

    def ipv6(self, raw: bytes) -> bytes:
        cached = self._ipv6.get(raw)
        return cached if cached is not None else self._remember(self._ipv6, raw, self._map_ipv6(raw))

    def _map_ipv6(self, raw: bytes) -> bytes:
        if raw[:12] == _IPV4_MAPPED_PREFIX:
            # ::ffff:a.b.c.d is an IPv4 address written as IPv6, and it gets the
            # IPv4 stand-in -- otherwise one host would appear under two
            # unrelated sanitized addresses depending on which socket saw it.
            return raw[:12] + self.ipv4(raw[12:])
        value = int.from_bytes(raw, "big")
        if _in_ranges(value, 128, _IPV6_ALWAYS_KEPT):
            return raw
        if self.keep_private and _in_ranges(value, 128, _IPV6_PRIVATE):
            return raw
        return self._prefix_map.map(value, 128).to_bytes(16, "big")

    def mac(self, raw: bytes) -> bytes:
        cached = self._mac.get(raw)
        return cached if cached is not None else self._remember(self._mac, raw, self._map_mac(raw))

    def _map_mac(self, raw: bytes) -> bytes:
        # Group addresses (broadcast, multicast) name a service, not a device,
        # and an all-zero address names nothing at all.
        if raw[0] & 0x01 or raw == b"\x00" * 6:
            return raw
        digest = hmac.new(self._hash_key, b"mac\x00" + raw, hashlib.sha256).digest()
        if self.keep_oui:
            return raw[:3] + digest[:3]
        # Unicast, locally administered: a stand-in that cannot collide with any
        # address a manufacturer could have burned into a card.
        return bytes([(digest[0] & 0xFC) | 0x02]) + digest[1:6]


_LOWER = b"abcdefghijklmnopqrstuvwxyz"
_UPPER = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_DIGIT = b"0123456789"

# Labels that are structure rather than identity: reverse-lookup names keep
# their suffix so they still read as reverse lookups.
_STRUCTURAL_LABELS = frozenset({"arpa", "in-addr", "ip6"})


class Pseudonyms:
    """Same-length keyed stand-ins for names.

    Letters stay letters, digits stay digits, and everything else stays exactly
    where it was, so "alice.smith@corp" becomes something like "kqwmr.ztvbe@hxfa"
    rather than a string of asterisks: the shape of a value is often what makes
    a capture readable, and it gives nothing away that its length did not.
    """

    def __init__(self, key: bytes) -> None:
        self._key = key[32:]
        self._labels: dict[str, bytes] = {}

    def _stream(self, kind: bytes, value: str, length: int) -> bytes:
        out = bytearray()
        counter = 0
        seed = kind + b"\x00" + value.lower().encode("utf-8", "surrogatepass")
        while len(out) < length:
            out += hmac.new(self._key, seed + counter.to_bytes(4, "big"), hashlib.sha256).digest()
            counter += 1
        return bytes(out[:length])

    @staticmethod
    def _apply(template: bytes, stream: bytes) -> bytes:
        out = bytearray(template)
        for i, byte in enumerate(template):
            pick = stream[i]
            if 0x61 <= byte <= 0x7A:
                out[i] = _LOWER[pick % 26]
            elif 0x41 <= byte <= 0x5A:
                out[i] = _UPPER[pick % 26]
            elif 0x30 <= byte <= 0x39:
                out[i] = _DIGIT[pick % 10]
            elif byte >= 0x80:
                # Part of a multi-byte character. Replaced with a plain letter,
                # byte for byte, so the length does not move.
                out[i] = _LOWER[pick % 26]
        return bytes(out)

    def text(self, kind: bytes, value: str, template: bytes) -> bytes:
        """`template` (the original bytes) with every letter and digit replaced."""
        return self._apply(template, self._stream(kind, value, len(template)))

    def label(self, label: bytes) -> bytes:
        """One hostname label. Keyed on the label alone, so shared suffixes match."""
        text = label.decode("latin-1").lower()
        if text in _STRUCTURAL_LABELS:
            return label
        cached = self._labels.get(text)
        if cached is None:
            cached = self.text(b"label", text, label.lower())
            if len(self._labels) < CACHE_LIMIT:
                self._labels[text] = cached
        return cached

    def hostname(self, name: bytes) -> bytes:
        """A dotted name, label by label, keeping the last label.

        The last label is kept because it is almost never the identifying part
        ("com", "local", "lan") and because keeping it is what lets a reader
        still tell a public name from an internal one. A name with a single
        label has nothing to keep.
        """
        labels = name.split(b".")
        if len(labels) == 1:
            return self.label(name)
        mapped = [self.label(part) if part else part for part in labels[:-1]]
        return b".".join(mapped + [labels[-1]])
