"""Where the addresses and checksums are in one frame, read from its headers.

The sanitizer asks tshark for the byte positions of payload fields -- a
credential inside an HTTP header, a hostname inside a DNS answer -- because
finding those means dissecting hundreds of protocols. The headers that carry
the addresses on every single packet are a different problem: a handful of
fixed formats, present millions of times over. Asking tshark for their
positions costs about 20 KB of JSON per packet; reading them here costs a few
struct lookups.

So this module walks a frame's headers from the link layer down to the
transport, and reports two things:

* **addresses** -- the offset and kind of every IPv4, IPv6 and MAC address it
  passed, including the ones inside tunnels, ICMP errors and IPv6 neighbour
  discovery;
* **checksum scopes** -- for every checksum it passed, where the checksum is,
  which bytes it covers, and which address bytes enter it through a pseudo
  header.

Every read is bounds-checked against what was actually captured. A frame cut
short by the snapshot length yields whatever was captured of it, and never an
address that runs off the end.

Checksums are updated incrementally (RFC 1624), not recomputed, which is the
difference between right and wrong in two common cases: a frame truncated by
the snapshot length, whose checksum covers bytes that were never captured; and
an outgoing packet captured before the NIC filled its checksum in, which was
"wrong" in the original and should stay exactly as wrong rather than be
silently repaired into something the original never was.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Link types this walker understands, by their pcap LINKTYPE_ number. A capture
# in any other is refused outright: a sanitizer that cannot find the addresses
# must not hand back a file that looks sanitized.
LINKTYPE_NAMES = {
    0: "BSD loopback",
    1: "Ethernet",
    12: "raw IP",
    14: "raw IP",
    101: "raw IP",
    108: "OpenBSD loopback",
    113: "Linux cooked (SLL)",
    276: "Linux cooked v2 (SLL2)",
}

_ETH_IPV4 = 0x0800
_ETH_ARP = 0x0806
_ETH_RARP = 0x8035
_ETH_IPV6 = 0x86DD
_ETH_VLAN = frozenset({0x8100, 0x88A8, 0x9100})
_ETH_MPLS = frozenset({0x8847, 0x8848})
_ETH_PPPOE_SESSION = 0x8864
_ETH_TRANSPARENT_BRIDGING = 0x6558

_VXLAN_PORT = 4789
_GENEVE_PORT = 6081

_ICMP_ERRORS = frozenset({3, 4, 5, 11, 12})
_ICMPV6_ERRORS = frozenset({1, 2, 3, 4})
_IPV6_EXTENSIONS = frozenset({0, 43, 44, 51, 60})

# Tunnels, ICMP errors and IP-in-IP all recurse. Nothing legitimate nests
# this deep; a frame that claims to is not worth following.
MAX_DEPTH = 8


class UnsupportedLinkType(ValueError):
    pass


@dataclass(slots=True)
class Scope:
    """One checksum: where it is, what it covers, what else feeds it."""

    checksum_at: int
    start: int
    end: int
    pseudo: tuple[tuple[int, int], ...] = ()


@dataclass(slots=True)
class Layout:
    addresses: list[tuple[int, str]] = field(default_factory=list)
    scopes: list[Scope] = field(default_factory=list)
    # The end of the deepest header understood: what "strip payload" keeps.
    payload_start: int = 0
    # The innermost transport seen, as (name, source port, destination port).
    transport: tuple[str, int, int] | None = None


def walk(frame: bytes, linktype: int) -> Layout:
    if linktype not in LINKTYPE_NAMES:
        raise UnsupportedLinkType(linktype)
    walker = _Walker(frame)
    walker.link(linktype)
    return walker.layout


class _Walker:
    __slots__ = ("f", "n", "layout")

    def __init__(self, frame: bytes) -> None:
        self.f = frame
        self.n = len(frame)
        self.layout = Layout()

    # --- helpers ---

    def has(self, offset: int, length: int) -> bool:
        return offset >= 0 and offset + length <= self.n

    def u16(self, offset: int) -> int:
        return (self.f[offset] << 8) | self.f[offset + 1]

    def address(self, offset: int, length: int, kind: str) -> None:
        if self.has(offset, length):
            self.layout.addresses.append((offset, kind))

    def header_end(self, offset: int) -> None:
        self.layout.payload_start = min(offset, self.n)

    # --- link layer ---

    def link(self, linktype: int) -> None:
        if linktype == 1:
            self.ethernet(0, 0)
        elif linktype == 113:
            self.sll(0)
        elif linktype == 276:
            self.sll2(0)
        elif linktype in (12, 14, 101):
            self.raw_ip(0, 0)
        elif linktype in (0, 108):
            self.loopback(0, linktype)

    def ethernet(self, off: int, depth: int) -> None:
        if depth > MAX_DEPTH or not self.has(off, 14):
            return
        self.address(off, 6, "mac")
        self.address(off + 6, 6, "mac")
        self.header_end(off + 14)
        self.ethertype(self.u16(off + 12), off + 14, depth)

    def sll(self, off: int) -> None:
        if not self.has(off, 16):
            return
        if self.u16(off + 4) == 6:
            self.address(off + 6, 6, "mac")
        self.header_end(off + 16)
        self.ethertype(self.u16(off + 14), off + 16, 0)

    def sll2(self, off: int) -> None:
        if not self.has(off, 20):
            return
        if self.f[off + 11] == 6:
            self.address(off + 12, 6, "mac")
        self.header_end(off + 20)
        self.ethertype(self.u16(off), off + 20, 0)

    def loopback(self, off: int, linktype: int) -> None:
        if not self.has(off, 4):
            return
        # LINKTYPE_NULL stores the family in the capturing host's byte order,
        # which the file does not record, so both readings are tried.
        family_be = int.from_bytes(self.f[off:off + 4], "big")
        family_le = int.from_bytes(self.f[off:off + 4], "little")
        families = (family_be,) if linktype == 108 else (family_be, family_le)
        self.header_end(off + 4)
        if 2 in families:
            self.ipv4(off + 4, 0)
        elif any(f in (10, 24, 28, 30) for f in families):
            self.ipv6(off + 4, 0)

    def raw_ip(self, off: int, depth: int) -> None:
        if not self.has(off, 1):
            return
        version = self.f[off] >> 4
        if version == 4:
            self.ipv4(off, depth)
        elif version == 6:
            self.ipv6(off, depth)

    def ethertype(self, etype: int, off: int, depth: int) -> None:
        while etype in _ETH_VLAN and self.has(off, 4):
            etype = self.u16(off + 2)
            off += 4
            self.header_end(off)
        if etype == _ETH_IPV4:
            self.ipv4(off, depth)
        elif etype == _ETH_IPV6:
            self.ipv6(off, depth)
        elif etype in (_ETH_ARP, _ETH_RARP):
            self.arp(off)
        elif etype in _ETH_MPLS:
            self.mpls(off, depth)
        elif etype == _ETH_PPPOE_SESSION:
            self.pppoe(off, depth)

    def mpls(self, off: int, depth: int) -> None:
        while self.has(off, 4):
            bottom = self.f[off + 2] & 0x01
            off += 4
            self.header_end(off)
            if bottom:
                self.raw_ip(off, depth)
                return

    def pppoe(self, off: int, depth: int) -> None:
        if not self.has(off, 8):
            return
        protocol = self.u16(off + 6)
        self.header_end(off + 8)
        if protocol == 0x0021:
            self.ipv4(off + 8, depth)
        elif protocol == 0x0057:
            self.ipv6(off + 8, depth)

    def arp(self, off: int) -> None:
        if not self.has(off, 8):
            return
        hlen, plen = self.f[off + 4], self.f[off + 5]
        self.header_end(off + 8 + 2 * (hlen + plen))
        if hlen != 6 or plen != 4 or self.u16(off + 2) != _ETH_IPV4:
            return
        self.address(off + 8, 6, "mac")
        self.address(off + 14, 4, "ipv4")
        self.address(off + 18, 6, "mac")
        self.address(off + 24, 4, "ipv4")

    # --- network layer ---

    def ipv4(self, off: int, depth: int) -> None:
        if depth > MAX_DEPTH or not self.has(off, 20) or self.f[off] >> 4 != 4:
            return
        ihl = (self.f[off] & 0x0F) * 4
        if ihl < 20:
            return
        total = self.u16(off + 2)
        end = min(off + total, self.n) if total >= ihl else self.n
        self.address(off + 12, 4, "ipv4")
        self.address(off + 16, 4, "ipv4")
        if self.has(off, ihl):
            self.layout.scopes.append(Scope(off + 10, off, off + ihl))
        self.header_end(off + ihl)
        if self.u16(off + 6) & 0x1FFF:
            # A later fragment: what follows is the middle of a datagram, not
            # a transport header.
            return
        pseudo = ((off + 12, 4), (off + 16, 4))
        self.transport(self.f[off + 9], off + ihl, end, pseudo, depth, ipv4=True)

    def ipv6(self, off: int, depth: int) -> None:
        if depth > MAX_DEPTH or not self.has(off, 40) or self.f[off] >> 4 != 6:
            return
        payload = self.u16(off + 4)
        end = min(off + 40 + payload, self.n) if payload else self.n
        self.address(off + 8, 16, "ipv6")
        self.address(off + 24, 16, "ipv6")
        next_header = self.f[off + 6]
        cur = off + 40
        self.header_end(cur)
        while next_header in _IPV6_EXTENSIONS:
            if next_header == 44:
                if not self.has(cur, 8):
                    return
                fragment_offset = self.u16(cur + 2) >> 3
                next_header = self.f[cur]
                cur += 8
                self.header_end(cur)
                if fragment_offset:
                    return
                continue
            if not self.has(cur, 2):
                return
            length = (self.f[cur + 1] + 2) * 4 if next_header == 51 else (self.f[cur + 1] + 1) * 8
            next_header = self.f[cur]
            cur += length
            self.header_end(cur)
        pseudo = ((off + 8, 16), (off + 24, 16))
        self.transport(next_header, cur, end, pseudo, depth, ipv4=False)

    # --- transport and what rides on it ---

    def transport(self, proto: int, off: int, end: int, pseudo, depth: int, *, ipv4: bool) -> None:
        if proto == 6:
            self.tcp(off, end, pseudo)
        elif proto == 17:
            self.udp(off, end, pseudo, depth, ipv4=ipv4)
        elif proto == 1:
            self.icmp(off, end, depth)
        elif proto == 58:
            self.icmpv6(off, end, pseudo, depth)
        elif proto == 4:
            self.ipv4(off, depth + 1)
        elif proto == 41:
            self.ipv6(off, depth + 1)
        elif proto == 47:
            self.gre(off, end, depth)

    def tcp(self, off: int, end: int, pseudo) -> None:
        if not self.has(off, 20):
            return
        self.layout.scopes.append(Scope(off + 16, off, end, pseudo))
        self.header_end(off + max((self.f[off + 12] >> 4) * 4, 20))
        self.layout.transport = ("tcp", self.u16(off), self.u16(off + 2))

    def udp(self, off: int, end: int, pseudo, depth: int, *, ipv4: bool) -> None:
        if not self.has(off, 8):
            return
        # Over IPv4 a zero checksum means "none was computed", and it has to
        # stay zero. Over IPv6 zero is simply invalid, and is left to be so.
        if not (ipv4 and self.u16(off + 6) == 0):
            self.layout.scopes.append(Scope(off + 6, off, end, pseudo))
        self.header_end(off + 8)
        sport, dport = self.u16(off), self.u16(off + 2)
        self.layout.transport = ("udp", sport, dport)
        if dport == _VXLAN_PORT and self.has(off + 8, 8) and self.f[off + 8] & 0x08:
            self.header_end(off + 16)
            self.ethernet(off + 16, depth + 1)
        elif dport == _GENEVE_PORT and self.has(off + 8, 8):
            inner = off + 16 + (self.f[off + 8] & 0x3F) * 4
            self.header_end(inner)
            protocol = self.u16(off + 10)
            if protocol == _ETH_TRANSPARENT_BRIDGING:
                self.ethernet(inner, depth + 1)
            else:
                self.ethertype(protocol, inner, depth + 1)

    def icmp(self, off: int, end: int, depth: int) -> None:
        if not self.has(off, 8):
            return
        self.layout.scopes.append(Scope(off + 2, off, end))
        self.header_end(off + 8)
        self.layout.transport = ("icmp", 0, 0)
        if self.f[off] in _ICMP_ERRORS:
            self.ipv4(off + 8, depth + 1)

    def icmpv6(self, off: int, end: int, pseudo, depth: int) -> None:
        if not self.has(off, 8):
            return
        self.layout.scopes.append(Scope(off + 2, off, end, pseudo))
        self.header_end(off + 8)
        self.layout.transport = ("icmpv6", 0, 0)
        kind = self.f[off]
        if kind in _ICMPV6_ERRORS:
            self.ipv6(off + 8, depth + 1)
        elif kind == 133:          # router solicitation
            self.nd_options(off + 8, end)
        elif kind == 134:          # router advertisement
            self.nd_options(off + 16, end)
        elif kind in (135, 136):   # neighbour solicitation / advertisement
            self.address(off + 8, 16, "ipv6")
            self.nd_options(off + 24, end)
        elif kind == 137:          # redirect
            self.address(off + 8, 16, "ipv6")
            self.address(off + 24, 16, "ipv6")
            self.nd_options(off + 40, end)

    def nd_options(self, cur: int, end: int) -> None:
        while cur + 2 <= end and self.has(cur, 2):
            kind, length = self.f[cur], self.f[cur + 1] * 8
            if not length:
                return
            if kind in (1, 2) and length >= 8:
                self.address(cur + 2, 6, "mac")
            elif kind == 3 and length >= 32:
                self.address(cur + 16, 16, "ipv6")
            cur += length

    def gre(self, off: int, end: int, depth: int) -> None:
        if not self.has(off, 4):
            return
        flags = self.u16(off)
        if flags & 0x0007:
            return  # version 1 (PPTP) is a different header
        cur = off + 4
        if flags & 0x8000:
            if self.has(off + 4, 2):
                self.layout.scopes.append(Scope(off + 4, off, end))
            cur += 4
        if flags & 0x2000:
            cur += 4
        if flags & 0x1000:
            cur += 4
        self.header_end(cur)
        protocol = self.u16(off + 2)
        if protocol == _ETH_TRANSPARENT_BRIDGING:
            self.ethernet(cur, depth + 1)
        else:
            self.ethertype(protocol, cur, depth + 1)


def _ones_sum(data) -> int:
    """The one's-complement sum of `data` as 16-bit words, reduced mod 0xFFFF.

    2**16 is 1 mod 0xFFFF, so the sum of big-endian 16-bit words and the whole
    buffer read as one big-endian integer are congruent mod 0xFFFF. That lets
    CPython's integer conversion do in C what a Python loop would do slowly.
    An odd trailing byte is padded on the right, as the checksum defines.
    """
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    return int.from_bytes(data, "big") % 0xFFFF


def refresh_checksums(original: bytes, edited: bytearray, scopes: list[Scope]) -> None:
    """Update every checksum whose coverage the edits touched, in place.

    Innermost first. The walker appends a scope before recursing into whatever
    it carries, so reversed order is inside-out -- and inside-out matters: a
    VXLAN outer UDP checksum covers the inner packet's checksums, so the inner
    ones must already hold their new values when the outer one is computed.
    """
    for scope in reversed(scopes):
        at = scope.checksum_at
        if at + 2 > len(edited):
            continue
        end = min(scope.end, len(edited))
        before = bytearray(original[scope.start:end])
        after = bytearray(edited[scope.start:end])
        pseudo_before = b"".join(original[p:p + n] for p, n in scope.pseudo)
        pseudo_after = b"".join(bytes(edited[p:p + n]) for p, n in scope.pseudo)
        rel = at - scope.start
        # The checksum's own current value is excluded from both sums -- but
        # an inner checksum inside this coverage that has already changed is
        # exactly the kind of difference that must be counted.
        before[rel:rel + 2] = b"\x00\x00"
        after[rel:rel + 2] = b"\x00\x00"
        if before == after and pseudo_before == pseudo_after:
            continue
        old_sum = (_ones_sum(before) + _ones_sum(pseudo_before)) % 0xFFFF
        new_sum = (_ones_sum(after) + _ones_sum(pseudo_after)) % 0xFFFF
        checksum = (edited[at] << 8) | edited[at + 1]
        # RFC 1624 eqn. 3, HC' = ~(~HC + ~m + m'), in modular form. The result
        # is never 0x0000, which is what UDP needs: zero there means "none".
        folded = ((~checksum & 0xFFFF) + new_sum - old_sum) % 0xFFFF
        updated = ~folded & 0xFFFF
        edited[at] = updated >> 8
        edited[at + 1] = updated & 0xFF
