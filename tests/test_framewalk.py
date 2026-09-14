"""Finding addresses and checksums in frame headers, and updating checksums.

Every layout here is built by hand in tests/packet_builders.py, so the offsets
asserted below are the RFC layouts, not whatever the walker happens to report.
The checksum tests compare the walker's incremental update against a checksum
computed from scratch over the whole edited packet.
"""

from __future__ import annotations

import struct

import pytest

from backend.framewalk import MAX_DEPTH, UnsupportedLinkType, refresh_checksums, walk
from tests.packet_builders import (
    ethernet,
    icmp,
    icmpv6,
    ip4,
    ip6,
    ipv4,
    ipv6,
    mac,
    ones_complement_checksum,
    sll,
    sll2,
    tcp,
    udp,
)

SRC4, DST4 = ip4("192.0.2.10"), ip4("198.51.100.20")
SRC6, DST6 = ip6("2001:db8::10"), ip6("2001:db8:1::20")
MAC_A, MAC_B = mac("00:11:22:33:44:55"), mac("a4:bb:6d:01:02:03")


def _http_frame(payload: bytes = b"GET / HTTP/1.1\r\n\r\n", vlan=None) -> bytes:
    return ethernet(MAC_A, MAC_B, 0x0800,
                    ipv4(SRC4, DST4, 6, tcp(SRC4, DST4, 50000, 80, payload)), vlan=vlan)


def test_ethernet_ipv4_tcp_layout():
    layout = walk(_http_frame(), 1)
    assert layout.addresses == [(0, "mac"), (6, "mac"), (26, "ipv4"), (30, "ipv4")]
    assert [(s.checksum_at, s.start) for s in layout.scopes] == [(24, 14), (50, 34)]
    assert layout.scopes[1].pseudo == ((26, 4), (30, 4))
    assert layout.payload_start == 54
    assert layout.transport == ("tcp", 50000, 80)


def test_a_vlan_tag_moves_everything_four_bytes():
    layout = walk(_http_frame(vlan=100), 1)
    assert layout.addresses == [(0, "mac"), (6, "mac"), (30, "ipv4"), (34, "ipv4")]
    assert layout.payload_start == 58


def test_linux_cooked_v2():
    frame = sll2(MAC_B, 0x0800, ipv4(SRC4, DST4, 17, udp(SRC4, DST4, 5353, 5353, b"x")))
    layout = walk(frame, 276)
    assert layout.addresses == [(12, "mac"), (32, "ipv4"), (36, "ipv4")]
    assert layout.transport == ("udp", 5353, 5353)


def test_linux_cooked_v1():
    frame = sll(MAC_B, 0x0800, ipv4(SRC4, DST4, 17, udp(SRC4, DST4, 53, 5353, b"x")))
    assert walk(frame, 113).addresses == [(6, "mac"), (28, "ipv4"), (32, "ipv4")]


def test_raw_ip():
    frame = ipv6(SRC6, DST6, 17, udp(SRC6, DST6, 1, 2, b"x"))
    assert walk(frame, 101).addresses == [(8, "ipv6"), (24, "ipv6")]


def test_a_frame_cut_short_reports_only_what_was_captured():
    frame = _http_frame()[:29]  # ends inside the IPv4 source address
    layout = walk(frame, 1)
    assert layout.addresses == [(0, "mac"), (6, "mac")]
    assert all(s.checksum_at + 2 <= len(frame) for s in layout.scopes)


def test_a_later_ipv4_fragment_has_no_transport_header():
    frame = ethernet(MAC_A, MAC_B, 0x0800, ipv4(SRC4, DST4, 17, b"\x00" * 16, frag=185))
    layout = walk(frame, 1)
    assert layout.transport is None
    assert (26, "ipv4") in layout.addresses


def test_a_later_ipv6_fragment_has_no_transport_header():
    fragment = struct.pack("!BBHI", 17, 0, (185 << 3), 1) + b"\x00" * 16
    layout = walk(ipv6(SRC6, DST6, 44, fragment), 101)
    assert layout.transport is None


def test_ipv6_extension_headers_are_skipped_to_the_transport():
    hop_by_hop = bytes([17, 0]) + b"\x01\x04\x00\x00\x00\x00"
    frame = ipv6(SRC6, DST6, 0, hop_by_hop + udp(SRC6, DST6, 1000, 2000, b"hi"))
    layout = walk(frame, 101)
    assert layout.transport == ("udp", 1000, 2000)
    assert layout.payload_start == 40 + 8 + 8


def test_an_icmp_error_exposes_the_addresses_it_quotes():
    quoted = ipv4(DST4, SRC4, 17, udp(DST4, SRC4, 33434, 53, b""))
    frame = ethernet(MAC_A, MAC_B, 0x0800, ipv4(SRC4, DST4, 1, icmp(3, 3, b"\x00" * 4 + quoted)))
    offsets = [off for off, kind in walk(frame, 1).addresses if kind == "ipv4"]
    quoted_at = 14 + 20 + 8
    assert offsets == [26, 30, quoted_at + 12, quoted_at + 16]


def test_neighbour_discovery_target_and_link_layer_option():
    body = b"\x00" * 4 + DST6 + bytes([1, 1]) + MAC_B
    frame = ethernet(MAC_A, MAC_B, 0x86DD, ipv6(SRC6, ip6("ff02::1:ff00:20"), 58, icmpv6(SRC6, DST6, 135, 0, body)))
    layout = walk(frame, 1)
    icmp_at = 14 + 40
    assert (icmp_at + 8, "ipv6") in layout.addresses
    assert (icmp_at + 26, "mac") in layout.addresses


def test_vxlan_inner_frame_is_walked():
    inner = ethernet(MAC_B, MAC_A, 0x0800, ipv4(DST4, SRC4, 6, tcp(DST4, SRC4, 22, 40000)))
    vxlan = b"\x08\x00\x00\x00\x00\x00\x01\x00" + inner
    frame = ethernet(MAC_A, MAC_B, 0x0800, ipv4(SRC4, DST4, 17, udp(SRC4, DST4, 51000, 4789, vxlan)))
    layout = walk(frame, 1)
    inner_at = 14 + 20 + 8 + 8
    assert (inner_at, "mac") in layout.addresses
    assert (inner_at + 14 + 12, "ipv4") in layout.addresses
    assert layout.transport == ("tcp", 22, 40000)


def test_arp_addresses():
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, MAC_B, SRC4, b"\x00" * 6, DST4)
    layout = walk(ethernet(b"\xff" * 6, MAC_B, 0x0806, arp), 1)
    assert layout.addresses[2:] == [(22, "mac"), (28, "ipv4"), (32, "mac"), (38, "ipv4")]


def test_an_unsupported_link_type_is_refused():
    with pytest.raises(UnsupportedLinkType):
        walk(b"\x00" * 40, 127)


def test_nesting_stops_at_the_depth_limit():
    packet = udp(SRC4, DST4, 1, 2, b"x")
    proto = 17
    for _ in range(MAX_DEPTH + 5):
        packet = ipv4(SRC4, DST4, proto, packet)
        proto = 4
    layout = walk(packet, 101)
    assert len(layout.addresses) <= 2 * (MAX_DEPTH + 2)


# --- checksums -----------------------------------------------------------------


def _edit_addresses(frame: bytes, layout, new4: bytes) -> bytearray:
    edited = bytearray(frame)
    for off, kind in layout.addresses:
        if kind == "ipv4":
            edited[off:off + 4] = new4
    return edited


def _tcp_checksum_is_valid(frame: bytes, ip_at: int = 14) -> bool:
    header_len = (frame[ip_at] & 0x0F) * 4
    total = struct.unpack("!H", frame[ip_at + 2:ip_at + 4])[0]
    segment = frame[ip_at + header_len:ip_at + total]
    pseudo = frame[ip_at + 12:ip_at + 20] + struct.pack("!BBH", 0, 6, len(segment))
    return ones_complement_checksum(pseudo + segment) == 0


def _ipv4_header_is_valid(frame: bytes, ip_at: int = 14) -> bool:
    return ones_complement_checksum(frame[ip_at:ip_at + 20]) == 0


def test_rewritten_addresses_leave_valid_checksums():
    frame = _http_frame()
    layout = walk(frame, 1)
    edited = _edit_addresses(frame, layout, ip4("203.0.113.77"))
    refresh_checksums(frame, edited, layout.scopes)
    assert _ipv4_header_is_valid(bytes(edited))
    assert _tcp_checksum_is_valid(bytes(edited))


def test_a_truncated_frame_gets_the_checksum_the_whole_packet_would_have():
    """The case recomputing cannot handle: the checksum covers bytes that were
    never captured. The incremental update must agree with a full recomputation
    over the complete edited packet."""
    full = _http_frame(b"x" * 400)
    full_layout = walk(full, 1)
    full_edited = _edit_addresses(full, full_layout, ip4("203.0.113.77"))
    refresh_checksums(full, full_edited, full_layout.scopes)
    assert _tcp_checksum_is_valid(bytes(full_edited))

    cut = full[:96]
    cut_layout = walk(cut, 1)
    cut_edited = _edit_addresses(cut, cut_layout, ip4("203.0.113.77"))
    refresh_checksums(cut, cut_edited, cut_layout.scopes)
    assert cut_edited == full_edited[:96]


def test_a_checksum_that_was_wrong_is_not_silently_repaired():
    """An outgoing packet captured before checksum offload shows a wrong
    checksum. The sanitized copy must be exactly as wrong, not fixed."""
    frame = bytearray(_http_frame())
    frame[50:52] = b"\x12\x34"
    frame = bytes(frame)
    layout = walk(frame, 1)
    edited = _edit_addresses(frame, layout, ip4("203.0.113.77"))
    refresh_checksums(frame, edited, layout.scopes)
    assert not _tcp_checksum_is_valid(bytes(edited))

    def error(buf):
        segment = buf[34:]
        pseudo = buf[26:34] + struct.pack("!BBH", 0, 6, len(segment))
        return ones_complement_checksum(pseudo + segment)

    assert error(bytes(edited)) == error(frame)


def test_a_zero_udp_checksum_over_ipv4_stays_zero():
    frame = ethernet(MAC_A, MAC_B, 0x0800, ipv4(SRC4, DST4, 17, udp(SRC4, DST4, 1, 2, b"abc", checksum=False)))
    layout = walk(frame, 1)
    edited = _edit_addresses(frame, layout, ip4("203.0.113.77"))
    refresh_checksums(frame, edited, layout.scopes)
    assert edited[40:42] == b"\x00\x00"


def test_an_outer_checksum_sees_the_inner_checksum_change():
    """VXLAN with an outer UDP checksum: the inner TCP checksum sits inside
    the outer coverage, so it must be updated first and counted by the outer."""
    inner = ethernet(MAC_B, MAC_A, 0x0800, ipv4(DST4, SRC4, 6, tcp(DST4, SRC4, 22, 40000, b"data")))
    vxlan = b"\x08\x00\x00\x00\x00\x00\x01\x00" + inner
    frame = ethernet(MAC_A, MAC_B, 0x0800, ipv4(SRC4, DST4, 17, udp(SRC4, DST4, 51000, 4789, vxlan)))
    layout = walk(frame, 1)
    edited = _edit_addresses(frame, layout, ip4("203.0.113.77"))
    refresh_checksums(frame, edited, layout.scopes)
    out = bytes(edited)
    udp_segment = out[34:]
    pseudo = out[26:34] + struct.pack("!BBH", 0, 17, len(udp_segment))
    assert ones_complement_checksum(pseudo + udp_segment) == 0
    assert _tcp_checksum_is_valid(out, ip_at=14 + 20 + 8 + 8 + 14)
