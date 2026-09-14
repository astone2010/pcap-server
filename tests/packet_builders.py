"""Just enough packet construction for the sanitizer tests, from the RFCs.

No scapy: every byte here is built by hand, so a test that asserts an offset is
asserting against a layout written down in the test suite, not against
whatever a third-party library decided. Checksums are computed in full, which
is the independent check against the sanitizer's incremental updates.
"""

from __future__ import annotations

import ipaddress
import struct


def ones_complement_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip4(text: str) -> bytes:
    return ipaddress.IPv4Address(text).packed


def ip6(text: str) -> bytes:
    return ipaddress.IPv6Address(text).packed


def mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def _with_checksum(segment: bytes, at: int, pseudo: bytes) -> bytes:
    value = ones_complement_checksum(pseudo + segment[:at] + b"\x00\x00" + segment[at + 2:])
    return segment[:at] + struct.pack("!H", value) + segment[at + 2:]


def _pseudo(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    if len(src) == 4:
        return src + dst + struct.pack("!BBH", 0, proto, length)
    return src + dst + struct.pack("!IxxxB", length, proto)


def tcp(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes = b"",
        seq: int = 1, flags: int = 0x18) -> bytes:
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 0x50, flags, 65535, 0, 0) + payload
    return _with_checksum(segment, 16, _pseudo(src, dst, 6, len(segment)))


def udp(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes = b"",
        checksum: bool = True) -> bytes:
    segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    if not checksum:
        return segment
    return _with_checksum(segment, 6, _pseudo(src, dst, 17, len(segment)))


def icmp(kind: int, code: int, body: bytes) -> bytes:
    message = struct.pack("!BBH", kind, code, 0) + body
    return _with_checksum(message, 2, b"")


def icmpv6(src: bytes, dst: bytes, kind: int, code: int, body: bytes) -> bytes:
    message = struct.pack("!BBH", kind, code, 0) + body
    return _with_checksum(message, 2, _pseudo(src, dst, 58, len(message)))


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes, *,
         frag: int = 0, ident: int = 1) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, frag, 64, proto, 0, src, dst)
    return _with_checksum(header, 10, b"") + payload


def ipv6(src: bytes, dst: bytes, next_header: int, payload: bytes) -> bytes:
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), next_header, 64, src, dst) + payload


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes, vlan: int | None = None) -> bytes:
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return dst + src + tag + struct.pack("!H", ethertype) + payload


def sll2(src_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    return struct.pack("!HHiHBB8s", ethertype, 0, 2, 1, 0, 6, src_mac + b"\x00\x00") + payload


def sll(src_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    return struct.pack("!HHH8sH", 0, 1, 6, src_mac + b"\x00\x00", ethertype) + payload


def pcap(frames: list[bytes], linktype: int = 1, snaplen: int = 65535,
         orig_lengths: list[int] | None = None) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)
    for i, frame in enumerate(frames):
        orig = orig_lengths[i] if orig_lengths else len(frame)
        out += struct.pack("<IIII", i, 0, len(frame), orig) + frame
    return out


def read_pcap(data: bytes) -> list[tuple[int, int, bytes]]:
    """(incl_len, orig_len, frame) for each record of a little-endian pcap."""
    records = []
    pos = 24
    while pos < len(data):
        _, _, incl, orig = struct.unpack("<IIII", data[pos:pos + 16])
        records.append((incl, orig, data[pos + 16:pos + 16 + incl]))
        pos += 16 + incl
    return records


# --- application payloads ---------------------------------------------------


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_response_a(name: str, address: str) -> bytes:
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip4(address)
    return struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + answer


def dns_query(name: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def tls_client_hello(server_name: str) -> bytes:
    name = server_name.encode()
    sni = struct.pack("!BH", 0, len(name)) + name
    sni = struct.pack("!H", len(sni)) + sni
    extensions = struct.pack("!HH", 0, len(sni)) + sni
    body = (
        b"\x03\x03" + b"\x11" * 32 + b"\x00"
        + struct.pack("!H", 2) + b"\x00\x2f"
        + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def snmp_get(community: str) -> bytes:
    """An SNMPv1 GetRequest for sysDescr.0, BER by hand."""
    def tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value
    oid = tlv(0x06, bytes([0x2B, 6, 1, 2, 1, 1, 1, 0]))
    varbind = tlv(0x30, oid + tlv(0x05, b""))
    pdu = tlv(0xA0, tlv(0x02, b"\x01") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + tlv(0x30, varbind))
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x04, community.encode()) + pdu)
