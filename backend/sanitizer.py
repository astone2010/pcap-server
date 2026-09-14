"""Sanitized copies of a finished capture, made on the way out and never stored.

A sanitized capture is built while it is being downloaded. The stored capture
is decrypted in flight exactly as a normal download is, rewritten record by
record, and streamed to the browser. No sanitized copy, and no plaintext copy,
ever exists on the data volume -- the same guarantee every other download
already makes.

Two readers go over the capture side by side, each with its own decrypting
stream:

* **The frame walker** (backend.framewalk) reads every record and finds the
  addresses and checksums in its headers. That covers the addresses on every
  packet without tshark.
* **tshark**, run once with a display filter, reports the packets that carry
  anything the headers cannot show -- a credential, a username, a hostname, an
  address inside a DNS answer -- as JSON that includes each field's byte
  position.

The two are kept in step by frame number. tshark only prints the packets its
filter selects, so the walker waits for it, which bounds memory to one packet
from each side.

Every position tshark reports is checked against the frame's own bytes before
anything is written there. Reassembly is switched off so positions refer to the
frame rather than a reassembled buffer, and any field whose reported bytes are
not where tshark says they are (decompressed or reassembled data, which has no
place in the frame) is counted in the summary as not sanitized rather than
being written to a guessed location. The summary is where a sanitized capture
admits what it could not do.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator

from backend.anonymize import KEY_INFO, AddressMapper, Pseudonyms, derive_key
from backend.framewalk import LINKTYPE_NAMES, refresh_checksums, walk
from backend.livestream import (
    GLOBAL_HEADER_LEN,
    MAX_RECORD_BYTES,
    RECORD_HEADER_LEN,
    _MAGICS as PCAP_MAGICS,
    _PCAPNG_MAGIC as PCAPNG_MAGIC,
)
from backend.packet_parser import reap_tool, spawn_tool, stream_filtered_pcap
from backend.pcapsource import PcapSource

logger = logging.getLogger(__name__)

# How much sanitized output to gather before handing it to the response.
OUTPUT_CHUNK_BYTES = 64 * 1024

# The most one packet's JSON may take before it is refused: enough for a whole
# record as hex several times over, with its dissection around it.
_JSON_PACKET_LIMIT = 64 * MAX_RECORD_BYTES

INSTALL_SECRET_NAME = "sanitize.key"
_INSTALL_SECRET_LEN = 32


class SanitizeError(Exception):
    """The capture could not be sanitized. Never a partial success."""


@dataclass(frozen=True)
class SanitizeOptions:
    credentials: bool = True
    ips: bool = True
    keep_private: bool = False
    macs: bool = True
    keep_oui: bool = False
    hostnames: bool = False
    usernames: bool = False
    strip_payload: bool = False

    def anything_selected(self) -> bool:
        return any((
            self.credentials, self.ips, self.macs,
            self.hostnames, self.usernames, self.strip_payload,
        ))


# --- what gets masked ------------------------------------------------------
#
# A rule names a tshark field, which option it belongs to, and how its bytes are
# replaced. Styles:
#
#   secret  every byte of the value masked: '*' for text, zero for binary
#   auth    an Authorization-style header: the scheme word kept, the rest masked
#   cookie  a name=value pair: the name kept, the value masked
#   name    a same-length keyed pseudonym (usernames)
#   host    a hostname, label by label, keeping the last label
#   nbns    a NetBIOS-encoded name
#
# `when` restricts a rule to packets where another field has one of the given
# values -- FTP's argument is a password after PASS and a username after USER.


@dataclass(frozen=True)
class _Rule:
    field: str
    category: str
    style: str
    when: tuple[str, frozenset[str]] | None = None


def _when(field_name: str, *values: str) -> tuple[str, frozenset[str]]:
    return (field_name, frozenset(values))


RULES: tuple[_Rule, ...] = (
    # credentials
    _Rule("http.authorization", "credentials", "auth"),
    _Rule("http.proxy_authorization", "credentials", "auth"),
    _Rule("sip.Authorization", "credentials", "auth"),
    _Rule("http.cookie_pair", "credentials", "cookie"),
    _Rule("http.set_cookie", "credentials", "cookie"),
    _Rule("ftp.request.arg", "credentials", "secret", _when("ftp.request.command", "PASS", "ACCT")),
    _Rule("pop.request.parameter", "credentials", "secret", _when("pop.request.command", "PASS", "APOP")),
    _Rule("imap.request.password", "credentials", "secret"),
    _Rule("smtp.auth.password", "credentials", "secret"),
    _Rule("smtp.auth.username_password", "credentials", "secret"),
    _Rule("snmp.community", "credentials", "secret"),
    _Rule("radius.User_Password", "credentials", "secret"),
    _Rule("ntlmssp.auth.ntresponse", "credentials", "secret"),
    _Rule("ntlmssp.auth.lmresponse", "credentials", "secret"),
    _Rule("kerberos.cipher", "credentials", "secret"),
    _Rule("ldap.simple", "credentials", "secret"),
    _Rule("mysql.passwd", "credentials", "secret"),
    _Rule("pgsql.password", "credentials", "secret"),
    _Rule("tds.login.password", "credentials", "secret"),
    _Rule("vnc.auth_response", "credentials", "secret"),
    # usernames
    _Rule("ftp.request.arg", "usernames", "name", _when("ftp.request.command", "USER")),
    _Rule("pop.request.parameter", "usernames", "name", _when("pop.request.command", "USER")),
    _Rule("imap.request.username", "usernames", "name"),
    _Rule("smtp.auth.username", "usernames", "name"),
    _Rule("radius.User_Name", "usernames", "name"),
    _Rule("ntlmssp.auth.username", "usernames", "name"),
    _Rule("ntlmssp.auth.domain", "usernames", "name"),
    _Rule("kerberos.CNameString", "usernames", "name"),
    _Rule("ldap.name", "usernames", "name"),
    _Rule("mysql.user", "usernames", "name"),
    _Rule("pgsql.parameter_value", "usernames", "name", _when("pgsql.parameter_name", "USER")),
    _Rule("smb2.acct", "usernames", "name"),
    _Rule("smb2.domain", "usernames", "name"),
    _Rule("sip.auth.username", "usernames", "name"),
    # hostnames
    _Rule("dns.qry.name", "hostnames", "host"),
    _Rule("dns.resp.name", "hostnames", "host"),
    _Rule("dns.cname", "hostnames", "host"),
    _Rule("dns.ptr.domain_name", "hostnames", "host"),
    _Rule("dns.ns", "hostnames", "host"),
    _Rule("dns.soa.mname", "hostnames", "host"),
    _Rule("dns.soa.rname", "hostnames", "host"),
    _Rule("dns.srv.target", "hostnames", "host"),
    _Rule("dns.mx.mail_exchange", "hostnames", "host"),
    _Rule("tls.handshake.extensions_server_name", "hostnames", "host"),
    _Rule("http.host", "hostnames", "host"),
    _Rule("dhcp.option.hostname", "hostnames", "host"),
    _Rule("dhcp.fqdn.name", "hostnames", "host"),
    _Rule("dhcp.option.domain_name", "hostnames", "host"),
    _Rule("smb2.host", "hostnames", "host"),
    _Rule("ntlmssp.auth.hostname", "hostnames", "host"),
    _Rule("nbns.name", "hostnames", "nbns"),
)

# Protocols whose payloads carry addresses of their own: a DNS answer, a DHCP
# lease, a routing update. Frames of these are sent through tshark when IPs or
# MACs are being replaced, and every IPv4, IPv6 and MAC typed field in them is
# mapped like a header address.
ADDRESS_PROTOCOLS = (
    "dns", "dhcp", "dhcpv6", "nbns", "lldp", "cdp", "snmp", "radius",
    "bgp", "ospf", "rip", "eigrp", "vrrp", "hsrp", "pim",
)

_REVERSE_DNS_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")

_ADDRESS_FTYPES = {"FT_IPv4": "ipv4", "FT_IPv6": "ipv6", "FT_ETHER": "mac"}
_BINARY_FTYPES = frozenset({"FT_BYTES", "FT_UINT_BYTES"})

_RULES_BY_FIELD: dict[str, list[_Rule]] = {}
for _rule in RULES:
    _RULES_BY_FIELD.setdefault(_rule.field, []).append(_rule)
del _rule


# --- what this tshark knows about --------------------------------------------


@dataclass
class FieldCatalog:
    """The parts of `tshark -G fields` the sanitizer needs, read once.

    Asked of the installed tshark rather than written down here, because field
    type numbers and even field names drift between Wireshark releases, and a
    display filter naming a field that this tshark lacks is refused outright.
    """

    types: dict[str, str]
    address_kinds: dict[str, str]
    protocols: set[str]


_catalog: FieldCatalog | None = None
_catalog_lock: asyncio.Lock | None = None


async def field_catalog() -> FieldCatalog:
    global _catalog, _catalog_lock
    if _catalog is not None:
        return _catalog
    if _catalog_lock is None:
        _catalog_lock = asyncio.Lock()
    async with _catalog_lock:
        if _catalog is None:
            _catalog = await _read_catalog()
    return _catalog


async def _read_catalog() -> FieldCatalog:
    wanted = set(_RULES_BY_FIELD) | {r.when[0] for r in RULES if r.when}
    types: dict[str, str] = {}
    address_kinds: dict[str, str] = {}
    protocols: set[str] = set()
    proc = await asyncio.create_subprocess_exec(
        "tshark", "-G", "fields",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        limit=1024 * 1024,
    )
    try:
        async for raw_line in proc.stdout:
            parts = raw_line.decode("utf-8", "replace").rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            if parts[0] == "P":
                protocols.add(parts[2])
            elif parts[0] == "F" and len(parts) >= 4:
                abbrev, ftype = parts[2], parts[3]
                if abbrev in wanted:
                    types[abbrev] = ftype
                kind = _ADDRESS_FTYPES.get(ftype)
                if kind:
                    address_kinds[abbrev] = kind
    except BaseException:
        if proc.returncode is None:
            proc.kill()
        raise
    finally:
        await proc.wait()
    if not protocols:
        raise SanitizeError("tshark did not report its protocol list")
    return FieldCatalog(types=types, address_kinds=address_kinds, protocols=protocols)


# --- the tshark pass ---------------------------------------------------------


def _rule_selected(rule: _Rule, options: SanitizeOptions) -> bool:
    if rule.category == "hostnames":
        # Reverse-lookup names are addresses spelled as names, so they go with
        # the IP option even when hostnames are being left alone.
        return options.hostnames or (options.ips and rule.field.startswith("dns."))
    return bool(getattr(options, rule.category))


def tshark_plan(options: SanitizeOptions, catalog: FieldCatalog) -> str | None:
    """The display filter for the tshark pass, or None.

    None when stripping payloads: every field this pass could find lives in a
    payload that is about to be removed anyway, and the headers are handled
    without tshark.
    """
    if options.strip_payload:
        return None
    terms: list[str] = []
    for name, rules in _RULES_BY_FIELD.items():
        if name in catalog.types and any(_rule_selected(r, options) for r in rules):
            terms.append(name)
    if options.ips or options.macs:
        terms += [proto for proto in ADDRESS_PROTOCOLS if proto in catalog.protocols]
    # Undissected payload is reported whatever was ticked: it is the one place
    # a credential could be sitting that no rule here can see.
    if "data" in catalog.protocols:
        terms.append("data")
    if not terms:
        return None
    return " or ".join(terms)


# Layers the frame walker has already covered. Walking them again would find
# nothing a rule wants and only duplicate the header addresses.
_WALKED_LAYERS = frozenset({"frame", "eth", "sll", "vlan", "ip", "ipv6", "tcp", "udp"})


def _tshark_command(display_filter: str) -> list[str]:
    cmd = [
        "tshark", "-r", "-", "-n",
        # Positions must refer to the frame. A reassembled or defragmented
        # buffer has positions of its own that do not.
        "-o", "tcp.desegment_tcp_streams:FALSE",
        "-o", "ip.defragment:FALSE",
        "-o", "ipv6.defragment:FALSE",
        # A segment tshark judges to be a retransmission is not handed to the
        # protocol above TCP, so its fields are never reported -- and a
        # retransmitted login carries the password just as the original did.
        # Measured: 50,000 frames holding HTTP Authorization headers reported
        # one without these, all of them with either. Both are set so a future
        # change to either default does not quietly bring the gap back.
        "-o", "tcp.analyze_sequence_numbers:FALSE",
        "-o", "tcp.no_subdissector_on_error:FALSE",
        "-T", "json", "-x", "--no-duplicate-keys",
        "-Y", display_filter,
        # No -J protocol filter, although it would cut the output fivefold:
        # -J matches top-level layers only, and the fields that matter most
        # are often nested -- NTLMSSP inside SMB2 or HTTP, Kerberos inside
        # SPNEGO. Measured: -J ntlmssp reports nothing for an HTTP NTLM login.
    ]
    return cmd


async def _json_packets(stdout: asyncio.StreamReader) -> AsyncIterator[dict]:
    """One dict per packet from tshark's JSON, without holding the whole array.

    tshark pretty-prints a top-level array whose packet objects open with
    "\\n  {" and close with "\\n  }". Everything inside a packet is indented at
    least four spaces, and a JSON string cannot contain a raw newline, so
    "\\n  }" appears nowhere but at the end of a packet.

    Read in large chunks and split on that, rather than line by line: a
    packet's JSON runs to hundreds of lines, and reading them one at a time
    was most of the cost of a sanitize.
    """
    buf = bytearray()
    start = -1
    while True:
        chunk = await stdout.read(_JSON_READ_BYTES)
        if not chunk:
            break
        buf += chunk
        scan = 0
        while True:
            if start < 0:
                opening = buf.find(b"\n  {", scan)
                if opening < 0:
                    break
                start = opening + 3
            closing = buf.find(b"\n  }", start)
            if closing < 0:
                break
            yield json.loads(buf[start:closing + 4])
            scan = closing + 4
            start = -1
        if start >= 0:
            del buf[:start]
            start = 0
        else:
            # Keep a few bytes: an opening marker may straddle two chunks.
            del buf[:max(scan, len(buf) - 4)]
        if len(buf) > _JSON_PACKET_LIMIT:
            raise SanitizeError("tshark reported a packet too large to be a real one")
    if start >= 0:
        raise SanitizeError("tshark's output ended in the middle of a packet")


_JSON_READ_BYTES = 1024 * 1024


def _collect_fields(node, out: list[tuple[str, object, object]]) -> None:
    """Every (field, value, raw) under a layer, duplicates included."""
    if isinstance(node, list):
        for item in node:
            _collect_fields(item, out)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key.endswith("_raw"):
            name = key[:-4]
            shown = node.get(name)
            if isinstance(value, list) and value and isinstance(value[0], list):
                shown_list = shown if isinstance(shown, list) else [shown] * len(value)
                for i, raw in enumerate(value):
                    out.append((name, shown_list[i] if i < len(shown_list) else None, raw))
            else:
                out.append((name, shown[0] if isinstance(shown, list) and shown else shown, value))
        elif isinstance(value, (dict, list)):
            _collect_fields(value, out)


def _locate(raw, frame: bytes) -> tuple[int, int] | None:
    """Where a field's bytes are in the frame, confirmed against the frame.

    tshark's raw form is [hex, position, length, bitmask, type, ...]. A field
    from a reassembled, decompressed or decoded buffer has a position in that
    buffer, not in the frame, and the only reliable way to tell is that its
    bytes are not at that position in the frame. Bitmask fields share bytes
    with their neighbours and are never rewritten.
    """
    if not isinstance(raw, list) or len(raw) < 4:
        return None
    hex_value, position, length, bitmask = raw[0], raw[1], raw[2], raw[3]
    if not (isinstance(hex_value, str) and isinstance(position, int) and isinstance(length, int)):
        return None
    if bitmask or length <= 0 or position < 0 or position + length > len(frame):
        return None
    if frame[position:position + length].hex() != hex_value.lower():
        return None
    return position, length


# --- rewriting one frame -----------------------------------------------------


@dataclass
class SanitizeSummary:
    frames: int = 0
    masked: dict[str, int] = field(default_factory=lambda: {
        "credentials": 0, "usernames": 0, "hostnames": 0, "reverse_dns_names": 0,
    })
    addresses: dict[str, int] = field(default_factory=lambda: {"ipv4": 0, "ipv6": 0, "mac": 0})
    stripped_frames: int = 0
    unplaced: dict[str, int] = field(default_factory=dict)
    undissected: dict[tuple[str, int], list[int]] = field(default_factory=dict)

    def note_undissected(self, transport: tuple[str, int, int] | None, size: int) -> None:
        name, sport, dport = transport or ("other", 0, 0)
        ports = [p for p in (sport, dport) if p]
        key = (name, min(ports) if ports else 0)
        entry = self.undissected.setdefault(key, [0, 0])
        entry[0] += 1
        entry[1] += size

    def as_dict(self) -> dict:
        undissected = sorted(self.undissected.items(), key=lambda item: -item[1][1])
        return {
            "frames": self.frames,
            "masked": dict(self.masked),
            "addresses": dict(self.addresses),
            "stripped_frames": self.stripped_frames,
            "unplaced": dict(sorted(self.unplaced.items())),
            "undissected": [
                {"transport": name, "port": port, "frames": frames, "bytes": size}
                for (name, port), (frames, size) in undissected[:20]
            ],
        }


def _find_value(segment: bytes, value, encodings=("utf-8", "utf-16-le")) -> tuple[int, int, str] | None:
    if not isinstance(value, str) or not value:
        return None
    for encoding in encodings:
        try:
            needle = value.encode(encoding)
        except UnicodeEncodeError:
            continue
        index = segment.rfind(needle)
        if index >= 0:
            return index, index + len(needle), encoding
    return None


_SCHEME = re.compile(rb"[A-Za-z][A-Za-z0-9_-]*[ \t]+")


class _FrameRewriter:
    def __init__(self, options: SanitizeOptions, key: bytes, catalog: FieldCatalog | None,
                 linktype: int, summary: SanitizeSummary) -> None:
        self.options = options
        self.mapper = AddressMapper(key, keep_private=options.keep_private, keep_oui=options.keep_oui)
        self.names = Pseudonyms(key)
        self.catalog = catalog
        self.linktype = linktype
        self.summary = summary

    # --- headers ---

    def _map_address(self, kind: str, original: bytes) -> bytes | None:
        if kind == "mac":
            return self.mapper.mac(original) if self.options.macs else None
        if not self.options.ips:
            return None
        return self.mapper.ipv4(original) if kind == "ipv4" else self.mapper.ipv6(original)

    def rewrite(self, frame: bytes, packet: dict | None) -> bytes:
        layout = walk(frame, self.linktype)
        edited = bytearray(frame)
        placed: set[tuple[int, int]] = set()
        for offset, kind in layout.addresses:
            length = 16 if kind == "ipv6" else 6 if kind == "mac" else 4
            replacement = self._map_address(kind, frame[offset:offset + length])
            if replacement is not None:
                edited[offset:offset + length] = replacement
                placed.add((offset, length))
        if packet is not None:
            self._apply_packet(packet, frame, edited, placed, layout.transport)
        if edited != frame:
            refresh_checksums(frame, edited, layout.scopes)
        if self.options.strip_payload and layout.payload_start < len(edited):
            del edited[layout.payload_start:]
            self.summary.stripped_frames += 1
        return bytes(edited)

    # --- fields tshark located ---

    def _apply_packet(self, packet: dict, frame: bytes, edited: bytearray,
                      placed: set[tuple[int, int]], transport) -> None:
        layers = (packet.get("_source") or {}).get("layers") or {}
        frame_raw = layers.get("frame_raw")
        if not (isinstance(frame_raw, list) and frame_raw and str(frame_raw[0]).lower() == frame.hex()):
            raise SanitizeError("tshark and the frame reader disagree about a frame's bytes")

        frame_layer = layers.get("frame") or {}
        if isinstance(frame_layer, dict) and "data" in str(frame_layer.get("frame.protocols", "")).split(":"):
            self.summary.note_undissected(transport, len(frame))

        fields: list[tuple[str, object, object]] = []
        for layer, node in layers.items():
            if layer not in _WALKED_LAYERS and not layer.endswith("_raw"):
                _collect_fields(node, fields)

        seen: dict[str, set[str]] = {}
        for name, value, _raw in fields:
            if isinstance(value, str):
                seen.setdefault(name, set()).add(value.upper())

        for name, value, raw in fields:
            kind = self.catalog.address_kinds.get(name) if self.catalog else None
            if kind:
                self._apply_address(name, kind, value, raw, frame, edited, placed)
            for rule in _RULES_BY_FIELD.get(name, ()):
                if rule.when and not (seen.get(rule.when[0], set()) & rule.when[1]):
                    continue
                self._apply_rule(rule, name, value, raw, frame, edited)

    def _apply_address(self, name, kind, value, raw, frame, edited, placed) -> None:
        if (kind == "mac" and not self.options.macs) or (kind != "mac" and not self.options.ips):
            return
        if "mask" in name or not isinstance(value, str):
            return  # a netmask is an address-shaped number, not an address
        location = _locate(raw, frame)
        if location is None:
            if isinstance(raw, list) and len(raw) > 2 and raw[2]:
                self._unplaced(name)
            return
        position, length = location
        if (position, length) in placed:
            return
        original = frame[position:position + length]
        if not _address_matches(kind, original, value):
            # Shown as an address but not stored as one -- STUN's XOR-mapped
            # address is the usual case. Rewriting those bytes as if they were
            # the address would corrupt the field and hide nothing.
            return
        edited[position:position + length] = self._map_address(kind, original)
        placed.add((position, length))

    def _apply_rule(self, rule: _Rule, name: str, value, raw, frame: bytes, edited: bytearray) -> None:
        category = rule.category
        if category == "hostnames" and not self.options.hostnames:
            if not (self.options.ips and isinstance(value, str)
                    and value.lower().endswith(_REVERSE_DNS_SUFFIXES)):
                return
            category = "reverse_dns_names"
        elif not _rule_selected(rule, self.options):
            return
        location = _locate(raw, frame)
        if location is None:
            if isinstance(raw, list) and len(raw) > 2 and raw[2]:
                self._unplaced(name)
            return
        position, length = location
        segment = frame[position:position + length]
        replacement = self._replacement(rule, name, value, segment)
        if replacement is None or len(replacement) != length:
            self._unplaced(name)
            return
        if replacement != segment:
            edited[position:position + length] = replacement
            self.summary.masked[category] += 1

    def _unplaced(self, name: str) -> None:
        self.summary.unplaced[name] = self.summary.unplaced.get(name, 0) + 1

    def _replacement(self, rule: _Rule, name: str, value, segment: bytes) -> bytes | None:
        binary = self.catalog is not None and self.catalog.types.get(name) in _BINARY_FTYPES
        style = rule.style
        if style == "secret":
            return _mask_secret(segment, value, binary)
        if style == "auth":
            return _mask_auth(segment, value)
        if style == "cookie":
            return _mask_cookie(segment, value)
        if style == "name":
            return self._pseudonym(segment, value)
        if style == "host":
            return self._hostname(segment, value)
        if style == "nbns":
            return self._netbios(segment)
        return None

    def _pseudonym(self, segment: bytes, value) -> bytes:
        text = value if isinstance(value, str) else segment.hex()
        found = _find_value(segment, value)
        if found is None:
            return self.names.text(b"user", text, segment)
        start, end, encoding = found
        if encoding == "utf-16-le":
            template = bytes(ord(c) if ord(c) < 0x80 else 0x78 for c in text)
            stand_in = self.names.text(b"user", text, template).decode("ascii").encode("utf-16-le")
            if len(stand_in) != end - start:
                return _mask_secret(segment, value, False)
        else:
            stand_in = self.names.text(b"user", text, segment[start:end])
        return segment[:start] + stand_in + segment[end:]

    def _hostname(self, segment: bytes, value) -> bytes | None:
        found = _find_value(segment, value, ("utf-8",))
        if found is not None:
            start, end, _ = found
            return segment[:start] + self.names.hostname(segment[start:end]) + segment[end:]
        return _map_dns_labels(segment, self.names)

    def _netbios(self, segment: bytes) -> bytes | None:
        """A NetBIOS name: 32 letters encoding 16 bytes, the last a type suffix."""
        if len(segment) < 33 or segment[0] != 32:
            return None
        encoded = segment[1:33]
        if any(not 0x41 <= b <= 0x50 for b in encoded):
            return None
        decoded = bytes(((encoded[2 * i] - 0x41) << 4) | (encoded[2 * i + 1] - 0x41) for i in range(16))
        name, suffix = decoded[:15].rstrip(b" "), decoded[15]
        if not name or not chr(name[0]).isalnum():
            return segment  # "*", "\x01\x02__MSBROWSE__" and friends name no host
        # Through the DNS label mapping, so a host's NetBIOS name and the first
        # label of its DNS name get the same stand-in.
        stand_in = self.names.label(name.lower()).upper()[:15].ljust(15, b" ") + bytes([suffix])
        reencoded = bytearray()
        for byte in stand_in:
            reencoded += bytes([0x41 + (byte >> 4), 0x41 + (byte & 0x0F)])
        return segment[:1] + bytes(reencoded) + segment[33:]


def _address_matches(kind: str, original: bytes, shown: str) -> bool:
    try:
        if kind == "ipv4":
            return len(original) == 4 and ipaddress.IPv4Address(original) == ipaddress.IPv4Address(shown)
        if kind == "ipv6":
            return len(original) == 16 and ipaddress.IPv6Address(original) == ipaddress.IPv6Address(shown)
    except ValueError:
        return False
    return len(original) == 6 and original.hex(":") == shown.lower()


def _fill(length: int, encoding: str) -> bytes:
    return b"*\x00" * (length // 2) if encoding == "utf-16-le" else b"*" * length


def _mask_secret(segment: bytes, value, binary: bool) -> bytes:
    if binary:
        return b"\x00" * len(segment)
    found = _find_value(segment, value)
    if found is not None:
        start, end, encoding = found
        return segment[:start] + _fill(end - start, encoding) + segment[end:]
    # The value is not in the field's bytes as shown -- encoded, escaped, or
    # displayed differently. Mask everything but line structure rather than
    # guess which part is the secret.
    return bytes(b if b in (0x0D, 0x0A, 0x00) else 0x2A for b in segment)


def _mask_auth(segment: bytes, value) -> bytes:
    found = _find_value(segment, value, ("utf-8",))
    if found is None:
        return _mask_secret(segment, value, False)
    start, end, _ = found
    scheme = _SCHEME.match(segment, start, end)
    keep = scheme.end() if scheme else start
    return segment[:keep] + b"*" * (end - keep) + segment[end:]


def _mask_cookie(segment: bytes, value) -> bytes:
    found = _find_value(segment, value, ("utf-8",))
    if found is None:
        return _mask_secret(segment, value, False)
    start, end, _ = found
    equals = segment.find(b"=", start, end)
    if equals < 0:
        return segment[:start] + b"*" * (end - start) + segment[end:]
    stop = segment.find(b";", equals, end)
    stop = end if stop < 0 else stop
    return segment[:equals + 1] + b"*" * (stop - equals - 1) + segment[stop:]


def _map_dns_labels(segment: bytes, names: Pseudonyms) -> bytes | None:
    """A name in DNS wire format: length-prefixed labels, maybe a pointer.

    Only label bytes change, never a length or a pointer. The last label is
    kept only when the name ends here: a name that continues through a
    compression pointer ends somewhere else, and its last label here is not
    the name's last label.
    """
    labels: list[tuple[int, int]] = []
    terminated = False
    i = 0
    while i < len(segment):
        length = segment[i]
        if length == 0:
            terminated = True
            break
        if length & 0xC0:
            break
        if i + 1 + length > len(segment):
            return None
        labels.append((i + 1, length))
        i += 1 + length
    if not labels:
        return segment if terminated or i < len(segment) else None
    out = bytearray(segment)
    for index, (start, length) in enumerate(labels):
        if terminated and len(labels) > 1 and index == len(labels) - 1:
            continue
        out[start:start + length] = names.label(segment[start:start + length])
    return bytes(out)


# --- the capture as records -----------------------------------------------------


class _PcapReader:
    def __init__(self, source: PcapSource) -> None:
        self._chunks = source.chunks()
        self._buf = bytearray()
        self._pos = 0
        self.endian = "little"
        self.linktype = -1

    async def _fill(self, need: int) -> bool:
        while len(self._buf) - self._pos < need:
            chunk = await anext(self._chunks, None)
            if chunk is None:
                return False
            if self._pos > MAX_RECORD_BYTES:
                del self._buf[:self._pos]
                self._pos = 0
            self._buf += chunk
        return True

    def _take(self, n: int) -> bytes:
        out = bytes(self._buf[self._pos:self._pos + n])
        self._pos += n
        return out

    async def global_header(self) -> bytes:
        if not await self._fill(GLOBAL_HEADER_LEN):
            raise SanitizeError("the capture is empty or too short to be a pcap file")
        header = self._take(GLOBAL_HEADER_LEN)
        endian = PCAP_MAGICS.get(header[:4])
        if endian is None:
            if header[:4] == PCAPNG_MAGIC:
                raise SanitizeError("the capture is pcapng, and only classic pcap can be sanitized")
            raise SanitizeError("the capture is not a pcap file")
        self.endian = endian
        # The top bits of the link-type field carry FCS information, not the type.
        self.linktype = int.from_bytes(header[20:24], endian) & 0x03FFFFFF
        if self.linktype not in LINKTYPE_NAMES:
            raise SanitizeError(
                f"captures with link type {self.linktype} cannot be sanitized "
                f"(supported: {', '.join(sorted(set(LINKTYPE_NAMES.values())))})"
            )
        return header

    async def records(self) -> AsyncIterator[tuple[bytes, bytes]]:
        while True:
            if not await self._fill(RECORD_HEADER_LEN):
                if len(self._buf) > self._pos:
                    raise SanitizeError("the capture ends in the middle of a record header")
                return
            header = self._take(RECORD_HEADER_LEN)
            incl_len = int.from_bytes(header[8:12], self.endian)
            if incl_len > MAX_RECORD_BYTES:
                raise SanitizeError(f"a record claims {incl_len} bytes, which is not a real record")
            if not await self._fill(incl_len):
                raise SanitizeError("the capture ends in the middle of a record")
            yield header, self._take(incl_len)

    async def aclose(self) -> None:
        await self._chunks.aclose()


async def check_capture(source: PcapSource) -> None:
    """Refuse, before a response starts, a capture that cannot be sanitized."""
    reader = _PcapReader(source)
    try:
        await reader.global_header()
    finally:
        await reader.aclose()


class FilteredSource(PcapSource):
    """A capture seen through a saved view's display filter."""

    def __init__(self, source: PcapSource, display_filter: str) -> None:
        self._source = source
        self._filter = display_filter

    async def chunks(self) -> AsyncIterator[bytes]:
        async for chunk in stream_filtered_pcap(self._source, self._filter):
            yield chunk

    async def size(self) -> int:
        total = 0
        async for chunk in self.chunks():
            total += len(chunk)
        return total


class _TsharkPass:
    """The tshark half of a sanitize: its process, and which frame it is on.

    tshark prints only the packets its filter selects, so for each record the
    reader asks "is this one yours?" and gets the packet or None. Anything out
    of order means the two readers have lost each other, and the sanitize fails
    rather than applying one frame's positions to another.
    """

    def __init__(self, display_filter: str, source: PcapSource) -> None:
        self._filter = display_filter
        self._source = source
        self._proc = None
        self._feeder = None
        self._stderr = None
        self._packets: AsyncIterator[dict] | None = None
        self._pending: tuple[int, dict] | None = None
        self._exhausted = False

    async def start(self) -> None:
        self._proc, self._feeder = await spawn_tool(_tshark_command(self._filter), self._source)
        self._stderr = asyncio.create_task(_drain(self._proc.stderr))
        self._packets = _json_packets(self._proc.stdout)

    async def _advance(self) -> None:
        packet = await anext(self._packets, None)
        if packet is None:
            self._exhausted = True
            return
        try:
            number = int(packet["_source"]["layers"]["frame"]["frame.number"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SanitizeError("tshark reported a packet without a frame number") from exc
        self._pending = (number, packet)

    async def packet_for(self, index: int) -> dict | None:
        if self._pending is None and not self._exhausted:
            await self._advance()
        if self._pending is None:
            return None
        number, packet = self._pending
        if number < index:
            raise SanitizeError("tshark reported a frame the reader never saw")
        if number > index:
            return None
        self._pending = None
        return packet

    async def finish(self) -> None:
        """Confirm tshark saw no more frames than the reader, and exited cleanly."""
        if self._pending is None and not self._exhausted:
            await self._advance()
        if self._pending is not None:
            raise SanitizeError("tshark reported more frames than the capture holds")
        await self._proc.wait()
        if self._proc.returncode not in (0, None):
            detail = (await self._stderr).decode("utf-8", "replace").strip()[:300]
            raise SanitizeError(f"tshark failed while sanitizing: {detail or self._proc.returncode}")

    async def close(self) -> None:
        if self._proc is not None:
            await reap_tool(self._proc, self._feeder)
        if self._stderr is not None and not self._stderr.done():
            self._stderr.cancel()


# Frames rewritten between yields to the event loop. Rewriting is pure CPU, and
# a large capture would otherwise hold the loop -- and every other request --
# for as long as the reader's buffer kept it from awaiting.
_FRAMES_PER_YIELD = 64


async def stream_sanitized_pcap(
    source: PcapSource,
    key: bytes,
    options: SanitizeOptions,
    summary: SanitizeSummary,
) -> AsyncIterator[bytes]:
    """Yield a sanitized pcap of `source`, filling `summary` as it goes.

    `source` is read twice at once -- by the frame reader here and by tshark --
    so it must be able to produce its chunks more than once, which every
    PcapSource does.
    """
    catalog = await field_catalog() if not options.strip_payload else None
    plan = tshark_plan(options, catalog) if catalog is not None else None

    reader = _PcapReader(source)
    tshark = _TsharkPass(plan, source) if plan is not None else None
    try:
        out = bytearray(await reader.global_header())
        rewriter = _FrameRewriter(options, key, catalog, reader.linktype, summary)
        if tshark is not None:
            await tshark.start()

        index = 0
        async for record_header, frame in reader.records():
            index += 1
            packet = await tshark.packet_for(index) if tshark is not None else None
            rewritten = rewriter.rewrite(frame, packet)
            out += record_header[:8] + len(rewritten).to_bytes(4, reader.endian) + record_header[12:]
            out += rewritten
            summary.frames = index
            if len(out) >= OUTPUT_CHUNK_BYTES:
                yield bytes(out)
                out.clear()
            if index % _FRAMES_PER_YIELD == 0:
                await asyncio.sleep(0)

        if tshark is not None:
            await tshark.finish()
        summary.addresses = rewriter.mapper.counts
        if out:
            yield bytes(out)
    finally:
        await reader.aclose()
        if tshark is not None:
            await tshark.close()


async def _drain(stream: asyncio.StreamReader, cap: int = 64 * 1024) -> bytes:
    """Read a tool's stderr to the end, keeping only the start of it.

    Drained concurrently because a tool that fills its stderr pipe stops
    writing stdout, and this module waits on stdout.
    """
    kept = bytearray()
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return bytes(kept)
        if len(kept) < cap:
            kept += chunk[:cap - len(kept)]


# --- keys --------------------------------------------------------------------


def install_secret(data_dir: Path) -> bytes:
    """The fallback secret for captures that were stored without encryption.

    Created once, on first use, and never replaced: replacing it would change
    every unencrypted capture's mapping. Written to a temporary name and
    hard-linked into place, so two first sanitizes at once cannot leave one of
    them reading a half-written file.
    """
    path = data_dir / INSTALL_SECRET_NAME
    if not path.exists():
        temp = data_dir / f".{INSTALL_SECRET_NAME}.{secrets.token_hex(8)}"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(_INSTALL_SECRET_LEN))
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(temp, path)
            except FileExistsError:
                pass
        finally:
            temp.unlink(missing_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        secret = fh.read(_INSTALL_SECRET_LEN + 1)
    if len(secret) != _INSTALL_SECRET_LEN:
        # The data directory's real path stays in the log, not in the reply.
        logger.error("sanitize key %s is %d bytes, expected %d", path, len(secret), _INSTALL_SECRET_LEN)
        raise SanitizeError(
            f"the data directory's {INSTALL_SECRET_NAME} is damaged; move it aside to create "
            "a new one (sanitized unencrypted captures will then map differently)"
        )
    return secret


def capture_key(vault, path: Path, capture_id: str, data_dir: Path) -> bytes:
    """The 64 bytes of key material one capture's mapping is built from.

    An encrypted capture's key comes from its own data key, which never
    changes -- not when the master key is rotated -- and is as well guarded as
    the capture itself. An unencrypted capture has no key of its own, so the
    install-wide secret is combined with the capture's id instead.
    """
    derived = vault.derived_key(path, KEY_INFO, 64)
    if derived is not None:
        return derived
    return derive_key(install_secret(data_dir), capture_id.encode())
