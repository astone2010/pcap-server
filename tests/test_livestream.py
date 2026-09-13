"""The record walk that lets tshark read a capture that is still being written.

The whole point of LiveBuffer is that tshark is never shown a torn record. Fed
a file cut mid-packet, tshark emits every complete packet, warns that the
capture "appears to have been cut short in the middle of a packet", and exits
2 -- and get_packet_list reads a non-zero exit with a display filter present as
"tshark refused your filter". So without the trimming here, every poll of a
live view with a filter applied would report the operator's perfectly good
filter as invalid.

test_tshark_accepts_what_the_buffer_hands_it is therefore the load-bearing test
in this file: it puts the same bytes through real tshark both ways and asserts
the difference. The unit tests around it cover the cases that walk is made of.
"""

from __future__ import annotations

import asyncio
import shutil
import struct
import subprocess

import pytest

from backend.livestream import (
    GLOBAL_HEADER_LEN,
    LiveBuffer,
    MAX_RECORD_BYTES,
    RECORD_HEADER_LEN,
)

LITTLE_ENDIAN_MAGIC = 0xA1B2C3D4  # written through struct with "<"
BIG_ENDIAN_MAGIC = 0xA1B2C3D4     # ...and the same value through ">"
NANOSECOND_MAGIC = 0xA1B23C4D


def build_pcap(packet_count: int, *, endian: str = "<", magic: int = LITTLE_ENDIAN_MAGIC) -> bytes:
    """A real classic-pcap file of Ethernet/IPv4/UDP packets.

    Built here rather than captured, so the tests do not need an interface, a
    fixture file, or root -- and so a record's exact byte length is known to the
    test that truncates it.
    """
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    for i in range(packet_count):
        payload = b"live" * 5
        udp = struct.pack("!HHHH", 1000 + i, 2000, 8 + len(payload), 0) + payload
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i, 0, 64, 17, 0,
            bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
        )
        frame = bytes.fromhex("aabbccddee01aabbccddee02") + b"\x08\x00" + ip + udp
        out += struct.pack(endian + "IIII", 1700000000 + i, i * 1000, len(frame), len(frame))
        out += frame
    return out


def drain(buffer: LiveBuffer) -> bytes:
    """Everything the buffer would hand tshark, as one bytes object."""
    source = buffer.source()
    if source is None:
        return b""

    async def collect():
        return b"".join([chunk async for chunk in source.chunks()])

    return asyncio.run(collect())


# --- the walk -----------------------------------------------------------


def test_whole_records_are_counted_and_offered():
    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(build_pcap(5))
    assert buffer.packets == 5
    assert buffer.complete == buffer.size
    assert not buffer.frozen
    assert buffer.problem == ""


def test_a_torn_final_record_is_held_back_until_the_rest_arrives():
    """The case the whole class exists for.

    A live read lands mid-record constantly -- tcpdump is writing while SFTP is
    reading -- so this is the normal state of the buffer, not an edge case.
    """
    full = build_pcap(5)
    torn = full[:-10]

    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(torn)
    assert buffer.packets == 4, "the incomplete fifth record must not be counted"
    assert buffer.complete < buffer.size, "the torn tail is held, not offered"
    assert len(drain(buffer)) == buffer.complete

    # The rest of the packet arrives on the next poll and completes it.
    buffer.feed(full[-10:])
    assert buffer.packets == 5
    assert buffer.complete == buffer.size == len(full)


def test_a_record_header_split_across_two_reads_is_not_misread():
    """A read can end inside the 16-byte record header, not just inside the body.

    Reading a length out of a half-arrived header is how a walk desynchronises
    permanently, so the split is placed deliberately inside one.
    """
    full = build_pcap(3)
    first_record_end = GLOBAL_HEADER_LEN + RECORD_HEADER_LEN + 62
    split = first_record_end + 6  # six bytes into the second record's header

    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(full[:split])
    assert buffer.packets == 1

    buffer.feed(full[split:])
    assert buffer.packets == 3
    assert buffer.complete == len(full)


def test_feeding_one_byte_at_a_time_gives_the_same_answer_as_feeding_it_whole():
    """The walk keeps a cursor across feeds; this is what proves it keeps it right."""
    full = build_pcap(4)

    whole = LiveBuffer(1024 * 1024)
    whole.feed(full)

    dribbled = LiveBuffer(1024 * 1024)
    for i in range(len(full)):
        dribbled.feed(full[i:i + 1])

    assert dribbled.packets == whole.packets == 4
    assert dribbled.complete == whole.complete
    assert drain(dribbled) == drain(whole)


def test_nothing_is_offered_before_the_first_whole_packet():
    """tshark given zero bytes is an error, not an empty capture."""
    buffer = LiveBuffer(1024 * 1024)
    assert buffer.source() is None

    buffer.feed(build_pcap(0))  # the 24-byte header and nothing else
    assert buffer.packets == 0
    assert buffer.source() is None, "a header with no packets is still nothing to parse"

    buffer.feed(build_pcap(1)[GLOBAL_HEADER_LEN:])
    assert buffer.packets == 1
    assert buffer.source() is not None


def test_a_big_endian_capture_is_walked_as_correctly_as_a_little_endian_one():
    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(build_pcap(4, endian=">", magic=BIG_ENDIAN_MAGIC))
    assert buffer.packets == 4
    assert buffer.problem == ""


def test_the_nanosecond_magic_is_walked_too():
    """It changes the units of the timestamp fraction, not any length field."""
    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(build_pcap(3, magic=NANOSECOND_MAGIC))
    assert buffer.packets == 3
    assert buffer.problem == ""


# --- refusing what cannot be walked -------------------------------------


def test_a_format_that_is_not_classic_pcap_is_refused_by_name():
    """pcapng is named rather than reported as a generic failure.

    tcpdump -w writes classic pcap, so this should not happen -- which is
    exactly why it must say something specific if it ever does.
    """
    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
    assert "pcapng" in buffer.problem
    assert "save and open normally" in buffer.problem, (
        "the operator must be told the capture itself is fine"
    )
    assert buffer.packets == 0
    assert buffer.source() is None


def test_an_unrecognised_magic_is_refused_without_guessing_at_it():
    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(b"notapcap" + b"\x00" * 60)
    assert buffer.problem
    assert "pcapng" not in buffer.problem
    assert buffer.packets == 0


def test_an_impossible_record_length_stops_the_walk_and_says_so():
    """Without the bound, the walk waits forever for bytes that never come.

    The capture file sits on a host being investigated, so a length field that
    cannot be true is worth refusing rather than trusting.
    """
    header = build_pcap(0)
    bogus = struct.pack("<IIII", 1700000000, 0, MAX_RECORD_BYTES + 1, MAX_RECORD_BYTES + 1)

    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(header + bogus)
    assert buffer.problem
    assert "capture is unaffected" in buffer.problem
    assert buffer.packets == 0


def test_a_problem_stops_later_feeds_from_being_parsed():
    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(b"notapcap" + b"\x00" * 60)
    before = buffer.size
    buffer.feed(build_pcap(3))
    assert buffer.size == before, "a stream that lost its place does not silently resume"


# --- the cap ------------------------------------------------------------


def test_the_buffer_freezes_at_its_cap_rather_than_growing():
    full = build_pcap(200)
    cap = len(full) // 2

    buffer = LiveBuffer(cap)
    buffer.feed(full)
    assert buffer.frozen
    assert 0 < buffer.packets < 200
    assert buffer.complete <= buffer.size

    # And stays frozen: the capture keeps running, the preview does not.
    packets_at_freeze = buffer.packets
    buffer.feed(build_pcap(50))
    assert buffer.packets == packets_at_freeze
    assert buffer.size <= len(full)


def test_what_a_frozen_buffer_holds_is_still_whole_records():
    """Freezing must not be a second way to hand tshark a torn tail."""
    full = build_pcap(200)
    buffer = LiveBuffer(len(full) // 2)
    buffer.feed(full)
    assert buffer.frozen
    held = drain(buffer)
    assert len(held) == buffer.complete
    assert held == full[:buffer.complete]


# --- the reason all of the above exists ---------------------------------


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_tshark_accepts_what_the_buffer_hands_it(tmp_path):
    """Both halves, against the real tool.

    Fed the torn bytes, tshark exits non-zero -- which get_packet_list reports
    as a rejected display filter, blaming the operator for the capture being
    mid-write. Fed what LiveBuffer holds back to a record boundary, it exits 0
    with the same packets. That difference is the feature.
    """
    full = build_pcap(5)
    torn = full[:-10]

    buffer = LiveBuffer(1024 * 1024)
    buffer.feed(torn)
    trimmed = drain(buffer)

    def run(data: bytes, name: str):
        path = tmp_path / name
        path.write_bytes(data)
        return subprocess.run(
            ["tshark", "-r", str(path), "-T", "fields", "-e", "frame.number", "-Y", "udp"],
            capture_output=True, text=True,
        )

    torn_result = run(torn, "torn.pcap")
    trimmed_result = run(trimmed, "trimmed.pcap")

    assert torn_result.returncode != 0, (
        "if tshark ever stops objecting to a torn tail, the trimming here is "
        "no longer load-bearing and this module can be simplified"
    )
    assert trimmed_result.returncode == 0, (
        "a display filter over the live buffer must not be reported as invalid "
        "merely because the capture is still being written"
    )
    assert trimmed_result.stdout.split() == ["1", "2", "3", "4"]
