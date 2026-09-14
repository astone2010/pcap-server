from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from xml.etree import ElementTree

from backend.models import (
    DisplayFilterError,
    FILTER_FORBIDDEN,
    FILTER_MAX_LEN,
    PacketDetail,
    PacketSummary,
    validate_display_filter,
)
from backend.pcapsource import PcapSource

logger = logging.getLogger(__name__)




async def _run_tool(cmd: list[str], source: PcapSource) -> tuple[bytes, bytes, int]:
    """Run a pcap tool with the capture on stdin.

    Every tool used here (tshark, capinfos) reads "-" as stdin, which is what
    keeps a decrypted capture out of the filesystem entirely -- it exists only
    as chunks in flight between this process and the tool.

    stdin is an explicit os.pipe(), never stdin=PIPE. Wiretap -- the library
    behind both tools -- accepts a regular file or a FIFO and rejects anything
    else outright:

        tshark: The standard input is a "special file" or socket or other
        non-regular file.

    asyncio's PIPE is a real pipe, so that check passes. uvloop's is a Unix
    socketpair, so it does not, and uvloop is what the container runs. Every
    tshark call returned nothing and every capinfos call returned no count,
    which is why a capture that downloaded and opened perfectly well showed an
    empty packet list and a packet count of zero.

    The pipe is fed by a separate task while stdout is drained, because a
    capture larger than the pipe buffer would otherwise deadlock: the writer
    blocks on a full stdin pipe while the reader waits for output that cannot
    come.
    """
    read_fd, write_fd = os.pipe()
    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=read_fd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        finally:
            # The child holds its own duplicate. Leaving this end open in the
            # parent means the tool never sees EOF and waits for input forever.
            os.close(read_fd)
    except BaseException:
        os.close(write_fd)
        raise

    async def feed() -> None:
        try:
            async for chunk in source.chunks():
                # A blocking write on a full pipe parks a worker thread, not the
                # event loop. os.write is not guaranteed to take the whole chunk.
                await asyncio.to_thread(_write_all, write_fd, chunk)
        except (BrokenPipeError, ConnectionResetError):
            # Normal when the tool stops early, e.g. tshark with -c.
            pass
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass

    feeder = asyncio.create_task(feed())
    stdout, stderr = await proc.communicate()
    feed_error = None
    try:
        await feeder
    except Exception as exc:  # noqa: BLE001 - re-raised below with context
        feed_error = exc

    if feed_error is not None:
        # The tool saw truncated input or none at all, so whatever it printed is
        # not trustworthy. Failing loudly beats returning a plausible empty result.
        logger.error("failed while feeding %s: %s", cmd[0], feed_error)
        raise RuntimeError(f"could not supply capture data to {cmd[0]}") from feed_error

    return stdout, stderr, proc.returncode or 0


async def spawn_tool(
    cmd: list[str],
    source: PcapSource,
    *,
    limit: int | None = None,
) -> tuple[asyncio.subprocess.Process, asyncio.Task]:
    """Start a pcap tool reading the capture on stdin, for a caller that streams.

    _run_tool collects everything the tool prints; this hands back the running
    process for a caller that reads its output as it comes, and the task
    feeding it, which the caller must pass to reap_tool when done. Same
    os.pipe() stdin and same separate feeder as _run_tool, for the same reasons.

    `limit` raises the per-line bound on proc.stdout.readline() for tools
    whose output lines can be long.
    """
    read_fd, write_fd = os.pipe()
    try:
        try:
            kwargs = {"limit": limit} if limit else {}
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=read_fd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **kwargs,
            )
        finally:
            os.close(read_fd)
    except BaseException:
        os.close(write_fd)
        raise

    async def feed() -> None:
        try:
            async for chunk in source.chunks():
                await asyncio.to_thread(_write_all, write_fd, chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass

    return proc, asyncio.create_task(feed())


async def reap_tool(proc: asyncio.subprocess.Process, feeder: asyncio.Task) -> None:
    """Stop whatever spawn_tool started that is still running.

    A client that disconnects mid-download leaves both the tool and its feeder
    running; this is what ends them.
    """
    if not feeder.done():
        feeder.cancel()
    if proc.returncode is None:
        proc.kill()
    await asyncio.gather(feeder, proc.wait(), return_exceptions=True)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


async def get_packet_count(source: PcapSource) -> int:
    """The capture's packet count, or a raised error -- never a silent zero.

    This used to return 0 both for an empty capture and for a capinfos that
    never ran, which is indistinguishable to every caller and hid the socketpair
    failure above for an entire release.
    """
    stdout, stderr, rc = await _run_tool(["capinfos", "-c", "-M", "-"], source)
    for line in stdout.decode(errors="replace").splitlines():
        if "Number of packets" in line:
            parts = line.split(":")
            if len(parts) == 2:
                return int(parts[1].strip())
    detail = stderr.decode(errors="replace").strip()[:300] or f"exit status {rc}"
    raise RuntimeError(f"capinfos reported no packet count: {detail}")


# tcpdump-style view flags, mapped onto how tshark renders the packet list.
# Only flags that genuinely change this view are accepted.
VIEW_FLAG_TIME_FIELD = {
    "-tt": "frame.time_epoch",
    "-ttt": "frame.time_delta",
    "-tttt": "frame.time",
    # Epoch seconds, formatted into a real date and time by the browser. tshark's
    # own frame.time is the capture host's local time, and this container runs on
    # UTC with no idea what zone the operator reading the capture is in -- the
    # browser is the only place that knows, so it does the formatting.
    "-tz": "frame.time_epoch",
}
ALLOWED_VIEW_FLAGS = {"-e", "-t", *VIEW_FLAG_TIME_FIELD}

# Name resolution is a single explicit opt-in, not a pair of tcpdump-style
# flags, because tcpdump's -n/-nn distinction cannot be expressed in this view:
#
#   * tshark's Info column prints ports numerically whatever the resolution
#     settings say -- verified against a capture on port 80, where -N mt and -n
#     produce byte-identical output. So "ports named" has nowhere to appear.
#   * Host names need nameres.network_name AND
#     nameres.use_external_name_resolver. -N mnt alone changes nothing; the
#     hosts file is only consulted when the external resolver is enabled too.
#
# So the only resolution that alters this view is host lookup, and that sends a
# reverse-DNS query for every address in the capture. On a tool used to examine
# suspicious traffic, that tells the resolver what is being investigated -- so
# it is off unless the operator asks for it, and the UI says what it does.
_RESOLVE_OFF = ["-n"]
_RESOLVE_ON = [
    "-N", "mnt",
    "-o", "nameres.network_name:TRUE",
    "-o", "nameres.use_external_name_resolver:TRUE",
]


def _name_resolution_args(resolve_names: bool) -> list[str]:
    return list(_RESOLVE_ON if resolve_names else _RESOLVE_OFF)


async def get_packet_list(
    source: PcapSource,
    offset: int = 0,
    limit: int = 200,
    display_filter: str = "",
    view_flags: list[str] | None = None,
    resolve_names: bool = False,
    interface_names: dict[int, str] | None = None,
) -> list[PacketSummary]:
    flags = set(view_flags or [])
    time_field = "frame.time_relative"
    for flag, field in VIEW_FLAG_TIME_FIELD.items():
        if flag in flags:
            time_field = field
            break
    show_time = "-t" not in flags
    show_mac = "-e" in flags

    cmd = ["tshark", "-r", "-"]
    cmd += _name_resolution_args(resolve_names)
    cmd += [
        "-T", "fields",
        "-e", "frame.number",
        "-e", time_field,
        "-e", "_ws.col.Source",
        "-e", "_ws.col.Destination",
        "-e", "frame.protocols",
        "-e", "frame.len",
        # Before Info, so the one free-text column stays last but for the MACs.
        "-e", "sll.ifindex",
        "-e", "sll.pkttype",
        "-e", "_ws.col.Info",
    ]
    if show_mac:
        # sll.src.eth as well as eth.src: "tcpdump -i any" produces a Linux
        # cooked capture, which has no Ethernet header, so eth.src and eth.dst
        # are both empty on it. Since "any" is the default interface, -e showed
        # two blank columns for most captures. The cooked header records the
        # sender's address but no destination, so that column stays empty and
        # the flag's help says why.
        cmd += ["-e", "eth.src", "-e", "eth.dst", "-e", "sll.src.eth"]
    cmd += [
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ]
    if display_filter:
        _validate_display_filter(display_filter)
        cmd += ["-Y", display_filter]

    stdout, stderr, rc = await _run_tool(cmd, source)
    if rc != 0:
        logger.warning("tshark stderr: %s", stderr.decode(errors="replace")[:500])
        if display_filter:
            # A valid filter that matches nothing still exits 0, so a non-zero
            # exit with a filter present means the filter is the problem.
            raise DisplayFilterError(_filter_rejection(stderr))

    packets = []
    for line in stdout.decode(errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 9:
            continue
        num = int(parts[0])
        if num <= offset:
            continue
        if len(packets) >= limit:
            break

        protocol = parts[4].split(":")[-1] if parts[4] else "?"
        # Empty unless the capture is Linux cooked v2, which is "any".
        ifindex = int(parts[6]) if parts[6].isascii() and parts[6].isdigit() else 0
        packets.append(PacketSummary(
            number=num,
            timestamp=parts[1] if show_time else "",
            source=parts[2] or "N/A",
            destination=parts[3] or "N/A",
            protocol=protocol.upper(),
            length=int(parts[5]) if parts[5] else 0,
            info=parts[8],
            src_mac=_mac(parts, 9, 11) if show_mac else "",
            dst_mac=_mac(parts, 10) if show_mac else "",
            interface=_interface(ifindex, interface_names or {}),
            ifindex=ifindex,
            direction=_SLL_DIRECTION.get(parts[7], ""),
        ))

    return packets


# The kernel's PACKET_* types as tshark prints sll.pkttype under -T fields.
_SLL_DIRECTION = {"0": "in", "1": "broadcast", "2": "multicast", "3": "other-host", "4": "out"}


def _interface(ifindex: int, names: dict[int, str]) -> str:
    if not ifindex:
        return ""
    return names.get(ifindex) or f"#{ifindex}"


def _mac(parts: list[str], *indexes: int) -> str:
    """First address present at any of these column positions.

    Ethernet and Linux-cooked captures record the address in different fields
    and never both, so the columns are requested together and whichever one the
    frame actually has wins.
    """
    for index in indexes:
        if len(parts) > index and parts[index]:
            return parts[index]
    return ""


async def stream_filtered_pcap(
    source: PcapSource,
    display_filter: str,
) -> AsyncIterator[bytes]:
    """Yield a pcap containing only the packets a display filter selects.

    Streamed rather than buffered, unlike every other tool call here. A packet
    list is bounded by its own limit parameter and a PDML tree is one frame,
    but this is a whole capture minus whatever the filter removed -- reading it
    into memory to hand it to a response would put a multi-gigabyte object in
    the process just to copy it out again.

    `-F pcap` because tshark writes pcapng by default. A saved view downloads
    beside the full capture and should be the same kind of file, not a second
    format that some tools read and others do not.

    The filter is validated here as well as wherever it was stored: this is the
    function that turns it into an argument, and validation belongs next to
    the thing it protects.
    """
    validate_display_filter(display_filter)
    cmd = ["tshark", "-r", "-", "-Y", display_filter, "-w", "-", "-F", "pcap"]

    proc, feeder = await spawn_tool(cmd, source)
    try:
        while True:
            chunk = await proc.stdout.read(CHUNK_BYTES)
            if not chunk:
                break
            yield chunk
        stderr = await proc.stderr.read()
        await proc.wait()
    finally:
        await reap_tool(proc, feeder)

    if proc.returncode not in (0, None):
        raise DisplayFilterError(_filter_rejection(stderr))


# What to read off tshark's stdout at a time. Matches the crypto layer's chunk
# size so a filtered download moves in the same units the capture was sealed in.
CHUNK_BYTES = 64 * 1024


async def get_packet_detail(source: PcapSource, frame_number: int) -> PacketDetail:
    """The dissection tree for one frame, plus its raw bytes.

    PDML, not `-T json`. The JSON output gives a field's name and value and
    nothing else; PDML gives four more things the viewer cannot work without:

        <field name="tcp.srcport" showname="Source Port: 51234"
               size="2" pos="34" show="51234" value="c822"/>

    `name` and `show` are what a click turns into `tcp.srcport == 51234`.
    `pos` and `size` are what lets that same click highlight bytes 34-35 in the
    hex pane, and what lets a click in the hex pane find the field covering the
    byte under the cursor. `showname` is Wireshark's own label, including the
    bit diagrams for flag fields (".... ..1. = Syn: Set"), which would otherwise
    have to be reconstructed from a bitmask by hand.

    Two tool runs, the same as before: PDML carries no frame bytes, so the
    second run fetches them. It asks for `-T json -x` rather than plain `-x`
    because that reports the frame data source as one unambiguous hex string in
    `frame_raw`, where the text form has to be scraped and can carry a second
    block for reassembled data whose offsets do not match PDML's `pos`.
    """
    cmd = [
        "tshark", "-r", "-",
        "-T", "pdml",
        "-Y", f"frame.number == {int(frame_number)}",
    ]
    stdout, stderr, _ = await _run_tool(cmd, source)
    layers = _parse_pdml(stdout)
    if layers is None:
        logger.warning("tshark stderr: %s", stderr.decode(errors="replace")[:500])
        raise ValueError(f"frame {frame_number} not found")

    timestamp = ""
    for layer in layers:
        if layer["name"] == "frame":
            timestamp = _find_field_value(layer["fields"], "frame.time_relative")
            break

    frame_hex, hex_dump = await _get_frame_bytes(source, frame_number)

    return PacketDetail(
        number=frame_number,
        timestamp=timestamp,
        layers=layers,
        hex_dump=hex_dump,
        frame_hex=frame_hex,
    )


def _find_field_value(fields: list[dict], name: str) -> str:
    for field in fields:
        if field.get("name") == name:
            return field.get("value", "")
        found = _find_field_value(field.get("children") or [], name)
        if found:
            return found
    return ""


# tshark's PDML carries no document type declaration and no entities. Anything
# claiming to is not tshark's output, so it is refused rather than handed to a
# parser: expat resolves internal entity definitions, which is the one way a
# packet's own bytes could turn into an expansion attack against this process.
# Matched case-insensitively even though XML only permits these uppercase: the
# cost is nothing and it does not depend on the parser rejecting the lowercase
# form for us.
_XML_REFUSED = (b"<!doctype", b"<!entity")


def _parse_pdml(raw: bytes) -> list[dict] | None:
    """PDML for a single packet, as a list of protocol layers.

    Returns None when the filter matched no frame, which the caller reports as
    a missing frame -- distinct from a frame that dissects to nothing.
    """
    lowered = raw.lower()
    for marker in _XML_REFUSED:
        if marker in lowered:
            raise ValueError("refusing to parse PDML containing a document type declaration")

    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise ValueError(f"could not parse tshark PDML output: {exc}") from None

    packet = root.find("packet")
    if packet is None:
        return None

    layers = []
    for proto in packet.findall("proto"):
        name = proto.get("name", "")
        # geninfo is PDML's own synthetic summary, not a protocol in the frame.
        # Wireshark does not show it and its fields have no meaningful offsets.
        if name == "geninfo":
            continue
        layers.append({
            "name": name,
            "label": proto.get("showname") or name,
            "pos": _int_attr(proto, "pos"),
            "size": _int_attr(proto, "size"),
            "fields": [_pdml_field(child) for child in proto.findall("field")],
        })
    return layers


def _pdml_field(el) -> dict:
    """One PDML <field> and everything nested under it.

    `show` is the displayed value and the one to filter on; `value` is the raw
    hex of the same bytes. Where a field has no `show` -- some container fields
    do not -- the hex stands in so the row is not blank.
    """
    show = el.get("show")
    return {
        "name": el.get("name", ""),
        "label": el.get("showname") or el.get("name", ""),
        "value": show if show is not None else (el.get("value") or ""),
        "pos": _int_attr(el, "pos"),
        "size": _int_attr(el, "size"),
        "hidden": el.get("hide") == "yes",
        "children": [_pdml_field(child) for child in el.findall("field")],
    }


def _int_attr(el, attr: str) -> int:
    try:
        return int(el.get(attr, ""))
    except ValueError:
        return -1 if attr == "pos" else 0


async def _get_frame_bytes(source: PcapSource, frame_number: int) -> tuple[str, str]:
    """The frame's raw bytes, as a hex string and as a printable dump.

    The hex string is what the viewer renders its own panes from. The text dump
    is kept because it is what a copy-paste into a bug report wants, and because
    removing it would change the API for no gain.
    """
    stdout, _, _ = await _run_tool(
        [
            "tshark", "-r", "-",
            "-T", "json", "-x",
            "-Y", f"frame.number == {int(frame_number)}",
        ],
        source,
    )
    try:
        data = json.loads(stdout.decode())
    except json.JSONDecodeError:
        return "", ""
    if not data:
        return "", ""

    raw = data[0].get("_source", {}).get("layers", {}).get("frame_raw")
    # frame_raw is [hex, pos, size, bitmask, type]; only the hex is wanted, and
    # a tshark that ever reports it as a bare string is handled rather than
    # indexed into character by character.
    if isinstance(raw, list) and raw:
        frame_hex = str(raw[0])
    elif isinstance(raw, str):
        frame_hex = raw
    else:
        return "", ""

    frame_hex = frame_hex.strip().lower()
    if not _HEX_ONLY.fullmatch(frame_hex):
        return "", ""
    return frame_hex, _hex_dump_text(frame_hex)


_HEX_ONLY = re.compile(r"(?:[0-9a-f]{2})*")


def _hex_dump_text(frame_hex: str) -> str:
    """The classic offset / hex / ASCII dump, built from the bytes themselves."""
    data = bytes.fromhex(frame_hex)
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part:<47}  {text}")
    return "\n".join(lines)


# The rule itself lives in backend.models, so that a filter being *saved* as a
# view and a filter being *run* right now are checked by one function rather
# than two that can drift. These names are kept because they are what this
# module's callers and tests already reach for.
_FILTER_FORBIDDEN = FILTER_FORBIDDEN
_FILTER_MAX_LEN = FILTER_MAX_LEN
_validate_display_filter = validate_display_filter


def _filter_rejection(stderr: bytes) -> str:
    """tshark's own complaint about a filter, tidied for display.

    It writes something like:

        tshark: Constant expression is invalid.
            tcp.porrt == 80
            ^~~~~~~~~~~~~~~

    The caret line is the useful part, so it is kept; the "Running as user"
    banner and the tool name prefix are not.
    """
    lines = [
        line.rstrip()
        for line in stderr.decode(errors="replace").splitlines()
        if line.strip() and "Running as user" not in line
    ]
    if not lines:
        return "tshark rejected this display filter"
    lines[0] = lines[0].removeprefix("tshark: ")
    return "\n".join(lines)[:400]
