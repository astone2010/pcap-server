from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from backend.models import PacketDetail, PacketSummary
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
        "-e", "_ws.col.Info",
    ]
    if show_mac:
        cmd += ["-e", "eth.src", "-e", "eth.dst"]
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
        if len(parts) < 7:
            continue
        num = int(parts[0])
        if num <= offset:
            continue
        if len(packets) >= limit:
            break

        protocol = parts[4].split(":")[-1] if parts[4] else "?"
        packets.append(PacketSummary(
            number=num,
            timestamp=parts[1] if show_time else "",
            source=parts[2] or "N/A",
            destination=parts[3] or "N/A",
            protocol=protocol.upper(),
            length=int(parts[5]) if parts[5] else 0,
            info=parts[6],
            src_mac=parts[7] if show_mac and len(parts) > 7 else "",
            dst_mac=parts[8] if show_mac and len(parts) > 8 else "",
        ))

    return packets


async def get_packet_detail(source: PcapSource, frame_number: int) -> PacketDetail:
    cmd = [
        "tshark", "-r", "-",
        "-T", "json",
        "-Y", f"frame.number == {int(frame_number)}",
        "--no-duplicate-keys",
    ]
    stdout, _, _ = await _run_tool(cmd, source)
    data = json.loads(stdout.decode())
    if not data:
        raise ValueError(f"frame {frame_number} not found")

    pkt = data[0]
    # Named pkt_source, not source: `source` is the PcapSource parameter, and
    # shadowing it here silently fed a dict to the hex dump.
    pkt_source = pkt.get("_source", {})
    layers_raw = pkt_source.get("layers", {})

    layers = []
    for layer_name, layer_data in layers_raw.items():
        if isinstance(layer_data, dict):
            layers.append({"name": layer_name, "fields": _flatten_fields(layer_data)})

    timestamp = ""
    if "frame" in layers_raw and isinstance(layers_raw["frame"], dict):
        timestamp = layers_raw["frame"].get("frame.time_relative", "")

    hex_dump = await _get_hex_dump(source, frame_number)

    return PacketDetail(
        number=frame_number,
        timestamp=str(timestamp),
        layers=layers,
        hex_dump=hex_dump,
    )


async def _get_hex_dump(source: PcapSource, frame_number: int) -> str:
    stdout, _, _ = await _run_tool(
        ["tshark", "-r", "-", "-Y", f"frame.number == {int(frame_number)}", "-x"], source
    )
    return stdout.decode(errors="replace")


def _flatten_fields(d: dict, prefix: str = "") -> list[dict]:
    result = []
    for key, value in d.items():
        display_key = key
        if isinstance(value, dict):
            result.append({"key": display_key, "value": "", "children": _flatten_fields(value, key)})
        elif isinstance(value, list):
            result.append({"key": display_key, "value": ", ".join(str(v) for v in value)})
        else:
            result.append({"key": display_key, "value": str(value)})
    return result


class DisplayFilterError(ValueError):
    """The display filter was rejected -- by us, or by tshark itself.

    Distinct from "nothing matched", which is a legitimate empty result. Both
    used to reach the user as the same thing: a mistyped field name produced an
    empty packet list reading "No packets match", so a typo was indistinguishable
    from a filter that genuinely selected nothing.
    """


# Rejected on the way in. `&` and `|` are deliberately NOT here: the display
# filter reaches tshark through create_subprocess_exec as a single argv element,
# with no shell anywhere on the path, and Wireshark's syntax needs both -- `&&`
# and `||` are the operators most people type, and `&` is bitwise matching such
# as `tcp.flags & 0x02`. Rejecting them turned correct filter syntax into
# "contains forbidden characters".
#
# The capture filter is a different matter and keeps the stricter rule: it goes
# to tcpdump inside a command string over SSH, where a shell does parse it.
_FILTER_FORBIDDEN = set(";$`\\")
_FILTER_MAX_LEN = 1024


def _validate_display_filter(f: str) -> None:
    if len(f) > _FILTER_MAX_LEN:
        raise DisplayFilterError(
            f"display filter is too long (limit {_FILTER_MAX_LEN} characters)"
        )
    found = sorted(set(f) & _FILTER_FORBIDDEN)
    if found:
        raise DisplayFilterError(
            "display filter cannot contain " + " ".join(repr(c) for c in found)
        )


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
