from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from backend.models import PacketDetail, PacketSummary
from backend.pcapsource import PcapSource

logger = logging.getLogger(__name__)




async def _run_tool(cmd: list[str], source: PcapSource) -> tuple[bytes, bytes, int]:
    """Run a pcap tool with the capture on stdin.

    Every tool used here (tshark, capinfos) reads "-" as stdin, which is what
    keeps a decrypted capture out of the filesystem entirely -- it exists only
    as chunks in flight between this process and the tool.

    stdin is fed by a separate task while stdout is drained, because a capture
    larger than the pipe buffer would otherwise deadlock: the writer blocks on a
    full stdin pipe while the reader waits for output that cannot come.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def feed() -> None:
        try:
            async for chunk in source.chunks():
                proc.stdin.write(chunk)
                await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            # Normal when the tool stops early, e.g. tshark with -c.
            pass
        finally:
            try:
                proc.stdin.close()
            except (BrokenPipeError, OSError):
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

async def get_packet_count(source: PcapSource) -> int:
    stdout, _, _ = await _run_tool(["capinfos", "-c", "-M", "-"], source)
    for line in stdout.decode().splitlines():
        if "Number of packets" in line:
            parts = line.split(":")
            if len(parts) == 2:
                return int(parts[1].strip())
    return 0


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
        logger.warning("tshark stderr: %s", stderr.decode()[:500])

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


def _validate_display_filter(f: str) -> None:
    forbidden = set(";|&$`\\")
    if any(c in forbidden for c in f):
        raise ValueError("display filter contains forbidden characters")
