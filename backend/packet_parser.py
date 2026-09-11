from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from backend.models import PacketDetail, PacketSummary

logger = logging.getLogger(__name__)


async def get_packet_count(pcap_path: Path) -> int:
    proc = await asyncio.create_subprocess_exec(
        "capinfos", "-c", "-M", str(pcap_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
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
ALLOWED_VIEW_FLAGS = {"-n", "-nn", "-e", "-t", *VIEW_FLAG_TIME_FIELD}


async def get_packet_list(
    pcap_path: Path,
    offset: int = 0,
    limit: int = 200,
    display_filter: str = "",
    view_flags: list[str] | None = None,
) -> list[PacketSummary]:
    flags = set(view_flags or [])
    time_field = "frame.time_relative"
    for flag, field in VIEW_FLAG_TIME_FIELD.items():
        if flag in flags:
            time_field = field
            break
    show_time = "-t" not in flags
    show_mac = "-e" in flags

    cmd = ["tshark", "-r", str(pcap_path)]
    if flags & {"-n", "-nn"}:
        cmd.append("-n")
    cmd += [
        "-T", "fields",
        "-e", "frame.number",
        "-e", time_field,
        "-e", "ip.src",
        "-e", "ip.dst",
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

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
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


async def get_packet_detail(pcap_path: Path, frame_number: int) -> PacketDetail:
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-T", "json",
        "-Y", f"frame.number == {int(frame_number)}",
        "--no-duplicate-keys",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()

    data = json.loads(stdout.decode())
    if not data:
        raise ValueError(f"frame {frame_number} not found")

    pkt = data[0]
    source = pkt.get("_source", {})
    layers_raw = source.get("layers", {})

    layers = []
    for layer_name, layer_data in layers_raw.items():
        if isinstance(layer_data, dict):
            layers.append({"name": layer_name, "fields": _flatten_fields(layer_data)})

    timestamp = ""
    if "frame" in layers_raw and isinstance(layers_raw["frame"], dict):
        timestamp = layers_raw["frame"].get("frame.time_relative", "")

    hex_dump = await _get_hex_dump(pcap_path, frame_number)

    return PacketDetail(
        number=frame_number,
        timestamp=str(timestamp),
        layers=layers,
        hex_dump=hex_dump,
    )


async def _get_hex_dump(pcap_path: Path, frame_number: int) -> str:
    proc = await asyncio.create_subprocess_exec(
        "tshark", "-r", str(pcap_path),
        "-Y", f"frame.number == {int(frame_number)}",
        "-x",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
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
