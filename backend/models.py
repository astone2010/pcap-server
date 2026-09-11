from __future__ import annotations

import enum
import re
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath

from pydantic import BaseModel, Field, field_validator


class ServerAuth(BaseModel):
    hostname: str
    port: int = 22
    username: str
    ssh_key_name: str
    use_sudo: bool = False
    name: str = ""

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return v.strip()[:100]

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        v = v.strip()
        if not v or " " in v or ";" in v or "|" in v or "&" in v:
            raise ValueError("invalid hostname")
        return v

    @field_validator("ssh_key_name")
    @classmethod
    def validate_key_name(cls, v: str) -> str:
        path = PurePosixPath(v)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("key name must be a plain filename, no path traversal")
        if "/" in v:
            raise ValueError("key name must be a plain filename")
        return v


class ServerInfo(ServerAuth):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CaptureStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    STOPPING = "stopping"
    TRANSFERRING = "transferring"
    COMPLETED = "completed"
    FAILED = "failed"


# A capture is always written with `tcpdump -w`, which makes tcpdump a writer
# rather than a printer. Everything tcpdump does with -v/-q/-A/-X/-e/-t/-n is
# formatting for text it never emits under -w, so those flags cannot change one
# byte of the resulting pcap. They used to be accepted here, which advertised a
# control that did nothing.
#
# Four things decide what a capture contains, and all four are structured fields
# on CaptureRequest rather than free-form flags:
#
#   interface   -i   which link to read
#   count       -c   how many packets to keep
#   snap_len    -s   how many bytes of each packet to keep
#   bpf_filter  --   which packets match at all
#
# Selecting specific traffic is the filter's job, not a flag's. There is no
# remaining tcpdump flag a caller could usefully pass, so none is accepted.

# tcpdump may run under sudo, so these turn a capture into root code execution or
# arbitrary file reads. -z runs a command on rotation; -W/-G/-C enable rotation so
# it fires; -r/-F/-V read attacker-chosen paths. Never let any of them through.
FORBIDDEN_TCPDUMP_FLAGS = {
    "-z", "--postrotate-command", "-W", "-G", "-C", "-r", "-F", "-V", "-Z",
}


def assert_no_forbidden_flags(args: list[str]) -> None:
    """Last line of defence on the fully-built argument list.

    Nothing user-supplied reaches tcpdump as a flag any more, so this should be
    unreachable -- which is exactly why it is checked rather than assumed. If a
    future change routes input into the argument list again, it fails here
    instead of silently handing root a -z.
    """
    found = sorted(set(args) & FORBIDDEN_TCPDUMP_FLAGS)
    if found:
        raise ValueError(f"refusing to run tcpdump with privilege-escalating flags: {found}")


class CaptureRequest(BaseModel):
    server_id: str
    interface: str = "any"
    count: int | None = Field(default=None, ge=1, le=1_000_000)
    snap_len: int | None = Field(default=None, ge=0, le=65535)
    duration_seconds: int | None = Field(default=None, ge=1, le=600)
    bpf_filter: str = ""

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@-]*", v):
            raise ValueError("invalid interface name")
        return v

    @field_validator("bpf_filter")
    @classmethod
    def validate_bpf(cls, v: str) -> str:
        if any(c in v for c in ";|&$`\\"):
            raise ValueError("BPF filter contains disallowed characters")
        return v


class CaptureInfo(BaseModel):
    id: str
    server_id: str
    # Denormalised on purpose: a capture must still say where it came from after
    # the server it ran against has been deleted.
    server_label: str = ""
    user_id: str = ""
    status: CaptureStatus
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    command: str = ""
    remote_path: str = ""
    local_path: str = ""
    packet_count: int = 0
    file_size: int = 0
    error: str = ""


class PacketSummary(BaseModel):
    number: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    src_mac: str = ""
    dst_mac: str = ""


class PacketDetail(BaseModel):
    number: int
    timestamp: str
    layers: list[dict]
    hex_dump: str
