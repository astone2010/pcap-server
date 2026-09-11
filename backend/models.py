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


ALLOWED_TCPDUMP_FLAGS = {
    "-i", "-c", "-s", "-n", "-nn", "-v", "-vv", "-vvv",
    "-e", "-q", "-A", "-X", "-XX",
    "-tttt", "-ttt", "-tt", "-t",
}

# tcpdump may run under sudo, so these turn a capture into root code execution or
# arbitrary file reads. -z runs a command on rotation; -W/-G/-C enable rotation so
# it fires; -r/-F/-V read attacker-chosen paths. Never allowlist any of them.
FORBIDDEN_TCPDUMP_FLAGS = {
    "-z", "--postrotate-command", "-W", "-G", "-C", "-r", "-F", "-V", "-Z",
}

_overlap = ALLOWED_TCPDUMP_FLAGS & FORBIDDEN_TCPDUMP_FLAGS
if _overlap:
    raise RuntimeError(f"tcpdump flag allowlist contains privilege-escalating flags: {sorted(_overlap)}")


class CaptureRequest(BaseModel):
    server_id: str
    interface: str = "any"
    count: int | None = Field(default=None, ge=1, le=1_000_000)
    snap_len: int | None = Field(default=None, ge=0, le=65535)
    duration_seconds: int | None = Field(default=None, ge=1, le=600)
    bpf_filter: str = ""
    extra_flags: list[str] = Field(default_factory=list)

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

    @field_validator("extra_flags")
    @classmethod
    def validate_extra_flags(cls, flags: list[str]) -> list[str]:
        for f in flags:
            if f in FORBIDDEN_TCPDUMP_FLAGS:
                raise ValueError(f"flag {f!r} can execute commands or read files as root and is never permitted")
            if f not in ALLOWED_TCPDUMP_FLAGS:
                raise ValueError(f"flag {f!r} is not in the allowlist: {sorted(ALLOWED_TCPDUMP_FLAGS)}")
        return flags


class CaptureInfo(BaseModel):
    id: str
    server_id: str
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
