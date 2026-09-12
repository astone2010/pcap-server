from __future__ import annotations

import enum
import re
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath

from pydantic import BaseModel, Field, field_validator


def validate_ssh_username(v: str) -> str:
    """Constrained to a real login name's characters.

    The prerequisite check prints a sudoers rule naming this user for the
    operator to paste as root. Everything sudoers gives meaning to --
    whitespace, `#`, `,`, `=`, `(`, `)`, `:`, `!` -- is excluded here, so a
    username can never extend that rule into a broader grant than the one
    binary it names.

    Shared by the server forms and the stored-username list on purpose: a name
    saved in the list is offered straight back into a server, so anything the
    list accepts is something the sudoers rule will eventually carry.
    """
    v = v.strip()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._@-]{0,63}", v):
        raise ValueError(
            "username must be 1-64 characters of letters, digits, dot, "
            "underscore, hyphen or @, and cannot start with a hyphen"
        )
    return v


class StoredUsername(BaseModel):
    id: str
    username: str
    last_used_at: str = ""


class UsernameRequest(BaseModel):
    username: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return validate_ssh_username(v)


class ServerAuth(BaseModel):
    hostname: str
    port: int = 22
    username: str
    ssh_key_name: str
    use_sudo: bool = False
    name: str = ""
    # Absolute path discovered by the prerequisite check. Validated there before
    # it is ever stored; empty means "not probed yet, fall back to PATH".
    tcpdump_path: str = ""

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return v.strip()[:100]

    @field_validator("tcpdump_path")
    @classmethod
    def validate_tcpdump_path(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return ""
        if not re.fullmatch(r"/[A-Za-z0-9._/-]{1,255}", v) or PurePosixPath(v).name != "tcpdump":
            raise ValueError("tcpdump path must be an absolute path ending in /tcpdump")
        return v

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        v = v.strip()
        if not v or " " in v or ";" in v or "|" in v or "&" in v:
            raise ValueError("invalid hostname")
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return validate_ssh_username(v)

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
    # Operator-chosen label. Empty until someone renames the capture, at which
    # point it replaces the bare UUID everywhere the capture is listed.
    name: str = ""
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


class PacketField(BaseModel):
    """One row of the detail tree, carrying what Wireshark shows and what it filters on.

    `name` is the display-filter field (`tcp.srcport`) and `value` the value to
    filter against; together they are what a click on this row turns into an
    expression. `label` is tshark's own `showname` -- "Source Port: 51234", or
    the bit diagram ".... ..1. = Syn: Set" for a flag -- so the tree reads the
    way Wireshark's does rather than showing raw field identifiers.

    `pos` and `size` are the field's byte offset and length within the frame.
    They are the entire reason this comes from PDML instead of `-T json`, which
    reports neither: without them a field cannot highlight its own bytes.
    """

    name: str = ""
    label: str = ""
    value: str = ""
    pos: int = -1
    size: int = 0
    # tshark marks generated and duplicate fields (ip.src_host beside ip.src)
    # hide="yes". Wireshark does not draw them; neither do we, but they are
    # carried rather than dropped so the viewer can offer them behind a toggle.
    hidden: bool = False
    children: list["PacketField"] = []


class PacketDetail(BaseModel):
    number: int
    timestamp: str
    layers: list[dict]
    hex_dump: str
    # The frame's bytes as one lowercase hex string. The viewer renders its own
    # offset/hex/ASCII panes from this so individual bytes are addressable and
    # can be highlighted; tshark's own -x text is a single blob that cannot be.
    frame_hex: str = ""


CAPTURE_NAME_MAX = 120


class CaptureRename(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """A display label, so the only rules are length and printability.

        Control characters are stripped rather than rejected: they cannot render
        anywhere useful, and a name pasted from a terminal picks them up easily.
        """
        cleaned = "".join(ch for ch in v if ch.isprintable()).strip()
        if len(cleaned) > CAPTURE_NAME_MAX:
            raise ValueError(f"name must be at most {CAPTURE_NAME_MAX} characters")
        return cleaned
