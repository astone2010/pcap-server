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


def validate_ssh_hostname(v: str) -> str:
    """Rejects a hostname that could forge a known_hosts entry, a log line, or a
    shell command.

    Shared by every model that takes a hostname bound for asyncssh or the
    known_hosts store, so the rule can only drift by being changed here.
    ServerAuth.hostname used to accept a smaller set than this -- $, backtick,
    backslash, and the line breaks that let one entry forge another -- until
    that gap was closed by pointing both validators at this function.
    """
    v = v.strip()
    if not v or any(c in v for c in " ;|&$`\\\n\r"):
        raise ValueError("invalid hostname")
    return v


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
#
# Lives here rather than in packet_parser because a saved view stores a filter
# long before any tool runs it, and the rule that decides what may be run has
# to be the same one that decides what may be stored.
FILTER_FORBIDDEN = frozenset(";$`\\")
FILTER_MAX_LEN = 1024


def validate_display_filter(f: str) -> str:
    """Returns the filter, or raises DisplayFilterError."""
    if len(f) > FILTER_MAX_LEN:
        raise DisplayFilterError(
            f"display filter is too long (limit {FILTER_MAX_LEN} characters)"
        )
    found = sorted(set(f) & FILTER_FORBIDDEN)
    if found:
        raise DisplayFilterError(
            "display filter cannot contain " + " ".join(repr(c) for c in found)
        )
    return f


VIEW_NAME_MAX = 60

# A saved filter's label. Shorter than a view's name because it is read in a
# list beside eighty-odd built-in labels, the longest of which is well under
# this -- a label that dwarfs the library it sits in stops being a label.
FILTER_LABEL_MAX = 48

# The expression itself. Matches the max_length already on the /api/bpf/check
# query parameter, so an expression that can be checked can be saved.
FILTER_EXPRESSION_MAX = 2000


class CaptureViewRequest(BaseModel):
    """A saved filtered view of one capture: a name and the filter behind it.

    The filter goes through the same validator the live query parameter does.
    A view is stored once and replayed on every later visit, so a filter that
    would be refused when typed must not become storable by being typed into a
    different box.
    """

    name: str
    display_filter: str = ""

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        cleaned = "".join(ch for ch in v if ch.isprintable()).strip()
        if not cleaned:
            raise ValueError("a view needs a name")
        if len(cleaned) > VIEW_NAME_MAX:
            raise ValueError(f"name must be at most {VIEW_NAME_MAX} characters")
        return cleaned

    @field_validator("display_filter")
    @classmethod
    def validate_filter(cls, v: str) -> str:
        try:
            return validate_display_filter(v.strip())
        except DisplayFilterError as exc:
            raise ValueError(str(exc)) from exc


class CaptureView(BaseModel):
    id: str
    capture_id: str
    name: str
    display_filter: str = ""
    # Tab order, as the operator arranged it. Assigned on create as one past
    # the current highest, so a new view lands on the right rather than
    # wherever an id happens to sort.
    position: int = 0
    created_at: str = ""


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


class KnownHostEndpoint(BaseModel):
    """The (hostname, port) pair both host-key endpoints take.

    These two routes used to read their body as a raw dict and check it by
    hand. The checks themselves were sound, but everything before them was
    unguarded: a JSON array, a bare string, an empty body, or anything that is
    not JSON at all raised inside the handler and came back as a 500. They were
    the only two routes in the API not backed by a model, and they were the
    only two that answered malformed input with a server error.

    The rules are the ones that were already here, now shared with
    ServerAuth.hostname via validate_ssh_hostname.
    """

    hostname: str
    port: int = Field(default=22, ge=1, le=65535)

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        return validate_ssh_hostname(v)


class KnownHostKey(BaseModel):
    """One public key exactly as it was shown to the operator for review.

    The confirm route stores what comes back in these fields rather than
    re-scanning, so this model is the boundary between "a key an admin looked
    at" and "a key this server will verify every future connection against".
    It is deliberately strict about shape: a malformed blob would be written
    into known_hosts and only surface later, as an unexplained connection
    failure, at the point where the file is handed to ssh.
    """

    key_type: str = Field(min_length=1, max_length=64)
    host_key: str = Field(min_length=1, max_length=8192)

    @field_validator("key_type")
    @classmethod
    def validate_key_type(cls, v: str) -> str:
        # The algorithm names OpenSSH actually emits: letters, digits, dash,
        # dot, and the '@' of certificate types like
        # ssh-ed25519-cert-v01@openssh.com.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@.\-]*", v):
            raise ValueError("not a host key algorithm name")
        return v

    @field_validator("host_key")
    @classmethod
    def validate_host_key(cls, v: str) -> str:
        # base64, and nothing that could add a field to the known_hosts line
        # it is written into -- no whitespace, no newline.
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v):
            raise ValueError("not a base64 host key blob")
        return v


class KnownHostConfirm(KnownHostEndpoint):
    """The endpoint plus the reviewed keys, for /known-hosts/confirm.

    Bounded at 8 keys because it is the operator's own review being sent back,
    not a bulk import: a host answers with one key per algorithm it supports,
    and OpenSSH ships five.
    """

    keys: list[KnownHostKey] = Field(min_length=1, max_length=8)


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
        return validate_ssh_hostname(v)

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


# Module level rather than a class attribute: pydantic claims any name starting
# with an underscore on a BaseModel as a private attribute, so the constant
# came back as a ModelPrivateAttr rather than the string.
BPF_FORBIDDEN_CHARS = ";$`\\"


# tcpdump's pseudo-interface: every link on the host at once. The right default
# for a capture you are going to read afterwards, and the one thing a live
# stream cannot be pointed at -- see LiveStreamNotTargeted in capture.py.
ANY_INTERFACE = "any"


class CaptureRequest(BaseModel):
    # What this capture is for, in the operator's words.
    #
    # OPTIONAL HERE, REQUIRED BY THE FORM, and the asymmetry is deliberate.
    # The rule is a working convention -- a list of captures called "3f2a..."
    # is a list nobody can read a week later -- not a safety property, and the
    # live-stream targeting rule is the shape safety properties take in this
    # file: refused on both sides. Refusing a name-less capture at the API
    # would break a scripted capture for a cosmetic reason, which is a worse
    # trade than an unnamed row.
    #
    # Captures taken before the form asked for one keep the empty name they
    # have, and can still be renamed afterwards.
    name: str = ""
    server_id: str
    interface: str = ANY_INTERFACE
    count: int | None = Field(default=None, ge=1, le=1_000_000)
    snap_len: int | None = Field(default=None, ge=0, le=65535)
    duration_seconds: int | None = Field(default=None, ge=1, le=600)
    bpf_filter: str = ""
    # Watch the packets arrive instead of waiting for the transfer. Changes two
    # things about the capture itself: tcpdump is given -U so the remote file
    # grows packet by packet rather than a buffer at a time, and the capture
    # counts against max_live_streams as well as max_concurrent_captures.
    #
    # It does NOT change what is captured or how it is stored. The authoritative
    # pcap still accumulates on the remote host and is still fetched and sealed
    # at the end, so a live-streamed capture and an ordinary one are the same
    # file by the time either is saved.
    live_stream: bool = False

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Same treatment CaptureRename gives it: strip, not reject.

        Both write the same column and both are the same act -- naming a
        capture -- so a name accepted at the start must be one that can still be
        set later, and the other way round.
        """
        cleaned = "".join(ch for ch in v if ch.isprintable()).strip()
        if len(cleaned) > CAPTURE_NAME_MAX:
            raise ValueError(f"name must be at most {CAPTURE_NAME_MAX} characters")
        return cleaned

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@-]*", v):
            raise ValueError("invalid interface name")
        return v

    # `&` and `|` are BPF's own bitwise operators and the library cannot do
    # without them: every tcpflags filter needs `&`, `(tcp-syn|tcp-fin|tcp-rst)`
    # needs both, and a fragment test is `ip[6] & 0x20`. They were banned with
    # the shell metacharacters, which left the app offering eight filters its
    # own API refused -- the whole TCP-behaviour group, and one of the worked
    # examples on the Capture tab.
    #
    # They are safe to allow because the expression never reaches the remote
    # shell as bare text. It is one argv element, quoted by _shell_quote before
    # the command string is assembled, and inside single quotes a `&` is a
    # `&`. It also sits after `--`, so it cannot be read as an option, and the
    # dangerous tcpdump flags are refused separately by
    # assert_no_forbidden_flags.
    #
    # The rest of the list stays. `;` and backtick and `$` have no meaning in
    # BPF at all, so refusing them costs nothing and keeps a second line of
    # defence under the quoting rather than relying on it alone.
    @field_validator("bpf_filter")
    @classmethod
    def validate_bpf(cls, v: str) -> str:
        if any(c in v for c in BPF_FORBIDDEN_CHARS):
            raise ValueError("BPF filter contains disallowed characters")
        return v


def _clean_filter_label(v: str) -> str:
    cleaned = "".join(ch for ch in v if ch.isprintable()).strip()
    if not cleaned:
        raise ValueError("a saved filter needs a name")
    if len(cleaned) > FILTER_LABEL_MAX:
        raise ValueError(f"name must be at most {FILTER_LABEL_MAX} characters")
    return cleaned


class CustomFilterRequest(BaseModel):
    """One of the operator's own capture filters: a label and the expression.

    The expression goes through the same validator a capture request's does.
    A saved filter is replayed into a real capture later, so an expression that
    would be refused when typed into the Capture form must not become runnable
    by being typed into this box instead -- the same reasoning CaptureViewRequest
    applies to display filters.
    """

    label: str
    expression: str

    @field_validator("label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        return _clean_filter_label(v)

    @field_validator("expression")
    @classmethod
    def validate_expression(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("a saved filter needs an expression")
        if len(cleaned) > FILTER_EXPRESSION_MAX:
            raise ValueError(
                f"expression must be at most {FILTER_EXPRESSION_MAX} characters"
            )
        if any(c in cleaned for c in BPF_FORBIDDEN_CHARS):
            raise ValueError("BPF filter contains disallowed characters")
        return cleaned


class DisplayFilterRequest(BaseModel):
    """One of the operator's own display filters, reusable on any capture.

    Not a saved view: a view belongs to one capture and appears as a tab on it.
    This is a filter kept for use anywhere, and it goes through the same
    validator the Viewer's filter box does, for the reason CaptureViewRequest
    gives -- storing must not accept what running would refuse.
    """

    label: str
    expression: str

    @field_validator("label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        return _clean_filter_label(v)

    @field_validator("expression")
    @classmethod
    def validate_expression(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("a saved filter needs an expression")
        try:
            return validate_display_filter(cleaned)
        except DisplayFilterError as exc:
            raise ValueError(str(exc)) from exc


class CustomFilter(BaseModel):
    id: str
    label: str
    expression: str
    created_at: str = ""


class CaptureInfo(BaseModel):
    id: str
    # Operator-chosen label. Empty until someone renames the capture, at which
    # point it replaces the bare UUID everywhere the capture is listed.
    name: str = ""
    server_id: str
    # Denormalised on purpose: a capture must still say where it came from after
    # the server it ran against has been deleted.
    server_label: str = ""
    # Which link this capture is reading. Stored rather than parsed back out of
    # the command string, because one capture per server per interface is an
    # invariant enforced against it -- and a rule that depends on re-parsing a
    # shell command is a rule that breaks the first time the command changes
    # shape. Empty on captures written before the column existed; those are all
    # restored as FAILED, so no stale record can hold an interface hostage.
    interface: str = ""
    user_id: str = ""
    # Recorded rather than inferred, and kept after the capture completes: the
    # operator asked for a live stream and the finished capture should still say
    # so. It also decides what the viewer does when the capture is opened while
    # it is still running -- without the flag there is no way to tell a capture
    # that can be watched from one that merely happens to be RUNNING.
    live_stream: bool = False
    # The capture filter this ran with, kept so a finished capture can still say
    # what it was selecting for. Stored in its own right rather than read back
    # out of `command` for the same reason `interface` is: a rule that depends
    # on re-parsing a shell command breaks the first time the command changes
    # shape, and here it would mean a second BPF parser living next to bpf.py.
    #
    # Empty means one of two things and the UI does not try to tell them apart:
    # no filter was given, or the capture predates the column. Both read as
    # unfiltered, which is the safe direction -- see the migration in
    # database.py.
    bpf_filter: str = ""
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
