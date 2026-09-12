"""Tests for backend.capture.CaptureManager's concurrent-capture limit.

Before this, start() had no bound at all: any authenticated user could call
POST /api/captures as many times as they liked, each one opening a new SSH
connection to a target host and a new local file, with nothing capping how
many ran at once. A fake SSHManager whose run_tcpdump() raises if it is ever
called lets these tests prove the limit is enforced BEFORE any connection is
opened -- not just that a well-behaved caller sees an error afterward.
"""

from __future__ import annotations

import re
from pathlib import Path
from backend.database import Database

import asyncio
from datetime import datetime, timezone

import pytest

from backend.capture import (
    _MONITOR_GRACE_SECONDS,
    _STDERR_COLLAPSE_PARTS,
    _STDERR_KEEP_CHARS,
    _pump_stderr,
    CaptureLimitExceeded,
    InterfaceAlreadyCapturing,
    CaptureManager,
)
from pydantic import ValidationError

from backend.models import (
    CAPTURE_NAME_MAX,
    CaptureInfo,
    CaptureRename,
    CaptureRequest,
    CaptureStatus,
    ServerInfo,
)


class ScriptedStderr:
    """Hands back one scripted chunk per read, then blocks.

    That is how a real capture's stderr behaves: tcpdump keeps writing progress
    lines and the stream only reaches EOF when the process exits.
    """

    def __init__(self, chunks: list[str]) -> None:
        self._chunks = list(chunks)

    async def read(self, n: int = -1) -> str:
        if self._chunks:
            return self._chunks.pop(0)
        await asyncio.Event().wait()


class FakeProcess:
    """A tcpdump process that never exits on its own -- the monitor task just
    waits on it, same as a real long-running capture would, until shutdown()
    cancels it in fixture teardown."""

    def __init__(self, stderr_chunks: list[str] | None = None) -> None:
        self.closed = False
        self._stderr = ScriptedStderr(stderr_chunks or [])

    async def wait(self):
        await asyncio.Event().wait()

    @property
    def exit_status(self):
        return None

    @property
    def stderr(self):
        return self._stderr

    def send_signal(self, sig: str) -> None:
        pass

    def kill(self) -> None:
        pass

    async def close(self) -> None:
        self.closed = True


class FakeSSHManager:
    def __init__(self) -> None:
        self.run_tcpdump_calls = 0
        self.stderr_chunks: list[str] = []
        self.last_args: list[str] = []

    async def run_tcpdump(self, server, args, remote_path, *, duration=None):
        self.run_tcpdump_calls += 1
        self.last_args = list(args)
        return FakeProcess(self.stderr_chunks)

    async def stop_tcpdump(self, process) -> None:
        pass

    async def fetch_file(self, *a, **k) -> None:
        pass

    async def delete_remote_file(self, *a, **k) -> None:
        pass


class FakeCaptureDB:
    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}

    def list_captures(self) -> list[dict]:
        return list(self.rows.values())

    def upsert_capture(self, row: dict) -> None:
        self.rows[row["id"]] = row

    def delete_capture(self, capture_id: str) -> None:
        self.rows.pop(capture_id, None)


def make_server() -> ServerInfo:
    return ServerInfo(hostname="target.example", username="alice", ssh_key_name="alice-key")


def make_settings(max_concurrent: int = 2) -> dict:
    return {
        "max_capture_seconds": 300,
        "max_capture_packets": 100_000,
        "max_concurrent_captures": max_concurrent,
    }


@pytest.fixture()
async def manager(tmp_path):
    ssh = FakeSSHManager()
    settings = make_settings()
    mgr = CaptureManager(ssh, tmp_path, lambda k: settings[k], FakeCaptureDB(), vault=None)
    try:
        yield mgr, ssh, settings
    finally:
        await mgr.shutdown()


def seed_running_capture(
    mgr: CaptureManager,
    status: CaptureStatus = CaptureStatus.RUNNING,
    server_id: str = "some-server",
    interface: str = "",
) -> str:
    """Populate _captures directly, bypassing start() -- active_count() only
    reads this dict, so this is enough to simulate N captures already active
    without spinning up N real fake processes and monitor tasks.

    server_id and interface default to values that match no real server under
    test, so seeding for the concurrency limit never trips the per-interface
    rule by accident; the per-interface tests pass them explicitly."""
    info = CaptureInfo(
        id=f"seed-{len(mgr._captures)}",
        server_id=server_id,
        interface=interface,
        status=status,
        started_at=datetime.now(timezone.utc),
    )
    mgr._captures[info.id] = info
    return info.id


# --- active_count() ----------------------------------------------------------


@pytest.mark.parametrize(
    "status,counts_as_active",
    [
        (CaptureStatus.PENDING, False),
        (CaptureStatus.RUNNING, True),
        (CaptureStatus.STOPPING, True),
        (CaptureStatus.TRANSFERRING, True),
        (CaptureStatus.COMPLETED, False),
        (CaptureStatus.FAILED, False),
    ],
)
async def test_active_count_per_status(manager, status, counts_as_active):
    mgr, _, _ = manager
    seed_running_capture(mgr, status)
    assert mgr.active_count() == (1 if counts_as_active else 0)


async def test_active_count_sums_multiple_active_captures(manager):
    mgr, _, _ = manager
    seed_running_capture(mgr, CaptureStatus.RUNNING)
    seed_running_capture(mgr, CaptureStatus.STOPPING)
    seed_running_capture(mgr, CaptureStatus.COMPLETED)
    assert mgr.active_count() == 2


# --- start(): the limit itself ------------------------------------------------


async def test_start_succeeds_below_the_limit(manager):
    mgr, ssh, _ = manager
    req = CaptureRequest(server_id="s1", interface="eth0")
    info = await mgr.start(req, make_server(), user_id="u1")
    assert info.status == CaptureStatus.RUNNING
    assert ssh.run_tcpdump_calls == 1


async def test_start_raises_at_the_limit_without_opening_a_connection(manager):
    mgr, ssh, settings = manager
    settings["max_concurrent_captures"] = 1
    seed_running_capture(mgr, CaptureStatus.RUNNING)

    req = CaptureRequest(server_id="s1", interface="eth0")
    with pytest.raises(CaptureLimitExceeded):
        await mgr.start(req, make_server(), user_id="u1")

    # The whole point: rejected before any SSH connection is opened, not
    # opened-then-torn-down.
    assert ssh.run_tcpdump_calls == 0


async def test_start_raises_when_over_the_limit_via_stopping_and_transferring(manager):
    """The limit counts every resource-holding state, not just RUNNING --
    a capture that is STOPPING or TRANSFERRING still holds its connection."""
    mgr, ssh, settings = manager
    settings["max_concurrent_captures"] = 2
    seed_running_capture(mgr, CaptureStatus.STOPPING)
    seed_running_capture(mgr, CaptureStatus.TRANSFERRING)

    req = CaptureRequest(server_id="s1", interface="eth0")
    with pytest.raises(CaptureLimitExceeded):
        await mgr.start(req, make_server(), user_id="u1")
    assert ssh.run_tcpdump_calls == 0


async def test_start_allowed_again_after_a_capture_completes(manager):
    mgr, ssh, settings = manager
    settings["max_concurrent_captures"] = 1
    completed_id = seed_running_capture(mgr, CaptureStatus.RUNNING)
    mgr._captures[completed_id].status = CaptureStatus.COMPLETED  # it finished

    req = CaptureRequest(server_id="s1", interface="eth0")
    info = await mgr.start(req, make_server(), user_id="u1")
    assert info.status == CaptureStatus.RUNNING
    assert ssh.run_tcpdump_calls == 1


async def test_capture_limit_exceeded_message_is_actionable(manager):
    mgr, ssh, settings = manager
    settings["max_concurrent_captures"] = 3
    for _ in range(3):
        seed_running_capture(mgr)

    req = CaptureRequest(server_id="s1", interface="eth0")
    with pytest.raises(CaptureLimitExceeded, match="3"):
        await mgr.start(req, make_server(), user_id="u1")


# --- start() failing to launch: the leaked concurrency slot -------------------
#
# start() registers the capture as RUNNING before run_tcpdump, and only
# _monitor ever ends a RUNNING capture. When the launch itself raised, no
# monitor was created, so the record stayed RUNNING for the life of the
# process and held a slot against max_concurrent_captures. Every unreachable
# host burned one, and after max_concurrent_captures of them nothing could
# start again until a restart swept them.


class ExplodingSSHManager(FakeSSHManager):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self._error = error

    async def run_tcpdump(self, server, args, remote_path, *, duration=None):
        self.run_tcpdump_calls += 1
        raise self._error


@pytest.fixture()
async def exploding_manager(tmp_path):
    def build(error):
        ssh = ExplodingSSHManager(error)
        settings = make_settings(max_concurrent=2)
        return CaptureManager(ssh, tmp_path, lambda k: settings[k], FakeCaptureDB(), vault=None), ssh
    yield build


@pytest.mark.parametrize(
    "error",
    [
        ConnectionError("SSH connection failed"),
        FileNotFoundError("SSH key not found: alice-key"),
        RuntimeError("sudo: a password is required"),
    ],
    ids=["unreachable", "missing-key", "sudo-refused"],
)
async def test_failed_launch_does_not_hold_a_concurrency_slot(exploding_manager, error):
    mgr, _ = exploding_manager(error)
    req = CaptureRequest(server_id="s1", interface="eth0")

    with pytest.raises(type(error)):
        await mgr.start(req, make_server(), user_id="u1")

    assert mgr.active_count() == 0


async def test_failed_launch_is_recorded_as_failed_not_left_running(exploding_manager):
    mgr, _ = exploding_manager(ConnectionError("SSH connection failed"))
    req = CaptureRequest(server_id="s1", interface="eth0")

    with pytest.raises(ConnectionError):
        await mgr.start(req, make_server(), user_id="u1")

    info = next(iter(mgr.captures.values()))
    assert info.status == CaptureStatus.FAILED
    assert "SSH connection failed" in info.error
    # Stamped, so the row does not read as a capture still in progress.
    assert info.stopped_at is not None


async def test_repeated_failed_launches_never_exhaust_the_limit(exploding_manager):
    """The consecutive-capture symptom: the limit is 2, so without releasing
    the slot the third attempt would be refused with CaptureLimitExceeded
    instead of the real reason the host cannot be reached."""
    mgr, _ = exploding_manager(ConnectionError("SSH connection failed"))
    req = CaptureRequest(server_id="s1", interface="eth0")

    for _ in range(5):
        with pytest.raises(ConnectionError):
            await mgr.start(req, make_server(), user_id="u1")

    assert mgr.active_count() == 0


async def test_a_good_capture_still_starts_after_failed_launches(exploding_manager, tmp_path):
    mgr, _ = exploding_manager(ConnectionError("SSH connection failed"))
    req = CaptureRequest(server_id="s1", interface="eth0")
    for _ in range(3):
        with pytest.raises(ConnectionError):
            await mgr.start(req, make_server(), user_id="u1")

    # The host comes back; the next attempt must not be refused by the limiter.
    mgr._ssh = FakeSSHManager()
    try:
        info = await mgr.start(req, make_server(), user_id="u1")
        assert info.status == CaptureStatus.RUNNING
    finally:
        await mgr.shutdown()


async def test_failed_launch_is_persisted_so_a_restart_does_not_resurrect_it(exploding_manager):
    mgr, _ = exploding_manager(ConnectionError("SSH connection failed"))
    req = CaptureRequest(server_id="s1", interface="eth0")

    with pytest.raises(ConnectionError):
        await mgr.start(req, make_server(), user_id="u1")

    rows = mgr._db.list_captures()
    assert len(rows) == 1
    assert rows[0]["status"] == CaptureStatus.FAILED.value


# --- progress reporting -------------------------------------------------------
#
# A capture used to show nothing at all until it finished and transferred: the
# pcap is on the remote host for the whole run, so there is nothing local to
# count. tcpdump -v, when writing with -w, prints its own running total to
# stderr once a second as "Got 1234\r", and that is the only signal available.


async def _eventually(predicate, timeout: float = 2.0) -> None:
    async def poll():
        while not predicate():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), timeout)


def test_build_command_args_asks_tcpdump_to_report_its_progress(manager):
    mgr, _, _ = manager
    args = mgr.build_command_args(CaptureRequest(server_id="s1", interface="eth0"))
    assert "-v" in args


def test_build_command_args_still_puts_the_filter_last_behind_a_separator(manager):
    """-v goes at the front, so it must not disturb the -- that keeps a filter
    beginning with a dash from being read as an option."""
    mgr, _, _ = manager
    args = mgr.build_command_args(
        CaptureRequest(server_id="s1", interface="eth0", bpf_filter="tcp port 80")
    )
    assert args[-2:] == ["--", "tcp port 80"]
    assert args[0] == "-v"


async def test_running_capture_reports_the_count_tcpdump_prints(manager):
    mgr, ssh, _ = manager
    ssh.stderr_chunks = [
        "tcpdump: listening on any, link-type LINUX_SLL2\n",
        "Got 12\r",
        "Got 4096\r",
    ]
    info = await mgr.start(
        CaptureRequest(server_id="s1", interface="eth0"), make_server(), user_id="u1"
    )
    await _eventually(lambda: info.packet_count == 4096)
    assert info.status == CaptureStatus.RUNNING


async def test_several_counts_in_one_read_take_the_last(manager):
    """A second's worth of output can arrive as one chunk; the newest total is
    the current one, not the first one parsed."""
    mgr, ssh, _ = manager
    ssh.stderr_chunks = ["Got 3\rGot 40\rGot 900\r"]
    info = await mgr.start(
        CaptureRequest(server_id="s1", interface="eth0"), make_server(), user_id="u1"
    )
    await _eventually(lambda: info.packet_count == 900)


async def test_the_live_count_reaches_the_database(manager):
    """Persisted as well as held in memory, so a count survives a restart."""
    mgr, ssh, _ = manager
    ssh.stderr_chunks = ["Got 77\r"]
    info = await mgr.start(
        CaptureRequest(server_id="s1", interface="eth0"), make_server(), user_id="u1"
    )
    await _eventually(lambda: mgr._db.rows[info.id]["packet_count"] == 77)


async def test_unreadable_stderr_does_not_fail_the_capture(manager):
    """Losing the progress counter is not a reason to fail a running capture."""
    mgr, ssh, _ = manager

    class Broken:
        async def read(self, n: int = -1):
            raise OSError("channel gone")

    info = await mgr.start(
        CaptureRequest(server_id="s1", interface="eth0"), make_server(), user_id="u1"
    )
    mgr._processes[info.id]._stderr = Broken()
    await asyncio.sleep(0.05)
    assert info.status == CaptureStatus.RUNNING


# --- rename -------------------------------------------------------------------


async def test_rename_sets_the_name_and_persists_it(manager):
    mgr, _, _ = manager
    capture_id = seed_running_capture(mgr)
    info = mgr.rename(capture_id, "Friday DNS storm")
    assert info.name == "Friday DNS storm"
    assert mgr.get(capture_id).name == "Friday DNS storm"
    assert mgr._db.rows[capture_id]["name"] == "Friday DNS storm"


async def test_rename_can_clear_a_name(manager):
    mgr, _, _ = manager
    capture_id = seed_running_capture(mgr)
    mgr.rename(capture_id, "temporary")
    assert mgr.rename(capture_id, "").name == ""


async def test_rename_rejects_an_unknown_capture(manager):
    mgr, _, _ = manager
    with pytest.raises(KeyError):
        mgr.rename("no-such-capture", "anything")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("  spaced  ", "spaced"),
        ("with\x00a null", "witha null"),
        ("tab\tseparated", "tabseparated"),
        ("plain name", "plain name"),
    ],
)
def test_capture_rename_cleans_the_name(raw, expected):
    assert CaptureRename(name=raw).name == expected


def test_capture_rename_rejects_an_overlong_name():
    with pytest.raises(ValidationError):
        CaptureRename(name="x" * (CAPTURE_NAME_MAX + 1))


def test_capture_rename_accepts_a_name_at_the_limit():
    assert len(CaptureRename(name="x" * CAPTURE_NAME_MAX).name) == CAPTURE_NAME_MAX


async def test_an_absurd_count_is_ignored_rather_than_parsed(manager):
    """stderr comes from the host being captured on. An unbounded digit run
    would hand int() a quadratic parse, so the pattern refuses it outright."""
    mgr, ssh, _ = manager
    ssh.stderr_chunks = ["Got " + "9" * 5000 + "\r", "Got 7\r"]
    info = await mgr.start(
        CaptureRequest(server_id="s1", interface="eth0"), make_server(), user_id="u1"
    )
    await _eventually(lambda: info.packet_count == 7)


async def test_flooding_stderr_does_not_grow_without_bound():
    """The buffer is held open for the whole capture, so a chatty or hostile
    host must not be able to fill memory through it."""

    class Flood:
        def __init__(self, chunks: int) -> None:
            self._left = chunks

        async def read(self, n: int = -1) -> str:
            if not self._left:
                return ""
            self._left -= 1
            return "x" * 8192

    class Proc:
        stderr = Flood(500)

    buf: list[str] = []
    await _pump_stderr(Proc(), buf, lambda c: None)

    assert sum(len(part) for part in buf) <= _STDERR_KEEP_CHARS + _STDERR_COLLAPSE_PARTS * 8192
    assert sum(len(part) for part in buf) < 500 * 8192


async def test_the_kept_stderr_is_the_tail_that_diagnoses_the_exit():
    class Proc:
        def __init__(self) -> None:
            self._chunks = ["filler" * 4000] * 40 + ["sudo: a password is required\n"]

        @property
        def stderr(self):
            outer = self

            class Reader:
                async def read(self, n: int = -1) -> str:
                    return outer._chunks.pop(0) if outer._chunks else ""

            return Reader()

    buf: list[str] = []
    await _pump_stderr(Proc(), buf, lambda c: None)
    assert "sudo: a password is required" in "".join(buf)


def test_every_setting_the_backend_defaults_is_editable_in_the_admin_panel():
    """A setting the panel cannot draw can only be changed in the database.

    max_concurrent_captures was enforced from the start and missing from the
    panel's label map, so the limit on simultaneous captures was real and
    unreachable.
    """
    labels = re.search(
        r"const SETTING_LABELS = \{(.*?)\n\};",
        (Path(__file__).resolve().parents[1] / "frontend/js/app.js").read_text(),
        re.S,
    ).group(1)
    for key in Database.DEFAULTS:
        assert f"{key}:" in labels, f"{key} has a default but no row in the admin panel"


# --- one capture per server per interface -------------------------------------
#
# The concurrency limit is a global quota and says nothing about where captures
# point, so five captures could all read the same link of the same host: five
# copies of one capture, five tcpdumps of load on the target.


async def test_second_capture_on_the_same_interface_is_refused(manager):
    mgr, ssh, settings = manager
    srv = make_server()
    seed_running_capture(mgr, CaptureStatus.RUNNING, server_id=srv.id, interface="eth0")

    req = CaptureRequest(server_id=srv.id, interface="eth0")
    with pytest.raises(InterfaceAlreadyCapturing):
        await mgr.start(req, srv, user_id="u1")

    # Refused before any connection is opened, like the limit check above it.
    assert ssh.run_tcpdump_calls == 0


async def test_a_different_interface_on_the_same_server_is_allowed(manager):
    """eth0 and eth1 on one host do not overlap, so this must not be blocked."""
    mgr, ssh, settings = manager
    srv = make_server()
    seed_running_capture(mgr, CaptureStatus.RUNNING, server_id=srv.id, interface="eth0")

    info = await mgr.start(CaptureRequest(server_id=srv.id, interface="eth1"), srv, user_id="u1")
    assert info.status == CaptureStatus.RUNNING
    assert info.interface == "eth1"
    assert ssh.run_tcpdump_calls == 1


async def test_the_same_interface_name_on_a_different_server_is_allowed(manager):
    """eth0 is not one resource -- every host has its own."""
    mgr, ssh, settings = manager
    srv = make_server()
    seed_running_capture(mgr, CaptureStatus.RUNNING, server_id="another-server", interface="eth0")

    info = await mgr.start(CaptureRequest(server_id=srv.id, interface="eth0"), srv, user_id="u1")
    assert info.status == CaptureStatus.RUNNING
    assert ssh.run_tcpdump_calls == 1


@pytest.mark.parametrize("status", [CaptureStatus.STOPPING, CaptureStatus.TRANSFERRING])
async def test_interface_is_held_while_a_capture_is_finishing_up(manager, status):
    """A capture that is stopping or transferring still owns the link."""
    mgr, ssh, settings = manager
    srv = make_server()
    seed_running_capture(mgr, status, server_id=srv.id, interface="any")

    with pytest.raises(InterfaceAlreadyCapturing):
        await mgr.start(CaptureRequest(server_id=srv.id, interface="any"), srv, user_id="u1")
    assert ssh.run_tcpdump_calls == 0


async def test_interface_is_free_again_once_the_capture_finishes(manager):
    mgr, ssh, settings = manager
    srv = make_server()
    done = seed_running_capture(mgr, CaptureStatus.RUNNING, server_id=srv.id, interface="eth0")
    mgr._captures[done].status = CaptureStatus.COMPLETED

    info = await mgr.start(CaptureRequest(server_id=srv.id, interface="eth0"), srv, user_id="u1")
    assert info.status == CaptureStatus.RUNNING
    assert ssh.run_tcpdump_calls == 1


async def test_refusal_names_the_interface_and_the_capture_holding_it(manager):
    mgr, ssh, settings = manager
    srv = make_server()
    held = seed_running_capture(mgr, CaptureStatus.RUNNING, server_id=srv.id, interface="eth0")
    mgr._captures[held].name = "friday-debug"

    with pytest.raises(InterfaceAlreadyCapturing, match="eth0") as exc:
        await mgr.start(CaptureRequest(server_id=srv.id, interface="eth0"), srv, user_id="u1")
    # The operator has to be able to find the capture they need to stop.
    assert "friday-debug" in str(exc.value)


async def test_default_any_interface_conflicts_with_itself(manager):
    """"any" is the default, so this is the collision people hit first."""
    mgr, ssh, settings = manager
    srv = make_server()
    first = await mgr.start(CaptureRequest(server_id=srv.id), srv, user_id="u1")
    assert first.interface == "any"

    with pytest.raises(InterfaceAlreadyCapturing):
        await mgr.start(CaptureRequest(server_id=srv.id), srv, user_id="u1")


async def test_interface_survives_a_persist_and_restore_round_trip(manager, tmp_path):
    """The rule reads CaptureInfo.interface, so it has to come back from the DB
    rather than be re-derived from the command string."""
    mgr, ssh, settings = manager
    srv = make_server()
    info = await mgr.start(CaptureRequest(server_id=srv.id, interface="eth2"), srv, user_id="u1")

    row = next(r for r in mgr._db.list_captures() if r["id"] == info.id)
    assert row["interface"] == "eth2"
    assert CaptureInfo(**row).interface == "eth2"


# --- per-capture monitor timeout ---------------------------------------------
#
# The timeout was an attribute on the manager, written by start() and read by
# whichever monitor task happened to get there first. With
# max_concurrent_captures above 1 that is a race between two captures for one
# variable: a long capture started before a short one had its deadline
# rewritten to the short one's and was abandoned at that point instead of its
# own.


async def test_each_capture_monitor_gets_its_own_timeout(manager):
    mgr, _ssh, _settings = manager
    server = make_server()
    seen: list[float] = []

    async def record(process, pump, timeout):
        seen.append(timeout)
        await asyncio.Event().wait()

    mgr._await_exit = record

    # Different interfaces, so the one-capture-per-interface rule stays out of
    # this; the point is two live captures with different durations.
    await mgr.start(
        CaptureRequest(server_id=server.id, interface="eth0", duration_seconds=300),
        server, "user-1",
    )
    await mgr.start(
        CaptureRequest(server_id=server.id, interface="eth1", duration_seconds=5),
        server, "user-1",
    )
    # Let both monitor tasks reach _await_exit.
    for _ in range(5):
        await asyncio.sleep(0)

    assert sorted(seen) == [5 + _MONITOR_GRACE_SECONDS, 300 + _MONITOR_GRACE_SECONDS]


async def test_capture_duration_is_capped_by_max_capture_seconds(manager):
    mgr, _ssh, settings = manager
    server = make_server()
    seen: list[float] = []

    async def record(process, pump, timeout):
        seen.append(timeout)
        await asyncio.Event().wait()

    mgr._await_exit = record

    await mgr.start(
        CaptureRequest(server_id=server.id, interface="eth0", duration_seconds=600),
        server, "user-1",
    )
    for _ in range(5):
        await asyncio.sleep(0)

    assert seen == [settings["max_capture_seconds"] + _MONITOR_GRACE_SECONDS]
