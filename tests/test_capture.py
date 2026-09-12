"""Tests for backend.capture.CaptureManager's concurrent-capture limit.

Before this, start() had no bound at all: any authenticated user could call
POST /api/captures as many times as they liked, each one opening a new SSH
connection to a target host and a new local file, with nothing capping how
many ran at once. A fake SSHManager whose run_tcpdump() raises if it is ever
called lets these tests prove the limit is enforced BEFORE any connection is
opened -- not just that a well-behaved caller sees an error afterward.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from backend.capture import CaptureLimitExceeded, CaptureManager
from backend.models import CaptureInfo, CaptureRequest, CaptureStatus, ServerInfo


class FakeProcess:
    """A tcpdump process that never exits on its own -- the monitor task just
    waits on it, same as a real long-running capture would, until shutdown()
    cancels it in fixture teardown."""

    def __init__(self) -> None:
        self.closed = False

    async def wait(self):
        await asyncio.Event().wait()

    @property
    def exit_status(self):
        return None

    @property
    def stderr(self):
        return None

    def send_signal(self, sig: str) -> None:
        pass

    def kill(self) -> None:
        pass

    async def close(self) -> None:
        self.closed = True


class FakeSSHManager:
    def __init__(self) -> None:
        self.run_tcpdump_calls = 0

    async def run_tcpdump(self, server, args, remote_path, *, duration=None):
        self.run_tcpdump_calls += 1
        return FakeProcess()

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


def seed_running_capture(mgr: CaptureManager, status: CaptureStatus = CaptureStatus.RUNNING) -> str:
    """Populate _captures directly, bypassing start() -- active_count() only
    reads this dict, so this is enough to simulate N captures already active
    without spinning up N real fake processes and monitor tasks."""
    info = CaptureInfo(
        id=f"seed-{len(mgr._captures)}",
        server_id="some-server",
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
