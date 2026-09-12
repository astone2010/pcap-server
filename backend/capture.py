from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from backend.models import (
    assert_no_forbidden_flags,
    CaptureInfo,
    CaptureRequest,
    CaptureStatus,
    ServerInfo,
)
from backend.packet_parser import get_packet_count
from backend.ssh_manager import SSHManager

logger = logging.getLogger(__name__)

# tcpdump always announces itself on stderr; only the rest is a diagnosis.
_STDERR_NOISE = ("listening on", "packets captured", "packets received", "packets dropped", "Got ")

# Allowance on top of a capture's own duration before the monitor gives up and
# releases the connection.
_MONITOR_GRACE_SECONDS = 60

# tcpdump -v, when writing with -w, reports its running total on stderr once a
# second as "Got 1234\r". It is the only progress signal that exists while a
# capture runs: the pcap is on the remote host until the transfer, so there is
# nothing local to count.
# Bounded on purpose. This parses stderr from the host being captured on --
# frequently a machine under investigation -- so the digit run is attacker
# influenced, and int() on a multi-megabyte digit string is quadratic. Twelve
# digits is more packets than any capture this tool can take.
_GOT_PACKETS = re.compile(r"Got (\d{1,12})")

# The same stderr accumulates for the whole capture, so it cannot be allowed to
# grow without limit either. The tail is what diagnoses an exit; a flood that
# pushes the opening lines out has already told us all it is going to.
_STDERR_KEEP_CHARS = 64 * 1024
_STDERR_COLLAPSE_PARTS = 32

# The live count is read from memory by the status endpoint. Writing the row on
# every tick would be a database write per second per capture to persist a
# number that is superseded a second later, so the row lags deliberately.
_LIVE_COUNT_PERSIST_SECONDS = 2.0

# Captures that are still consuming a resource -- an SSH connection to the
# target, a local file being written, a monitor task -- as opposed to ones
# that have finished one way or another and are just sitting in history.
_ACTIVE_STATUSES = (CaptureStatus.RUNNING, CaptureStatus.STOPPING, CaptureStatus.TRANSFERRING)


class CaptureLimitExceeded(Exception):
    """Raised when starting a capture would exceed max_concurrent_captures."""


def server_label(server: ServerInfo) -> str:
    """A human-readable stamp of where a capture ran, frozen at start time."""
    endpoint = f"{server.username}@{server.hostname}"
    if server.port != 22:
        endpoint += f":{server.port}"
    return f"{server.name} ({endpoint})" if server.name else endpoint


def _row(info: CaptureInfo) -> dict:
    row = info.model_dump()
    row["status"] = info.status.value
    for key in ("started_at", "stopped_at"):
        row[key] = row[key].isoformat() if row[key] else None
    return row


async def _pump_stderr(process: object, buf: list[str], on_count) -> None:
    """Drain stderr as it arrives, reporting each running packet count seen.

    Draining continuously rather than once at exit does two things: it surfaces
    the count while the capture is still running, and it keeps a chatty tcpdump
    from stalling on a full channel window with nobody reading.

    Appends to a caller-owned buffer so a cancelled or timed-out pump still
    leaves behind whatever it read for the failure message.
    """
    stream = getattr(process, "stderr", None)
    if stream is None:
        return
    try:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return
            buf.append(chunk)
            if len(buf) > _STDERR_COLLAPSE_PARTS:
                buf[:] = ["".join(buf)[-_STDERR_KEEP_CHARS:]]
            # "Got 12\rGot 34\r" can arrive in one read; only the last is current.
            found = _GOT_PACKETS.findall(chunk)
            if found:
                on_count(int(found[-1]))
    except asyncio.CancelledError:
        raise
    except Exception:
        # A progress counter is not worth failing a capture over. The
        # authoritative count still comes from capinfos after the transfer.
        logger.warning("stopped reading capture stderr", exc_info=True)


def _discard_partial(local_path: Path) -> None:
    try:
        if local_path.exists():
            local_path.unlink()
    except OSError:
        logger.warning("could not remove partial capture %s", local_path)


def _describe_failure(exc: Exception, stderr_text: str) -> str:
    lines = [
        line.strip()
        for line in stderr_text.splitlines()
        if line.strip() and not any(noise in line for noise in _STDERR_NOISE)
    ]
    if lines:
        return " | ".join(lines)[:300]
    return str(exc)[:300] or "capture failed"


class CaptureManager:
    def __init__(self, ssh: SSHManager, captures_dir: Path, get_setting: Callable[[str], int], db, vault=None) -> None:
        self._ssh = ssh
        self._captures_dir = captures_dir
        self._captures_dir.mkdir(parents=True, exist_ok=True)
        self._get_setting = get_setting
        self._db = db
        self._vault = vault
        self._monitor_timeout: float = 600 + _MONITOR_GRACE_SECONDS
        self._captures: dict[str, CaptureInfo] = {}
        # RemoteCapture objects: the tcpdump process bound to its SSH connection,
        # so closing one closes both.
        self._processes: dict[str, object] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._restore()

    def _restore(self) -> None:
        for row in self._db.list_captures():
            info = CaptureInfo(**row)
            # The process died with the previous container; nothing can resume it.
            if info.status in (CaptureStatus.RUNNING, CaptureStatus.STOPPING, CaptureStatus.TRANSFERRING):
                info.status = CaptureStatus.FAILED
                info.error = "interrupted by a server restart"
                self._db.upsert_capture(_row(info))
            self._captures[info.id] = info

    def _pcap_source(self, path: Path):
        if self._vault:
            return self._vault.source_for(path)
        from backend.pcapsource import PlaintextSource
        return PlaintextSource(path)

    def _persist(self, info: CaptureInfo) -> None:
        self._db.upsert_capture(_row(info))

    @property
    def captures(self) -> dict[str, CaptureInfo]:
        return dict(self._captures)

    def get(self, capture_id: str) -> CaptureInfo | None:
        return self._captures.get(capture_id)

    def list_for_user(self, user_id: str) -> list[CaptureInfo]:
        return [c for c in self._captures.values() if c.user_id == user_id]

    def active_count(self) -> int:
        return sum(1 for c in self._captures.values() if c.status in _ACTIVE_STATUSES)

    def build_command_args(self, req: CaptureRequest) -> list[str]:
        """The complete set of things that change what a -w capture contains.

        -n used to be appended here as well. Under -w tcpdump prints nothing, so
        it only made the command string shown to the user look like it did
        something.
        """
        max_packets = self._get_setting("max_capture_packets")
        # -v is what makes tcpdump report its running packet count on stderr.
        # Under -w it prints no packets, so it changes the progress reporting
        # and nothing about the capture file.
        args: list[str] = ["-v"]
        args += ["-i", req.interface]
        if req.count:
            count = min(req.count, max_packets)
            args += ["-c", str(count)]
        if req.snap_len is not None:
            args += ["-s", str(req.snap_len)]
        if req.bpf_filter:
            # After --, so a filter starting with a dash is read as an expression
            # rather than as an option.
            args.append("--")
            args.append(req.bpf_filter)
        assert_no_forbidden_flags(args)
        return args

    async def start(self, req: CaptureRequest, server: ServerInfo, user_id: str) -> CaptureInfo:
        # Checked first, before any connection is opened or file created: each
        # running capture holds an SSH connection to a target host plus a local
        # file handle, and neither this container's descriptor table nor the
        # remote host's tolerance for simultaneous sessions is unlimited.
        max_concurrent = self._get_setting("max_concurrent_captures")
        if self.active_count() >= max_concurrent:
            raise CaptureLimitExceeded(
                f"{max_concurrent} capture(s) already running or finishing up -- "
                "stop or wait for one to finish before starting another"
            )

        max_seconds = self._get_setting("max_capture_seconds")
        capture_id = str(uuid.uuid4())
        remote_path = f"/tmp/pcap_{capture_id}.pcap"
        # The vault decides the on-disk name, so an encrypted capture is never
        # mistaken for a readable pcap by anything that scans the directory.
        local_path = (
            self._vault.stored_path(capture_id) if self._vault
            else self._captures_dir / f"{capture_id}.pcap"
        )

        args = self.build_command_args(req)
        duration = req.duration_seconds
        if duration:
            duration = min(duration, max_seconds)
        else:
            duration = max_seconds
        # Grace for tcpdump to flush and exit after timeout(1) fires.
        self._monitor_timeout = duration + _MONITOR_GRACE_SECONDS

        binary = server.tcpdump_path or "tcpdump"
        full_cmd = [binary, "-w", remote_path] + args
        if server.use_sudo:
            full_cmd = ["sudo", "-n"] + full_cmd
        assert_no_forbidden_flags(full_cmd)
        cmd_str = " ".join(full_cmd)

        info = CaptureInfo(
            id=capture_id,
            server_id=server.id,
            server_label=server_label(server),
            user_id=user_id,
            status=CaptureStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            command=cmd_str,
            remote_path=remote_path,
            local_path=str(local_path),
        )
        self._captures[capture_id] = info
        self._persist(info)

        # From here the capture counts against max_concurrent_captures. Only
        # _monitor ever ends a RUNNING capture, and it does not exist yet, so a
        # failure to launch has to close the record itself -- otherwise every
        # unreachable host leaks a slot permanently, and after
        # max_concurrent_captures of them nothing can start again until the
        # container restarts and _restore() sweeps them.
        try:
            process = await self._ssh.run_tcpdump(
                server,
                args,
                remote_path,
                duration=duration,
            )
        except BaseException as exc:
            info.status = CaptureStatus.FAILED
            info.stopped_at = datetime.now(timezone.utc)
            info.error = _describe_failure(exc, "")
            self._persist(info)
            raise

        self._processes[capture_id] = process

        task = asyncio.create_task(self._monitor(capture_id, server, process, remote_path, local_path))
        self._tasks[capture_id] = task

        return info

    async def stop(self, capture_id: str) -> CaptureInfo:
        info = self._captures.get(capture_id)
        if not info:
            raise KeyError(f"capture {capture_id} not found")

        if info.status != CaptureStatus.RUNNING:
            return info

        info.status = CaptureStatus.STOPPING
        self._persist(info)
        process = self._processes.get(capture_id)
        if process:
            await self._ssh.stop_tcpdump(process)

        return info

    def rename(self, capture_id: str, name: str) -> CaptureInfo:
        info = self._captures.get(capture_id)
        if not info:
            raise KeyError(f"capture {capture_id} not found")
        info.name = name
        self._persist(info)
        return info

    async def delete(self, capture_id: str) -> None:
        process = self._processes.pop(capture_id, None)
        if process:
            await self._ssh.stop_tcpdump(process)
            await process.close()

        if capture_id in self._tasks:
            self._tasks[capture_id].cancel()
            del self._tasks[capture_id]

        self._db.delete_capture(capture_id)
        info = self._captures.pop(capture_id, None)
        if info and info.local_path:
            path = Path(info.local_path)
            if path.exists():
                path.unlink()

    async def shutdown(self) -> None:
        for capture_id in list(self._processes.keys()):
            process = self._processes.pop(capture_id, None)
            if process:
                try:
                    await self._ssh.stop_tcpdump(process)
                except Exception:
                    logger.warning("failed to stop capture %s during shutdown", capture_id)
                finally:
                    # Stopping tcpdump is not the same as releasing its
                    # connection; shutdown must do both.
                    try:
                        await process.close()
                    except Exception:
                        logger.warning("failed to close connection for %s", capture_id)
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            # Awaiting is the point, not politeness: a cancelled task has not
            # run its finally until it is awaited, and the monitor's finally is
            # what releases the connection and writes the closing row. Without
            # this the coroutine is finalised by the garbage collector after the
            # loop has already closed.
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()

    async def _monitor(
        self,
        capture_id: str,
        server: ServerInfo,
        process: object,
        remote_path: str,
        local_path: Path,
    ) -> None:
        info = self._captures[capture_id]
        stderr_buf: list[str] = []
        stderr_text = ""
        last_persist = 0.0

        def on_live_count(count: int) -> None:
            nonlocal last_persist
            if count == info.packet_count:
                return
            info.packet_count = count
            now = time.monotonic()
            if now - last_persist >= _LIVE_COUNT_PERSIST_SECONDS:
                last_persist = now
                self._persist(info)

        pump = asyncio.create_task(_pump_stderr(process, stderr_buf, on_live_count))
        try:
            # The remote command is wrapped in timeout(1), but that only helps if
            # timeout(1) is present and behaves. This is the backstop: without it
            # a process that never exits holds its SSH connection open forever.
            await asyncio.wait_for(process.wait(), timeout=self._monitor_timeout)
            try:
                # Everything tcpdump has left to say arrives in the moment after
                # it exits: the summary counts, and any diagnosis of a failure.
                await asyncio.wait_for(pump, timeout=5)
            except Exception:
                pass
            stderr_text = "".join(stderr_buf)
            # timeout(1) exits 124 and SIGINT exits 130 — both are how a capture ends normally.
            if process.exit_status not in (0, 124, 130, None):
                raise RuntimeError(f"tcpdump exited {process.exit_status}")
            info.stopped_at = datetime.now(timezone.utc)
            info.status = CaptureStatus.TRANSFERRING
            self._persist(info)

            cryptor = self._vault.cryptor if self._vault else None
            await self._ssh.fetch_file(server, remote_path, local_path, cryptor=cryptor)

            try:
                await self._ssh.delete_remote_file(server, remote_path)
            except Exception:
                logger.warning("failed to clean up remote file %s", remote_path)

            if local_path.exists():
                info.file_size = local_path.stat().st_size

            try:
                info.packet_count = await get_packet_count(self._pcap_source(local_path))
            except Exception:
                # The capture itself is intact and downloadable. Failing it over
                # a count that tcpdump already reported would throw away a good
                # pcap to report a number twice.
                logger.warning(
                    "could not count packets in %s; keeping tcpdump's own total of %d",
                    capture_id, info.packet_count,
                )
            info.status = CaptureStatus.COMPLETED

        except asyncio.CancelledError:
            info.status = CaptureStatus.FAILED
            info.error = "cancelled"
            raise
        except asyncio.TimeoutError:
            info.status = CaptureStatus.FAILED
            info.error = "capture did not finish in time and was abandoned"
        except Exception as exc:
            logger.exception("capture %s failed", capture_id)
            info.status = CaptureStatus.FAILED
            info.error = _describe_failure(exc, stderr_text)
            # A transfer interrupted partway leaves a truncated pcap. It is
            # unreachable -- downloads require COMPLETED -- but leaving half a
            # capture on the volume is misleading.
            _discard_partial(local_path)
        finally:
            pump.cancel()
            # The SSH connection is released here, on every path -- success,
            # failure, timeout and cancellation alike.
            capture = self._processes.pop(capture_id, None)
            if capture is not None:
                await capture.close()
            self._persist(info)
            self._tasks.pop(capture_id, None)
