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
    ANY_INTERFACE,
    assert_no_forbidden_flags,
    CaptureInfo,
    CaptureRequest,
    CaptureStatus,
    ServerInfo,
)
from backend.livestream import LiveBuffer
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

# How long to keep reading stderr after tcpdump exits. Its last words -- the
# summary counts, and any diagnosis of a failure -- all arrive in that moment.
_STDERR_DRAIN_SECONDS = 5

# Captures that are still consuming a resource -- an SSH connection to the
# target, a local file being written, a monitor task -- as opposed to ones
# that have finished one way or another and are just sitting in history.
_ACTIVE_STATUSES = (CaptureStatus.RUNNING, CaptureStatus.STOPPING, CaptureStatus.TRANSFERRING)

# How much to ask the remote host for in one SFTP read while catching a live
# stream up. A poll reads in a loop until it runs out of new bytes, so this is
# the granularity of that loop rather than a limit on how much a poll may take.
_LIVE_READ_CHUNK = 512 * 1024


class _LiveCount:
    """Applies tcpdump's running total to a capture record as it is reported.

    Held in memory immediately, which is what the status endpoint serves, and
    written to the database at most once every _LIVE_COUNT_PERSIST_SECONDS: a
    row rewrite per second per capture buys nothing to persist a number that is
    superseded a second later.
    """

    __slots__ = ("_info", "_persist", "_last_write")

    def __init__(self, info: CaptureInfo, persist: Callable[[CaptureInfo], None]) -> None:
        self._info = info
        self._persist = persist
        self._last_write = 0.0

    def __call__(self, count: int) -> None:
        if count == self._info.packet_count:
            return
        self._info.packet_count = count
        now = time.monotonic()
        if now - self._last_write >= _LIVE_COUNT_PERSIST_SECONDS:
            self._last_write = now
            self._persist(self._info)


class CaptureLimitExceeded(Exception):
    """Raised when starting a capture would exceed max_concurrent_captures."""


class LiveStreamLimitExceeded(Exception):
    """Raised when starting a capture would exceed max_live_streams.

    Separate from CaptureLimitExceeded because the remedy is different and the
    operator can act on it without waiting: an ordinary capture still starts.
    Live streaming is the part that is full, and it is capped far lower than
    max_concurrent_captures because it costs far more -- an SFTP channel held
    open on the target, and a tshark spawn per poll over the whole buffer.
    """


class _LiveSession:
    """A live view's buffer, and the lock that stops two polls racing it.

    The lock is not optional. Both polls would read from the same offset and
    both would feed what they read, appending the same bytes twice in the
    middle of a record -- which desynchronises the record walk permanently,
    with no error anywhere to say so.
    """

    __slots__ = ("buffer", "lock")

    def __init__(self, cap_bytes: int) -> None:
        self.buffer = LiveBuffer(cap_bytes)
        self.lock = asyncio.Lock()


class LiveStreamNotTargeted(Exception):
    """Raised when a live stream is asked for without narrowing what is captured.

    The preview buffer is a fixed number of megabytes (live_stream_buffer_mb),
    and the whole of it is held in this container's memory. `-i any` with no
    filter points that buffer at every packet on every link the target host
    has, which fills it in seconds on any host doing real work: the preview
    freezes almost immediately and the live view stops being live.

    Refused rather than warned about, because the buffer is the one resource
    here the operator cannot get back by waiting -- once it is full the view is
    frozen for the rest of the capture, and the only fix is to start again.
    Raising the cap instead would trade a frozen preview for this container's
    memory, which is the worse of the two.

    An interface OR a filter is enough. Either one bounds the traffic, and
    which one is right depends on what is being hunted: `-i eth0` when the
    question is about one link, a filter when it is about one conversation.
    """


class InterfaceAlreadyCapturing(Exception):
    """Raised when this server's interface already has a capture running.

    Separate from CaptureLimitExceeded because it is a different kind of no:
    the limit is a quota on this container's resources and clears by waiting,
    while this is a conflict over one specific link that clears only by
    stopping the capture that holds it -- or by choosing another interface.
    """


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
        self._captures: dict[str, CaptureInfo] = {}
        # RemoteCapture objects: the tcpdump process bound to its SSH connection,
        # so closing one closes both.
        self._processes: dict[str, object] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        # Live-stream buffers, keyed the same way. Purely a view onto a running
        # capture: created on the first poll, dropped when the capture ends, and
        # never the source of anything that gets stored.
        self._live: dict[str, _LiveSession] = {}
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

    def live_count(self) -> int:
        """Live-streamed captures still holding resources.

        Counted over _ACTIVE_STATUSES rather than RUNNING alone, the same as
        active_count: a capture in TRANSFERRING is no longer being watched, but
        it is still holding the connection and the file handle that the cap
        exists to bound, and a limit that lets a resource go uncounted while it
        is still held is not a limit.
        """
        return sum(
            1 for c in self._captures.values()
            if c.live_stream and c.status in _ACTIVE_STATUSES
        )

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
        if req.live_stream:
            # Packet-buffered. Without it tcpdump fills a buffer before writing,
            # so the remote file -- which is the only thing a live view can read
            # -- lags the traffic by a whole buffer, which on a quiet link is
            # many seconds of watching nothing happen.
            #
            # It changes when bytes reach the file, not which bytes, so the
            # saved capture is identical either way.
            args.append("-U")
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
        # Before the resource limits, because this one is about the shape of the
        # request rather than what else is running: an operator who gets "too
        # many captures" for a form that would never have worked is sent looking
        # in the wrong place, and the message they need is the one below.
        if req.live_stream and req.interface == ANY_INTERFACE and not req.bpf_filter.strip():
            raise LiveStreamNotTargeted(
                "a live stream needs to be pointed at something: choose an interface "
                f'instead of "{ANY_INTERFACE}", or set a BPF filter -- or both. Watching '
                "every packet on every link fills the preview buffer in seconds, and it "
                "does not refill. Capturing without live streaming has no such limit."
            )

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

        # One capture per interface per server. Two tcpdumps reading the same
        # link record the same packets twice, doubling load on the target host
        # for a second copy of a capture you already have -- and leave two
        # captures nothing in the UI distinguishes. Different interfaces on one
        # host stay allowed: reading eth0 and eth1 at once is a real thing to
        # want, and they do not overlap.
        #
        # Deliberately in the same synchronous stretch as the limit check above
        # and the _captures insert below. Nothing awaits between them, so two
        # simultaneous requests cannot both pass this and then both register;
        # an await anywhere in here would open exactly that window.
        busy = next(
            (
                c for c in self._captures.values()
                if c.status in _ACTIVE_STATUSES
                and c.server_id == server.id
                and c.interface == req.interface
            ),
            None,
        )
        if busy:
            held = busy.name or busy.id
            raise InterfaceAlreadyCapturing(
                f"a capture is already running on {req.interface} on this server "
                f"({held}) -- stop it first, or capture a different interface"
            )

        # In the same await-free stretch as the two checks above and the
        # _captures insert below, for the same reason: an await here would open
        # the window where two simultaneous live-stream requests both pass the
        # cap and then both register, which is exactly the third live stream the
        # cap exists to refuse.
        if req.live_stream:
            max_live = self._get_setting("max_live_streams")
            if self.live_count() >= max_live:
                raise LiveStreamLimitExceeded(
                    f"{max_live} live stream(s) already running -- stop one before "
                    "starting another, or start this capture without live streaming"
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
        # Grace for tcpdump to flush and exit after timeout(1) fires. Carried
        # to this capture's own monitor rather than held on the manager: with
        # max_concurrent_captures above 1, a second start() overwrote the
        # shared value before the first monitor had read it, so a 10-minute
        # capture started alongside a 5-second one was abandoned after 65s.
        monitor_timeout = duration + _MONITOR_GRACE_SECONDS

        binary = server.tcpdump_path or "tcpdump"
        full_cmd = [binary, "-w", remote_path] + args
        if server.use_sudo:
            full_cmd = ["sudo", "-n"] + full_cmd
        assert_no_forbidden_flags(full_cmd)
        cmd_str = " ".join(full_cmd)

        info = CaptureInfo(
            id=capture_id,
            name=req.name,
            server_id=server.id,
            server_label=server_label(server),
            interface=req.interface,
            user_id=user_id,
            live_stream=req.live_stream,
            bpf_filter=req.bpf_filter,
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

        task = asyncio.create_task(
            self._monitor(
                capture_id, server, process, remote_path, local_path,
                monitor_timeout=monitor_timeout,
            )
        )
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

    def live_buffer(self, capture_id: str) -> LiveBuffer | None:
        """What a live view already holds, without going to the remote host."""
        session = self._live.get(capture_id)
        return session.buffer if session else None

    async def live_poll(self, capture_id: str) -> LiveBuffer:
        """Catch a live stream up with the remote file, and hand back the buffer.

        Reads in a loop rather than once, because a poll that only ever took one
        chunk would fall permanently behind a link busier than the chunk size
        per poll interval -- and would never say so. The loop ends when the
        remote file has no more to give, or the buffer reaches its cap.
        """
        info = self._captures.get(capture_id)
        if not info:
            raise KeyError(f"capture {capture_id} not found")

        # No await between the lookup and the insert, deliberately, and for the
        # same reason start()'s limit checks have none: two first polls landing
        # together would otherwise each build a session and each keep a
        # different lock, which is the one arrangement the lock cannot save.
        session = self._live.get(capture_id)
        if session is None:
            session = _LiveSession(self._live_buffer_bytes())
            self._live[capture_id] = session
        buffer = session.buffer

        process = self._processes.get(capture_id)
        if process is None:
            # The capture is over and its connection released. Whatever was
            # read is still worth serving -- the viewer is about to move to the
            # saved capture anyway.
            return buffer

        async with session.lock:
            while not buffer.frozen and not buffer.problem:
                room = buffer.capacity - buffer.size
                if room <= 0:
                    buffer.frozen = True
                    break
                want = min(_LIVE_READ_CHUNK, room)
                try:
                    data = await process.read_at(info.remote_path, buffer.offset, want)
                except Exception as exc:
                    # Not fatal and not silent. A capture whose connection has
                    # gone is about to reach a terminal status on its own, and a
                    # momentary failure is one the next poll may well recover
                    # from -- so this is recorded for the operator to see and
                    # cleared by the next read that works, rather than ending
                    # the stream.
                    # Truncated because an SFTP error can carry text from the
                    # target host, which is frequently the machine under
                    # investigation. It reaches the browser as textContent, the
                    # same way a capture's own failure message already does.
                    buffer.read_error = str(exc)[:200] or exc.__class__.__name__
                    logger.warning(
                        "live stream %s could not read the remote capture: %s",
                        capture_id, buffer.read_error,
                    )
                    break
                buffer.read_error = ""
                if not data:
                    break
                buffer.feed(data)
                if len(data) < want:
                    # Short read: the file has nothing more yet.
                    break

        return buffer

    def _live_buffer_bytes(self) -> int:
        # Floored at one megabyte. A cap below the pcap header plus a packet
        # would freeze every live stream before its first frame, which looks
        # exactly like live streaming being broken rather than misconfigured.
        return max(1, self._get_setting("live_stream_buffer_mb")) * 1024 * 1024

    def rename(self, capture_id: str, name: str) -> CaptureInfo:
        info = self._captures.get(capture_id)
        if not info:
            raise KeyError(f"capture {capture_id} not found")
        info.name = name
        self._persist(info)
        return info

    async def delete(self, capture_id: str) -> dict:
        """Remove a capture, terminating it first if it is still running.

        Deleting a running capture is a stop that keeps nothing, and it has to
        do everything a stop does: interrupt tcpdump the same way, take the
        file it was writing off the target host, release the SSH session, and
        only then drop the record and the local copy.

        Delete used to diverge from stop on all three counts. It signalled the
        process but cancelled the monitor without awaiting it, so the monitor's
        finally -- which ends in _persist() -- ran after the row had been
        deleted and wrote it straight back, as a FAILED capture whose file was
        already gone. And because the monitor never reached _collect, nothing
        removed the remote pcap: the capture an operator deleted stayed on the
        target, complete.

        Returns what actually happened, so the caller can say so rather than
        having the capture disappear with no account of what was done.
        """
        info = self._captures.get(capture_id)
        remote_path = info.remote_path if info else ""
        result = {"terminated": False, "remote_file_removed": False}

        # Out of the monitor's reach before it is cancelled: terminating the
        # capture is this method's job, done deliberately, rather than a side
        # effect of the connection being torn down underneath it.
        process = self._processes.pop(capture_id, None)

        task = self._tasks.pop(capture_id, None)
        if task:
            task.cancel()
            # A cancelled task has not run its finally until it is awaited.
            # Waiting here is what keeps the delete final.
            await asyncio.gather(task, return_exceptions=True)

        if process:
            # Live in this process, so it gets exactly the interrupt-then-kill a
            # Stop performs. Signalling a process that has already exited raises
            # instead, which is not a reason to fail the delete: closing the
            # session below ends it either way, and refusing here would leave
            # the record behind for a capture that is already over.
            try:
                await self._ssh.stop_tcpdump(process)
            except Exception:
                logger.warning("could not interrupt capture %s cleanly; closing its session", capture_id)
            result["terminated"] = True
            if remote_path:
                try:
                    await process.remove_remote_file(remote_path)
                    result["remote_file_removed"] = True
                except Exception:
                    # The record and the local copy still go. A file left in
                    # the target's /tmp is worth a warning and a word to the
                    # caller, not a refusal to delete.
                    logger.warning(
                        "failed to remove remote file %s for deleted capture %s",
                        remote_path, capture_id,
                    )
            await process.close()

        self._live.pop(capture_id, None)
        self._db.delete_capture(capture_id)
        info = self._captures.pop(capture_id, None)
        if info and info.local_path:
            path = Path(info.local_path)
            if path.exists():
                path.unlink()
        return result

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
        self._live.clear()

    async def _monitor(
        self,
        capture_id: str,
        server: ServerInfo,
        process: object,
        remote_path: str,
        local_path: Path,
        *,
        monitor_timeout: float,
    ) -> None:
        """Own a running capture from launch to a terminal status.

        Split three ways deliberately: waiting for the process, bringing the
        pcap back, and deciding what a failure means are separate concerns, and
        the middle one is the only part that touches the remote host twice.
        """
        info = self._captures[capture_id]
        stderr: list[str] = []
        pump = asyncio.create_task(
            _pump_stderr(process, stderr, _LiveCount(info, self._persist))
        )
        try:
            await self._await_exit(process, pump, monitor_timeout)

            info.stopped_at = datetime.now(timezone.utc)
            info.status = CaptureStatus.TRANSFERRING
            self._persist(info)

            await self._collect(capture_id, server, remote_path, local_path, info)
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
            info.error = _describe_failure(exc, "".join(stderr))
            # A transfer interrupted partway leaves a truncated pcap. It is
            # unreachable -- downloads require COMPLETED -- but leaving half a
            # capture on the volume is misleading.
            _discard_partial(local_path)
        finally:
            pump.cancel()
            # The live buffer goes with the capture, on every path. It is up to
            # megabytes of packet data held only to be looked at, and the viewer
            # moves to the sealed file from here -- keeping it would be holding
            # the whole capture in memory for as long as the process lives.
            self._live.pop(capture_id, None)
            # The SSH connection is released here, on every path -- success,
            # failure, timeout and cancellation alike.
            capture = self._processes.pop(capture_id, None)
            if capture is not None:
                await capture.close()
            self._persist(info)
            self._tasks.pop(capture_id, None)

    async def _await_exit(self, process: object, pump: asyncio.Task, timeout: float) -> None:
        """Wait for tcpdump to finish, then let the rest of its stderr land."""
        # The remote command is wrapped in timeout(1), but that only helps if
        # timeout(1) is present and behaves. This is the backstop: without it a
        # process that never exits holds its SSH connection open forever.
        await asyncio.wait_for(process.wait(), timeout=timeout)
        try:
            await asyncio.wait_for(pump, timeout=_STDERR_DRAIN_SECONDS)
        except Exception:
            # Failing to read the epilogue is not a failed capture. Whatever the
            # pump did manage to read is still in the buffer for diagnosis.
            pass
        # timeout(1) exits 124 and SIGINT exits 130 -- both are how a capture ends normally.
        if process.exit_status not in (0, 124, 130, None):
            raise RuntimeError(f"tcpdump exited {process.exit_status}")

    async def _collect(
        self,
        capture_id: str,
        server: ServerInfo,
        remote_path: str,
        local_path: Path,
        info: CaptureInfo,
    ) -> None:
        """Bring the pcap back, tidy the remote host, and record size and count."""
        cryptor = self._vault.cryptor if self._vault else None
        await self._ssh.fetch_file(server, remote_path, local_path, cryptor=cryptor)

        try:
            await self._ssh.delete_remote_file(server, remote_path)
        except Exception:
            # The capture is already here. A file left in the target's /tmp is
            # worth a warning, not a failed capture.
            logger.warning("failed to clean up remote file %s", remote_path)

        if local_path.exists():
            info.file_size = local_path.stat().st_size

        try:
            info.packet_count = await get_packet_count(self._pcap_source(local_path))
        except Exception:
            # The capture itself is intact and downloadable. Failing it over a
            # count tcpdump already reported would throw away a good pcap to
            # report a number twice.
            logger.warning(
                "could not count packets in %s; keeping tcpdump's own total of %d",
                capture_id, info.packet_count,
            )
