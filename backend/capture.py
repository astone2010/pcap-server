from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from backend.models import (
    CaptureInfo,
    CaptureRequest,
    CaptureStatus,
    ServerInfo,
)
from backend.packet_parser import get_packet_count
from backend.ssh_manager import SSHManager

logger = logging.getLogger(__name__)


class CaptureManager:
    def __init__(self, ssh: SSHManager, captures_dir: Path, get_setting: Callable[[str], int]) -> None:
        self._ssh = ssh
        self._captures_dir = captures_dir
        self._captures_dir.mkdir(parents=True, exist_ok=True)
        self._get_setting = get_setting
        self._captures: dict[str, CaptureInfo] = {}
        self._processes: dict[str, object] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    @property
    def captures(self) -> dict[str, CaptureInfo]:
        return dict(self._captures)

    def get(self, capture_id: str) -> CaptureInfo | None:
        return self._captures.get(capture_id)

    def list_for_user(self, user_id: str) -> list[CaptureInfo]:
        return [c for c in self._captures.values() if c.user_id == user_id]

    def build_command_args(self, req: CaptureRequest) -> list[str]:
        max_packets = self._get_setting("max_capture_packets")
        args: list[str] = []
        args += ["-i", req.interface]
        if req.count:
            count = min(req.count, max_packets)
            args += ["-c", str(count)]
        if req.snap_len is not None:
            args += ["-s", str(req.snap_len)]
        args.append("-n")
        args += req.extra_flags
        if req.bpf_filter:
            args.append("--")
            args.append(req.bpf_filter)
        return args

    async def start(self, req: CaptureRequest, server: ServerInfo, user_id: str) -> CaptureInfo:
        max_seconds = self._get_setting("max_capture_seconds")
        capture_id = str(uuid.uuid4())
        remote_path = f"/tmp/pcap_{capture_id}.pcap"
        local_path = self._captures_dir / f"{capture_id}.pcap"

        args = self.build_command_args(req)
        duration = req.duration_seconds
        if duration:
            duration = min(duration, max_seconds)
        else:
            duration = max_seconds

        full_cmd = ["tcpdump", "-w", remote_path] + args
        cmd_str = " ".join(full_cmd)

        info = CaptureInfo(
            id=capture_id,
            server_id=server.id,
            user_id=user_id,
            status=CaptureStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            command=cmd_str,
            remote_path=remote_path,
            local_path=str(local_path),
        )
        self._captures[capture_id] = info

        process = await self._ssh.run_tcpdump(
            server,
            args,
            remote_path,
            duration=duration,
        )
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
        process = self._processes.get(capture_id)
        if process:
            await self._ssh.stop_tcpdump(process)

        return info

    async def delete(self, capture_id: str) -> None:
        process = self._processes.pop(capture_id, None)
        if process:
            await self._ssh.stop_tcpdump(process)

        if capture_id in self._tasks:
            self._tasks[capture_id].cancel()
            del self._tasks[capture_id]

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
        for task in self._tasks.values():
            task.cancel()
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
        try:
            await process.wait()
            info.stopped_at = datetime.now(timezone.utc)
            info.status = CaptureStatus.TRANSFERRING

            await self._ssh.fetch_file(server, remote_path, local_path)

            try:
                await self._ssh.delete_remote_file(server, remote_path)
            except Exception:
                logger.warning("failed to clean up remote file %s", remote_path)

            if local_path.exists():
                info.file_size = local_path.stat().st_size

            info.packet_count = await get_packet_count(local_path)
            info.status = CaptureStatus.COMPLETED

        except asyncio.CancelledError:
            info.status = CaptureStatus.FAILED
            info.error = "cancelled"
        except Exception:
            logger.exception("capture %s failed", capture_id)
            info.status = CaptureStatus.FAILED
            info.error = "capture failed"
        finally:
            self._processes.pop(capture_id, None)
            self._tasks.pop(capture_id, None)
