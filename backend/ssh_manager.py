from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import asyncssh

from backend.models import ServerAuth

logger = logging.getLogger(__name__)


class SSHManager:
    def __init__(self, keys_dir: Path) -> None:
        self._keys_dir = keys_dir

    def _key_path(self, key_name: str) -> Path:
        path = (self._keys_dir / key_name).resolve()
        if not str(path).startswith(str(self._keys_dir.resolve())):
            raise ValueError("path traversal blocked")
        return path

    async def test_connection(self, server: ServerAuth) -> str:
        key_path = self._key_path(server.ssh_key_name)
        if not key_path.exists():
            raise FileNotFoundError(f"SSH key not found: {server.ssh_key_name}")

        conn = await asyncssh.connect(
            server.hostname,
            port=server.port,
            username=server.username,
            client_keys=[str(key_path)],
            known_hosts=None,
            password=None,
            passphrase=None,
        )
        async with conn:
            result = await conn.run("echo ok", check=True, timeout=10)
            return result.stdout.strip()

    async def run_tcpdump(
        self,
        server: ServerAuth,
        command_args: list[str],
        remote_path: str,
        *,
        duration: int | None = None,
    ) -> asyncssh.SSHClientProcess:
        key_path = self._key_path(server.ssh_key_name)

        full_cmd = ["tcpdump", "-w", remote_path] + command_args
        cmd_str = " ".join(_shell_quote(a) for a in full_cmd)

        if duration:
            cmd_str = f"timeout {duration} {cmd_str}; true"

        conn = await asyncssh.connect(
            server.hostname,
            port=server.port,
            username=server.username,
            client_keys=[str(key_path)],
            known_hosts=None,
            password=None,
            passphrase=None,
        )
        logger.info("running on %s: %s", server.hostname, cmd_str)
        process = await conn.create_process(cmd_str)
        return process

    async def stop_tcpdump(self, process: asyncssh.SSHClientProcess) -> None:
        try:
            process.send_signal("INT")
            await asyncio.wait_for(process.wait(), timeout=10)
        except (asyncio.TimeoutError, OSError):
            process.kill()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass

    async def fetch_file(
        self,
        server: ServerAuth,
        remote_path: str,
        local_path: Path,
    ) -> None:
        key_path = self._key_path(server.ssh_key_name)
        async with asyncssh.connect(
            server.hostname,
            port=server.port,
            username=server.username,
            client_keys=[str(key_path)],
            known_hosts=None,
            password=None,
            passphrase=None,
        ) as conn:
            await asyncssh.scp((conn, remote_path), str(local_path))

    async def delete_remote_file(
        self,
        server: ServerAuth,
        remote_path: str,
    ) -> None:
        key_path = self._key_path(server.ssh_key_name)
        safe_path = _shell_quote(remote_path)
        async with asyncssh.connect(
            server.hostname,
            port=server.port,
            username=server.username,
            client_keys=[str(key_path)],
            known_hosts=None,
            password=None,
            passphrase=None,
        ) as conn:
            await conn.run(f"rm -f {safe_path}", check=True, timeout=10)


def _shell_quote(s: str) -> str:
    if not s:
        return "''"
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=")
    if all(c in safe for c in s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"
