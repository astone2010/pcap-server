from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path

import asyncssh

from backend.database import Database
from backend.models import ServerAuth

logger = logging.getLogger(__name__)


class SSHManager:
    def __init__(self, keys_dir: Path, db: Database, data_dir: Path) -> None:
        self._keys_dir = keys_dir
        self._db = db
        self._data_dir = data_dir

    def _key_path(self, key_name: str) -> Path:
        path = (self._keys_dir / key_name).resolve()
        if not str(path).startswith(str(self._keys_dir.resolve())):
            raise ValueError("path traversal blocked")
        return path

    async def _get_known_hosts_file(self, hostname: str, port: int) -> str | None:
        entries = self._db.get_known_hosts(hostname, port)
        if not entries:
            return None
        lines = []
        for e in entries:
            if port == 22:
                lines.append(f"{hostname} {e['key_type']} {e['host_key']}")
            else:
                lines.append(f"[{hostname}]:{port} {e['key_type']} {e['host_key']}")
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False, dir=str(self._data_dir))
        tmp.write("\n".join(lines) + "\n")
        tmp.close()
        return tmp.name

    async def scan_host_keys(self, hostname: str, port: int, user_id: str | None = None) -> list[dict]:
        proc = await asyncio.create_subprocess_exec(
            "ssh-keyscan", "-p", str(port), "-T", "5", hostname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.warning("ssh-keyscan failed for %s:%d: %s", hostname, port, stderr.decode()[:200])

        keys = []
        for line in stdout.decode().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 2)
            if len(parts) != 3:
                continue
            _, key_type, host_key = parts
            self._db.add_known_host(hostname, port, key_type, host_key, user_id)
            keys.append({"hostname": hostname, "port": port, "key_type": key_type, "host_key": host_key})
        return keys

    async def _connect(self, server: ServerAuth) -> asyncssh.SSHClientConnection:
        key_path = self._key_path(server.ssh_key_name)
        if not key_path.exists():
            raise FileNotFoundError(f"SSH key not found: {server.ssh_key_name}")

        kh_file = await self._get_known_hosts_file(server.hostname, server.port)

        try:
            conn = await asyncssh.connect(
                server.hostname,
                port=server.port,
                username=server.username,
                client_keys=[str(key_path)],
                known_hosts=kh_file if kh_file else None,
                password=None,
                passphrase=None,
            )
        except asyncssh.HostKeyNotVerifiable:
            raise ConnectionError("Host key verification failed. Scan the host key first via Admin > Known Hosts.")
        finally:
            if kh_file:
                Path(kh_file).unlink(missing_ok=True)

        return conn

    async def test_connection(self, server: ServerAuth) -> str:
        try:
            conn = await self._connect(server)
            async with conn:
                result = await conn.run("echo ok", check=True, timeout=10)
                return result.stdout.strip()
        except (ConnectionError, FileNotFoundError):
            raise
        except Exception:
            raise ConnectionError("SSH connection failed")

    async def list_interfaces(self, server: ServerAuth) -> list[str]:
        # /sys/class/net needs no privileges, unlike `tcpdump -D` on most hosts.
        try:
            conn = await self._connect(server)
            async with conn:
                result = await conn.run("ls -1 /sys/class/net", check=True, timeout=10)
        except (ConnectionError, FileNotFoundError):
            raise
        except Exception:
            raise ConnectionError("could not list interfaces")
        names = sorted(n.strip() for n in result.stdout.splitlines() if n.strip())
        return ["any"] + names

    async def run_tcpdump(
        self,
        server: ServerAuth,
        command_args: list[str],
        remote_path: str,
        *,
        duration: int | None = None,
    ) -> asyncssh.SSHClientProcess:
        full_cmd = ["tcpdump", "-w", remote_path] + command_args
        if server.use_sudo:
            # -n so a password prompt fails fast instead of hanging on a non-tty.
            full_cmd = ["sudo", "-n"] + full_cmd
        cmd_str = " ".join(_shell_quote(a) for a in full_cmd)

        if duration:
            cmd_str = f"timeout {duration} {cmd_str}"

        conn = await self._connect(server)
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
        conn = await self._connect(server)
        async with conn:
            await asyncssh.scp((conn, remote_path), str(local_path))

    async def delete_remote_file(
        self,
        server: ServerAuth,
        remote_path: str,
    ) -> None:
        safe_path = _shell_quote(remote_path)
        conn = await self._connect(server)
        async with conn:
            await conn.run(f"rm -f {safe_path}", check=True, timeout=10)


def _shell_quote(s: str) -> str:
    if not s:
        return "''"
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=")
    if all(c in safe for c in s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"
