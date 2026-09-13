from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
from pathlib import Path, PurePosixPath

import asyncssh

from backend.crypto import CryptoError, looks_encrypted
from backend.database import Database
from backend.models import ServerAuth

logger = logging.getLogger(__name__)

LOGIN_TIMEOUT = 15          # seconds to complete TCP connect + SSH auth
KEEPALIVE_INTERVAL = 30     # seconds between keepalives on a long capture
KEEPALIVE_COUNT_MAX = 3     # missed keepalives before the connection is dropped
FETCH_TIMEOUT = 300        # seconds for the pcap download before it is abandoned
DOWNLOAD_CHUNK = 64 * 1024  # bytes read per SFTP round trip

# Host key algorithms, weakest first. The rank is what "strongest" is measured
# against; anything unlisted sorts below everything known rather than above it.
#
# ssh-rsa is last among the usable ones because it signs with SHA-1 regardless
# of the key's size -- OpenSSH disabled it by default in 8.8. ssh-dss is worse
# still: 1024-bit DSA, removed entirely in OpenSSH 7.0.
_HOST_KEY_RANK = [
    "ssh-dss",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ssh-ed25519",
]


def host_key_strength(algorithm: str) -> int:
    """Where an algorithm sits in _HOST_KEY_RANK; -1 if it isn't known."""
    try:
        return _HOST_KEY_RANK.index(algorithm)
    except ValueError:
        return -1


def weaker_host_key_than_available(negotiated: str, available: list[str]) -> str:
    """The strongest offered algorithm, when it beats the negotiated one.

    Empty when the connection already took the best on offer, so a caller can
    treat any non-empty result as the thing worth warning about.
    """
    if not negotiated or not available:
        return ""
    best = max(available, key=host_key_strength)
    if host_key_strength(best) > host_key_strength(negotiated):
        return best
    return ""


class RemoteCapture:
    """A running tcpdump and the connection carrying it, closed as one unit.

    run_tcpdump used to return only the process, leaving its connection with no
    owner and no close path: it stayed open after tcpdump exited and was
    reclaimed only whenever the garbage collector got to it. Binding the two
    together means the connection closes when the capture does, on every exit
    path including cancellation.
    """

    __slots__ = ("process", "_conn", "_closed")

    def __init__(self, process: asyncssh.SSHClientProcess, conn: asyncssh.SSHClientConnection) -> None:
        self.process = process
        self._conn = conn
        self._closed = False

    @property
    def exit_status(self):
        return self.process.exit_status

    @property
    def stderr(self):
        return self.process.stderr

    async def wait(self):
        return await self.process.wait()

    def send_signal(self, sig: str) -> None:
        self.process.send_signal(sig)

    def kill(self) -> None:
        self.process.kill()

    async def remove_remote_file(self, remote_path: str) -> None:
        """Delete this capture's file on the target, over its own connection.

        A capture deleted while it is running never reaches _collect, which is
        what normally tidies the target host -- so without this the pcap an
        operator just deleted is still sitting in the target's /tmp, complete
        and readable by anyone with an account there. Reusing the connection
        the capture is already running on keeps it to one round trip against a
        host that is already authenticated, and it has to happen before
        close(): afterwards there is nothing left to run it on.
        """
        await self._conn.run(f"rm -f {_shell_quote(remote_path)}", check=True, timeout=10)

    async def close(self) -> None:
        """Idempotent: safe to call from the monitor, from delete, and at shutdown."""
        if self._closed:
            return
        self._closed = True
        try:
            self.process.close()
        except Exception:
            pass
        try:
            self._conn.close()
            await self._conn.wait_closed()
        except Exception:
            logger.debug("connection already gone while closing capture", exc_info=True)


def resolve_key_path(keys_dir: Path, key_name: str) -> Path:
    """The file a key name refers to, or ValueError if it escapes keys_dir.

    Path.is_relative_to, not `str(path).startswith(str(base))`. The string test
    was in four places and is wrong in the same way in all of them: with a base
    of /app/ssh-keys it accepts /app/ssh-keys-backup/id_rsa, because the string
    genuinely is a prefix even though the directory is a different one. Nothing
    reachable today gets past the model validators to exercise that -- which is
    exactly why it should not be four separately-written checks waiting for the
    fifth caller who forgets one.
    """
    base = keys_dir.resolve()
    path = (base / key_name).resolve()
    if path == base or not path.is_relative_to(base):
        raise ValueError("path traversal blocked")
    return path


class SSHManager:
    def __init__(self, keys_dir: Path, db: Database, data_dir: Path, vault=None) -> None:
        self._keys_dir = keys_dir
        self._db = db
        self._data_dir = data_dir
        self._vault = vault

    def _key_path(self, key_name: str) -> Path:
        return resolve_key_path(self._keys_dir, key_name)

    def _read_key_bytes(self, path: Path) -> bytes:
        """Sealed keys are content-sniffed, not named by suffix -- same reason
        as CaptureVault.source_for: nothing here should have to trust a
        filename to know whether it needs the vault's cryptor."""
        if looks_encrypted(path):
            if not self._vault or not self._vault.cryptor:
                raise CryptoError(f"SSH key {path.name!r} is encrypted and the vault is locked")
            return self._vault.cryptor.open_bytes(path)
        return path.read_bytes()

    def _load_client_key(self, path: Path) -> asyncssh.SSHKey:
        return asyncssh.import_private_key(self._read_key_bytes(path))

    async def _get_known_hosts_file(self, hostname: str, port: int) -> str | None:
        entries = self._db.get_known_hosts(hostname, port)
        if not entries:
            return None
        # Strongest first, and the ordering is the point rather than tidiness.
        # asyncssh builds its list of acceptable server host key algorithms by
        # walking the matched entries in file order, and SSH settles on the
        # first algorithm the server also holds -- so the first line here
        # decides what the handshake actually uses.
        #
        # The rows arrive in insertion order, which is whichever order
        # ssh-keyscan happened to print them in -- and every write reshuffles
        # it, because add_known_host is an INSERT OR REPLACE against a UNIQUE
        # key and a replaced row is re-inserted with a new autoincrement id.
        # So which algorithm a verified host used came down to the order of
        # the last scan: rescanning, or forgetting and rescanning, could move
        # a host onto its RSA key with nothing said. Sorting here makes the
        # result independent of whatever order the keys arrive in.
        # _HOST_KEY_RANK already knew which was better; it was only ever
        # consulted to report the mismatch afterwards, never to prevent it.
        entries = sorted(
            entries, key=lambda e: host_key_strength(e["key_type"]), reverse=True
        )
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

        # A locked or absent vault preventing key access reads to every caller
        # exactly like any other reason a connection can't be established --
        # _connect()'s documented failure modes stay FileNotFoundError and
        # ConnectionError, so nothing downstream needs a third except clause.
        try:
            client_key = self._load_client_key(key_path)
        except CryptoError as exc:
            raise ConnectionError(str(exc)) from exc

        kh_file = await self._get_known_hosts_file(server.hostname, server.port)
        if not kh_file:
            # Fail closed. asyncssh reads known_hosts=None as "skip host key
            # validation entirely" rather than "fall back to the default
            # file", so connecting without stored keys does not mean
            # "unverified but otherwise normal" -- it means this client offers
            # its private key to whatever answers on that address, with
            # nothing checked. Refusing is the only honest reading of a host
            # nobody has vouched for.
            #
            # No chicken and egg: trusting a host goes through ssh-keyscan in
            # scan_host_keys(), which does not come through here.
            raise ConnectionError(
                f"{server.hostname}:{server.port} has no trusted host keys, so its "
                "identity cannot be checked. An admin must trust it under "
                "Admin > Known Hosts before it can be used."
            )

        try:
            conn = await asyncssh.connect(
                server.hostname,
                port=server.port,
                username=server.username,
                client_keys=[client_key],
                # Never None: that is asyncssh's "disable validation" value,
                # and the empty case is refused above rather than reaching here.
                known_hosts=kh_file,
                password=None,
                passphrase=None,
                # A host that accepts TCP but never finishes the handshake would
                # otherwise hang the request indefinitely.
                login_timeout=LOGIN_TIMEOUT,
                # A capture can run for minutes. Without keepalives a peer that
                # disappears mid-capture leaves us waiting on a dead socket.
                keepalive_interval=KEEPALIVE_INTERVAL,
                keepalive_count_max=KEEPALIVE_COUNT_MAX,
            )
        except asyncssh.HostKeyNotVerifiable:
            # Reachable only when keys ARE stored and the host answered with
            # something else -- the no-keys case is refused above. This used to
            # say "scan the host key first", which described the one situation
            # it can never be raised for, and read as a setup step rather than
            # as the alarm it is.
            raise ConnectionError(
                f"{server.hostname}:{server.port} answered with a host key that does not "
                "match the keys trusted for it. Either the host was rebuilt or re-keyed, "
                "or something else is answering on that address. Confirm which before "
                "forgetting and re-trusting it."
            )
        finally:
            if kh_file:
                Path(kh_file).unlink(missing_ok=True)

        return conn

    async def test_connection(self, server: ServerAuth) -> dict:
        """Connect, and report which host key the handshake actually settled on.

        Which algorithm is negotiated is invisible otherwise, and a host that
        still has an ssh-rsa key will happily use it with a client that offers
        nothing better. Reporting it turns that into something an operator can
        see; it is never a reason to refuse the connection.
        """
        try:
            conn = await self._connect(server)
            async with conn:
                result = await conn.run("echo ok", check=True, timeout=10)
                negotiated = self._negotiated_host_key(conn)
                stored = [e["key_type"] for e in self._db.get_known_hosts(server.hostname, server.port)]
                return {
                    "output": result.stdout.strip(),
                    "host_key_algorithm": negotiated,
                    "stronger_available": weaker_host_key_than_available(negotiated, stored),
                }
        except (ConnectionError, FileNotFoundError):
            raise
        except Exception:
            raise ConnectionError("SSH connection failed")

    @staticmethod
    def _negotiated_host_key(conn) -> str:
        """asyncssh names this differently across versions, and it is only ever
        informational -- never fail a working connection over reading it."""
        try:
            key = conn.get_server_host_key()
        except Exception:
            return ""
        algorithm = getattr(key, "algorithm", "") if key else ""
        # asyncssh returns the algorithm as wire bytes on most versions.
        if isinstance(algorithm, (bytes, bytearray)):
            algorithm = algorithm.decode("ascii", "replace")
        return algorithm

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

    async def check_prerequisites(self, server: ServerAuth) -> dict:
        """Run the read-only probe and return validated facts plus a checklist.

        Read-only by construction: see _PREREQ_SCRIPT. Nothing is installed and
        nothing is elevated beyond `sudo -n true`.
        """
        conn = await self._connect(server)
        async with conn:
            result = await conn.run(_PREREQ_SCRIPT, check=False, timeout=30)
        raw = (result.stdout or "") + "\n" + (result.stderr or "")
        facts = parse_prereq_output(raw)
        return {
            "facts": facts,
            "checks": evaluate_prereqs(
                facts, bool(getattr(server, "use_sudo", False)), server.username
            ),
            "tcpdump_path": facts["tcpdump_path"],
        }

    async def run_tcpdump(
        self,
        server: ServerAuth,
        command_args: list[str],
        remote_path: str,
        *,
        duration: int | None = None,
    ) -> asyncssh.SSHClientProcess:
        # The discovered absolute path, when the prereq check has found one. A
        # non-login SSH session frequently has no /usr/sbin on PATH, so a bare
        # "tcpdump" is not reliably resolvable even where it is installed.
        binary = getattr(server, "tcpdump_path", "") or "tcpdump"
        full_cmd = [binary, "-w", remote_path] + command_args
        if server.use_sudo:
            # -n so a password prompt fails fast instead of hanging on a non-tty.
            full_cmd = ["sudo", "-n"] + full_cmd
        cmd_str = " ".join(_shell_quote(a) for a in full_cmd)

        if duration:
            cmd_str = f"timeout {duration} {cmd_str}"

        conn = await self._connect(server)
        logger.info("running on %s: %s", server.hostname, cmd_str)
        try:
            process = await conn.create_process(cmd_str)
        except Exception:
            # Never leave the connection behind if the exec itself fails.
            conn.close()
            await conn.wait_closed()
            raise
        return RemoteCapture(process, conn)

    async def stop_tcpdump(self, capture: RemoteCapture) -> None:
        """Interrupt tcpdump so it flushes its pcap, then escalate if it ignores us.

        Does not close the connection: the caller still needs it to fetch the
        file. Closing is the monitor's job, in its finally.
        """
        try:
            capture.send_signal("INT")
            await asyncio.wait_for(capture.wait(), timeout=10)
        except (asyncio.TimeoutError, OSError):
            capture.kill()
            try:
                await asyncio.wait_for(capture.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass

    async def fetch_file(
        self,
        server: ServerAuth,
        remote_path: str,
        local_path: Path,
        *,
        cryptor=None,
        timeout: float = FETCH_TIMEOUT,
    ) -> None:
        """Download over its own short-lived connection, bounded and always closed.

        When a cryptor is given the capture is sealed as it arrives, chunk by
        chunk over SFTP, so the plaintext pcap never exists as a local file --
        not even briefly before being encrypted and deleted.
        """
        conn = await self._connect(server)
        async with conn:
            await asyncio.wait_for(
                self._download(conn, remote_path, local_path, cryptor), timeout=timeout
            )

    async def _download(self, conn, remote_path: str, local_path: Path, cryptor) -> None:
        if cryptor is None:
            await asyncssh.scp((conn, remote_path), str(local_path))
            return

        # Sealed as it arrives: the plaintext capture never becomes a local file.
        sealer = cryptor.sealer()
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(remote_path, "rb") as remote:
                with open(local_path, "wb") as out:
                    out.write(sealer.header())
                    while True:
                        data = await remote.read(DOWNLOAD_CHUNK)
                        if not data:
                            break
                        out.write(sealer.seal(data))
                    out.write(sealer.finish())
        os.chmod(local_path, 0o600)

    async def delete_remote_file(
        self,
        server: ServerAuth,
        remote_path: str,
    ) -> None:
        safe_path = _shell_quote(remote_path)
        conn = await self._connect(server)
        async with conn:
            await conn.run(f"rm -f {safe_path}", check=True, timeout=10)

    def migrate_plaintext_keys(self) -> tuple[int, int]:
        """Seal SSH keys uploaded before encryption was switched on.

        Same verify-then-replace safety as CaptureVault.migrate_plaintext:
        seal to a temp file, confirm it decrypts back to the original bytes,
        only then replace -- so a crash at any point leaves either the
        original key or a verified sealed replacement, never a half-written
        one that would silently lock an admin out of a saved server.
        """
        cryptor = self._vault.cryptor if self._vault else None
        if cryptor is None or not self._keys_dir.exists():
            return (0, 0)
        done = failed = 0
        for path in self._keys_dir.iterdir():
            if not path.is_file() or path.name == ".gitkeep" or looks_encrypted(path):
                continue
            tmp = path.with_name(path.name + ".sealing")
            try:
                cryptor.seal_file(path, tmp)
                if cryptor.open_bytes(tmp) != path.read_bytes():
                    raise CryptoError("verification mismatch")
                tmp.replace(path)
                done += 1
                logger.info("encrypted existing SSH key %s", path.name)
            except (OSError, CryptoError) as exc:
                failed += 1
                logger.error("could not encrypt SSH key %s: %s", path.name, exc)
                tmp.unlink(missing_ok=True)
        if done or failed:
            logger.info("SSH key migration complete: %d encrypted, %d failed", done, failed)
        return (done, failed)


def _shell_quote(s: str) -> str:
    if not s:
        return "''"
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=")
    if all(c in safe for c in s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


# Read-only prerequisite probe.
#
# Every command below either reads state or runs `true`. Nothing is installed,
# no package manager is invoked -- not even in simulate mode, which still
# touches lock files and caches -- and nothing is elevated beyond `sudo -n
# true`, which exists precisely to answer "would sudo work" without doing
# anything. If a check comes up short the caller is told what to run; running
# it is the operator's job, never ours.
#
# /bin/sh only: no bashisms, since the target may be BusyBox.
_PREREQ_SCRIPT = r"""
echo "OSREL_BEGIN"
cat /etc/os-release 2>/dev/null | head -20
echo "OSREL_END"
echo "UID=$(id -u 2>/dev/null)"
echo "USERGROUPS=$(id -Gn 2>/dev/null)"
echo "PATHVAL=$PATH"
echo "ONPATH=$(command -v tcpdump 2>/dev/null)"
for p in /usr/sbin/tcpdump /sbin/tcpdump /usr/bin/tcpdump /bin/tcpdump \
         /usr/local/sbin/tcpdump /usr/local/bin/tcpdump; do
    if [ -x "$p" ]; then echo "FOUND=$p"; fi
done
echo "SUDO=$(command -v sudo 2>/dev/null)"
if sudo -n true 2>/dev/null; then echo "SUDO_NOPASSWD=yes"; else echo "SUDO_NOPASSWD=no"; fi
TD=$(command -v tcpdump 2>/dev/null)
if [ -z "$TD" ]; then
    for p in /usr/sbin/tcpdump /sbin/tcpdump /usr/bin/tcpdump; do
        if [ -x "$p" ]; then TD="$p"; break; fi
    done
fi
if [ -n "$TD" ]; then
    echo "VERSION=$("$TD" --version 2>&1 | head -1)"
    # Same sbin fallback as tcpdump above: getcap is installed into /sbin on
    # Debian and Ubuntu, which a non-login SSH session for a non-root user
    # does not have on PATH. Trusting command -v alone reported "getcap is not
    # installed" on hosts where it was installed all along.
    GC=$(command -v getcap 2>/dev/null)
    if [ -z "$GC" ]; then
        for p in /sbin/getcap /usr/sbin/getcap /usr/bin/getcap /bin/getcap \
                 /usr/local/sbin/getcap /usr/local/bin/getcap; do
            if [ -x "$p" ]; then GC="$p"; break; fi
        done
    fi
    if [ -n "$GC" ]; then
        echo "CAPS=$("$GC" "$TD" 2>/dev/null)"
    else
        echo "CAPS_UNAVAILABLE=1"
    fi
fi
echo "SELINUX=$(getenforce 2>/dev/null)"
if [ -w /tmp ]; then echo "TMPWRITE=yes"; else echo "TMPWRITE=no"; fi
echo "PROBE_COMPLETE"
"""

# Anything parsed out of the probe came from the remote host, so it is
# untrusted. The discovered path in particular ends up in the tcpdump command,
# and a compromised or hostile host could answer with
# "FOUND=/bin/sh -c curl|sh". Absolute path, no metacharacters, and the binary
# must actually be called tcpdump.
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,255}$")


def _is_safe_tcpdump_path(path: str) -> bool:
    return bool(_SAFE_PATH.fullmatch(path)) and PurePosixPath(path).name == "tcpdump"


def _clean(text: str, limit: int = 200) -> str:
    """Collapse remote output to one printable, bounded line."""
    return "".join(c for c in text if c.isprintable())[:limit].strip()


def parse_prereq_output(raw: str) -> dict:
    """Turn probe output into validated facts. Never trusts a value as given."""
    facts: dict = {
        "complete": "PROBE_COMPLETE" in raw,
        "os_release": {}, "found_paths": [], "uid": None, "groups": [],
        "on_path": "", "tcpdump_path": "", "version": "", "caps": "",
        "caps_unavailable": False, "sudo_present": False, "sudo_nopasswd": False,
        "selinux": "", "tmp_writable": None, "path_env": "",
    }
    in_osrel = False
    for line in raw.splitlines():
        line = line.rstrip()
        if line == "OSREL_BEGIN":
            in_osrel = True
            continue
        if line == "OSREL_END":
            in_osrel = False
            continue
        if in_osrel:
            if "=" in line:
                k, _, v = line.partition("=")
                facts["os_release"][_clean(k, 40)] = _clean(v.strip('"'), 80)
            continue
        key, _, value = line.partition("=")
        value = _clean(value)
        if key == "UID" and value.isdigit():
            facts["uid"] = int(value)
        elif key == "USERGROUPS":
            facts["groups"] = [_clean(g, 40) for g in value.split()][:40]
        elif key == "PATHVAL":
            facts["path_env"] = _clean(value, 400)
        elif key == "ONPATH" and _is_safe_tcpdump_path(value):
            facts["on_path"] = value
        elif key == "FOUND" and _is_safe_tcpdump_path(value):
            if value not in facts["found_paths"]:
                facts["found_paths"].append(value)
        elif key == "SUDO":
            facts["sudo_present"] = bool(value)
        elif key == "SUDO_NOPASSWD":
            facts["sudo_nopasswd"] = value == "yes"
        elif key == "VERSION":
            facts["version"] = value
        elif key == "CAPS":
            facts["caps"] = value
        elif key == "CAPS_UNAVAILABLE":
            facts["caps_unavailable"] = True
        elif key == "SELINUX":
            facts["selinux"] = value
        elif key == "TMPWRITE":
            facts["tmp_writable"] = value == "yes"

    # Prefer whatever the shell itself resolves; fall back to the scan. Either
    # way the value has already been through _is_safe_tcpdump_path.
    facts["tcpdump_path"] = facts["on_path"] or (facts["found_paths"][0] if facts["found_paths"] else "")
    return facts


# Distro identity is used for exactly one thing: rendering the right install
# command as *text*. It never decides behaviour -- behaviour comes from the
# probe, because a template encodes a guess that goes stale while a probe reads
# the truth off the host.
_INSTALL_HINTS = {
    ("debian", "ubuntu", "raspbian", "linuxmint", "pop", "devuan"): "sudo apt-get install {package}",
    ("rhel", "centos", "rocky", "almalinux", "fedora", "ol"): "sudo dnf install {package}",
    ("opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled"): "sudo zypper install {package}",
    ("alpine",): "sudo apk add {package}",
    ("arch", "manjaro", "endeavouros"): "sudo pacman -S {package}",
    ("freebsd",): "sudo pkg install {package}",
}

# getcap ships under a different name per family, unlike tcpdump. FreeBSD has no
# Linux file capabilities at all, so there is nothing there to suggest.
_GETCAP_PACKAGES = {
    ("debian", "ubuntu", "raspbian", "linuxmint", "pop", "devuan"): "libcap2-bin",
    ("rhel", "centos", "rocky", "almalinux", "fedora", "ol"): "libcap",
    ("opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled"): "libcap-progs",
    ("alpine",): "libcap",
    ("arch", "manjaro", "endeavouros"): "libcap",
    ("freebsd",): "",
}


def _by_os_family(os_release: dict, table: dict):
    ids = []
    for key in ("ID", "ID_LIKE"):
        ids += os_release.get(key, "").lower().split()
    for names, value in table.items():
        if any(i in names for i in ids):
            return value
    return None


def install_hint(os_release: dict, package: str = "tcpdump") -> str:
    command = _by_os_family(os_release, _INSTALL_HINTS)
    if command:
        return command.format(package=package)
    return f"install {package} using this host's package manager"


def getcap_install_hint(os_release: dict) -> str:
    """How to get getcap on this host, or "" where the concept doesn't apply."""
    package = _by_os_family(os_release, _GETCAP_PACKAGES)
    if package is None:
        return "install the package providing getcap using this host's package manager"
    if not package:
        return ""
    return install_hint(os_release, package)


def evaluate_prereqs(facts: dict, use_sudo: bool, username: str = "") -> list[dict]:
    """One entry per check: status ok | warn | fail, plus what to run on a miss.

    Remediation is always text for the operator. Nothing here executes it.
    """
    checks: list[dict] = []

    def add(name, status, detail, fix=""):
        checks.append({"name": name, "status": status, "detail": detail, "fix": fix})

    if not facts["complete"]:
        add("Probe completed", "fail",
            "The probe did not finish; the SSH session ended early or the shell rejected it.")
        return checks

    os_name = facts["os_release"].get("PRETTY_NAME") or facts["os_release"].get("NAME") or "unknown"
    add("Operating system", "ok", os_name)

    # tcpdump present
    path = facts["tcpdump_path"]
    if path:
        add("tcpdump installed", "ok", f"{path}" + (f" — {facts['version']}" if facts["version"] else ""))
    else:
        add("tcpdump installed", "fail", "Not found on PATH or in the usual sbin directories.",
            install_hint(facts["os_release"]))
        return checks

    # On PATH, or only reachable absolutely. Not fatal: captures use the
    # absolute path precisely because non-login SSH sessions often drop
    # /usr/sbin from PATH for non-root users.
    if facts["on_path"]:
        add("tcpdump on the SSH PATH", "ok", "Resolved by the shell without a full path.")
    else:
        add("tcpdump on the SSH PATH", "warn",
            f"Installed at {path}, but not on this SSH session's PATH "
            f"({facts['path_env'] or 'unknown'}). Captures will use the full path, so this is "
            f"informational — but a plain `tcpdump` command would fail here.")

    # Privilege to capture: root, file capabilities, or passwordless sudo.
    uid, groups = facts["uid"], facts["groups"]
    caps = facts["caps"]
    has_caps = "cap_net_raw" in caps.lower()
    sudo_group = next((g for g in groups if g in ("sudo", "wheel", "admin")), "")

    if uid == 0:
        add("Capture privilege", "ok", "Connecting as root.")
    elif has_caps:
        add("Capture privilege", "ok", f"File capabilities set on tcpdump ({caps}) — no sudo needed.")
    elif use_sudo and facts["sudo_nopasswd"]:
        add("Capture privilege", "ok", "Passwordless sudo works for this user.")
    elif use_sudo and facts["sudo_present"]:
        add("Capture privilege", "fail",
            "This server is set to use sudo, but `sudo -n` failed — sudo is installed and is "
            "demanding a password. pcap-server runs non-interactively and cannot supply one."
            + (f" This user is in: {sudo_group}." if sudo_group else
               " This user is in none of sudo/wheel/admin."),
            f"Grant passwordless sudo for tcpdump only — not NOPASSWD: ALL:\n"
            f"{_sudoers_remedy(path, username)}\n"
            f"Or avoid sudo altogether:\n"
            f"  sudo setcap cap_net_raw,cap_net_admin+eip {path}")
    elif use_sudo:
        add("Capture privilege", "fail",
            "This server is set to use sudo, but sudo is not installed on the host.",
            f"Either install sudo, or grant the capability directly and untick sudo:\n"
            f"  sudo setcap cap_net_raw,cap_net_admin+eip {path}")
    else:
        add("Capture privilege", "fail",
            "Not root, tcpdump has no cap_net_raw, and this server is not set to use sudo. "
            "tcpdump needs privileges to open a capture device.",
            f"Preferred — grant the capability, no sudo required:\n"
            f"  sudo setcap cap_net_raw,cap_net_admin+eip {path}\n"
            f"Or tick 'Run tcpdump with sudo' on this server and add:\n"
            f"{_sudoers_remedy(path, username)}")

    if facts["caps_unavailable"] and not has_caps and uid != 0:
        getcap_hint = getcap_install_hint(facts["os_release"])
        add("Capability check", "warn",
            "getcap is not installed, so file capabilities could not be read. getcap reports "
            "whether tcpdump already carries cap_net_raw, which would let it capture with no "
            "sudo at all. Captures are unaffected either way -- this check just cannot tell "
            "you which privilege route is already in place.",
            (f"To let this check read capabilities:\n  {getcap_hint}\n"
             f"Only needed for the check itself -- setcap works without it."
             if getcap_hint else ""))

    # Writable /tmp for the intermediate pcap.
    if facts["tmp_writable"] is True:
        add("Temp space writable", "ok", "/tmp is writable — the capture file is staged there.")
    elif facts["tmp_writable"] is False:
        add("Temp space writable", "fail",
            "/tmp is not writable by this user, so tcpdump cannot write the capture.",
            "Make /tmp writable, or give this user a writable directory.")

    selinux = facts["selinux"].lower()
    if selinux == "enforcing":
        add("SELinux", "warn",
            "SELinux is enforcing. This does not usually block tcpdump, but if a capture fails "
            "with no useful error, check `sudo ausearch -m avc -ts recent`.")
    elif selinux in ("permissive", "disabled"):
        add("SELinux", "ok", facts["selinux"])

    return checks


def _sudoers_line(tcpdump_path: str, username: str = "") -> str:
    """The narrowest rule that lets a capture run: this one binary, nothing else.

    Never the blanket `NOPASSWD: ALL` that a search for "passwordless sudo"
    turns up -- that would hand unrestricted root to an account whose key is
    sitting in this app's key store, to buy a privilege only tcpdump needs.
    """
    who = username if username else "%pcap"
    return f"{who} ALL=(root) NOPASSWD: {tcpdump_path}"


def _sudoers_remedy(tcpdump_path: str, username: str = "") -> str:
    """Copy-pasteable steps that install the scoped rule without risking sudo.

    Piped through `visudo`, not written with `tee`: visudo validates before
    installing, and a syntactically broken file dropped into /etc/sudoers.d/
    breaks sudo for everyone on the host until someone with existing root
    fixes it by hand.
    """
    line = _sudoers_line(tcpdump_path, username)
    steps = ""
    if not username:
        steps = "  sudo groupadd -f pcap && sudo usermod -aG pcap <user>\n"
    return (
        steps
        + f"  echo '{line}' | sudo EDITOR='tee' visudo -f /etc/sudoers.d/pcap-server"
    )
