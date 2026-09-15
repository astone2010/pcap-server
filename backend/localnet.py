"""Detecting when a capture target is the machine pcap-server itself runs on.

Capturing an interface that carries pcap-server's own traffic records its own
web session. Over plain HTTP that recovers the admin password verbatim from the
resulting pcap, along with session cookies and TOTP codes -- and the capture is
then stored and browsable in the UI. So the target is checked before a server
can be added.

What can actually be detected from inside a container, in decreasing certainty:

  * loopback, and any address the container itself holds -- unambiguous
  * the default gateway, which on a Docker bridge network IS the host
  * the names Docker publishes for the host (host.docker.internal and friends)

What no address check can detect: the host's LAN address, when the container
sits behind a bridge and has never been told what the host is called. `docker
run --add-host` or an extra_hosts entry makes that resolvable, and the check
picks it up when it is -- but the address a person actually types for their own
Docker host looks like any other target from in here.

That is what `describe_if_same_kernel` is for, and it is the strong check.
Containers share the host's kernel, so `/proc/sys/kernel/random/boot_id` inside
this container is the *host's* boot id. A target that reports the same value is
running on this kernel: it is this machine, whatever address was used to reach
it. Network topology does not enter into it, so LAN addresses, aliases, VPN
addresses and macvlan are all covered by one comparison. It costs a single
world-readable file read over a connection that is already open.

It is a POSITIVE identification test and is deliberately not treated as
anything more. A target that reports no boot id -- a BSD host, a masked /proc --
has proved nothing either way, and refusing it would break legitimate targets
for no security gain. Absence of proof is not proof of non-locality, so the
address checks still apply underneath and the module says what it found rather
than claiming more than it knows.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

# Names Docker and friends publish for "the machine hosting this container".
HOST_ALIASES = frozenset({
    "localhost",
    "host.docker.internal",
    "gateway.docker.internal",
    "host.containers.internal",  # Podman
    "host.lima.internal",
})

_RESOLVE_TIMEOUT = 3.0

# The kernel's own boot id, shared by every container running on it.
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")

# A boot id is a UUID and nothing else. The remote half of the comparison comes
# off a target host, so it is validated into shape before it is compared or
# logged rather than being trusted as whatever arrived.
_BOOT_ID_RE = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)

# Long enough for a UUID and a newline, short enough that a target answering
# with a stream of bytes cannot make us hold any of it.
BOOT_ID_MAX_CHARS = 64


class SelfCaptureRefused(Exception):
    """A capture target was proven to be the machine pcap-server runs on."""


def normalise_boot_id(raw: str) -> str:
    """A well-formed boot id from whatever the host said, or "" if it is not one."""
    if not raw:
        return ""
    candidate = raw[:BOOT_ID_MAX_CHARS].strip().lower()
    return candidate if _BOOT_ID_RE.match(candidate) else ""


def own_boot_id() -> str:
    """This kernel's boot id, or "" where /proc does not carry one.

    Read on each call rather than cached: it is one small file, and a cached
    empty string from an early call would disable the check for the life of the
    process.
    """
    try:
        return normalise_boot_id(BOOT_ID_PATH.read_text())
    except OSError:
        logger.debug("could not read %s", BOOT_ID_PATH, exc_info=True)
        return ""


def describe_if_same_kernel(remote_boot_id: str) -> str:
    """Return why a target is this machine, or "" when it is not (or unknown).

    Unknown covers both halves: a target that reported nothing usable, and a
    container whose own /proc is virtualised. Neither is evidence of anything,
    so neither refuses.
    """
    remote = normalise_boot_id(remote_boot_id)
    if not remote:
        return ""
    mine = own_boot_id()
    if not mine:
        return ""
    if remote != mine:
        return ""
    return (
        "the target reports the same kernel boot id as pcap-server itself, so it "
        "is the machine this container is running on"
    )


def _default_gateways() -> set[str]:
    """The next hop out of this container: on a bridge network, the host."""
    gateways: set[str] = set()

    route = Path("/proc/net/route")
    if route.exists():
        try:
            for line in route.read_text().splitlines()[1:]:
                fields = line.split()
                # destination 00000000 marks the default route
                if len(fields) > 2 and fields[1] == "00000000" and fields[2] != "00000000":
                    packed = struct.pack("<L", int(fields[2], 16))
                    gateways.add(socket.inet_ntoa(packed))
        except (OSError, ValueError, struct.error):
            logger.debug("could not read IPv4 default route", exc_info=True)

    route6 = Path("/proc/net/ipv6_route")
    if route6.exists():
        try:
            for line in route6.read_text().splitlines():
                fields = line.split()
                # a ::/0 destination with a non-zero next hop
                if len(fields) > 4 and fields[1] == "00" and fields[4] != "0" * 32:
                    raw = bytes.fromhex(fields[4])
                    gateways.add(str(ipaddress.IPv6Address(raw)))
        except (OSError, ValueError):
            logger.debug("could not read IPv6 default route", exc_info=True)

    return gateways


def _own_addresses() -> set[str]:
    """Every address this container answers on, best effort."""
    addrs: set[str] = {"127.0.0.1", "::1", "0.0.0.0", "::"}

    # The address used to reach the outside world. connect() on UDP assigns a
    # local address without sending anything.
    for family, probe in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        sock = None
        try:
            # A host without IPv6 raises on socket(), not on connect().
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.connect((probe, 9))
            addrs.add(sock.getsockname()[0].split("%")[0])
        except OSError:
            pass
        finally:
            if sock is not None:
                sock.close()

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addrs.add(info[4][0].split("%")[0])
    except (OSError, socket.gaierror):
        logger.debug("could not resolve own hostname", exc_info=True)

    return addrs


def _declared_host_addresses() -> set[str]:
    """Addresses the operator has told us belong to the host, via HOST_ADDRESSES.

    The one answer to the gap this module's docstring describes at length: a
    bridged container cannot see its host's LAN address, and that address is
    exactly what a person types when they mean their own Docker host. Every
    other way of catching it needs a connection -- the boot-id check needs one
    by definition -- so this is the only check that works with no connection,
    no trusted host keys and no reachable target at all.

    Read from the environment on each call rather than captured at import, so
    the value can be changed without a code path caring when it was set.
    Anything that is not an IP address is dropped with a warning rather than
    quietly ignored: a typo here silently removes a protection the operator
    believes they turned on.
    """
    addresses: set[str] = set()
    for entry in os.environ.get("HOST_ADDRESSES", "").replace(";", ",").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            addresses.add(str(ipaddress.ip_address(entry)))
        except ValueError:
            logger.warning(
                "HOST_ADDRESSES entry %r is not an IP address and will be ignored", entry
            )
    return addresses


def local_addresses() -> set[str]:
    """Addresses that mean 'this machine' or 'the machine hosting it'."""
    return _own_addresses() | _default_gateways() | _declared_host_addresses()


def resolve(hostname: str) -> set[str]:
    """Every address a target name resolves to. Empty when it cannot be resolved."""
    hostname = hostname.strip()
    if not hostname:
        return set()
    try:
        ipaddress.ip_address(hostname)
        return {hostname}
    except ValueError:
        pass

    original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_RESOLVE_TIMEOUT)
    try:
        return {info[4][0].split("%")[0] for info in socket.getaddrinfo(hostname, None)}
    except (OSError, socket.gaierror):
        # Unresolvable is not evidence of anything -- do not block on it.
        return set()
    finally:
        socket.setdefaulttimeout(original)


def describe_if_local(hostname: str) -> str:
    """Return why a target is this machine, or "" when it is not (or unknown)."""
    name = hostname.strip().lower().rstrip(".")
    if name in HOST_ALIASES:
        return f"{hostname!r} is a name for the machine pcap-server is running on"

    targets = resolve(hostname)
    if not targets:
        return ""

    loopback: set[str] = set()
    for addr in targets:
        try:
            if ipaddress.ip_address(addr).is_loopback:
                loopback.add(addr)
        except ValueError:
            continue
    if loopback:
        return f"{hostname!r} resolves to the loopback address {sorted(loopback)[0]}"

    own = _own_addresses()
    overlap = targets & own
    if overlap:
        return (
            f"{hostname!r} resolves to {sorted(overlap)[0]}, which is an address "
            "pcap-server itself answers on"
        )

    # Checked before the gateway, and phrased so it names HOST_ADDRESSES: an
    # operator who set this wants to know it is what refused the target, and an
    # operator who set it wrongly has no other way to find out.
    declared = _declared_host_addresses() & targets
    if declared:
        return (
            f"{hostname!r} resolves to {sorted(declared)[0]}, which HOST_ADDRESSES "
            "names as an address of the machine pcap-server runs on"
        )

    gateways = _default_gateways()
    gw_overlap = targets & gateways
    if gw_overlap:
        return (
            f"{hostname!r} resolves to {sorted(gw_overlap)[0]}, this container's default "
            "gateway -- on a Docker bridge network that is the host machine"
        )

    return ""


SELF_CAPTURE_EXPLANATION = (
    "Capturing from the machine that runs pcap-server records pcap-server's own "
    "traffic. Your sign-in would be written into the capture -- over plain HTTP that "
    "means your password in cleartext, and on any connection your session cookie and "
    "TOTP code -- and the capture is then stored and readable from this UI. On a Docker "
    "host, capturing the 'any' interface also sweeps the bridge interfaces, so every "
    "other container's traffic is recorded too. Add a different machine as the capture "
    "target, and run captures of this host from somewhere else."
)
