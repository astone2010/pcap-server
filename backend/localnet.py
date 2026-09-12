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

What cannot be detected: the host's LAN address, when the container sits behind
a bridge and has never been told what the host is called. `docker run
--add-host` or an extra_hosts entry makes that resolvable, and the check picks
it up when it is. The check is therefore a guard against the common mistakes,
not a proof of non-locality -- so it says what it found rather than claiming
more than it knows.
"""

from __future__ import annotations

import ipaddress
import logging
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


def local_addresses() -> set[str]:
    """Addresses that mean 'this machine' or 'the machine hosting it'."""
    return _own_addresses() | _default_gateways()


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
