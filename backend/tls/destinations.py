"""Where a provider setting may send lego.

Many DNS providers take an API URL or a server address -- a self-hosted
PowerDNS, an ISPConfig panel, an RFC 2136 nameserver. lego sends the admin's
credentials there, from inside the container, and reports the reply if it
fails. So a URL setting is a way to make the container issue requests.

Private LAN addresses stay allowed: a self-hosted DNS server on the same
network is the ordinary case for these settings, not an abuse of them. What is
refused is the set of destinations that are never a DNS provider and are
exactly what server-side request forgery goes after:

  loopback      the app itself, and anything else listening only inside the
                container -- where a request counts as local
  link-local    169.254.0.0/16 and fe80::/10, which include cloud metadata
                services and the credentials they hand out
  unspecified   0.0.0.0 and ::, which connect to the local host
  multicast

Checked twice: as typed, when the settings are saved, and again after name
resolution immediately before lego runs, so a hostname that resolves to one of
these is caught too.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

# A value is treated as a destination when it is a URL, or when the setting's
# name says it is a host or server address.
_ADDRESS_NAME = re.compile(r"(_HOST|_HOSTNAME|_SERVER|_NAMESERVER|_ADDRESS|_ENDPOINT|_URL)$")
_LOCAL_NAMES = ("localhost", "localhost.localdomain", "metadata.google.internal", "metadata")


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast


def destination_host(name: str, value: str) -> str | None:
    """The host a setting points lego at, or None if it is not a destination."""
    value = value.strip()
    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https"):
            raise ValueError(f"{name} must be an http:// or https:// URL")
        if not parts.hostname:
            raise ValueError(f"{name} has no host in it")
        return parts.hostname
    if not _ADDRESS_NAME.search(name):
        return None
    host = value
    if host.startswith("["):  # [v6]:port
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:  # host:port
        host = host.split(":", 1)[0]
    return host or None


def check_literal(name: str, host: str) -> None:
    """Refuse a forbidden destination that can be seen without a DNS lookup."""
    lowered = host.lower().rstrip(".")
    if lowered in _LOCAL_NAMES or lowered.endswith(".localhost"):
        raise ValueError(f"{name} points at this machine, which is not a DNS provider")
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return
    if _is_forbidden_ip(ip):
        raise ValueError(
            f"{name} points at {host}, a loopback, link-local or unspecified address -- "
            "never a DNS provider"
        )


def check_resolved(name: str, host: str) -> None:
    """Refuse a hostname that resolves to a forbidden address.

    A name that does not resolve is left to lego, which will fail on it with a
    clearer message than this could give.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if _is_forbidden_ip(ip):
            raise ValueError(
                f"{name} ({host}) resolves to {ip}, a loopback, link-local or "
                "unspecified address -- never a DNS provider"
            )


def check(name: str, value: str, *, resolve: bool) -> None:
    host = destination_host(name, value)
    if host is None:
        return
    check_literal(name, host)
    if resolve:
        check_resolved(name, host)
