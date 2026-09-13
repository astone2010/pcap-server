"""Handing the sealed key to the TLS library without it ever being a file.

uvicorn and Python's ssl module load a private key from a *path*. The key is
sealed on the data volume, so something has to give them a path to plaintext.
That path is a memfd: an anonymous file that lives only in this process's
memory, reachable as /proc/self/fd/N, with no directory entry on any
filesystem. It is opened, read by OpenSSL, and closed again -- after that the
plaintext key's only home is inside OpenSSL's own context.
"""

from __future__ import annotations

import contextlib
import os
import ssl

# ECDHE only (forward secrecy), AEAD only. TLS 1.3 suites are not governed by
# this string and are all acceptable. uvicorn's own default, "TLSv1", selects
# the TLS 1.0-era CBC/SHA-1 suites for TLS 1.2 clients.
TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"


@contextlib.contextmanager
def key_path_in_memory(key_pem: bytes):
    """A path OpenSSL can open that is backed by nothing but this process's RAM."""
    fd = os.memfd_create("pcap-server-tls-key", os.MFD_CLOEXEC)
    try:
        view = memoryview(key_pem)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        yield f"/proc/self/fd/{fd}"
    finally:
        os.close(fd)


def harden(context: ssl.SSLContext) -> None:
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(TLS12_CIPHERS)
