"""How a capture's bytes reach the tools, without ever becoming a plaintext file.

Both sources yield chunks. An encrypted capture is decrypted in flight and
handed to tshark on stdin, so the only plaintext that exists is the few kilobytes
in transit between this process and the tool -- never a file another process
could open, and never anything on the data volume.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import AsyncIterator

from backend.crypto import CHUNK_SIZE, Cryptor


class PcapSource:
    async def chunks(self) -> AsyncIterator[bytes]:
        raise NotImplementedError
        yield b""  # pragma: no cover

    async def size(self) -> int:
        raise NotImplementedError


class PlaintextSource(PcapSource):
    """A capture written before encryption was enabled."""

    def __init__(self, path: Path) -> None:
        self.path = path

    async def chunks(self) -> AsyncIterator[bytes]:
        with open(self.path, "rb") as fh:
            while True:
                chunk = await asyncio.to_thread(fh.read, CHUNK_SIZE)
                if not chunk:
                    return
                yield chunk

    async def size(self) -> int:
        return self.path.stat().st_size


class BytesSource(PcapSource):
    """A PcapSource over a prefix of an in-memory buffer.

    Takes the buffer itself rather than a copy, so a caller streaming bytes
    into a growing bytearray can hand this a `length` short of the buffer's
    current size and read a stable prefix while the rest keeps arriving.
    """

    def __init__(self, data, length: int, chunk_size: int = 256 * 1024) -> None:
        self._data = data
        self._length = length
        self._chunk = chunk_size

    async def chunks(self) -> AsyncIterator[bytes]:
        for start in range(0, self._length, self._chunk):
            yield bytes(self._data[start:min(start + self._chunk, self._length)])

    async def size(self) -> int:
        return self._length


class EncryptedSource(PcapSource):
    """Decrypts in flight. Reading and decryption run off the event loop."""

    def __init__(self, path: Path, cryptor: Cryptor) -> None:
        self.path = path
        self._cryptor = cryptor

    async def chunks(self) -> AsyncIterator[bytes]:
        # The generator is synchronous and CPU-bound; step it in a worker thread
        # so decryption never stalls the event loop.
        it = self._cryptor.open_stream(self.path)
        sentinel = object()
        while True:
            chunk = await asyncio.to_thread(next, it, sentinel)
            if chunk is sentinel:
                return
            yield chunk

    async def size(self) -> int:
        total = 0
        async for chunk in self.chunks():
            total += len(chunk)
        return total
