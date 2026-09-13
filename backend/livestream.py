"""Reading a capture while it is still being written.

Nothing here changes where a capture is stored. tcpdump keeps writing the
authoritative pcap on the remote host, and it is still fetched and sealed into
the vault when the capture ends, exactly as it was before live streaming
existed. This module is a pass-through alongside that: it copies the growing
remote file down from a byte offset as it grows and holds the bytes in memory
so tshark can be pointed at them, and it is discarded when the capture ends.

Three facts decided the shape, all verified against real tools rather than
assumed:

1. **A partially written SEALED capture cannot be read at all.** Cryptor
   .open_stream raises "truncated: incomplete chunk" at 25%, 50% and 90% of a
   sealed file -- deliberate truncation detection, and an anti-tamper property
   worth more than a live view. So the obvious design, "read the partial file
   the transfer is writing", is not available, and the partial file does not
   exist during the capture anyway. Nothing here weakens that check, and no
   plaintext partial capture is ever written to the data volume.

2. **tshark reads a growing pcap, but complains about a torn tail.** Fed a file
   truncated mid-record it emits every complete packet, warns that the capture
   "appears to have been cut short in the middle of a packet", and exits 2. A
   non-zero exit with a display filter present is how get_packet_list detects a
   filter tshark refused -- so a torn tail would surface as "your filter is
   invalid" on every poll, which is the wrong complaint about the wrong thing.
   LiveBuffer therefore hands tshark only whole records: it walks the record
   headers itself and stops at the last complete one. tshark exits 0, and the
   filter path keeps its meaning.

3. **-U is not in FORBIDDEN_TCPDUMP_FLAGS.** Without it tcpdump buffers, and on
   a quiet link the remote file lags many seconds behind the traffic.

The buffer is capped and, at the cap, FREEZES: the preview stops advancing and
says so, while the capture runs on to its full length. The alternative -- a
rolling window that drops the oldest packets -- was considered and rejected,
because it renumbers frames underneath the packet-detail pane and makes a
packet you just watched scroll past unopenable.
"""

from __future__ import annotations

import logging

from backend.pcapsource import PcapSource

logger = logging.getLogger(__name__)

# libpcap's file header, and the per-packet header inside it.
GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16

# The four classic-pcap magics, mapped to the byte order the rest of the file is
# written in. The two "3c4d" variants only change the units of the timestamp
# fraction (nanoseconds rather than microseconds), which nothing here reads --
# but they change nothing about the lengths, so they are just as walkable.
_MAGICS = {
    b"\xa1\xb2\xc3\xd4": "big",
    b"\xd4\xc3\xb2\xa1": "little",
    b"\xa1\xb2\x3c\x4d": "big",
    b"\x4d\x3c\xb2\xa1": "little",
}

# pcapng, recognised only so it can be refused by name. tcpdump -w writes
# classic pcap, so this should not appear -- and if it ever does, saying which
# format was found beats a live view that silently shows nothing.
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# A record longer than this is not a record. tcpdump's own default snapshot
# length is 262144 and the API caps a requested one at 65535, so a claimed
# length beyond a megabyte means the bytes are not what they say they are.
# Without this bound a corrupt length field parks the walk forever, waiting for
# bytes that are never coming, and the preview stops with no account of why.
MAX_RECORD_BYTES = 1024 * 1024


class BytesSource(PcapSource):
    """A PcapSource over a prefix of an in-memory buffer.

    Takes the buffer itself rather than a copy, plus the length that was
    complete when the source was made. That is safe precisely because
    LiveBuffer only ever APPENDS: bytes below `length` never move or change, so
    a reader walking a prefix cannot be overtaken by a writer adding to the end.
    Copying 16MB per poll to avoid a hazard that cannot occur would be the more
    expensive way to be wrong.
    """

    def __init__(self, data, length: int, chunk_size: int = 256 * 1024) -> None:
        self._data = data
        self._length = length
        self._chunk = chunk_size

    async def chunks(self):
        for start in range(0, self._length, self._chunk):
            yield bytes(self._data[start:min(start + self._chunk, self._length)])

    async def size(self) -> int:
        return self._length


class LiveBuffer:
    """The bytes of a running capture, parsed only as far as they are whole.

    Two lengths matter and they are not the same. `len(self._buf)` is
    everything pulled off the remote host, torn final record included;
    `complete` is how much of that ends on a record boundary. Only the second
    is ever shown to tshark.
    """

    __slots__ = (
        "_buf", "_cap", "_endian", "_scan", "complete",
        "offset", "packets", "frozen", "problem", "read_error",
    )

    def __init__(self, cap_bytes: int) -> None:
        self._buf = bytearray()
        self._cap = cap_bytes
        self._endian: str | None = None
        # Where the next unread record header starts. Kept across feeds so the
        # walk is O(records) over the life of the capture rather than O(records)
        # per poll -- the whole buffer is re-parsed by tshark often enough
        # without this doing it too.
        self._scan = 0
        self.complete = 0
        # How many bytes of the remote file have been consumed. The next read
        # starts here.
        self.offset = 0
        self.packets = 0
        self.frozen = False
        # Set when the stream cannot be followed any further: an unknown format,
        # or a length field that cannot be true. Reported to the operator rather
        # than logged and swallowed, because the symptom otherwise is a live
        # view that simply stops with no explanation.
        self.problem = ""
        # The last remote read that failed, cleared by the next one that works.
        # Distinct from `problem` on purpose: a dropped read is a hiccup the
        # next poll may well recover from, while `problem` is the stream having
        # lost its place for good. Collapsing the two would either make a blip
        # permanent or leave a genuinely stuck preview looking merely slow.
        self.read_error = ""

    @property
    def size(self) -> int:
        return len(self._buf)

    @property
    def capacity(self) -> int:
        return self._cap

    def feed(self, data: bytes) -> None:
        """Append bytes read from the remote file and parse what is now whole.

        The cap is enforced here rather than trusted to the caller. live_poll
        does size its reads to the room left, but a buffer that only stays
        within its cap when asked nicely is not a cap -- and this one bounds
        both the memory held and the bytes tshark re-reads on every poll.
        """
        if not data or self.frozen or self.problem:
            return
        room = self._cap - len(self._buf)
        if len(data) > room:
            data = data[:room]
            # The capture itself is untouched and keeps running; only the
            # preview stops here. A record left torn by the cut is simply never
            # completed, which _walk already handles -- it is held back exactly
            # like the torn tail of any other read.
            self.frozen = True
        if data:
            self._buf.extend(data)
            # Only what was kept. The offset is where the next read would start,
            # and counting bytes that were dropped would make it a lie -- one
            # that matters the moment anything reads from it again.
            self.offset += len(data)
            self._walk()
        if len(self._buf) >= self._cap:
            self.frozen = True

    def source(self) -> BytesSource | None:
        """A source over the whole records held, or None if there are none yet.

        None rather than an empty source: tshark given zero bytes is an error,
        not an empty capture, and the caller has a better answer for "nothing
        has arrived yet" than tshark's complaint about it.
        """
        if self.complete <= GLOBAL_HEADER_LEN:
            return None
        return BytesSource(self._buf, self.complete)

    def _walk(self) -> None:
        if self._endian is None:
            if len(self._buf) < GLOBAL_HEADER_LEN:
                return
            magic = bytes(self._buf[:4])
            endian = _MAGICS.get(magic)
            if endian is None:
                self.problem = (
                    "the capture is not in classic pcap format and cannot be "
                    "previewed live"
                    + (" (it is pcapng)" if magic == _PCAPNG_MAGIC else "")
                    + " -- it will still save and open normally when it finishes"
                )
                return
            self._endian = endian
            self._scan = GLOBAL_HEADER_LEN
            self.complete = GLOBAL_HEADER_LEN

        buf = self._buf
        while True:
            header_end = self._scan + RECORD_HEADER_LEN
            if header_end > len(buf):
                return
            incl_len = int.from_bytes(buf[self._scan + 8:self._scan + 12], self._endian)
            if incl_len > MAX_RECORD_BYTES:
                self.problem = (
                    "the live stream lost its place in the capture file and "
                    "stopped -- the capture is unaffected and will save normally"
                )
                logger.warning(
                    "live buffer: implausible record length %d at offset %d",
                    incl_len, self._scan,
                )
                return
            record_end = header_end + incl_len
            if record_end > len(buf):
                # A torn tail. Everything before it is whole and already
                # counted; the rest of this record arrives on a later poll.
                return
            self._scan = record_end
            self.complete = record_end
            self.packets += 1
