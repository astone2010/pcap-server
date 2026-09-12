"""Envelope encryption for data at rest.

Design notes, because the threat model decides what this is worth:

A master key (KEK) comes from a source *outside* the data volume. Each encrypted
object gets its own random 256-bit data key (DEK), sealed with AES-256-GCM; the
DEK is wrapped by the KEK and stored in the object's header. Encrypting with a
key that lives beside the data would be theatre, so the KEK never touches the
data volume -- it arrives as a Docker secret, an environment variable, or is
derived from an admin passphrase that exists only in RAM.

What this protects against: someone who reads the data volume, a stolen backup,
a discarded disk, or a copied captures directory. What it does not protect
against: someone who can already execute inside the running container or read
its memory. That is the honest limit of any at-rest scheme whose key must be
present for the app to work unattended.

Format, versioned so it can change without guessing:

    magic        8 bytes   b"PCAPENC\\x01"
    kek_id      16 bytes   SHA-256(KEK)[:16] -- identifies the wrapping key
    dek_nonce   12 bytes   nonce for the wrapped DEK
    wrapped_dek 48 bytes   AES-256-GCM(KEK, DEK), AAD = magic || kek_id
    chunks      repeated   4-byte length | 12-byte nonce | ciphertext+tag
    terminator             a zero-length chunk marks a clean end

Each chunk is sealed with AAD = magic || chunk_index, so chunks cannot be
reordered or spliced between files, and the explicit terminator makes truncation
detectable rather than looking like a short capture.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import struct
from pathlib import Path
from typing import AsyncIterator, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

MAGIC = b"PCAPENC\x01"
KEK_ID_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
DEK_LEN = 32
WRAPPED_DEK_LEN = DEK_LEN + TAG_LEN
HEADER_LEN = len(MAGIC) + KEK_ID_LEN + NONCE_LEN + WRAPPED_DEK_LEN

# 64 KiB plaintext per chunk: small enough that a large capture never has to be
# held in memory, large enough that per-chunk overhead stays under 0.05%.
CHUNK_SIZE = 64 * 1024

ENCRYPTED_SUFFIX = ".enc"


class CryptoError(Exception):
    """Raised when data cannot be decrypted, or was tampered with."""


class NotEncrypted(CryptoError):
    """The file is not in the envelope format -- most likely a legacy plaintext capture."""


class WrongKey(CryptoError):
    """The file was encrypted under a different master key."""


def kek_id(kek: bytes) -> bytes:
    return hashlib.sha256(kek).digest()[:KEK_ID_LEN]


# The KEK is derived once, when an admin unlocks the app, so it can afford a
# cost no per-request operation could. N = 2**17 is ~128 MB and ~100 ms; an
# attacker with the data volume but not the passphrase pays that per guess.
KDF_N = 1 << 17
KDF_R = 8
KDF_P = 1


def derive_kek_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        passphrase.encode(), salt=salt, n=KDF_N, r=KDF_R, p=KDF_P, dklen=32,
        maxmem=(128 * KDF_N * KDF_R * 2),
    )


class Cryptor:
    """Seals and opens objects under one master key."""

    def __init__(self, kek: bytes) -> None:
        if len(kek) != 32:
            raise ValueError("master key must be 32 bytes")
        self._kek = kek
        self._aes = AESGCM(kek)
        self.kek_id = kek_id(kek)

    # --- header ---

    def _wrap_dek(self, dek: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(NONCE_LEN)
        wrapped = self._aes.encrypt(nonce, dek, MAGIC + self.kek_id)
        return nonce, wrapped

    def _build_header(self) -> tuple[bytes, AESGCM]:
        dek = os.urandom(DEK_LEN)
        nonce, wrapped = self._wrap_dek(dek)
        header = MAGIC + self.kek_id + nonce + wrapped
        assert len(header) == HEADER_LEN, len(header)
        return header, AESGCM(dek)

    def _open_header(self, header: bytes) -> AESGCM:
        if len(header) < HEADER_LEN or not header.startswith(MAGIC):
            raise NotEncrypted("missing envelope header")
        offset = len(MAGIC)
        file_kek_id = header[offset:offset + KEK_ID_LEN]
        offset += KEK_ID_LEN
        nonce = header[offset:offset + NONCE_LEN]
        offset += NONCE_LEN
        wrapped = header[offset:offset + WRAPPED_DEK_LEN]

        if not hmac.compare_digest(file_kek_id, self.kek_id):
            raise WrongKey(
                "encrypted under a different master key "
                f"(file {file_kek_id.hex()[:12]}, current {self.kek_id.hex()[:12]})"
            )
        try:
            dek = self._aes.decrypt(nonce, wrapped, MAGIC + file_kek_id)
        except InvalidTag as exc:
            raise WrongKey("master key does not open this file") from exc
        return AESGCM(dek)

    # --- sealing ---

    def seal_chunks(self, chunks: Iterator[bytes]) -> Iterator[bytes]:
        """Yield an encrypted stream from a plaintext chunk iterator."""
        header, dek_aes = self._build_header()
        yield header
        index = 0
        for chunk in chunks:
            if not chunk:
                continue
            yield self._seal_one(dek_aes, index, chunk)
            index += 1
        yield self._seal_one(dek_aes, index, b"")  # clean-end marker

    def _seal_one(self, dek_aes: AESGCM, index: int, plaintext: bytes) -> bytes:
        nonce = os.urandom(NONCE_LEN)
        aad = MAGIC + struct.pack(">Q", index)
        body = dek_aes.encrypt(nonce, plaintext, aad)
        return struct.pack(">I", len(plaintext)) + nonce + body

    def sealer(self) -> "Sealer":
        """Incremental sealing, for callers that receive data a chunk at a time.

        Lets an async producer -- an SFTP read loop, say -- seal as it goes
        without bridging between async and a synchronous generator. AES-GCM over
        a 64 KiB chunk is microseconds with AES-NI, so doing it inline does not
        meaningfully occupy the event loop.
        """
        header, dek_aes = self._build_header()
        return Sealer(self, header, dek_aes)

    def seal_file(self, plaintext_path: Path, out_path: Path) -> int:
        written = 0
        with open(plaintext_path, "rb") as src, open(out_path, "wb") as dst:
            for part in self.seal_chunks(iter(lambda: src.read(CHUNK_SIZE), b"")):
                dst.write(part)
                written += len(part)
        os.chmod(out_path, 0o600)
        return written

    def seal_bytes(self, data: bytes) -> bytes:
        chunks = (data[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE))
        return b"".join(self.seal_chunks(chunks))

    # --- opening ---

    def open_stream(self, path: Path) -> Iterator[bytes]:
        """Yield plaintext chunks. Raises on truncation or tampering."""
        with open(path, "rb") as fh:
            dek_aes = self._open_header(fh.read(HEADER_LEN))
            index = 0
            while True:
                length_raw = fh.read(4)
                if len(length_raw) < 4:
                    raise CryptoError("truncated: stream ended without a terminator")
                (length,) = struct.unpack(">I", length_raw)
                nonce = fh.read(NONCE_LEN)
                body = fh.read(length + TAG_LEN)
                if len(nonce) < NONCE_LEN or len(body) < length + TAG_LEN:
                    raise CryptoError("truncated: incomplete chunk")
                aad = MAGIC + struct.pack(">Q", index)
                try:
                    plaintext = dek_aes.decrypt(nonce, body, aad)
                except InvalidTag as exc:
                    raise CryptoError(f"chunk {index} failed authentication") from exc
                if length == 0:
                    return  # clean end
                yield plaintext
                index += 1

    def open_bytes(self, path: Path) -> bytes:
        return b"".join(self.open_stream(path))


class Sealer:
    """One object's sealing state: header first, then chunks, then finish()."""

    __slots__ = ("_cryptor", "_header", "_dek_aes", "_index", "_finished")

    def __init__(self, cryptor: Cryptor, header: bytes, dek_aes: AESGCM) -> None:
        self._cryptor = cryptor
        self._header = header
        self._dek_aes = dek_aes
        self._index = 0
        self._finished = False

    def header(self) -> bytes:
        return self._header

    def seal(self, plaintext: bytes) -> bytes:
        if self._finished:
            raise CryptoError("sealer already finished")
        if not plaintext:
            return b""
        out = self._cryptor._seal_one(self._dek_aes, self._index, plaintext)
        self._index += 1
        return out

    def finish(self) -> bytes:
        """The zero-length terminator. Without it the object reads as truncated."""
        if self._finished:
            raise CryptoError("sealer already finished")
        self._finished = True
        return self._cryptor._seal_one(self._dek_aes, self._index, b"")


def looks_encrypted(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


# --- key sources ---------------------------------------------------------
#
# The KEK must come from outside the data volume, or encrypting against it is
# pointless. Three sources, in the order they are tried.


class KeyUnavailable(Exception):
    """No master key is available yet. For passphrase mode this is normal until unlocked."""


class KeySource:
    name = "none"
    #: True when the key can only arrive from a human at runtime.
    interactive = False

    def load(self) -> bytes:
        raise KeyUnavailable(self.name)


class FileKeySource(KeySource):
    """A Docker secret, or any file the container can read but the data volume does not hold.

    Preferred over the environment: an env var is visible to anything that can
    read /proc/<pid>/environ or run `docker inspect`.
    """

    name = "file"

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> bytes:
        try:
            raw = self._path.read_bytes().strip()
        except OSError as exc:
            raise KeyUnavailable(f"cannot read master key file {self._path}: {exc}") from exc
        return _coerce_key(raw, str(self._path))


class EnvKeySource(KeySource):
    name = "env"

    def __init__(self, value: str) -> None:
        self._value = value

    def load(self) -> bytes:
        return _coerce_key(self._value.encode(), "PCAP_MASTER_KEY")


class PassphraseKeySource(KeySource):
    """RAM only: derived when an admin unlocks the app, never written anywhere.

    The salt is stored (it is not secret); the passphrase and the derived key
    exist only in this process, so a restart leaves the app locked until someone
    unlocks it again. That is the point of choosing this mode.
    """

    name = "passphrase"
    interactive = True

    def __init__(self, salt: bytes) -> None:
        self._salt = salt
        self._kek: bytes | None = None

    def unlock(self, passphrase: str) -> bytes:
        if len(passphrase) < 12:
            raise ValueError("passphrase must be at least 12 characters")
        self._kek = derive_kek_from_passphrase(passphrase, self._salt)
        return self._kek

    def lock(self) -> None:
        self._kek = None

    @property
    def unlocked(self) -> bool:
        return self._kek is not None

    def load(self) -> bytes:
        if self._kek is None:
            raise KeyUnavailable("locked -- an admin must supply the passphrase")
        return self._kek


def _coerce_key(raw: bytes, origin: str) -> bytes:
    """Accept 32 raw bytes, 64 hex characters, or base64 -- whatever the operator generated."""
    import base64
    import binascii

    if len(raw) == 32:
        return raw
    text = raw.decode("ascii", errors="ignore").strip()
    if len(text) == 64:
        try:
            return binascii.unhexlify(text)
        except binascii.Error:
            pass
    try:
        decoded = base64.b64decode(text, validate=True)
        if len(decoded) == 32:
            return decoded
    except (binascii.Error, ValueError):
        pass
    raise KeyUnavailable(
        f"master key from {origin} is not a 32-byte key "
        "(expected 32 raw bytes, 64 hex characters, or base64 of 32 bytes). "
        "Generate one with: openssl rand -base64 32"
    )


def resolve_key_source(env: dict, salt_provider) -> KeySource | None:
    """Pick a source from the environment. None means no key was configured."""
    mode = env.get("ENCRYPTION_MODE", "").strip().lower()
    if mode == "passphrase":
        return PassphraseKeySource(salt_provider())

    key_file = env.get("MASTER_KEY_FILE", "").strip()
    if key_file:
        return FileKeySource(Path(key_file))

    env_key = env.get("PCAP_MASTER_KEY", "").strip()
    if env_key:
        return EnvKeySource(env_key)

    return None


def generate_key_b64() -> str:
    import base64
    return base64.b64encode(secrets.token_bytes(32)).decode()
