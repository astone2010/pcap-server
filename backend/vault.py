"""Encryption state for captures: key resolution, startup policy, migration.

The policy is fail-closed. A tool that stores packet captures should not quietly
fall back to writing them in the clear, so a missing key stops the app rather
than downgrading it. Running unencrypted remains possible, but only when the
operator says so explicitly.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from backend.crypto import (
    Cryptor,
    CryptoError,
    WrongKey,
    KeySource,
    KeyUnavailable,
    PassphraseKeySource,
    looks_encrypted,
    resolve_key_source,
)
from backend.pcapsource import EncryptedSource, PcapSource, PlaintextSource

logger = logging.getLogger(__name__)

ENCRYPTED_SUFFIX = ".enc"
_SALT_SETTING = "encryption_salt"


class StartupRefused(Exception):
    """Raised when the app must not start: refusing is the safe outcome."""


class CaptureVault:
    def __init__(self, env: dict, db, captures_dir: Path) -> None:
        self._db = db
        self._captures_dir = captures_dir
        self._cryptor: Cryptor | None = None
        self._source: KeySource | None = None
        self.allow_unencrypted = str(env.get("ALLOW_UNENCRYPTED_CAPTURES", "")).lower() in (
            "1", "true", "yes"
        )
        self._resolve(env)

    # --- startup ---

    def _salt(self) -> bytes:
        stored = self._db.get_setting(_SALT_SETTING)
        if stored:
            return bytes.fromhex(stored)
        salt = os.urandom(16)
        self._db.set_setting(_SALT_SETTING, salt.hex())
        return salt

    def _resolve(self, env: dict) -> None:
        self._source = resolve_key_source(env, self._salt)

        if self._source is None:
            if self._has_encrypted_captures():
                raise StartupRefused(
                    "This installation has encrypted captures but no master key is configured.\n"
                    "Starting without the key would make every stored capture unreadable and\n"
                    "would silently write new ones in the clear.\n\n"
                    "Set MASTER_KEY_FILE (see docker-compose.yml) to the key these captures\n"
                    "were encrypted with."
                )
            if not self.allow_unencrypted:
                raise StartupRefused(
                    "No master key is configured, so captures would be stored unencrypted.\n"
                    "A packet capture routinely contains credentials, so this is not the default.\n\n"
                    "To enable encryption (recommended):\n"
                    "  mkdir -p secrets\n"
                    "  openssl rand -base64 32 > secrets/master.key\n"
                    "  chmod 0400 secrets/master.key\n"
                    "then add to docker-compose.yml:\n"
                    "  environment:\n"
                    "    - MASTER_KEY_FILE=/run/secrets/pcap_master_key\n"
                    "  secrets:\n"
                    "    - pcap_master_key\n"
                    "  (and a top-level secrets: block pointing at ./secrets/master.key)\n\n"
                    "KEEP A BACKUP OF THAT KEY. There is no recovery path without it.\n\n"
                    "To run without encryption anyway, set ALLOW_UNENCRYPTED_CAPTURES=true."
                )
            logger.warning(
                "ENCRYPTION DISABLED: captures are being stored unencrypted because "
                "ALLOW_UNENCRYPTED_CAPTURES is set."
            )
            return

        if self._source.interactive:
            logger.info("encryption locked: waiting for an admin passphrase")
            return

        try:
            self._cryptor = Cryptor(self._source.load())
        except (KeyUnavailable, ValueError) as exc:
            raise StartupRefused(
                f"The master key could not be loaded: {exc}\n\n"
                "Refusing to start rather than writing captures in the clear."
            ) from exc

        if self._has_encrypted_captures() and not self._key_opens_existing():
            raise StartupRefused(
                "The configured master key does not open the captures already stored here.\n"
                "This is usually the wrong key file, not corruption.\n\n"
                "Refusing to start, because continuing would leave the existing captures\n"
                "unreadable while new ones were written under a different key."
            )
        logger.info("encryption enabled (key id %s)", self._cryptor.kek_id.hex()[:12])

    def _encrypted_files(self) -> list[Path]:
        if not self._captures_dir.exists():
            return []
        return [p for p in self._captures_dir.glob(f"*{ENCRYPTED_SUFFIX}") if p.is_file()]

    def _plaintext_files(self) -> list[Path]:
        if not self._captures_dir.exists():
            return []
        return [p for p in self._captures_dir.glob("*.pcap") if p.is_file()]

    def _has_encrypted_captures(self) -> bool:
        return bool(self._encrypted_files())

    def _key_opens_existing(self) -> bool:
        """Is the configured key the one these captures were sealed with?

        Only a key mismatch answers no. A corrupt or truncated capture is a
        damaged file, not a wrong key, and must not stop the app from starting --
        so keep looking rather than condemning the key on one bad file.
        """
        damaged: list[str] = []
        for path in self._encrypted_files():
            try:
                next(self._cryptor.open_stream(path), b"")
                return True
            except WrongKey:
                return False
            except CryptoError as exc:
                damaged.append(f"{path.name}: {exc}")
        if damaged:
            # Every encrypted capture is unreadable but none said "wrong key",
            # so these are damaged files. Say so loudly and carry on.
            logger.error(
                "%d encrypted capture(s) could not be read and appear damaged: %s",
                len(damaged), "; ".join(damaged[:5]),
            )
        return True

    # --- state ---

    @property
    def enabled(self) -> bool:
        return self._source is not None

    @property
    def locked(self) -> bool:
        return self.enabled and self._cryptor is None

    @property
    def cryptor(self) -> Cryptor | None:
        return self._cryptor

    @property
    def mode(self) -> str:
        return self._source.name if self._source else "disabled"

    def unlock(self, passphrase: str) -> None:
        if not isinstance(self._source, PassphraseKeySource):
            raise ValueError("this installation does not use passphrase mode")
        kek = self._source.unlock(passphrase)
        candidate = Cryptor(kek)
        previous, self._cryptor = self._cryptor, candidate
        if self._has_encrypted_captures() and not self._key_opens_existing():
            self._cryptor = previous
            self._source.lock()
            raise ValueError("that passphrase does not open the stored captures")

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "locked": self.locked,
            "mode": self.mode,
            "allow_unencrypted": self.allow_unencrypted,
            "key_id": self._cryptor.kek_id.hex()[:12] if self._cryptor else "",
            "encrypted_count": len(self._encrypted_files()),
            "plaintext_count": len(self._plaintext_files()),
        }

    # --- paths and sources ---

    def stored_path(self, capture_id: str) -> Path:
        suffix = ENCRYPTED_SUFFIX if self._cryptor else ""
        return self._captures_dir / f"{capture_id}.pcap{suffix}"

    def source_for(self, path: Path) -> PcapSource:
        """Pick the reader by inspecting the file, not by trusting its name."""
        if looks_encrypted(path):
            if self._cryptor is None:
                raise CryptoError("this capture is encrypted and the vault is locked")
            return EncryptedSource(path, self._cryptor)
        return PlaintextSource(path)

    # --- migration ---

    def migrate_plaintext(self) -> tuple[int, int]:
        """Seal captures written before encryption was switched on.

        Writes the sealed copy alongside, verifies it opens, and only then
        removes the plaintext -- so a crash at any point leaves either the
        original or a verified replacement, never a half-written capture.
        """
        if self._cryptor is None:
            return (0, 0)
        done = failed = 0
        for path in self._plaintext_files():
            target = path.with_suffix(path.suffix + ENCRYPTED_SUFFIX)
            tmp = target.with_suffix(target.suffix + ".partial")
            try:
                self._cryptor.seal_file(path, tmp)
                if self._cryptor.open_bytes(tmp) != path.read_bytes():
                    raise CryptoError("verification mismatch")
                tmp.replace(target)
                path.unlink()
                done += 1
                logger.info("encrypted existing capture %s", path.name)
            except (OSError, CryptoError) as exc:
                failed += 1
                logger.error("could not encrypt %s: %s", path.name, exc)
                tmp.unlink(missing_ok=True)
        if done or failed:
            logger.info("capture migration complete: %d encrypted, %d failed", done, failed)
        return (done, failed)
