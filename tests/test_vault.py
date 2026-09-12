"""Tests for backend.vault -- the fail-closed startup policy and the key/damage
distinction that keeps a corrupted file from being misdiagnosed as a wrong key
(and vice versa)."""

from __future__ import annotations

import base64

import pytest

from backend import vault
from backend.crypto import HEADER_LEN, CryptoError, Cryptor
from backend.pcapsource import EncryptedSource, PlaintextSource


KEK_A = b"\x11" * 32
KEK_B = b"\x22" * 32


class FakeDB:
    """The only surface CaptureVault touches: get_setting/set_setting."""

    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def get_setting(self, key: str) -> str:
        return self._values.get(key, "")

    def set_setting(self, key: str, value: str) -> None:
        self._values[key] = value


def make_vault(env: dict, captures_dir, db: FakeDB | None = None) -> vault.CaptureVault:
    return vault.CaptureVault(env, db or FakeDB(), captures_dir)


def write_encrypted(captures_dir, name: str, kek: bytes, data: bytes = b"packets") -> None:
    captures_dir.mkdir(parents=True, exist_ok=True)
    path = captures_dir / name
    path.write_bytes(Cryptor(kek).seal_bytes(data))


# --- StartupRefused: no key configured --------------------------------------


def test_refuses_startup_with_no_key_and_no_override(tmp_path):
    with pytest.raises(vault.StartupRefused):
        make_vault({}, tmp_path)


def test_starts_with_no_key_when_explicitly_allowed(tmp_path):
    v = make_vault({"ALLOW_UNENCRYPTED_CAPTURES": "true"}, tmp_path)
    assert v.enabled is False
    assert v.cryptor is None


@pytest.mark.parametrize("truthy", ["1", "true", "True", "yes", "YES"])
def test_allow_unencrypted_accepts_common_truthy_spellings(tmp_path, truthy):
    v = make_vault({"ALLOW_UNENCRYPTED_CAPTURES": truthy}, tmp_path)
    assert v.enabled is False


@pytest.mark.parametrize("falsy", ["0", "false", "no", "", "nope"])
def test_allow_unencrypted_rejects_other_spellings(tmp_path, falsy):
    with pytest.raises(vault.StartupRefused):
        make_vault({"ALLOW_UNENCRYPTED_CAPTURES": falsy}, tmp_path)


def test_refuses_startup_when_encrypted_captures_exist_but_no_key(tmp_path):
    write_encrypted(tmp_path, "old.pcap.enc", KEK_A)
    with pytest.raises(vault.StartupRefused):
        # Even with the override set: existing encrypted captures with no key
        # at all is a stronger refusal than "no key, none exist yet".
        make_vault({"ALLOW_UNENCRYPTED_CAPTURES": "true"}, tmp_path)


# --- WrongKey (refuse) vs. damaged file (start anyway) ----------------------


def _key_env(kek: bytes) -> dict:
    return {"PCAP_MASTER_KEY": base64.b64encode(kek).decode()}


def test_refuses_startup_when_key_does_not_open_existing_captures(tmp_path):
    write_encrypted(tmp_path, "cap.pcap.enc", KEK_A)
    with pytest.raises(vault.StartupRefused):
        make_vault(_key_env(KEK_B), tmp_path)


def test_starts_normally_when_key_matches_existing_captures(tmp_path):
    write_encrypted(tmp_path, "cap.pcap.enc", KEK_A)
    v = make_vault(_key_env(KEK_A), tmp_path)
    assert v.enabled is True
    assert v.cryptor is not None


def test_starts_anyway_when_existing_capture_is_damaged_not_wrong_key(tmp_path):
    """A truncated/corrupted file must not be mistaken for a wrong key --
    _key_opens_existing keeps scanning and only a WrongKey stops it.

    The cut lands inside the first chunk (right after the header) so that
    the very first pull from open_stream raises CryptoError -- truncating
    only the tail would let the first, still-intact chunk decrypt
    successfully and never exercise this path at all."""
    captures_dir = tmp_path
    captures_dir.mkdir(parents=True, exist_ok=True)
    sealed = Cryptor(KEK_A).seal_bytes(b"packets")
    damaged_path = captures_dir / "damaged.pcap.enc"
    damaged_path.write_bytes(sealed[: HEADER_LEN + 5])

    v = make_vault(_key_env(KEK_A), tmp_path)
    assert v.enabled is True
    assert v.cryptor is not None


def test_wrong_key_takes_precedence_even_with_other_damaged_files(tmp_path):
    captures_dir = tmp_path
    captures_dir.mkdir(parents=True, exist_ok=True)
    # one damaged file (cut inside its first chunk, see above), one
    # genuinely wrong-key file
    sealed_a = Cryptor(KEK_A).seal_bytes(b"packets")
    (captures_dir / "damaged.pcap.enc").write_bytes(sealed_a[: HEADER_LEN + 5])
    write_encrypted(captures_dir, "wrongkey.pcap.enc", KEK_A)

    with pytest.raises(vault.StartupRefused):
        make_vault(_key_env(KEK_B), tmp_path)


# --- unlock() (passphrase mode) ---------------------------------------------


def test_unlock_wrong_passphrase_leaves_vault_locked(tmp_path):
    write_encrypted(tmp_path, "cap.pcap.enc", KEK_A)
    db = FakeDB()
    db.set_setting("encryption_salt", (b"\x00" * 16).hex())
    v = make_vault({"ENCRYPTION_MODE": "passphrase"}, tmp_path, db)
    assert v.locked is True

    with pytest.raises(ValueError):
        v.unlock("some passphrase that is at least 12 chars but wrong")
    assert v.locked is True
    assert v.cryptor is None


# --- stored_path -------------------------------------------------------------


def test_stored_path_adds_enc_suffix_when_cryptor_active(tmp_path):
    v = make_vault(_key_env(KEK_A), tmp_path)
    assert v.stored_path("abc123") == tmp_path / "abc123.pcap.enc"


def test_stored_path_has_no_enc_suffix_when_unencrypted(tmp_path):
    v = make_vault({"ALLOW_UNENCRYPTED_CAPTURES": "true"}, tmp_path)
    assert v.stored_path("abc123") == tmp_path / "abc123.pcap"


# --- source_for: inspects magic bytes, not the filename ---------------------


def test_source_for_picks_encrypted_source_by_content(tmp_path):
    v = make_vault(_key_env(KEK_A), tmp_path)
    # deliberately misleading extension: no .enc, but content is sealed
    path = tmp_path / "misnamed.pcap"
    path.write_bytes(Cryptor(KEK_A).seal_bytes(b"packets"))

    source = v.source_for(path)
    assert isinstance(source, EncryptedSource)


def test_source_for_picks_plaintext_source_by_content(tmp_path):
    v = make_vault(_key_env(KEK_A), tmp_path)
    # deliberately misleading extension: .enc, but content is plain
    path = tmp_path / "misnamed.pcap.enc"
    path.write_bytes(b"\xd4\xc3\xb2\xa1not encrypted")

    source = v.source_for(path)
    assert isinstance(source, PlaintextSource)


def test_source_for_raises_when_encrypted_and_vault_locked(tmp_path):
    write_encrypted(tmp_path, "cap.pcap.enc", KEK_A)
    db = FakeDB()
    db.set_setting("encryption_salt", (b"\x00" * 16).hex())
    v = make_vault({"ENCRYPTION_MODE": "passphrase"}, tmp_path, db)
    assert v.locked is True

    path = tmp_path / "cap.pcap.enc"
    with pytest.raises(CryptoError):
        v.source_for(path)


# --- migrate_plaintext: verify-then-unlink ----------------------------------


def test_migrate_plaintext_noop_when_no_cryptor(tmp_path):
    v = make_vault({"ALLOW_UNENCRYPTED_CAPTURES": "true"}, tmp_path)
    (tmp_path / "old.pcap").write_bytes(b"packets")
    assert v.migrate_plaintext() == (0, 0)
    assert (tmp_path / "old.pcap").exists()


def test_migrate_plaintext_seals_and_removes_original(tmp_path):
    v = make_vault(_key_env(KEK_A), tmp_path)
    plain_path = tmp_path / "old.pcap"
    plain_path.write_bytes(b"legacy capture bytes")

    done, failed = v.migrate_plaintext()

    assert (done, failed) == (1, 0)
    assert not plain_path.exists()
    sealed_path = tmp_path / "old.pcap.enc"
    assert sealed_path.exists()
    assert v.cryptor.open_bytes(sealed_path) == b"legacy capture bytes"


def test_migrate_plaintext_leaves_original_on_verification_failure(tmp_path, monkeypatch):
    v = make_vault(_key_env(KEK_A), tmp_path)
    plain_path = tmp_path / "old.pcap"
    plain_path.write_bytes(b"legacy capture bytes")

    # Force the post-seal verification to disagree with the source, simulating
    # a corrupted write: the plaintext must survive and no .enc must be left
    # behind as if migration had succeeded.
    monkeypatch.setattr(v.cryptor, "open_bytes", lambda path: b"not the same bytes")

    done, failed = v.migrate_plaintext()

    assert (done, failed) == (0, 1)
    assert plain_path.exists()
    assert not (tmp_path / "old.pcap.enc").exists()
    assert not (tmp_path / "old.pcap.enc.partial").exists()


def test_migrate_plaintext_handles_multiple_files(tmp_path):
    v = make_vault(_key_env(KEK_A), tmp_path)
    (tmp_path / "a.pcap").write_bytes(b"aaa")
    (tmp_path / "b.pcap").write_bytes(b"bbb")

    done, failed = v.migrate_plaintext()

    assert (done, failed) == (2, 0)
    assert v.cryptor.open_bytes(tmp_path / "a.pcap.enc") == b"aaa"
    assert v.cryptor.open_bytes(tmp_path / "b.pcap.enc") == b"bbb"


# --- status() ----------------------------------------------------------------


def test_status_reports_disabled_mode(tmp_path):
    v = make_vault({"ALLOW_UNENCRYPTED_CAPTURES": "true"}, tmp_path)
    status = v.status()
    assert status["enabled"] is False
    assert status["mode"] == "disabled"
    assert status["locked"] is False


def test_status_reports_enabled_and_key_id(tmp_path):
    v = make_vault(_key_env(KEK_A), tmp_path)
    status = v.status()
    assert status["enabled"] is True
    assert status["locked"] is False
    assert status["mode"] == "env"
    assert status["key_id"] == v.cryptor.kek_id.hex()[:12]


def test_status_counts_encrypted_and_plaintext_files(tmp_path):
    v = make_vault(_key_env(KEK_A), tmp_path)
    write_encrypted(tmp_path, "one.pcap.enc", KEK_A)
    (tmp_path / "two.pcap").write_bytes(b"plain")

    status = v.status()
    assert status["encrypted_count"] == 1
    assert status["plaintext_count"] == 1
