"""Tests for sealing SSH private keys at rest.

Before this, an uploaded key sat on the data volume as plaintext forever --
the one secret in this app that grants remote code execution on someone
else's machine, stored with less protection than a packet capture. These
tests cover the same three surfaces backend.vault's capture-sealing already
has tests for: reading (decrypt only when the vault can), writing (seal
before anything touches disk), and migrating pre-existing plaintext keys in
place with the same verify-then-replace safety.
"""

from __future__ import annotations

import asyncio

import asyncssh
import pytest

from backend.crypto import CryptoError, Cryptor
from backend.ssh_manager import SSHManager

KEK_A = b"\x11" * 32


class FakeVault:
    def __init__(self, cryptor: Cryptor | None = None) -> None:
        self.cryptor = cryptor


def generate_key_bytes() -> bytes:
    return asyncssh.generate_private_key("ssh-ed25519").export_private_key()


@pytest.fixture()
def keys_dir(tmp_path):
    d = tmp_path / "ssh-keys"
    d.mkdir()
    return d


# --- _read_key_bytes / _load_client_key -------------------------------------


def test_read_key_bytes_returns_raw_bytes_with_no_vault(keys_dir):
    raw = generate_key_bytes()
    path = keys_dir / "plain-key"
    path.write_bytes(raw)

    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=None)
    assert mgr._read_key_bytes(path) == raw


def test_read_key_bytes_decrypts_when_vault_has_a_cryptor(keys_dir):
    raw = generate_key_bytes()
    cryptor = Cryptor(KEK_A)
    path = keys_dir / "sealed-key"
    path.write_bytes(cryptor.seal_bytes(raw))

    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=FakeVault(cryptor))
    assert mgr._read_key_bytes(path) == raw


def test_read_key_bytes_raises_when_sealed_but_vault_absent(keys_dir):
    cryptor = Cryptor(KEK_A)
    path = keys_dir / "sealed-key"
    path.write_bytes(cryptor.seal_bytes(generate_key_bytes()))

    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=None)
    with pytest.raises(CryptoError):
        mgr._read_key_bytes(path)


def test_read_key_bytes_raises_when_sealed_but_vault_locked(keys_dir):
    """Vault present (passphrase mode) but not yet unlocked: .cryptor is None,
    same state a locked CaptureVault is in."""
    cryptor = Cryptor(KEK_A)
    path = keys_dir / "sealed-key"
    path.write_bytes(cryptor.seal_bytes(generate_key_bytes()))

    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=FakeVault(cryptor=None))
    with pytest.raises(CryptoError):
        mgr._read_key_bytes(path)


def test_load_client_key_parses_a_real_key(keys_dir):
    key = asyncssh.generate_private_key("ssh-ed25519")
    path = keys_dir / "real-key"
    path.write_bytes(key.export_private_key())

    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=None)
    loaded = mgr._load_client_key(path)
    assert loaded.get_fingerprint() == key.get_fingerprint()


def test_load_client_key_parses_a_sealed_real_key(keys_dir):
    key = asyncssh.generate_private_key("ecdsa-sha2-nistp256")
    cryptor = Cryptor(KEK_A)
    path = keys_dir / "sealed-real-key"
    path.write_bytes(cryptor.seal_bytes(key.export_private_key()))

    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=FakeVault(cryptor))
    loaded = mgr._load_client_key(path)
    assert loaded.get_fingerprint() == key.get_fingerprint()


# --- _connect(): a locked vault surfaces as ConnectionError, not a crash ----


async def test_connect_translates_locked_vault_into_connection_error(keys_dir):
    """_connect()'s documented failure modes are FileNotFoundError and
    ConnectionError -- every caller (test_connection, list_interfaces, ...)
    already knows how to turn those into an HTTP response. A third,
    undocumented exception type here would silently fall through their
    generic 'except Exception' handlers and lose this specific message."""
    from backend.models import ServerAuth

    cryptor = Cryptor(KEK_A)
    path = keys_dir / "sealed-key"
    path.write_bytes(cryptor.seal_bytes(generate_key_bytes()))

    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=FakeVault(cryptor=None))
    server = ServerAuth(hostname="example.com", username="alice", ssh_key_name="sealed-key")

    with pytest.raises(ConnectionError, match="locked"):
        await mgr._connect(server)


# --- migrate_plaintext_keys(): verify-then-replace --------------------------


def test_migrate_plaintext_keys_noop_when_no_cryptor(keys_dir):
    (keys_dir / "a-key").write_bytes(generate_key_bytes())
    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=None)
    assert mgr.migrate_plaintext_keys() == (0, 0)
    assert (keys_dir / "a-key").exists()


def test_migrate_plaintext_keys_seals_in_place(keys_dir):
    raw = generate_key_bytes()
    (keys_dir / "a-key").write_bytes(raw)
    cryptor = Cryptor(KEK_A)
    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=FakeVault(cryptor))

    done, failed = mgr.migrate_plaintext_keys()

    assert (done, failed) == (1, 0)
    sealed = (keys_dir / "a-key").read_bytes()
    assert sealed != raw
    assert cryptor.open_bytes(keys_dir / "a-key") == raw


def test_migrate_plaintext_keys_skips_gitkeep(keys_dir):
    (keys_dir / ".gitkeep").write_bytes(b"")
    cryptor = Cryptor(KEK_A)
    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=FakeVault(cryptor))

    assert mgr.migrate_plaintext_keys() == (0, 0)
    assert (keys_dir / ".gitkeep").read_bytes() == b""


def test_migrate_plaintext_keys_skips_already_sealed(keys_dir):
    cryptor = Cryptor(KEK_A)
    raw = generate_key_bytes()
    sealed_bytes = cryptor.seal_bytes(raw)
    (keys_dir / "already-sealed").write_bytes(sealed_bytes)
    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=FakeVault(cryptor))

    assert mgr.migrate_plaintext_keys() == (0, 0)
    # untouched byte-for-byte, not re-sealed into a double envelope
    assert (keys_dir / "already-sealed").read_bytes() == sealed_bytes


def test_migrate_plaintext_keys_leaves_original_on_verification_failure(keys_dir, monkeypatch):
    raw = generate_key_bytes()
    (keys_dir / "a-key").write_bytes(raw)
    cryptor = Cryptor(KEK_A)
    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=FakeVault(cryptor))

    monkeypatch.setattr(cryptor, "open_bytes", lambda path: b"not the same bytes")

    done, failed = mgr.migrate_plaintext_keys()

    assert (done, failed) == (0, 1)
    assert (keys_dir / "a-key").read_bytes() == raw
    assert not (keys_dir / "a-key.sealing").exists()


def test_migrate_plaintext_keys_handles_multiple_files(keys_dir):
    raw_a, raw_b = generate_key_bytes(), generate_key_bytes()
    (keys_dir / "key-a").write_bytes(raw_a)
    (keys_dir / "key-b").write_bytes(raw_b)
    cryptor = Cryptor(KEK_A)
    mgr = SSHManager(keys_dir, db=None, data_dir=keys_dir, vault=FakeVault(cryptor))

    assert mgr.migrate_plaintext_keys() == (2, 0)
    assert cryptor.open_bytes(keys_dir / "key-a") == raw_a
    assert cryptor.open_bytes(keys_dir / "key-b") == raw_b


def test_migrate_plaintext_keys_noop_when_dir_missing(tmp_path):
    missing = tmp_path / "does-not-exist"
    cryptor = Cryptor(KEK_A)
    mgr = SSHManager(missing, db=None, data_dir=tmp_path, vault=FakeVault(cryptor))
    assert mgr.migrate_plaintext_keys() == (0, 0)
