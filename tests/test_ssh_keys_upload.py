"""Tests that an uploaded SSH key is sealed before it ever touches disk.

Calls backend.main.upload_ssh_key directly rather than through TestClient:
FastAPI's route decorators return the function unchanged, so it's still a
plain callable, and calling it directly sidesteps the shared, session-wide
`db` singleton entirely (no need to register a real admin user just to
reach this one branch) -- the actual permission check (require_admin) is
main.py's concern and already exercised by main.py's own auth tests.
"""

from __future__ import annotations

from pathlib import Path

import asyncssh
import pytest
from fastapi import HTTPException

from backend import main
from backend.models import PastedPrivateKey

ADMIN = {"id": "u1", "username": "admin", "is_admin": True, "totp_confirmed": True}


class FakeUploadFile:
    def __init__(self, filename: str, content: bytes) -> None:
        self.filename = filename
        self._content = content

    async def read(self) -> bytes:
        return self._content


@pytest.fixture()
def real_key() -> bytes:
    """A genuine private key, because the store now parses what it is given.

    These tests used to hand in `b"fake key material"` between BEGIN/END lines,
    which passed only because nothing ever read it -- a key was parsed for the
    first time at connect time, against a host, on a different screen. That is
    precisely the gap _store_ssh_key closes, so the fixture has to be real.
    """
    return asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh")


@pytest.fixture()
def key_dest():
    """Somewhere to write, cleaned up however the test ends."""
    written: list[Path] = []

    def dest_for(name: str) -> Path:
        path = main.SSH_KEYS_DIR / name
        path.unlink(missing_ok=True)
        written.append(path)
        return path

    yield dest_for
    for path in written:
        path.unlink(missing_ok=True)


async def test_uploaded_key_is_sealed_when_vault_has_a_cryptor(real_key, key_dest):
    assert main.vault.cryptor is not None  # conftest.py configures a master key
    name = "test-upload-key-sealed"
    dest = key_dest(name)

    result = await main.upload_ssh_key(FakeUploadFile(name, real_key), user=ADMIN)
    assert result == {"ok": True, "name": name}

    on_disk = dest.read_bytes()
    assert on_disk != real_key
    assert main.vault.cryptor.open_bytes(dest) == real_key


async def test_uploaded_key_is_plaintext_when_no_cryptor(monkeypatch, real_key, key_dest):
    monkeypatch.setattr(main.vault, "_cryptor", None)
    name = "test-upload-key-plain"
    dest = key_dest(name)

    await main.upload_ssh_key(FakeUploadFile(name, real_key), user=ADMIN)
    assert dest.read_bytes() == real_key


# --- pasting, the other way in ----------------------------------------------


async def test_pasted_key_is_stored_exactly_like_an_uploaded_one(real_key, key_dest):
    """Same store, same sealing -- only the transport differs."""
    name = "test-paste-key"
    dest = key_dest(name)

    result = await main.paste_ssh_key(
        PastedPrivateKey(name=name, key=real_key.decode()), user=ADMIN
    )
    assert result == {"ok": True, "name": name}
    assert main.vault.cryptor.open_bytes(dest) == real_key


async def test_pasted_key_with_windows_line_endings_is_normalised(real_key, key_dest):
    """A key copied through a Windows editor arrives with CRLF.

    asyncssh imports it either way -- checked, not assumed -- so this is about
    what lands on disk being the conventional form for any other tool that
    reads it, not about making the connection work.
    """
    name = "test-paste-crlf"
    dest = key_dest(name)

    await main.paste_ssh_key(
        PastedPrivateKey(name=name, key=real_key.decode().replace("\n", "\r\n")),
        user=ADMIN,
    )
    stored = main.vault.cryptor.open_bytes(dest)
    assert b"\r" not in stored
    assert stored == real_key


async def test_pasted_key_without_a_trailing_newline_gets_one(real_key, key_dest):
    name = "test-paste-no-newline"
    dest = key_dest(name)

    await main.paste_ssh_key(
        PastedPrivateKey(name=name, key=real_key.decode().rstrip("\n")), user=ADMIN
    )
    assert main.vault.cryptor.open_bytes(dest).endswith(b"\n")


async def test_pasting_a_public_key_is_refused_by_name(key_dest):
    """The easy paste to get wrong: the two files sit side by side and differ
    by one suffix. It used to be accepted and fail minutes later against a
    host, from a screen that never mentioned the key."""
    pub = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh")
    key_dest("test-paste-public")

    with pytest.raises(HTTPException) as exc:
        await main.paste_ssh_key(
            PastedPrivateKey(name="test-paste-public", key=pub.decode()), user=ADMIN
        )
    assert exc.value.status_code == 400
    assert "public key" in str(exc.value.detail).lower()
    assert not (main.SSH_KEYS_DIR / "test-paste-public").exists()


async def test_pasting_a_passphrase_protected_key_is_refused(key_dest):
    """Nothing in this app can supply a passphrase, so such a key is broken
    here however valid it is elsewhere. Said at the point of pasting."""
    encrypted = asyncssh.generate_private_key("ssh-ed25519").export_private_key(
        "pkcs8-pem", passphrase="hunter2hunter2"
    )
    key_dest("test-paste-encrypted")

    with pytest.raises(HTTPException) as exc:
        await main.paste_ssh_key(
            PastedPrivateKey(name="test-paste-encrypted", key=encrypted.decode()),
            user=ADMIN,
        )
    assert exc.value.status_code == 400
    assert "passphrase" in str(exc.value.detail).lower()
    assert not (main.SSH_KEYS_DIR / "test-paste-encrypted").exists()


async def test_pasting_junk_is_refused(key_dest):
    key_dest("test-paste-junk")
    with pytest.raises(HTTPException) as exc:
        await main.paste_ssh_key(
            PastedPrivateKey(name="test-paste-junk", key="not a key at all"), user=ADMIN
        )
    assert exc.value.status_code == 400
    assert not (main.SSH_KEYS_DIR / "test-paste-junk").exists()


async def test_uploading_junk_is_refused_too(key_dest):
    """The check lives in the shared store, so it covers the older route as
    well -- upload validated the name and the size and never the bytes."""
    key_dest("test-upload-junk")
    with pytest.raises(HTTPException) as exc:
        await main.upload_ssh_key(
            FakeUploadFile("test-upload-junk", b"not a key at all"), user=ADMIN
        )
    assert exc.value.status_code == 400
    assert not (main.SSH_KEYS_DIR / "test-upload-junk").exists()


async def test_pasting_over_an_existing_name_is_refused(real_key, key_dest):
    """Same 409 the upload gives: replacing a key silently would break every
    server using it with nothing said."""
    name = "test-paste-duplicate"
    key_dest(name)
    await main.paste_ssh_key(PastedPrivateKey(name=name, key=real_key.decode()), user=ADMIN)

    with pytest.raises(HTTPException) as exc:
        await main.paste_ssh_key(
            PastedPrivateKey(name=name, key=real_key.decode()), user=ADMIN
        )
    assert exc.value.status_code == 409


async def test_a_stored_pasted_key_is_the_one_asyncssh_loads(real_key, key_dest):
    """End to end: what the paste stored is what a connection would use.

    The sealing means the bytes on disk are not the key, so this is the check
    that the round trip through the vault and back is lossless -- the thing a
    test asserting `dest.read_bytes()` could never see.

    Compared on the PUBLIC half, not by re-exporting the private one: OpenSSH's
    private format embeds a random check value, so exporting the same key twice
    gives different bytes. The public half is what identifies the key to a host,
    and it is deterministic.
    """
    name = "test-paste-loadable"
    key_dest(name)
    await main.paste_ssh_key(PastedPrivateKey(name=name, key=real_key.decode()), user=ADMIN)

    loaded = main.ssh_manager._load_client_key(main.SSH_KEYS_DIR / name)
    original = asyncssh.import_private_key(real_key)
    assert loaded.export_public_key("openssh") == original.export_public_key("openssh")
