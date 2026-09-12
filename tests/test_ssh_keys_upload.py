"""Tests that an uploaded SSH key is sealed before it ever touches disk.

Calls backend.main.upload_ssh_key directly rather than through TestClient:
FastAPI's route decorators return the function unchanged, so it's still a
plain callable, and calling it directly sidesteps the shared, session-wide
`db` singleton entirely (no need to register a real admin user just to
reach this one branch) -- the actual permission check (require_admin) is
main.py's concern and already exercised by main.py's own auth tests.
"""

from __future__ import annotations

from backend import main
from backend.crypto import Cryptor

ADMIN = {"id": "u1", "username": "admin", "is_admin": True, "totp_confirmed": True}


class FakeUploadFile:
    def __init__(self, filename: str, content: bytes) -> None:
        self.filename = filename
        self._content = content

    async def read(self) -> bytes:
        return self._content


async def test_uploaded_key_is_sealed_when_vault_has_a_cryptor():
    assert main.vault.cryptor is not None  # conftest.py configures a master key
    content = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake key material\n-----END OPENSSH PRIVATE KEY-----\n"
    name = "test-upload-key-sealed"
    dest = main.SSH_KEYS_DIR / name
    dest.unlink(missing_ok=True)

    try:
        result = await main.upload_ssh_key(FakeUploadFile(name, content), user=ADMIN)
        assert result == {"ok": True, "name": name}

        on_disk = dest.read_bytes()
        assert on_disk != content
        assert main.vault.cryptor.open_bytes(dest) == content
    finally:
        dest.unlink(missing_ok=True)


async def test_uploaded_key_is_plaintext_when_no_cryptor(monkeypatch):
    monkeypatch.setattr(main.vault, "_cryptor", None)
    content = b"plain key bytes, vault disabled"
    name = "test-upload-key-plain"
    dest = main.SSH_KEYS_DIR / name
    dest.unlink(missing_ok=True)

    try:
        await main.upload_ssh_key(FakeUploadFile(name, content), user=ADMIN)
        assert dest.read_bytes() == content
    finally:
        dest.unlink(missing_ok=True)
