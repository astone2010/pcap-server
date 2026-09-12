"""Tests for backend.crypto -- the envelope format is the whole security
boundary for data at rest, so these assert the format's guarantees directly
rather than just "encrypt then decrypt gives the input back"."""

from __future__ import annotations

import base64
import os

import pytest

from backend import crypto


KEK_A = b"\x11" * 32
KEK_B = b"\x22" * 32


def cryptor(kek: bytes = KEK_A) -> crypto.Cryptor:
    return crypto.Cryptor(kek)


# --- envelope round-trip ---------------------------------------------------


def test_seal_open_round_trip_bytes(tmp_path):
    c = cryptor()
    data = b"hello capture bytes" * 100
    sealed = c.seal_bytes(data)
    assert sealed.startswith(crypto.MAGIC)

    path = tmp_path / "sealed.enc"
    path.write_bytes(sealed)
    assert c.open_bytes(path) == data


def test_seal_open_round_trip_via_file(tmp_path):
    c = cryptor()
    plaintext_path = tmp_path / "plain.bin"
    sealed_path = tmp_path / "sealed.enc"
    data = os.urandom(200_000)
    plaintext_path.write_bytes(data)

    c.seal_file(plaintext_path, sealed_path)
    assert crypto.looks_encrypted(sealed_path)
    assert c.open_bytes(sealed_path) == data


def test_seal_empty_input_still_round_trips(tmp_path):
    c = cryptor()
    sealed = c.seal_bytes(b"")
    path = tmp_path / "empty.enc"
    path.write_bytes(sealed)
    assert c.open_bytes(path) == b""


def test_seal_file_sets_restrictive_permissions(tmp_path):
    c = cryptor()
    src = tmp_path / "p"
    dst = tmp_path / "d.enc"
    src.write_bytes(b"secret")
    c.seal_file(src, dst)
    mode = dst.stat().st_mode & 0o777
    assert mode == 0o600


# --- Sealer: header/seal/finish --------------------------------------------


def test_sealer_produces_valid_stream(tmp_path):
    c = cryptor()
    sealer = c.sealer()
    parts = [sealer.header()]
    parts.append(sealer.seal(b"chunk one"))
    parts.append(sealer.seal(b"chunk two"))
    parts.append(sealer.finish())

    path = tmp_path / "incremental.enc"
    path.write_bytes(b"".join(parts))
    assert c.open_bytes(path) == b"chunk onechunk two"


def test_sealer_seal_with_empty_bytes_is_noop():
    c = cryptor()
    sealer = c.sealer()
    sealer.header()
    assert sealer.seal(b"") == b""


def test_sealer_finish_twice_raises():
    c = cryptor()
    sealer = c.sealer()
    sealer.header()
    sealer.finish()
    with pytest.raises(crypto.CryptoError):
        sealer.finish()


def test_sealer_seal_after_finish_raises():
    c = cryptor()
    sealer = c.sealer()
    sealer.header()
    sealer.finish()
    with pytest.raises(crypto.CryptoError):
        sealer.seal(b"too late")


# --- WrongKey ---------------------------------------------------------------


def test_open_with_foreign_kek_id_raises_wrong_key(tmp_path):
    sealed = cryptor(KEK_A).seal_bytes(b"payload")
    path = tmp_path / "a.enc"
    path.write_bytes(sealed)

    with pytest.raises(crypto.WrongKey):
        cryptor(KEK_B).open_bytes(path)


def test_open_with_bad_wrap_tag_raises_wrong_key(tmp_path):
    """Same kek_id (so the mismatch path above isn't what's hit), but the
    wrapped-DEK ciphertext/tag is corrupted -- must still surface as WrongKey,
    not a generic CryptoError, since the header decrypt failure and a genuine
    key mismatch are indistinguishable to an operator and both mean 'this key
    does not open this file'."""
    c = cryptor()
    sealed = bytearray(c.seal_bytes(b"payload"))
    # last byte of the wrapped DEK, inside the header, before any chunks
    corrupt_index = crypto.HEADER_LEN - 1
    sealed[corrupt_index] ^= 0xFF
    path = tmp_path / "corrupt.enc"
    path.write_bytes(bytes(sealed))

    with pytest.raises(crypto.WrongKey):
        c.open_bytes(path)


# --- CryptoError: truncation and splicing -----------------------------------


def test_missing_terminator_raises_crypto_error(tmp_path):
    c = cryptor()
    sealer = c.sealer()
    data = sealer.header() + sealer.seal(b"partial chunk, then nothing")
    path = tmp_path / "truncated.enc"
    path.write_bytes(data)  # no finish() -- no terminator chunk

    with pytest.raises(crypto.CryptoError):
        c.open_bytes(path)


def test_truncated_mid_chunk_raises_crypto_error(tmp_path):
    c = cryptor()
    full = c.seal_bytes(b"some plaintext long enough to matter")
    path = tmp_path / "cut.enc"
    path.write_bytes(full[: len(full) - 5])

    with pytest.raises(crypto.CryptoError):
        c.open_bytes(path)


def test_spliced_chunks_between_files_fail_authentication(tmp_path):
    """AAD is MAGIC || chunk_index, not tied to a particular file, so this
    proves the *index* binding matters: taking chunk 0 from one sealed object
    and appending it into another (both index 0, both same DEK-independent
    header format) must not decrypt as if it belonged there once the indices
    disagree with what was actually sealed at that position."""
    c = cryptor()

    sealer1 = c.sealer()
    header1 = sealer1.header()
    chunk1_0 = sealer1.seal(b"AAAA")
    chunk1_1 = sealer1.seal(b"BBBB")
    finish1 = sealer1.finish()

    sealer2 = c.sealer()
    header2 = sealer2.header()
    chunk2_0 = sealer2.seal(b"CCCC")
    finish2 = sealer2.finish()

    # Splice: file2's header, but chunk index 1 from file1 spliced in at
    # position 0 (where file2 expects index 0) -- must fail, not decrypt
    # as garbage-but-valid.
    spliced = header2 + chunk1_1 + finish2
    path = tmp_path / "spliced.enc"
    path.write_bytes(spliced)

    with pytest.raises(crypto.CryptoError):
        c.open_bytes(path)

    # sanity: the untouched files still open fine under the same key
    ok_path = tmp_path / "ok1.enc"
    ok_path.write_bytes(header1 + chunk1_0 + chunk1_1 + finish1)
    assert c.open_bytes(ok_path) == b"AAAABBBB"


def test_not_encrypted_raises_not_encrypted(tmp_path):
    path = tmp_path / "plain.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1not really an envelope")
    with pytest.raises(crypto.NotEncrypted):
        cryptor().open_bytes(path)


def test_looks_encrypted_false_for_plaintext(tmp_path):
    path = tmp_path / "plain.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1")
    assert crypto.looks_encrypted(path) is False


def test_looks_encrypted_false_for_missing_file(tmp_path):
    assert crypto.looks_encrypted(tmp_path / "does-not-exist") is False


# --- _coerce_key -------------------------------------------------------------


def test_coerce_key_accepts_32_raw_bytes():
    raw = b"\x01" * 32
    assert crypto._coerce_key(raw, "test") == raw


def test_coerce_key_accepts_hex():
    raw = bytes(range(32))
    hex_text = raw.hex().encode()
    assert len(hex_text) == 64
    assert crypto._coerce_key(hex_text, "test") == raw


def test_coerce_key_accepts_base64():
    raw = bytes(range(32))
    b64_text = base64.b64encode(raw)
    assert crypto._coerce_key(b64_text, "test") == raw


@pytest.mark.parametrize(
    "bad",
    [
        b"too short",
        b"\x01" * 31,
        b"\x01" * 33,
        b"z" * 64,  # right length, not valid hex
        base64.b64encode(b"\x01" * 16),  # valid base64, wrong decoded length
        b"",
    ],
)
def test_coerce_key_rejects_invalid_input(bad):
    with pytest.raises(crypto.KeyUnavailable):
        crypto._coerce_key(bad, "test")


# --- KDF cost, pinned so it can't be silently weakened ----------------------


def test_kdf_cost_parameter_is_not_silently_lowered():
    assert crypto.KDF_N == 1 << 17


def test_derive_kek_from_passphrase_deterministic_and_sized():
    salt = b"\x00" * 16
    key1 = crypto.derive_kek_from_passphrase("correct horse battery staple", salt)
    key2 = crypto.derive_kek_from_passphrase("correct horse battery staple", salt)
    assert key1 == key2
    assert len(key1) == 32


def test_derive_kek_from_passphrase_differs_by_salt():
    key1 = crypto.derive_kek_from_passphrase("same passphrase", b"\x00" * 16)
    key2 = crypto.derive_kek_from_passphrase("same passphrase", b"\x01" * 16)
    assert key1 != key2
