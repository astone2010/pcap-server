"""Master key rotation.

The property under test throughout: after a rekey the new key opens exactly
what the old key opened, byte for byte, and nothing is ever left in a state
where neither key works.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from backend.crypto import HEADER_LEN, CryptoError, Cryptor, WrongKey
from backend.rekey import (
    Outcome,
    RekeyRefused,
    rekey_all,
    rekey_file,
)


def a_key() -> bytes:
    return os.urandom(32)


@pytest.fixture()
def dirs(tmp_path):
    caps = tmp_path / "captures"
    keys = tmp_path / "ssh-keys"
    caps.mkdir()
    keys.mkdir()
    return caps, keys


def seal(cryptor: Cryptor, path: Path, plaintext: bytes) -> Path:
    path.write_bytes(cryptor.seal_bytes(plaintext))
    return path


def backdate(path: Path, seconds: int = 60) -> None:
    """Push mtime into the past, clearing the live-write guard.

    Files written by a test are milliseconds old, which is exactly what the
    guard is designed to refuse.
    """
    old = time.time() - seconds
    os.utime(path, (old, old))


def backdate_all(*dirs_: Path) -> None:
    for d in dirs_:
        for p in d.iterdir():
            if p.is_file():
                backdate(p)


# --- the core guarantee ------------------------------------------------------


def test_new_key_opens_the_capture_after_rekey(dirs):
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    plaintext = b"\xd4\xc3\xb2\xa1" + os.urandom(5000)
    path = seal(old, caps / "c1.pcap.enc", plaintext)
    backdate_all(caps)

    out = rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)
    assert out.ok and len(out.rekeyed) == 1

    assert new.open_bytes(path) == plaintext
    # And the old key must no longer open it -- otherwise the rotation achieved
    # nothing, which is the failure mode that matters after a key disclosure.
    with pytest.raises(WrongKey):
        old.open_bytes(path)


def test_only_the_header_is_rewritten(dirs):
    """The whole reason this is cheap: the body is never re-encrypted."""
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    path = seal(old, caps / "c1.pcap.enc", os.urandom(200_000))
    before = path.read_bytes()
    backdate_all(caps)

    rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)
    after = path.read_bytes()

    assert len(after) == len(before)
    assert after[HEADER_LEN:] == before[HEADER_LEN:]
    assert after[:HEADER_LEN] != before[:HEADER_LEN]


def test_a_large_file_is_rekeyed_without_reading_it_all(dirs):
    """Sanity check on size handling: a multi-megabyte body round-trips."""
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    plaintext = os.urandom(3 * 1024 * 1024 + 7)
    path = seal(old, caps / "big.pcap.enc", plaintext)
    backdate_all(caps)

    rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)
    assert new.open_bytes(path) == plaintext


def test_ssh_keys_are_rekeyed_too(dirs):
    """A rotation covering only captures leaves the SSH keys unopenable, and
    startup refuses to continue past that."""
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    key_material = b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----\n"
    seal(old, caps / "c1.pcap.enc", b"pcap")
    key_path = seal(old, keys / "prod-key", key_material)
    backdate_all(caps, keys)

    out = rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)
    assert len(out.rekeyed) == 2
    assert new.open_bytes(key_path) == key_material


def test_file_mode_is_preserved(dirs):
    """An SSH private key is 0600 and must not come back world-readable."""
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    key_path = seal(old, keys / "prod-key", b"secret")
    key_path.chmod(0o600)
    backdate_all(keys)

    rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)
    assert key_path.stat().st_mode & 0o777 == 0o600


# --- dry run -----------------------------------------------------------------


def test_dry_run_writes_nothing(dirs):
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    path = seal(old, caps / "c1.pcap.enc", b"payload")
    before = path.read_bytes()
    backdate_all(caps)

    out = rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=False)

    assert len(out.rekeyed) == 1, "a dry run still reports what it would do"
    assert path.read_bytes() == before
    assert old.open_bytes(path) == b"payload"


# --- resumability and idempotence --------------------------------------------


def test_running_twice_is_a_no_op_the_second_time(dirs):
    """An interrupted run must be safe to repeat, so a file already under the
    new key is 'already', not an error."""
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    path = seal(old, caps / "c1.pcap.enc", b"payload")
    backdate_all(caps)

    rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)
    backdate_all(caps)
    out = rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)

    assert out.ok
    assert out.rekeyed == []
    assert out.already == [path]
    assert new.open_bytes(path) == b"payload"


def test_a_half_finished_run_completes_on_the_second_pass(dirs):
    """The real interrupted case: some files moved, some did not."""
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    done = seal(new, caps / "a.pcap.enc", b"already moved")
    todo = seal(old, caps / "b.pcap.enc", b"still to move")
    backdate_all(caps)

    out = rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)

    assert out.ok
    assert out.already == [done]
    assert out.rekeyed == [todo]
    assert new.open_bytes(todo) == b"still to move"


# --- refusals ----------------------------------------------------------------


def test_same_key_twice_is_refused(dirs):
    caps, keys = dirs
    kek = a_key()
    seal(Cryptor(kek), caps / "c1.pcap.enc", b"x")
    backdate_all(caps)

    with pytest.raises(RekeyRefused, match="same key"):
        rekey_all(Cryptor(kek), Cryptor(kek), captures_dir=caps, ssh_keys_dir=keys, apply=True)


def test_no_sealed_files_is_refused_rather_than_reported_as_success(dirs):
    """An empty run almost always means the directories are wrong, and
    reporting '0 rekeyed, done' would send the operator off to swap the key
    file with nothing rotated."""
    caps, keys = dirs
    with pytest.raises(RekeyRefused, match="no sealed files"):
        rekey_all(Cryptor(a_key()), Cryptor(a_key()),
                  captures_dir=caps, ssh_keys_dir=keys, apply=True)


def test_a_recently_written_file_is_refused(dirs):
    """A capture still being written must not have its header swapped."""
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    seal(old, caps / "live.pcap.enc", b"being written")
    # deliberately not backdated

    with pytest.raises(RekeyRefused, match="last 10 seconds"):
        rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)


def test_the_live_write_guard_names_the_file(dirs):
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    seal(old, caps / "live.pcap.enc", b"x")

    with pytest.raises(RekeyRefused) as exc:
        rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)
    assert "live.pcap.enc" in str(exc.value)


# --- files this routine must not touch ---------------------------------------


def test_a_file_under_neither_key_fails_and_is_left_alone(dirs):
    """A capture from some third key is not this rotation's to move, and
    guessing would destroy it."""
    caps, keys = dirs
    old, new, foreign = Cryptor(a_key()), Cryptor(a_key()), Cryptor(a_key())
    mine = seal(old, caps / "mine.pcap.enc", b"mine")
    theirs = seal(foreign, caps / "theirs.pcap.enc", b"theirs")
    before = theirs.read_bytes()
    backdate_all(caps)

    out = rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)

    assert not out.ok, "a partial rotation must not report success"
    assert out.rekeyed == [mine]
    assert [p for p, _ in out.failed] == [theirs]
    assert theirs.read_bytes() == before
    assert foreign.open_bytes(theirs) == b"theirs", "still opens with its own key"


def test_an_unencrypted_file_is_reported_and_untouched(dirs):
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    plain = caps / "old.pcap.enc"          # named .enc but never sealed
    plain.write_bytes(b"\xd4\xc3\xb2\xa1raw pcap bytes")
    before = plain.read_bytes()
    backdate_all(caps)

    out = rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)

    assert out.ok, "an unsealed file is not a failure, just not ours to move"
    assert out.plaintext == [plain]
    assert plain.read_bytes() == before


# --- crash safety ------------------------------------------------------------


def test_a_crash_mid_write_leaves_the_original_and_no_partial(dirs, monkeypatch):
    caps, keys = dirs
    old, new = Cryptor(a_key()), Cryptor(a_key())
    path = seal(old, caps / "c1.pcap.enc", b"payload that must survive")
    before = path.read_bytes()
    backdate_all(caps)

    real_replace = Path.replace

    def die(self, target):  # noqa: ARG001
        raise OSError("disk full")

    monkeypatch.setattr(Path, "replace", die)
    with pytest.raises(OSError):
        rekey_file(path, old, new, apply=True)
    monkeypatch.setattr(Path, "replace", real_replace)

    assert path.read_bytes() == before
    assert old.open_bytes(path) == b"payload that must survive"
    assert list(caps.glob("*.partial")) == [], "the temp file must be cleaned up"


def test_a_failure_is_collected_rather_than_aborting_the_whole_run(dirs):
    """One bad file must not strand the files after it in the list."""
    caps, keys = dirs
    old, new, foreign = Cryptor(a_key()), Cryptor(a_key()), Cryptor(a_key())
    seal(foreign, caps / "a-bad.pcap.enc", b"theirs")
    good = seal(old, caps / "b-good.pcap.enc", b"mine")
    backdate_all(caps)

    out = rekey_all(old, new, captures_dir=caps, ssh_keys_dir=keys, apply=True)

    assert len(out.failed) == 1
    assert out.rekeyed == [good], "the file after the failure was still processed"
    assert new.open_bytes(good) == b"mine"


# --- the primitive -----------------------------------------------------------


def test_header_for_dek_round_trips_through_a_new_key():
    old, new = Cryptor(a_key()), Cryptor(a_key())
    sealed = old.seal_bytes(b"data")
    dek = old.unwrap_dek(sealed[:HEADER_LEN])

    rewrapped = new.header_for_dek(dek)
    assert new.unwrap_dek(rewrapped) == dek
    with pytest.raises(WrongKey):
        old.unwrap_dek(rewrapped)


def test_header_for_dek_rejects_a_wrong_length_key():
    with pytest.raises(ValueError, match="32 bytes"):
        Cryptor(a_key()).header_for_dek(b"too short")


def test_unwrap_dek_still_rejects_a_foreign_header():
    """The refactor must not have loosened the kek_id check."""
    mine, theirs = Cryptor(a_key()), Cryptor(a_key())
    with pytest.raises(WrongKey, match="different master key"):
        mine.unwrap_dek(theirs.seal_bytes(b"x")[:HEADER_LEN])


def test_outcome_ok_is_false_only_when_something_failed():
    out = Outcome()
    assert out.ok
    out.plaintext.append(Path("x"))
    assert out.ok, "a skipped plaintext file is not a failure"
    out.failed.append((Path("y"), "boom"))
    assert not out.ok
