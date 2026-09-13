"""The capture filter, kept on the capture record.

It used to live on CaptureRequest and nowhere else: tcpdump was given it and
then it was gone. A finished capture could not say what it had been selecting
for, so a list of captures gave no way to tell "nothing was happening" from
"the filter excluded it" -- which are opposite conclusions drawn from the same
empty packet list.

What is covered here:

  * the column exists on a fresh database and on one built before it did,
  * a capture's filter survives the round trip through the row and back into
    CaptureInfo, which is the path _restore() takes on every restart,
  * an old row reads as unfiltered rather than as something invented from the
    command string.

The badge that displays all this is a browser test -- see
tests/browser/test_capture_ui.py.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.capture import _row
from backend.database import Database
from backend.models import CAPTURE_NAME_MAX, CaptureInfo, CaptureRequest, CaptureStatus


def _db(tmp_path) -> Database:
    """A database with the owning user already in it.

    captures.user_id is a foreign key onto users, so a capture row without one
    is refused -- which has nothing to do with what these tests are about.
    """
    db = Database(tmp_path / "t.db")
    db.create_user("u1", "alice", "scrypt$1$1$1$00$00")
    return db


def _info(**over) -> CaptureInfo:
    base = dict(
        id=str(uuid.uuid4()),
        server_id="s1",
        user_id="u1",
        status=CaptureStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
    )
    return CaptureInfo(**{**base, **over})


# --- the round trip ----------------------------------------------------------


def test_the_filter_survives_the_row_and_comes_back(tmp_path):
    """The path _restore() walks on every container start: row out, row in,
    CaptureInfo(**row). A column the writer sets and the reader drops would
    look correct until the first restart."""
    db = _db(tmp_path)
    info = _info(bpf_filter="tcp port 443 and host 10.0.0.1")
    db.upsert_capture(_row(info))

    stored = [c for c in db.list_captures() if c["id"] == info.id][0]
    assert stored["bpf_filter"] == "tcp port 443 and host 10.0.0.1"
    assert CaptureInfo(**stored).bpf_filter == "tcp port 443 and host 10.0.0.1"


def test_a_capture_with_no_filter_stores_an_empty_string(tmp_path):
    db = _db(tmp_path)
    info = _info()
    db.upsert_capture(_row(info))
    assert [c for c in db.list_captures() if c["id"] == info.id][0]["bpf_filter"] == ""


def test_the_name_makes_the_same_round_trip(tmp_path):
    """Captures used to be named only by renaming them afterwards. The form now
    asks at the start, which means the name arrives through CaptureRequest and
    has to reach the same column the rename writes."""
    db = _db(tmp_path)
    info = _info(name="slow logons on the file server")
    db.upsert_capture(_row(info))
    stored = [c for c in db.list_captures() if c["id"] == info.id][0]
    assert stored["name"] == "slow logons on the file server"


# --- the migration -----------------------------------------------------------


def _db_without_the_column(path) -> None:
    """A captures table as it was before the filter was persisted.

    Written out by hand rather than by checking out an old Database: the point
    is a table that genuinely lacks the column, and a schema that drifts with
    the code cannot demonstrate that.
    """
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, totp_secret TEXT,
            totp_confirmed INTEGER DEFAULT 0, created_at TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE captures (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            user_id TEXT NOT NULL,
            server_id TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT,
            stopped_at TEXT,
            command TEXT NOT NULL DEFAULT '',
            remote_path TEXT NOT NULL DEFAULT '',
            local_path TEXT NOT NULL DEFAULT '',
            packet_count INTEGER NOT NULL DEFAULT 0,
            file_size INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT '',
            server_label TEXT NOT NULL DEFAULT '',
            interface TEXT NOT NULL DEFAULT '',
            live_stream INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO users (id, username, password_hash, created_at)
            VALUES ('u1', 'alice', 'h', '2026-01-01T00:00:00');
        INSERT INTO captures (id, user_id, server_id, status, command)
            VALUES ('old', 'u1', 's1', 'completed',
                    'tcpdump -w /tmp/x.pcap -i eth0 -- tcp port 445');
    """)
    conn.commit()
    conn.close()


def test_the_migration_adds_the_column_to_an_existing_database(tmp_path):
    path = tmp_path / "legacy.db"
    _db_without_the_column(path)
    db = Database(path)
    columns = {r["name"] for r in db._conn().execute("PRAGMA table_info(captures)")}
    assert "bpf_filter" in columns


def test_a_capture_taken_before_the_column_reads_as_unfiltered(tmp_path):
    """And specifically NOT as `tcp port 445`, which is sitting right there in
    its command string.

    Recovering it from there would mean a second BPF parser in the codebase,
    picking a filter out of an argv that also carries -i, -w and -s. Guessing
    "unfiltered" loses a label on old captures; guessing wrong would put a
    filter on a capture that never ran one, which is a claim about what is
    inside the file.
    """
    path = tmp_path / "legacy.db"
    _db_without_the_column(path)
    old = [c for c in Database(path).list_captures() if c["id"] == "old"][0]
    assert old["bpf_filter"] == ""
    assert "tcp port 445" in old["command"], "the filter really is in the command"


def test_the_migration_runs_only_once(tmp_path):
    """Opening the same database twice must not fail on a duplicate column."""
    path = tmp_path / "legacy.db"
    _db_without_the_column(path)
    Database(path)
    Database(path)  # the assertion is that this does not raise


# --- what CaptureRequest accepts ---------------------------------------------


def test_a_request_may_still_omit_the_name():
    """Required by the form, optional at the API, and deliberately so -- see
    CaptureRequest in models.py. A scripted capture is not broken for a
    cosmetic rule."""
    assert CaptureRequest(server_id="s1", interface="eth0").name == ""


def test_a_name_is_stripped_and_control_characters_removed():
    req = CaptureRequest(server_id="s1", interface="eth0", name="  odd\x00 name\x07 ")
    assert req.name == "odd name"


def test_a_name_is_length_limited():
    with pytest.raises(ValidationError):
        CaptureRequest(server_id="s1", interface="eth0", name="x" * (CAPTURE_NAME_MAX + 1))


def test_the_filter_on_a_request_still_refuses_shell_metacharacters():
    """Unchanged by persisting it -- asserted here because the field now has a
    second life as a stored value, and a stored value is replayed."""
    with pytest.raises(ValidationError):
        CaptureRequest(server_id="s1", interface="eth0", bpf_filter="port 80; id")
