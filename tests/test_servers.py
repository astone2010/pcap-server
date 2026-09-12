"""Tests for the single server list that replaced the active/saved split.

There used to be two persistent tables holding the same columns -- servers you
had added, and "saved" profiles you copied into that list and back out again.
Both survived restarts, so the split bought nothing and the two names meant
almost the same thing. These cover the merge: the old rows survive it, the
remaining list behaves, and the add form can probe a host before committing to
it.

conftest.py sets DATA_DIR/CAPTURES_DIR/SSH_KEYS_DIR and a master key before
anything importing backend.main is collected.
"""

from __future__ import annotations

import sqlite3
import uuid

import pytest

from backend.database import Database


@pytest.fixture()
def db(tmp_path):
    return Database(tmp_path / "test.db")


def _user(db: Database) -> str:
    user_id = str(uuid.uuid4())
    db.create_user(user_id, f"u{user_id[:8]}", "hash")
    return user_id


# --- the migration off saved_servers -----------------------------------------


def _legacy_db(path) -> None:
    """A database as it was before the merge, carrying a saved_servers table."""
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, totp_secret TEXT,
            totp_confirmed INTEGER DEFAULT 0, created_at TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE saved_servers (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
            hostname TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL, ssh_key_name TEXT NOT NULL,
            use_sudo INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
        );
        INSERT INTO users (id, username, password_hash, created_at)
            VALUES ('u1', 'alice', 'h', '2026-01-01T00:00:00');
        INSERT INTO saved_servers VALUES
            ('s1', 'u1', 'edge', '10.0.0.1', 22, 'root', 'k', 1, '2026-01-01T00:00:00'),
            ('s2', 'u1', 'core', '10.0.0.2', 2222, 'netadmin', 'k', 0, '2026-01-02T00:00:00');
    """)
    conn.commit()
    conn.close()


def test_migration_carries_saved_servers_into_the_one_list(tmp_path):
    """A profile that was never loaded is still a server the user configured.
    Dropping the table without carrying it over would silently lose it."""
    path = tmp_path / "legacy.db"
    _legacy_db(path)

    servers = Database(path).list_active_servers("u1")

    assert {s["hostname"] for s in servers} == {"10.0.0.1", "10.0.0.2"}
    edge = next(s for s in servers if s["name"] == "edge")
    assert edge["port"] == 22
    assert edge["username"] == "root"
    assert edge["use_sudo"] == 1
    core = next(s for s in servers if s["name"] == "core")
    assert core["port"] == 2222
    assert core["use_sudo"] == 0


def test_migration_drops_the_retired_table(tmp_path):
    path = tmp_path / "legacy.db"
    _legacy_db(path)
    db = Database(path)

    tables = {r["name"] for r in db._conn().execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    assert "saved_servers" not in tables


def test_migration_does_not_duplicate_an_already_loaded_profile(tmp_path):
    """Loading a profile copied it into active_servers under the same id, so a
    user who had done that has the row in both tables. It must end up once."""
    path = tmp_path / "legacy.db"
    _legacy_db(path)
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE active_servers (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
            hostname TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL, ssh_key_name TEXT NOT NULL,
            use_sudo INTEGER NOT NULL DEFAULT 0, tcpdump_path TEXT NOT NULL DEFAULT '',
            added_at TEXT NOT NULL
        );
        INSERT INTO active_servers VALUES
            ('s1', 'u1', 'edge', '10.0.0.1', 22, 'root', 'k', 1,
             '/usr/sbin/tcpdump', '2026-01-03T00:00:00');
    """)
    conn.commit()
    conn.close()

    servers = Database(path).list_active_servers("u1")

    assert len(servers) == 2
    edge = next(s for s in servers if s["id"] == "s1")
    # The already-loaded row wins: it carries the discovered tcpdump path.
    assert edge["tcpdump_path"] == "/usr/sbin/tcpdump"


def test_migration_is_a_no_op_on_a_fresh_database(tmp_path):
    db = Database(tmp_path / "fresh.db")
    user_id = _user(db)
    assert db.list_active_servers(user_id) == []


def test_second_open_of_a_migrated_database_still_works(tmp_path):
    """The migration must not resurrect the table it just dropped, or every
    restart would re-run it."""
    path = tmp_path / "legacy.db"
    _legacy_db(path)
    Database(path)
    assert len(Database(path).list_active_servers("u1")) == 2


# --- editing a server ---------------------------------------------------------


def test_update_server_changes_every_field(db):
    user_id = _user(db)
    db.add_active_server("s1", user_id, "old", "10.0.0.1", 22, "root", "k1", False)

    assert db.update_active_server("s1", user_id, "new", "10.0.0.9", 2222, "netadmin", "k2", True)

    srv = db.get_active_server("s1", user_id)
    assert (srv["name"], srv["hostname"], srv["port"]) == ("new", "10.0.0.9", 2222)
    assert (srv["username"], srv["ssh_key_name"], srv["use_sudo"]) == ("netadmin", "k2", 1)


def test_update_server_clears_a_tcpdump_path_discovered_on_the_old_host(db):
    """The path was probed from the host this server used to point at. Keeping
    it would invoke an absolute path that need not exist on the new one."""
    user_id = _user(db)
    db.add_active_server("s1", user_id, "n", "10.0.0.1", 22, "root", "k", False)
    db.set_active_server_tcpdump_path("s1", user_id, "/usr/sbin/tcpdump")

    db.update_active_server("s1", user_id, "n", "10.0.0.2", 22, "root", "k", False)

    assert db.get_active_server("s1", user_id)["tcpdump_path"] == ""


def test_update_server_will_not_touch_another_users_row(db):
    owner, other = _user(db), _user(db)
    db.add_active_server("s1", owner, "mine", "10.0.0.1", 22, "root", "k", False)

    assert not db.update_active_server("s1", other, "theirs", "evil.example", 22, "root", "k", True)
    assert db.get_active_server("s1", owner)["hostname"] == "10.0.0.1"


# --- remembered usernames -----------------------------------------------------


def test_usernames_are_distinct_and_most_recently_used_first(db):
    user_id = _user(db)
    db.add_active_server("s1", user_id, "", "10.0.0.1", 22, "root", "k", False)
    db.add_active_server("s2", user_id, "", "10.0.0.2", 22, "netadmin", "k", False)
    db.add_active_server("s3", user_id, "", "10.0.0.3", 22, "root", "k", False)

    assert db.list_usernames(user_id) == ["root", "netadmin"]


def test_usernames_are_scoped_to_the_user_who_typed_them(db):
    mine, theirs = _user(db), _user(db)
    db.add_active_server("s1", mine, "", "10.0.0.1", 22, "alice", "k", False)
    db.add_active_server("s2", theirs, "", "10.0.0.2", 22, "bob", "k", False)

    assert db.list_usernames(mine) == ["alice"]
    assert db.list_usernames(theirs) == ["bob"]


def test_usernames_is_empty_for_a_user_with_no_servers(db):
    assert db.list_usernames(_user(db)) == []


# --- host trust ---------------------------------------------------------------
#
# Host keys are managed per endpoint, not per row. A host answers with one key
# per algorithm, so deleting a single row left the rest still verifying the
# host and the next scan restored the deleted one -- which read as "deleting
# does nothing, they come right back".


def test_forget_removes_every_key_for_the_host_in_one_go(db):
    user_id = _user(db)
    for key_type in ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"):
        db.add_known_host("10.0.0.230", 22, key_type, "AAAA" + key_type, user_id)

    assert db.forget_known_host("10.0.0.230", 22) == 3
    assert db.get_known_hosts("10.0.0.230", 22) == []


def test_forget_leaves_other_hosts_alone(db):
    user_id = _user(db)
    db.add_known_host("10.0.0.230", 22, "ssh-rsa", "A", user_id)
    db.add_known_host("10.0.0.231", 22, "ssh-rsa", "B", user_id)

    db.forget_known_host("10.0.0.230", 22)

    assert [h["hostname"] for h in db.list_known_hosts()] == ["10.0.0.231"]


def test_forget_distinguishes_ports_on_the_same_hostname(db):
    user_id = _user(db)
    db.add_known_host("10.0.0.230", 22, "ssh-rsa", "A", user_id)
    db.add_known_host("10.0.0.230", 2222, "ssh-rsa", "B", user_id)

    assert db.forget_known_host("10.0.0.230", 2222) == 1
    assert [h["port"] for h in db.list_known_hosts()] == [22]


def test_forget_reports_nothing_removed_for_an_unknown_host(db):
    assert db.forget_known_host("10.0.0.99", 22) == 0


def test_endpoints_come_from_configured_servers(db):
    user_id = _user(db)
    db.add_active_server("s1", user_id, "edge-fw", "10.0.0.230", 22, "root", "k", False)
    db.add_active_server("s2", user_id, "", "10.0.0.231", 2222, "netadmin", "k", False)

    endpoints = db.list_server_endpoints()

    assert [(e["hostname"], e["port"]) for e in endpoints] == [
        ("10.0.0.230", 22), ("10.0.0.231", 2222),
    ]
    assert endpoints[0]["labels"] == ["edge-fw"]
    # No name set, so the endpoint labels itself the way the UI shows it.
    assert endpoints[1]["labels"] == ["netadmin@10.0.0.231"]


def test_endpoints_group_several_servers_pointing_at_one_host(db):
    """They share a host key, so they are one trust decision, not two."""
    user_id = _user(db)
    db.add_active_server("s1", user_id, "edge-fw", "10.0.0.230", 22, "root", "k", False)
    db.add_active_server("s2", user_id, "backup-path", "10.0.0.230", 22, "netadmin", "k", False)

    endpoints = db.list_server_endpoints()

    assert len(endpoints) == 1
    assert endpoints[0]["labels"] == ["edge-fw", "backup-path"]


def test_endpoint_labels_are_deduplicated(db):
    mine, theirs = _user(db), _user(db)
    db.add_active_server("s1", mine, "edge-fw", "10.0.0.230", 22, "root", "k", False)
    db.add_active_server("s2", theirs, "edge-fw", "10.0.0.230", 22, "root", "k", False)

    assert db.list_server_endpoints()[0]["labels"] == ["edge-fw"]


def test_endpoint_label_containing_a_comma_stays_one_label(db):
    """The reason labels are grouped in Python: GROUP_CONCAT would split this
    into two hosts' worth of names."""
    user_id = _user(db)
    db.add_active_server("s1", user_id, "edge, rack 4", "10.0.0.230", 22, "root", "k", False)

    assert db.list_server_endpoints()[0]["labels"] == ["edge, rack 4"]


# --- host-key endpoint request validation -------------------------------------


@pytest.mark.parametrize(
    "body,field",
    [
        ({"hostname": "", "port": 22}, "hostname"),
        ({"hostname": "  ", "port": 22}, "hostname"),
        ({"hostname": "evil.example; rm -rf /", "port": 22}, "hostname"),
        ({"hostname": "a|b", "port": 22}, "hostname"),
        ({"hostname": "a`whoami`", "port": 22}, "hostname"),
        ({"hostname": "a\nb", "port": 22}, "hostname"),
        ({"hostname": "ok.example", "port": "not-a-number"}, "port"),
        ({"hostname": "ok.example", "port": None}, "port"),
        ({"hostname": "ok.example", "port": 0}, "port"),
        ({"hostname": "ok.example", "port": 70000}, "port"),
    ],
)
def test_endpoint_body_is_rejected_as_a_bad_request(body, field):
    """A non-numeric port used to hit int() unguarded and surface as a 500."""
    from fastapi import HTTPException

    from backend.main import _endpoint_from_body

    with pytest.raises(HTTPException) as excinfo:
        _endpoint_from_body(body)
    assert excinfo.value.status_code == 400
    assert field in excinfo.value.detail


def test_endpoint_body_defaults_the_port_to_22():
    from backend.main import _endpoint_from_body

    assert _endpoint_from_body({"hostname": "ok.example"}) == ("ok.example", 22)


def test_endpoint_body_accepts_a_numeric_string_port():
    from backend.main import _endpoint_from_body

    assert _endpoint_from_body({"hostname": "ok.example", "port": "2222"}) == ("ok.example", 2222)
