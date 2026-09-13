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


# --- stored usernames ---------------------------------------------------------
#
# These used to be derived from active_servers with a GROUP BY, which meant the
# list was only ever a view of the servers that happened to exist: deleting the
# last server that used a login name silently discarded the name too, and there
# was no way to add one ahead of time or remove one you never wanted offered.
# They are their own rows now, recorded by add/update_active_server so a server
# can never exist with a name the list has not seen.


def _names(db, user_id):
    return [u["username"] for u in db.list_usernames(user_id)]


def test_usernames_are_distinct_and_most_recently_used_first(db):
    user_id = _user(db)
    db.add_active_server("s1", user_id, "", "10.0.0.1", 22, "root", "k", False)
    db.add_active_server("s2", user_id, "", "10.0.0.2", 22, "netadmin", "k", False)
    db.add_active_server("s3", user_id, "", "10.0.0.3", 22, "root", "k", False)

    assert _names(db, user_id) == ["root", "netadmin"]


def test_usernames_are_scoped_to_the_user_who_typed_them(db):
    mine, theirs = _user(db), _user(db)
    db.add_active_server("s1", mine, "", "10.0.0.1", 22, "alice", "k", False)
    db.add_active_server("s2", theirs, "", "10.0.0.2", 22, "bob", "k", False)

    assert _names(db, mine) == ["alice"]
    assert _names(db, theirs) == ["bob"]


def test_usernames_is_empty_for_a_user_with_no_servers(db):
    assert db.list_usernames(_user(db)) == []


def test_a_username_outlives_the_server_it_was_typed_for(db):
    """The whole point of storing them: the old derived view lost the name the
    moment its last server went away."""
    user_id = _user(db)
    db.add_active_server("s1", user_id, "", "10.0.0.1", 22, "netadmin", "k", False)
    assert db.delete_active_server("s1", user_id)

    assert _names(db, user_id) == ["netadmin"]


def test_editing_a_server_records_its_new_username(db):
    user_id = _user(db)
    db.add_active_server("s1", user_id, "", "10.0.0.1", 22, "root", "k", False)
    db.update_active_server("s1", user_id, "", "10.0.0.1", 22, "netadmin", "k", False)

    assert sorted(_names(db, user_id)) == ["netadmin", "root"]


def test_a_failed_edit_records_nothing(db):
    """A rejected edit -- wrong owner, missing server -- must not leak the
    username it was attempted with into the list."""
    mine, theirs = _user(db), _user(db)
    db.add_active_server("s1", mine, "", "10.0.0.1", 22, "root", "k", False)

    assert not db.update_active_server("s1", theirs, "", "10.0.0.1", 22, "intruder", "k", False)
    assert _names(db, theirs) == []


def test_a_username_can_be_stored_before_any_server_uses_it(db):
    user_id = _user(db)
    db.remember_username(user_id, "netadmin")
    assert _names(db, user_id) == ["netadmin"]


def test_remembering_a_username_twice_keeps_one_row(db):
    user_id = _user(db)
    db.remember_username(user_id, "netadmin")
    db.remember_username(user_id, "netadmin")
    assert _names(db, user_id) == ["netadmin"]


def test_rename_changes_the_stored_username(db):
    user_id = _user(db)
    db.remember_username(user_id, "netadmn")
    stored_id = db.list_usernames(user_id)[0]["id"]

    assert db.rename_username(user_id, stored_id, "netadmin")
    assert _names(db, user_id) == ["netadmin"]


def test_rename_leaves_the_servers_using_the_old_name_alone(db):
    """The list is what the forms offer, not a reference the servers hold."""
    user_id = _user(db)
    db.add_active_server("s1", user_id, "", "10.0.0.1", 22, "root", "k", False)
    stored_id = db.list_usernames(user_id)[0]["id"]

    db.rename_username(user_id, stored_id, "netadmin")
    assert db.get_active_server("s1", user_id)["username"] == "root"


def test_rename_onto_an_existing_username_is_refused(db):
    user_id = _user(db)
    db.remember_username(user_id, "root")
    db.remember_username(user_id, "netadmin")
    stored_id = next(u["id"] for u in db.list_usernames(user_id) if u["username"] == "root")

    with pytest.raises(ValueError):
        db.rename_username(user_id, stored_id, "netadmin")
    assert sorted(_names(db, user_id)) == ["netadmin", "root"]


def test_rename_of_another_users_username_is_refused(db):
    mine, theirs = _user(db), _user(db)
    db.remember_username(mine, "alice")
    stored_id = db.list_usernames(mine)[0]["id"]

    assert not db.rename_username(theirs, stored_id, "mallory")
    assert _names(db, mine) == ["alice"]


def test_delete_removes_the_suggestion_but_not_the_server(db):
    user_id = _user(db)
    db.add_active_server("s1", user_id, "", "10.0.0.1", 22, "root", "k", False)
    stored_id = db.list_usernames(user_id)[0]["id"]

    assert db.delete_username(user_id, stored_id)
    assert _names(db, user_id) == []
    assert db.get_active_server("s1", user_id)["username"] == "root"


def test_delete_of_another_users_username_is_refused(db):
    mine, theirs = _user(db), _user(db)
    db.remember_username(mine, "alice")
    stored_id = db.list_usernames(mine)[0]["id"]

    assert not db.delete_username(theirs, stored_id)
    assert _names(db, mine) == ["alice"]


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
    """These rules used to live in a hand-written parser beside the routes.

    They are a model now, so the same table is checked against the model. The
    parser answered a bad body with a 400 and anything that was not a dict at
    all with a 500; the model answers both with a 422, and which field was
    wrong is still named. The route wiring is covered in test_main.py.
    """
    from pydantic import ValidationError

    from backend.models import KnownHostEndpoint

    with pytest.raises(ValidationError) as excinfo:
        KnownHostEndpoint(**body)
    assert field in {loc for err in excinfo.value.errors() for loc in err["loc"]}


def test_endpoint_body_defaults_the_port_to_22():
    from backend.models import KnownHostEndpoint

    endpoint = KnownHostEndpoint(hostname="ok.example")
    assert (endpoint.hostname, endpoint.port) == ("ok.example", 22)


def test_endpoint_body_accepts_a_numeric_string_port():
    """The parser ran int() over whatever arrived, so "2222" worked. Anything
    that used to be accepted has to stay accepted."""
    from backend.models import KnownHostEndpoint

    endpoint = KnownHostEndpoint(hostname="ok.example", port="2222")
    assert (endpoint.hostname, endpoint.port) == ("ok.example", 2222)


# --- ServerAuth.hostname now matches KnownHostEndpoint's stricter rule -------
#
# ServerAuth.hostname used to reject only space/;/|/& -- $, backtick, backslash
# and the line breaks were still let through, reaching asyncssh and the
# known_hosts store. Both validators now call the same validate_ssh_hostname,
# so this table is the same rejection set as test_endpoint_body_is_rejected_
# as_a_bad_request above, checked against the other model.


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "  ",
        "evil.example; rm -rf /",
        "a|b",
        "a&b",
        "a$b",
        "a`whoami`",
        "a\\b",
        "a\nb",
        "a\rb",
    ],
)
def test_server_auth_hostname_rejects_the_same_characters_as_known_host_endpoint(hostname):
    from pydantic import ValidationError

    from backend.models import ServerAuth

    with pytest.raises(ValidationError) as excinfo:
        ServerAuth(hostname=hostname, username="alice", ssh_key_name="k")
    assert "hostname" in {loc for err in excinfo.value.errors() for loc in err["loc"]}


def test_server_auth_hostname_still_accepts_an_ordinary_hostname():
    from backend.models import ServerAuth

    server = ServerAuth(hostname="  ok.example  ", username="alice", ssh_key_name="k")
    assert server.hostname == "ok.example"


def test_existing_servers_are_backfilled_into_the_username_list(tmp_path):
    """Upgrading an install that predates the table must not start empty: the
    derived view was showing these names, so the stored list has to keep them."""
    path = tmp_path / "upgrade.db"
    db = Database(path)
    user_id = _user(db)
    db.add_active_server("s1", user_id, "", "10.0.0.1", 22, "root", "k", False)
    db.add_active_server("s2", user_id, "", "10.0.0.2", 22, "netadmin", "k", False)

    # Rewind to the pre-migration state: rows present, list absent, flag unset.
    conn = db._conn()
    conn.execute("DELETE FROM known_usernames")
    conn.execute("DELETE FROM settings WHERE key = 'known_usernames_backfilled'")
    conn.commit()

    assert sorted(_names(Database(path), user_id)) == ["netadmin", "root"]


def test_the_backfill_does_not_resurrect_a_deleted_username(tmp_path):
    """A delete that undoes itself on the next restart is worse than no delete:
    the server still exists, so an unguarded backfill would put the name back."""
    path = tmp_path / "restart.db"
    db = Database(path)
    user_id = _user(db)
    db.add_active_server("s1", user_id, "", "10.0.0.1", 22, "root", "k", False)
    stored_id = db.list_usernames(user_id)[0]["id"]
    assert db.delete_username(user_id, stored_id)

    assert _names(Database(path), user_id) == []


# --- /api/servers reports host trust ------------------------------------------
#
# A connection to a host with no trusted keys is refused outright, so a server
# list that does not say which entries are unusable sends people to a failure
# they cannot explain from the screen they are standing on.

from fastapi.testclient import TestClient  # noqa: E402

from backend import main  # noqa: E402
from backend.auth import create_session_token  # noqa: E402


@pytest.fixture()
def api_client():
    with TestClient(main.app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def signed_in(api_client):
    user_id = str(uuid.uuid4())
    main.db.create_user(user_id, f"trust-{user_id[:8]}", "scrypt$1$1$1$00$00", is_admin=True)
    main.db.set_totp_secret(user_id, "A" * 32)
    main.db.confirm_totp(user_id)
    token, _ = create_session_token(main.db, user_id)
    api_client.cookies.set("session", token)
    try:
        yield user_id
    finally:
        main.db.delete_user(user_id)


def _add_server(user_id: str, hostname: str, port: int = 22) -> str:
    server_id = str(uuid.uuid4())
    main.db.add_active_server(
        server_id, user_id, "probe", hostname, port, "alice", "k", False,
    )
    return server_id


def test_server_is_reported_untrusted_until_its_host_is_trusted(api_client, signed_in):
    _add_server(signed_in, "never-scanned.example")
    rows = api_client.get("/api/servers").json()
    row = next(r for r in rows if r["hostname"] == "never-scanned.example")
    assert row["host_trusted"] is False


def test_server_is_reported_trusted_once_keys_are_stored(api_client, signed_in):
    _add_server(signed_in, "scanned.example")
    main.db.add_known_host("scanned.example", 22, "ssh-ed25519", "AAAAkey", signed_in)
    try:
        rows = api_client.get("/api/servers").json()
        row = next(r for r in rows if r["hostname"] == "scanned.example")
        assert row["host_trusted"] is True
    finally:
        main.db.forget_known_host("scanned.example", 22)


def test_trust_is_keyed_on_the_endpoint_not_the_server_row(api_client, signed_in):
    """Two servers on one host share one decision -- the reason trust lives in
    admin against an endpoint rather than inside a per-user server profile."""
    _add_server(signed_in, "shared.example")
    _add_server(signed_in, "shared.example")
    main.db.add_known_host("shared.example", 22, "ssh-ed25519", "AAAAkey", signed_in)
    try:
        rows = [r for r in api_client.get("/api/servers").json()
                if r["hostname"] == "shared.example"]
        assert len(rows) == 2
        assert all(r["host_trusted"] is True for r in rows)
    finally:
        main.db.forget_known_host("shared.example", 22)


def test_a_different_port_is_a_different_trust_decision(api_client, signed_in):
    _add_server(signed_in, "ported.example", 2222)
    main.db.add_known_host("ported.example", 22, "ssh-ed25519", "AAAAkey", signed_in)
    try:
        rows = api_client.get("/api/servers").json()
        row = next(r for r in rows if r["hostname"] == "ported.example")
        assert row["host_trusted"] is False, "port 22's keys must not vouch for 2222"
    finally:
        main.db.forget_known_host("ported.example", 22)
