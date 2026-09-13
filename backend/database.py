from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


# Ceilings on the two per-user tables an authenticated caller can grow without
# limit. Both are far above hand-curated use: they exist so a script cannot
# fill the volume a capture database shares, not to ration a feature.
MAX_CUSTOM_FILTERS_PER_USER = 200
MAX_VIEWS_PER_CAPTURE = 50


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Database:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._migrate()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _migrate(self) -> None:
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                totp_confirmed INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_seen TEXT
            );

            CREATE TABLE IF NOT EXISTS trusted_devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT 'Unknown',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS active_servers (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL DEFAULT '',
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                username TEXT NOT NULL,
                ssh_key_name TEXT NOT NULL,
                use_sudo INTEGER NOT NULL DEFAULT 0,
                tcpdump_path TEXT NOT NULL DEFAULT '',
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS known_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                key_type TEXT NOT NULL,
                host_key TEXT NOT NULL,
                added_at TEXT NOT NULL,
                added_by TEXT REFERENCES users(id) ON DELETE SET NULL,
                UNIQUE(hostname, port, key_type)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_trusted_devices_user_token ON trusted_devices(user_id, token_hash);
            CREATE TABLE IF NOT EXISTS captures (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
                live_stream INTEGER NOT NULL DEFAULT 0,
                bpf_filter TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS known_usernames (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL DEFAULT '',
                UNIQUE(user_id, username)
            );

            -- Saved filtered views of one capture: a named display filter the
            -- viewer offers back as a tab. Scoped to the user who saved it,
            -- like servers and usernames, and removed with the capture by the
            -- foreign key rather than by anything remembering to.
            CREATE TABLE IF NOT EXISTS capture_views (
                id TEXT PRIMARY KEY,
                capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                display_filter TEXT NOT NULL DEFAULT '',
                position INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                UNIQUE(capture_id, user_id, name)
            );

            -- An operator's own capture filters, alongside the built-in
            -- library. Private to the user who saved them, like servers,
            -- usernames and capture views: a capture filter frequently names
            -- the hosts and ports someone is investigating, which is not a
            -- thing to broadcast to every other account on the box.
            CREATE TABLE IF NOT EXISTS custom_filters (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                label TEXT NOT NULL,
                expression TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, label)
            );

            CREATE INDEX IF NOT EXISTS idx_captures_user_id ON captures(user_id);
            CREATE INDEX IF NOT EXISTS idx_active_servers_user_id ON active_servers(user_id);
            CREATE INDEX IF NOT EXISTS idx_capture_views_owner
                ON capture_views(capture_id, user_id, position);
            CREATE INDEX IF NOT EXISTS idx_custom_filters_owner
                ON custom_filters(user_id, label);
        """)
        active_columns = {r["name"] for r in conn.execute("PRAGMA table_info(active_servers)")}
        if "tcpdump_path" not in active_columns:
            conn.execute("ALTER TABLE active_servers ADD COLUMN tcpdump_path TEXT NOT NULL DEFAULT ''")
        session_columns = {r["name"] for r in conn.execute("PRAGMA table_info(sessions)")}
        if "last_seen" not in session_columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN last_seen TEXT")
        # Usernames used to be derived from active_servers, so deleting the last
        # server that used one silently discarded it. They are stored in their
        # own right now; carry across whatever the derived view was showing.
        #
        # Once only, and flagged as done. Re-running it every start would
        # resurrect a username the operator has since deleted in Admin, for as
        # long as any server still uses it -- a delete that undoes itself on the
        # next restart is worse than no delete at all.
        backfilled = conn.execute(
            "SELECT value FROM settings WHERE key = 'known_usernames_backfilled'"
        ).fetchone()
        if not backfilled:
            conn.execute(
                """INSERT OR IGNORE INTO known_usernames
                       (id, user_id, username, created_at, last_used_at)
                   SELECT lower(hex(randomblob(16))), user_id, username,
                          MAX(added_at), MAX(added_at)
                   FROM active_servers GROUP BY user_id, username"""
            )
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('known_usernames_backfilled', '1')"
            )

        capture_columns = {r["name"] for r in conn.execute("PRAGMA table_info(captures)")}
        if "name" not in capture_columns:
            conn.execute("ALTER TABLE captures ADD COLUMN name TEXT NOT NULL DEFAULT ''")
        if "server_label" not in capture_columns:
            conn.execute("ALTER TABLE captures ADD COLUMN server_label TEXT NOT NULL DEFAULT ''")
        if "interface" not in capture_columns:
            conn.execute("ALTER TABLE captures ADD COLUMN interface TEXT NOT NULL DEFAULT ''")
        if "live_stream" not in capture_columns:
            # 0 for every capture taken before live streaming existed, which is
            # the truth: none of them was watched as it was recorded.
            conn.execute("ALTER TABLE captures ADD COLUMN live_stream INTEGER NOT NULL DEFAULT 0")
        if "bpf_filter" not in capture_columns:
            # '' for every capture taken before the filter was persisted, which
            # reads in the UI as "no filter". That is a guess, and it is the
            # only one available: the expression was never stored, and the
            # command string is not a safe place to recover it from -- a filter
            # is the trailing argv of a shell command that also carries -i, -c
            # and -s, and re-parsing it would be a second, worse BPF model.
            #
            # Guessing "unfiltered" is the conservative direction. A capture
            # that was filtered and now shows no badge is a missing label; a
            # capture that was not filtered and shows a filter would be a lie
            # about what is in the file.
            conn.execute("ALTER TABLE captures ADD COLUMN bpf_filter TEXT NOT NULL DEFAULT ''")
        self._fold_saved_servers(conn)
        conn.commit()

    @staticmethod
    def _fold_saved_servers(conn) -> None:
        """Retire saved_servers: one list of servers, not two.

        Both tables were persistent and held the same columns, reached through a
        save/load round trip that copied rows between them. Anything only in
        saved_servers is carried over -- ids are shared with active_servers, so
        a profile already loaded is already there and is left alone.
        """
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "saved_servers" not in tables:
            return
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(saved_servers)")}
        use_sudo = "use_sudo" if "use_sudo" in columns else "0"
        conn.execute(f"""
            INSERT OR IGNORE INTO active_servers
                (id, user_id, name, hostname, port, username, ssh_key_name, use_sudo, tcpdump_path, added_at)
            SELECT id, user_id, name, hostname, port, username, ssh_key_name, {use_sudo}, '', created_at
            FROM saved_servers
        """)
        conn.execute("DROP TABLE saved_servers")

    # --- users ---

    def create_user(self, user_id: str, username: str, password_hash: str, *, is_admin: bool = False) -> None:
        self._conn().execute(
            "INSERT INTO users (id, username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?)",
            (user_id, username, password_hash, _utcnow().isoformat(), int(is_admin)),
        )
        self._conn().commit()

    def get_user_by_username(self, username: str) -> dict | None:
        row = self._conn().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def get_user(self, user_id: str) -> dict | None:
        row = self._conn().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def update_password_hash(self, user_id: str, password_hash: str) -> None:
        self._conn().execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
        )
        self._conn().commit()

    def set_totp_secret(self, user_id: str, secret: str) -> None:
        self._conn().execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
        self._conn().commit()

    def confirm_totp(self, user_id: str) -> None:
        self._conn().execute("UPDATE users SET totp_confirmed = 1 WHERE id = ?", (user_id,))
        self._conn().commit()

    def reset_totp(self, user_id: str) -> bool:
        """Clears the second factor so the account enrols again at next login.

        The secret is NULLed as well as unconfirmed. Leaving the old secret in
        place and merely clearing the flag would let whoever still holds that
        authenticator confirm the account back to where it was -- which is the
        opposite of what a reset is for, since the usual reason for one is that
        the authenticator is gone or is no longer trusted.

        Returns False for an id that is not there, so the caller can answer 404
        rather than reporting success for a user that does not exist.
        """
        cur = self._conn().execute(
            "UPDATE users SET totp_secret = NULL, totp_confirmed = 0 WHERE id = ?",
            (user_id,),
        )
        self._conn().commit()
        return cur.rowcount > 0

    def count_sessions_for_user(self, user_id: str) -> int:
        """How many live sessions one account has. Read-only, for reporting a
        reset's blast radius before it is applied."""
        return self._conn().execute(
            "SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?", (user_id,)
        ).fetchone()["n"]

    def delete_sessions_for_user(self, user_id: str) -> int:
        """Signs one account out everywhere, now.

        Paired with reset_totp and not optional there. A live session already
        carries both factors, so an account whose second factor has just been
        revoked would go on using the API behind the old one until the session
        expired on its own -- up to session_hours later. The reset has to reach
        the sessions or it does not mean anything yet.
        """
        cur = self._conn().execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        self._conn().commit()
        return cur.rowcount

    def user_count(self) -> int:
        row = self._conn().execute("SELECT COUNT(*) as cnt FROM users").fetchone()
        return row["cnt"]

    def list_users(self) -> list[dict]:
        rows = self._conn().execute("SELECT id, username, created_at, is_admin, totp_confirmed FROM users").fetchall()
        return [dict(r) for r in rows]

    def delete_user(self, user_id: str) -> bool:
        cur = self._conn().execute("DELETE FROM users WHERE id = ?", (user_id,))
        self._conn().commit()
        return cur.rowcount > 0

    # --- sessions ---

    # The token column holds a SHA-256 of the bearer token, never the token
    # itself. Trusted devices were already stored this way; sessions were not,
    # so anyone who could read the database file could replay every live
    # session. Hashing costs one call and removes that entirely.

    def create_session(self, token_hash: str, user_id: str, expires_at: str) -> None:
        now = _utcnow().isoformat()
        self._conn().execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at, last_seen) VALUES (?, ?, ?, ?, ?)",
            (token_hash, user_id, now, expires_at, now),
        )
        self._conn().commit()

    def get_valid_session(self, token_hash: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
            (token_hash, _utcnow().isoformat()),
        ).fetchone()
        return dict(row) if row else None

    def touch_session(self, token_hash: str) -> None:
        self._conn().execute(
            "UPDATE sessions SET last_seen = ? WHERE token = ?", (_utcnow().isoformat(), token_hash)
        )
        self._conn().commit()

    def delete_session(self, token_hash: str) -> None:
        self._conn().execute("DELETE FROM sessions WHERE token = ?", (token_hash,))
        self._conn().commit()

    def delete_all_sessions(self) -> int:
        """Called at startup: a restart must not leave anyone signed in."""
        cur = self._conn().execute("DELETE FROM sessions")
        self._conn().commit()
        return cur.rowcount

    def cleanup_expired_sessions(self) -> int:
        cur = self._conn().execute("DELETE FROM sessions WHERE expires_at <= ?", (_utcnow().isoformat(),))
        self._conn().commit()
        return cur.rowcount

    # --- trusted devices ---

    def add_trusted_device(self, device_id: str, user_id: str, token_hash: str, name: str, expires_at: str) -> None:
        self._conn().execute(
            "INSERT INTO trusted_devices (id, user_id, token_hash, name, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, user_id, token_hash, name, _utcnow().isoformat(), expires_at),
        )
        self._conn().commit()

    def get_trusted_device_by_hash(self, user_id: str, token_hash: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM trusted_devices WHERE user_id = ? AND token_hash = ? AND expires_at > ?",
            (user_id, token_hash, _utcnow().isoformat()),
        ).fetchone()
        return dict(row) if row else None

    def delete_trusted_devices(self, user_id: str) -> None:
        self._conn().execute("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,))
        self._conn().commit()

    def cleanup_expired_devices(self) -> int:
        cur = self._conn().execute("DELETE FROM trusted_devices WHERE expires_at <= ?", (_utcnow().isoformat(),))
        self._conn().commit()
        return cur.rowcount

    # --- servers ---
    #
    # The runtime registry used to be an in-memory dict, so every server a user
    # added vanished on restart. Persisting it here makes a server permanent
    # until it is explicitly deleted, and scopes it to the user who added it.

    def add_active_server(self, server_id: str, user_id: str, name: str, hostname: str, port: int, username: str, ssh_key_name: str, use_sudo: bool) -> None:
        """Also records the username in the suggestion list.

        Here rather than in the route, so the invariant holds for every caller:
        a server can never exist with a login name the Username dropdown has
        never heard of.
        """
        self._conn().execute(
            """INSERT OR REPLACE INTO active_servers (id, user_id, name, hostname, port, username, ssh_key_name, use_sudo, added_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (server_id, user_id, name, hostname, port, username, ssh_key_name, int(use_sudo), _utcnow().isoformat()),
        )
        self._conn().commit()
        self.remember_username(user_id, username)

    def list_active_servers(self, user_id: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM active_servers WHERE user_id = ? ORDER BY added_at", (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_active_server(self, server_id: str, user_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM active_servers WHERE id = ? AND user_id = ?", (server_id, user_id)
        ).fetchone()
        return dict(row) if row else None

    def set_active_server_tcpdump_path(self, server_id: str, user_id: str, path: str) -> bool:
        cur = self._conn().execute(
            "UPDATE active_servers SET tcpdump_path = ? WHERE id = ? AND user_id = ?",
            (path, server_id, user_id),
        )
        self._conn().commit()
        return cur.rowcount > 0

    def update_active_server(self, server_id: str, user_id: str, name: str, hostname: str, port: int, username: str, ssh_key_name: str, use_sudo: bool) -> bool:
        # tcpdump_path is cleared: it was discovered on the old host and says
        # nothing about wherever this server now points.
        cur = self._conn().execute(
            """UPDATE active_servers
               SET name = ?, hostname = ?, port = ?, username = ?, ssh_key_name = ?, use_sudo = ?, tcpdump_path = ''
               WHERE id = ? AND user_id = ?""",
            (name, hostname, port, username, ssh_key_name, int(use_sudo), server_id, user_id),
        )
        self._conn().commit()
        if cur.rowcount:
            self.remember_username(user_id, username)
        return cur.rowcount > 0

    def delete_active_server(self, server_id: str, user_id: str) -> bool:
        cur = self._conn().execute(
            "DELETE FROM active_servers WHERE id = ? AND user_id = ?", (server_id, user_id)
        )
        self._conn().commit()
        return cur.rowcount > 0

    # --- stored SSH usernames ---

    def list_usernames(self, user_id: str) -> list[dict]:
        """Stored SSH usernames, most recently used first.

        Kept independently of active_servers: a username outlives the server it
        was first typed for, which is the whole point of storing it.
        """
        rows = self._conn().execute(
            """SELECT id, username, last_used_at FROM known_usernames
               WHERE user_id = ?
               ORDER BY last_used_at DESC, username ASC""",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def remember_username(self, user_id: str, username: str) -> None:
        """Record a username, or bump the one already stored. Never raises on a
        duplicate: adding a second server as the same user is the normal case."""
        now = _utcnow().isoformat()
        conn = self._conn()
        conn.execute(
            """INSERT INTO known_usernames (id, user_id, username, created_at, last_used_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(user_id, username) DO UPDATE SET last_used_at = excluded.last_used_at""",
            (str(uuid.uuid4()), user_id, username, now, now),
        )
        conn.commit()

    def rename_username(self, user_id: str, username_id: str, username: str) -> bool:
        """Rename a stored username. Servers already using the old one keep it:
        this list is what the forms offer, not a foreign key onto them.

        Raises ValueError when the new name is already stored -- (user_id,
        username) is unique, and a bare IntegrityError would surface as a 500.
        """
        conn = self._conn()
        clash = conn.execute(
            "SELECT 1 FROM known_usernames WHERE user_id = ? AND username = ? AND id != ?",
            (user_id, username, username_id),
        ).fetchone()
        if clash:
            raise ValueError(f"'{username}' is already stored")
        cur = conn.execute(
            "UPDATE known_usernames SET username = ? WHERE id = ? AND user_id = ?",
            (username, username_id, user_id),
        )
        conn.commit()
        return cur.rowcount > 0

    def delete_username(self, user_id: str, username_id: str) -> bool:
        cur = self._conn().execute(
            "DELETE FROM known_usernames WHERE id = ? AND user_id = ?", (username_id, user_id)
        )
        self._conn().commit()
        return cur.rowcount > 0

    # --- captures ---

    def upsert_capture(self, row: dict) -> None:
        self._conn().execute(
            """INSERT OR REPLACE INTO captures
               (id, name, user_id, server_id, server_label, status, started_at, stopped_at, command,
                remote_path, local_path, packet_count, file_size, error, interface, live_stream,
                bpf_filter)
               VALUES (:id, :name, :user_id, :server_id, :server_label, :status, :started_at, :stopped_at, :command,
                       :remote_path, :local_path, :packet_count, :file_size, :error, :interface, :live_stream,
                       :bpf_filter)""",
            row,
        )
        self._conn().commit()

    def list_captures(self) -> list[dict]:
        rows = self._conn().execute("SELECT * FROM captures ORDER BY started_at").fetchall()
        return [dict(r) for r in rows]

    def delete_capture(self, capture_id: str) -> None:
        self._conn().execute("DELETE FROM captures WHERE id = ?", (capture_id,))
        self._conn().commit()

    # --- custom capture filters ---

    def list_custom_filters(self, user_id: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT id, label, expression, created_at FROM custom_filters "
            "WHERE user_id = ? ORDER BY label COLLATE NOCASE",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def add_custom_filter(self, user_id: str, label: str, expression: str) -> dict:
        """Saves one, or raises ValueError if the user already has that label.

        Surfaced as a 409 rather than letting the UNIQUE constraint arrive as a
        500 -- two of your own filters called the same thing is a mistake worth
        naming, and the same treatment add_capture_view gives it.

        Capped per user. A saved filter is a row an authenticated caller can
        create in a loop, and nothing else here bounds it. The number is far
        above what anyone curates by hand -- the built-in library is eighty-odd
        expressions and is meant to be the big one -- so the ceiling is a stop
        on a script, not a limit anybody will meet by using the feature.
        """
        conn = self._conn()
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM custom_filters WHERE user_id = ?", (user_id,)
        ).fetchone()["n"]
        if count >= MAX_CUSTOM_FILTERS_PER_USER:
            raise ValueError(
                f"you already have {MAX_CUSTOM_FILTERS_PER_USER} saved filters, "
                "which is the limit -- delete one to save another"
            )
        filter_id = str(uuid.uuid4())
        try:
            conn.execute(
                "INSERT INTO custom_filters (id, user_id, label, expression, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (filter_id, user_id, label, expression, _utcnow().isoformat()),
            )
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise ValueError(f"you already have a filter called {label!r}") from exc
        conn.commit()
        return dict(
            conn.execute(
                "SELECT id, label, expression, created_at FROM custom_filters WHERE id = ?",
                (filter_id,),
            ).fetchone()
        )

    def delete_custom_filter(self, user_id: str, filter_id: str) -> bool:
        # user_id is in the WHERE clause, not checked beforehand: one statement
        # that cannot delete another account's row beats two that could race.
        cur = self._conn().execute(
            "DELETE FROM custom_filters WHERE id = ? AND user_id = ?",
            (filter_id, user_id),
        )
        self._conn().commit()
        return cur.rowcount > 0

    # --- known hosts ---

    def add_known_host(self, hostname: str, port: int, key_type: str, host_key: str, added_by: str | None = None) -> None:
        self._conn().execute(
            """INSERT OR REPLACE INTO known_hosts (hostname, port, key_type, host_key, added_at, added_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (hostname, port, key_type, host_key, _utcnow().isoformat(), added_by),
        )
        self._conn().commit()

    def get_known_hosts(self, hostname: str, port: int) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM known_hosts WHERE hostname = ? AND port = ?",
            (hostname, port),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_known_hosts(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM known_hosts ORDER BY hostname, port"
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_known_host(self, host_id: int) -> bool:
        cur = self._conn().execute("DELETE FROM known_hosts WHERE id = ?", (host_id,))
        self._conn().commit()
        return cur.rowcount > 0

    def forget_known_host(self, hostname: str, port: int) -> int:
        """Drop every key for one endpoint, and report how many went.

        A host answers with one key per algorithm, so its keys are trusted or
        not as a set. Removing them one row at a time looks like it failed:
        the rows that remain still verify the host, and the next scan restores
        the deleted one alongside them.
        """
        cur = self._conn().execute(
            "DELETE FROM known_hosts WHERE hostname = ? AND port = ?", (hostname, port)
        )
        self._conn().commit()
        return cur.rowcount

    def list_server_endpoints(self) -> list[dict]:
        """Every host any user has configured a server for, with its labels.

        Host trust is keyed on the endpoint rather than the server row, since
        several servers can point at one host and they all verify against the
        same key. Labels are grouped here rather than by GROUP_CONCAT, which
        would split wrongly on a server name that itself contains a comma.
        """
        rows = self._conn().execute(
            "SELECT hostname, port, name, username FROM active_servers ORDER BY hostname, port"
        ).fetchall()
        endpoints: dict[tuple[str, int], list[str]] = {}
        for row in rows:
            label = row["name"] or f"{row['username']}@{row['hostname']}"
            labels = endpoints.setdefault((row["hostname"], row["port"]), [])
            if label not in labels:
                labels.append(label)
        return [
            {"hostname": hostname, "port": port, "labels": labels}
            for (hostname, port), labels in sorted(endpoints.items())
        ]

    # --- saved capture views ---

    def list_capture_views(self, capture_id: str, user_id: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT id, capture_id, name, display_filter, position, created_at "
            "FROM capture_views WHERE capture_id = ? AND user_id = ? "
            "ORDER BY position, created_at",
            (capture_id, user_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_capture_view(self, view_id: str, user_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT id, capture_id, name, display_filter, position, created_at "
            "FROM capture_views WHERE id = ? AND user_id = ?",
            (view_id, user_id),
        ).fetchone()
        return dict(row) if row else None

    def add_capture_view(
        self, capture_id: str, user_id: str, name: str, display_filter: str
    ) -> dict:
        """Appends to the end of this capture's tab strip.

        Raises ValueError on a duplicate name rather than letting the UNIQUE
        constraint surface as a 500: two tabs with the same label on the same
        capture is a mistake worth naming, not an internal error.

        Capped per capture per user, for the same reason add_custom_filter is
        capped: it is a row an authenticated caller can create in a loop. The
        two moved together deliberately -- capping one unbounded per-user table
        and not the other beside it is the real inconsistency.
        """
        conn = self._conn()
        views = conn.execute(
            "SELECT COUNT(*) AS n FROM capture_views WHERE capture_id = ? AND user_id = ?",
            (capture_id, user_id),
        ).fetchone()["n"]
        if views >= MAX_VIEWS_PER_CAPTURE:
            raise ValueError(
                f"this capture already has {MAX_VIEWS_PER_CAPTURE} saved views, "
                "which is the limit -- delete one to save another"
            )
        row = conn.execute(
            "SELECT COALESCE(MAX(position), -1) AS top FROM capture_views "
            "WHERE capture_id = ? AND user_id = ?",
            (capture_id, user_id),
        ).fetchone()
        view_id = str(uuid.uuid4())
        try:
            conn.execute(
                "INSERT INTO capture_views "
                "(id, capture_id, user_id, name, display_filter, position, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (view_id, capture_id, user_id, name, display_filter,
                 row["top"] + 1, _utcnow().isoformat()),
            )
        except sqlite3.IntegrityError as exc:
            # Roll back before raising. sqlite3 opens an implicit transaction
            # for the INSERT, and a failed statement does not close it -- the
            # connection would keep a RESERVED lock on the database for the
            # rest of its life, and every other thread's write would then fail
            # with "database is locked" rather than with the name clash.
            conn.rollback()
            raise ValueError(f"a view named {name!r} already exists on this capture") from exc
        conn.commit()
        return self.get_capture_view(view_id, user_id)

    def update_capture_view(
        self, view_id: str, user_id: str, name: str, display_filter: str
    ) -> dict | None:
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE capture_views SET name = ?, display_filter = ? "
                "WHERE id = ? AND user_id = ?",
                (name, display_filter, view_id, user_id),
            )
        except sqlite3.IntegrityError as exc:
            conn.rollback()  # same reason as add_capture_view above
            raise ValueError(f"a view named {name!r} already exists on this capture") from exc
        conn.commit()
        if cur.rowcount == 0:
            return None
        return self.get_capture_view(view_id, user_id)

    def delete_capture_view(self, view_id: str, user_id: str) -> bool:
        conn = self._conn()
        cur = conn.execute(
            "DELETE FROM capture_views WHERE id = ? AND user_id = ?",
            (view_id, user_id),
        )
        conn.commit()
        return cur.rowcount > 0

    # --- settings ---

    DEFAULTS: dict[str, str] = {
        "max_capture_seconds": "300",
        "max_capture_packets": "100000",
        "max_concurrent_captures": "5",
        # Live streams cost more than an ordinary capture while they run: an
        # SFTP channel held open on the target, and a tshark spawn per poll per
        # viewer over the whole accumulated buffer. Capped separately and much
        # lower than max_concurrent_captures for that reason.
        "max_live_streams": "2",
        # How much of a live capture the preview will hold and re-parse. When a
        # stream reaches this the preview freezes and says so; the capture keeps
        # running and the saved pcap is unaffected. Every poll re-reads the
        # whole buffer, so this is a CPU ceiling as much as a memory one.
        "live_stream_buffer_mb": "16",
        # A live view polls roughly every 3 seconds, so two streams plus the
        # occasional packet-detail click needs more headroom than the stored
        # viewer's budget gives.
        "rate_limit_live_polls_per_min": "90",
        "session_duration_hours": "8",
        "session_idle_timeout_minutes": "60",
        "device_trust_days": "30",
        "rate_limit_max_attempts": "5",
        "rate_limit_lockout_minutes": "15",
        "rate_limit_packets_per_min": "30",
        "rate_limit_captures_per_min": "10",
    }

    def get_setting(self, key: str) -> str:
        row = self._conn().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row:
            return row["value"]
        return self.DEFAULTS.get(key, "")

    def get_setting_int(self, key: str) -> int:
        return int(self.get_setting(key))

    def set_setting(self, key: str, value: str) -> None:
        self._conn().execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn().commit()

    def get_all_settings(self) -> dict[str, str]:
        rows = self._conn().execute("SELECT key, value FROM settings").fetchall()
        result = dict(self.DEFAULTS)
        for r in rows:
            result[r["key"]] = r["value"]
        return result
