from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


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
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS trusted_devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT 'Unknown',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS saved_servers (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                username TEXT NOT NULL,
                ssh_key_name TEXT NOT NULL,
                use_sudo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, name)
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
                error TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_saved_servers_user_id ON saved_servers(user_id);
            CREATE INDEX IF NOT EXISTS idx_captures_user_id ON captures(user_id);
        """)
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(saved_servers)")}
        if "use_sudo" not in columns:
            conn.execute("ALTER TABLE saved_servers ADD COLUMN use_sudo INTEGER NOT NULL DEFAULT 0")
        conn.commit()

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

    def set_totp_secret(self, user_id: str, secret: str) -> None:
        self._conn().execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
        self._conn().commit()

    def confirm_totp(self, user_id: str) -> None:
        self._conn().execute("UPDATE users SET totp_confirmed = 1 WHERE id = ?", (user_id,))
        self._conn().commit()

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

    def create_session(self, token: str, user_id: str, expires_at: str) -> None:
        self._conn().execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, _utcnow().isoformat(), expires_at),
        )
        self._conn().commit()

    def get_valid_session(self, token: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
            (token, _utcnow().isoformat()),
        ).fetchone()
        return dict(row) if row else None

    def delete_session(self, token: str) -> None:
        self._conn().execute("DELETE FROM sessions WHERE token = ?", (token,))
        self._conn().commit()

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

    # --- saved servers ---

    def save_server(self, server_id: str, user_id: str, name: str, hostname: str, port: int, username: str, ssh_key_name: str, use_sudo: bool = False) -> None:
        self._conn().execute(
            """INSERT OR REPLACE INTO saved_servers (id, user_id, name, hostname, port, username, ssh_key_name, use_sudo, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (server_id, user_id, name, hostname, port, username, ssh_key_name, int(use_sudo), _utcnow().isoformat()),
        )
        self._conn().commit()

    def update_saved_server(self, server_id: str, user_id: str, name: str, hostname: str, port: int, username: str, ssh_key_name: str, use_sudo: bool) -> bool:
        cur = self._conn().execute(
            """UPDATE saved_servers SET name = ?, hostname = ?, port = ?, username = ?, ssh_key_name = ?, use_sudo = ?
               WHERE id = ? AND user_id = ?""",
            (name, hostname, port, username, ssh_key_name, int(use_sudo), server_id, user_id),
        )
        self._conn().commit()
        return cur.rowcount > 0

    def list_saved_servers(self, user_id: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM saved_servers WHERE user_id = ? ORDER BY name", (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_saved_server(self, server_id: str, user_id: str) -> bool:
        cur = self._conn().execute(
            "DELETE FROM saved_servers WHERE id = ? AND user_id = ?", (server_id, user_id)
        )
        self._conn().commit()
        return cur.rowcount > 0

    def get_saved_server(self, server_id: str, user_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM saved_servers WHERE id = ? AND user_id = ?", (server_id, user_id)
        ).fetchone()
        return dict(row) if row else None

    # --- captures ---

    def upsert_capture(self, row: dict) -> None:
        self._conn().execute(
            """INSERT OR REPLACE INTO captures
               (id, user_id, server_id, status, started_at, stopped_at, command,
                remote_path, local_path, packet_count, file_size, error)
               VALUES (:id, :user_id, :server_id, :status, :started_at, :stopped_at, :command,
                       :remote_path, :local_path, :packet_count, :file_size, :error)""",
            row,
        )
        self._conn().commit()

    def list_captures(self) -> list[dict]:
        rows = self._conn().execute("SELECT * FROM captures ORDER BY started_at").fetchall()
        return [dict(r) for r in rows]

    def delete_capture(self, capture_id: str) -> None:
        self._conn().execute("DELETE FROM captures WHERE id = ?", (capture_id,))
        self._conn().commit()

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

    # --- settings ---

    DEFAULTS: dict[str, str] = {
        "max_capture_seconds": "300",
        "max_capture_packets": "100000",
        "session_duration_hours": "8",
        "device_trust_days": "30",
        "rate_limit_max_attempts": "5",
        "rate_limit_lockout_minutes": "15",
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
