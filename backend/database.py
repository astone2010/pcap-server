from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path


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
                user_id TEXT NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS trusted_devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                token_hash TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT 'Unknown',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS saved_servers (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                username TEXT NOT NULL,
                ssh_key_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, name)
            );
        """)
        conn.commit()

    # --- users ---

    def create_user(self, user_id: str, username: str, password_hash: str, *, is_admin: bool = False) -> None:
        self._conn().execute(
            "INSERT INTO users (id, username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, ?)",
            (user_id, username, password_hash, datetime.utcnow().isoformat(), int(is_admin)),
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

    # --- trusted devices ---

    def add_trusted_device(self, device_id: str, user_id: str, token_hash: str, name: str, expires_at: str) -> None:
        self._conn().execute(
            "INSERT INTO trusted_devices (id, user_id, token_hash, name, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, user_id, token_hash, name, datetime.utcnow().isoformat(), expires_at),
        )
        self._conn().commit()

    def get_trusted_device_by_hash(self, user_id: str, token_hash: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM trusted_devices WHERE user_id = ? AND token_hash = ? AND expires_at > ?",
            (user_id, token_hash, datetime.utcnow().isoformat()),
        ).fetchone()
        return dict(row) if row else None

    def delete_trusted_devices(self, user_id: str) -> None:
        self._conn().execute("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,))
        self._conn().commit()

    def cleanup_expired_devices(self) -> int:
        cur = self._conn().execute("DELETE FROM trusted_devices WHERE expires_at <= ?", (datetime.utcnow().isoformat(),))
        self._conn().commit()
        return cur.rowcount

    # --- saved servers ---

    def save_server(self, server_id: str, user_id: str, name: str, hostname: str, port: int, username: str, ssh_key_name: str) -> None:
        self._conn().execute(
            """INSERT OR REPLACE INTO saved_servers (id, user_id, name, hostname, port, username, ssh_key_name, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (server_id, user_id, name, hostname, port, username, ssh_key_name, datetime.utcnow().isoformat()),
        )
        self._conn().commit()

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
