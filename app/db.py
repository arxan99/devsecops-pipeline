"""SQLite persistence. Every query is parameterised, so user input is never
concatenated into SQL (prevents SQL injection)."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    owner      TEXT NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner);
"""


class NoteStore:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def create(self, owner: str, title: str, body: str) -> dict:
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO notes (owner, title, body, created_at) VALUES (?, ?, ?, ?)",
                (owner, title, body, now),
            )
            self._conn.commit()
            note_id = cur.lastrowid
        return {"id": note_id, "title": title, "body": body, "created_at": now}

    def list(self, owner: str, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, title, body, created_at FROM notes WHERE owner = ? ORDER BY id DESC LIMIT ?",
                (owner, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get(self, owner: str, note_id: int) -> dict | None:
        # Filtering by owner as well as id prevents one tenant reading another's notes (IDOR).
        with self._lock:
            row = self._conn.execute(
                "SELECT id, title, body, created_at FROM notes WHERE id = ? AND owner = ?",
                (note_id, owner),
            ).fetchone()
        return dict(row) if row else None

    def delete(self, owner: str, note_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM notes WHERE id = ? AND owner = ?", (note_id, owner))
            self._conn.commit()
        return cur.rowcount > 0

    def ping(self) -> bool:
        try:
            with self._lock:
                self._conn.execute("SELECT 1")
            return True
        except sqlite3.Error:
            return False
