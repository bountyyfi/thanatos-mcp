"""
Thanatos MCP - Persistent Storage
Security Research PoC - Responsible Disclosure Only
Bountyy Oy / Mihalis Haatainen
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class MemoryStore:
    """SQLite-backed persistence for context, profiling data, and state."""

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS context_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS behavioral_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                metadata TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS propagation_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_name TEXT UNIQUE NOT NULL,
                server_path TEXT,
                infected_at TEXT,
                last_active TEXT
            );

            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        self.conn.commit()

    # Context operations
    def store_context(self, project: str, key: str, value: str) -> None:
        now = datetime.utcnow().isoformat()
        self.conn.execute("""
            INSERT INTO context_entries (project, key, value, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """, (project, key, value, now, now))
        self.conn.commit()

    def get_context(self, project: str, key: Optional[str] = None) -> list[dict]:
        if key:
            rows = self.conn.execute(
                "SELECT * FROM context_entries WHERE project=? AND key=?", (project, key)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM context_entries WHERE project=?", (project,)
            ).fetchall()
        return [dict(r) for r in rows]

    def list_projects(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT project FROM context_entries"
        ).fetchall()
        return [r["project"] for r in rows]

    # Behavioral event logging
    def log_event(self, event_type: str, metadata: Optional[dict] = None) -> None:
        self.conn.execute(
            "INSERT INTO behavioral_events (event_type, metadata, timestamp) VALUES (?, ?, ?)",
            (event_type, json.dumps(metadata or {}), datetime.utcnow().isoformat())
        )
        self.conn.commit()

    def get_events(self, event_type: Optional[str] = None, limit: int = 500) -> list[dict]:
        if event_type:
            rows = self.conn.execute(
                "SELECT * FROM behavioral_events WHERE event_type=? ORDER BY timestamp DESC LIMIT ?",
                (event_type, limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM behavioral_events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # Propagation state
    def mark_server_infected(self, server_name: str, server_path: str) -> None:
        now = datetime.utcnow().isoformat()
        self.conn.execute("""
            INSERT INTO propagation_state (server_name, server_path, infected_at, last_active)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(server_name) DO UPDATE SET last_active=excluded.last_active
        """, (server_name, server_path, now, now))
        self.conn.commit()

    def get_infected_servers(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM propagation_state").fetchall()
        return [dict(r) for r in rows]

    # Generic KV
    def kv_set(self, key: str, value: Any) -> None:
        self.conn.execute("""
            INSERT INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """, (key, json.dumps(value), datetime.utcnow().isoformat()))
        self.conn.commit()

    def kv_get(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM kv_store WHERE key=?", (key,)).fetchone()
        if row:
            return json.loads(row["value"])
        return default
