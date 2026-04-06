"""SQLite-based structured logging for the SPIRE NHP daemon.

All log events are persisted to SQLite — no text log files are used anywhere
in this prototype.
"""

import json
import os
import sqlite3
import threading
import time
from enum import Enum


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SQLiteLogger:
    """Thread-safe structured logger backed by SQLite (WAL mode)."""

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    # ── connection management ──

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  REAL    NOT NULL,
                level      TEXT    NOT NULL,
                component  TEXT    NOT NULL,
                message    TEXT    NOT NULL,
                metadata   TEXT,
                spiffe_id  TEXT,
                event_type TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ts  ON logs(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_cmp ON logs(component)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_lvl ON logs(level)")
        conn.commit()

    # ── write helpers ──

    def log(
        self,
        level: LogLevel,
        component: str,
        message: str,
        metadata: dict | None = None,
        spiffe_id: str | None = None,
        event_type: str | None = None,
    ):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO logs "
            "(timestamp, level, component, message, metadata, spiffe_id, event_type) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                time.time(),
                level.value,
                component,
                message,
                json.dumps(metadata) if metadata else None,
                spiffe_id,
                event_type,
            ),
        )
        conn.commit()

    def debug(self, component: str, message: str, **kw):
        self.log(LogLevel.DEBUG, component, message, **kw)

    def info(self, component: str, message: str, **kw):
        self.log(LogLevel.INFO, component, message, **kw)

    def warning(self, component: str, message: str, **kw):
        self.log(LogLevel.WARNING, component, message, **kw)

    def error(self, component: str, message: str, **kw):
        self.log(LogLevel.ERROR, component, message, **kw)

    def critical(self, component: str, message: str, **kw):
        self.log(LogLevel.CRITICAL, component, message, **kw)

    # ── query ──

    def query(
        self,
        component: str | None = None,
        level: LogLevel | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list:
        conn = self._get_conn()
        sql = "SELECT * FROM logs WHERE 1=1"
        params: list = []
        if component:
            sql += " AND component = ?"
            params.append(component)
        if level:
            sql += " AND level = ?"
            params.append(level.value)
        if since:
            sql += " AND timestamp >= ?"
            params.append(since)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        return conn.execute(sql, params).fetchall()

    def query_logs(
        self,
        level: LogLevel | None = None,
        component: str | None = None,
        event_type: str | None = None,
        spiffe_id: str | None = None,
        since: float | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict]:
        """Filtered log query returning a list of row dicts for the admin UI."""
        conn = self._get_conn()
        sql = (
            "SELECT id, timestamp, level, component, message, "
            "metadata, spiffe_id, event_type FROM logs WHERE 1=1"
        )
        params: list = []
        if level is not None:
            sql += " AND level = ?"
            params.append(level.value)
        if component:
            sql += " AND component = ?"
            params.append(component)
        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type)
        if spiffe_id:
            sql += " AND spiffe_id = ?"
            params.append(spiffe_id)
        if since:
            sql += " AND timestamp >= ?"
            params.append(since)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "level": r[2],
                "component": r[3],
                "message": r[4],
                "metadata": json.loads(r[5]) if r[5] else None,
                "spiffe_id": r[6],
                "event_type": r[7],
            }
            for r in rows
        ]

    # ── lifecycle ──

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
