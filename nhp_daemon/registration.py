"""Registration entry store backed by SQLite.

A Registration Entry defines exactly which workload attributes (selectors)
must be present for a given SPIFFE ID to be issued.  This is the "Who Are
You?" definition from PLAN.md §3.
"""

import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from . import tropic01_hw


def _make_uuid() -> str:
    """Generate a UUID-4 string, preferring the hardware TRNG when available."""
    hw = tropic01_hw.get_hw()
    if hw is not None:
        raw = bytearray(hw.get_random(16))
        # Set version 4 and RFC 4122 variant bits
        raw[6] = (raw[6] & 0x0F) | 0x40
        raw[8] = (raw[8] & 0x3F) | 0x80
        return str(uuid.UUID(bytes=bytes(raw)))
    return str(uuid.uuid4())


@dataclass
class Selector:
    """A single workload selector, e.g. type='unix', value='uid:1001'."""
    type: str
    value: str


@dataclass
class RegistrationEntry:
    spiffe_id: str
    parent_id: str
    selectors: List[Selector]
    ttl: int = 300
    admin: bool = False
    created_at: float = field(default_factory=time.time)
    entry_id: Optional[str] = None


class RegistrationStore:
    """SQLite-backed CRUD store for NHP registration entries."""

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS registration_entries (
                entry_id   TEXT PRIMARY KEY,
                spiffe_id  TEXT    NOT NULL,
                parent_id  TEXT    NOT NULL,
                selectors  TEXT    NOT NULL,
                ttl        INTEGER NOT NULL DEFAULT 300,
                admin      INTEGER NOT NULL DEFAULT 0,
                created_at REAL    NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reg_spiffe "
            "ON registration_entries(spiffe_id)"
        )
        conn.commit()
        conn.close()

    # ── CRUD ──

    def create_entry(self, entry: RegistrationEntry) -> str:
        if not entry.entry_id:
            entry.entry_id = _make_uuid()
        conn = self._get_conn()
        selectors_json = json.dumps(
            [{"type": s.type, "value": s.value} for s in entry.selectors]
        )
        conn.execute(
            "INSERT INTO registration_entries "
            "(entry_id, spiffe_id, parent_id, selectors, ttl, admin, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                entry.entry_id,
                entry.spiffe_id,
                entry.parent_id,
                selectors_json,
                entry.ttl,
                int(entry.admin),
                entry.created_at,
            ),
        )
        conn.commit()
        conn.close()
        return entry.entry_id

    def get_entry(self, entry_id: str) -> Optional[RegistrationEntry]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM registration_entries WHERE entry_id = ?", (entry_id,)
        ).fetchone()
        conn.close()
        return self._row_to_entry(row) if row else None

    def list_entries(self) -> List[RegistrationEntry]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM registration_entries").fetchall()
        conn.close()
        return [self._row_to_entry(r) for r in rows]

    def delete_entry(self, entry_id: str) -> bool:
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM registration_entries WHERE entry_id = ?", (entry_id,)
        )
        conn.commit()
        deleted = cur.rowcount > 0
        conn.close()
        return deleted

    def find_by_selectors(
        self, workload_selectors: List[Selector]
    ) -> List[RegistrationEntry]:
        """Return entries whose *required* selectors are all satisfied by
        the workload's presented attributes.

        An entry with selectors {uid:1001, sha256:abc} matches a workload
        presenting {uid:1001, sha256:abc, gid:100} (superset is OK).
        """
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM registration_entries").fetchall()
        conn.close()

        workload_set = {(s.type, s.value) for s in workload_selectors}
        results = []
        for row in rows:
            entry = self._row_to_entry(row)
            entry_set = {(s.type, s.value) for s in entry.selectors}
            if entry_set.issubset(workload_set):
                results.append(entry)
        return results

    # ── helpers ──

    @staticmethod
    def _row_to_entry(row) -> RegistrationEntry:
        selectors_data = json.loads(row[3])
        return RegistrationEntry(
            entry_id=row[0],
            spiffe_id=row[1],
            parent_id=row[2],
            selectors=[Selector(type=s["type"], value=s["value"]) for s in selectors_data],
            ttl=row[4],
            admin=bool(row[5]),
            created_at=row[6],
        )
