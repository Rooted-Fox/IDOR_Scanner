"""SQLite persistence for scan history (local file, no server)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import ScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT, status TEXT, risk TEXT,
    start_time TEXT, end_time TEXT,
    endpoints INTEGER, parameters INTEGER, objects INTEGER,
    findings INTEGER, data TEXT
);
"""


class Store:
    def __init__(self, path: str = "idor_scanner.db") -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def save(self, result: ScanResult) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (target,status,risk,start_time,end_time,"
            "endpoints,parameters,objects,findings,data) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (result.target, result.status.value, result.risk_rating,
             result.start_time, result.end_time, result.endpoints,
             result.parameters, result.objects, len(result.findings),
             json.dumps(result.to_dict(), default=str)),
        )
        self.conn.commit()
        return cur.lastrowid

    def history(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT target,status,risk,start_time,end_time,findings "
            "FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        cols = ["target", "status", "risk", "start_time", "end_time", "findings"]
        return [dict(zip(cols, r)) for r in rows]

    def close(self) -> None:
        self.conn.close()
