"""SQLite storage for projects, scan history, ignored findings and the AI cache."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import DATA_DIR

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, source_type TEXT NOT NULL, path_or_url TEXT NOT NULL,
    base_ref TEXT DEFAULT '', sonar_host TEXT DEFAULT '', sonar_token TEXT DEFAULT '', sonar_project_key TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT NOT NULL,
    finished_at TEXT, verdict TEXT, score INTEGER, grade TEXT, error TEXT, result_json TEXT,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS scans_by_project ON scans(project_id, started_at);
CREATE TABLE IF NOT EXISTS suppressions (
    project_id TEXT NOT NULL, fingerprint TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT, created_at TEXT NOT NULL,
    PRIMARY KEY(project_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS baselines (
    project_id TEXT NOT NULL, fingerprint TEXT NOT NULL, PRIMARY KEY(project_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS ai_cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, created_at TEXT NOT NULL);
"""

PROJECT_FIELDS = ("name", "source_type", "path_or_url", "base_ref")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Storage:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path or DATA_DIR / "reviewer.db")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.executescript(SCHEMA)
            # Scans left running when the server stopped will never finish.
            self._conn.execute("UPDATE scans SET status='error', error='server restarted during scan' WHERE status='running'")
            self._conn.commit()

    def _exec(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _all(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    # projects --------------------------------------------------------------- #
    def add_project(self, data: Dict[str, Any]) -> Dict[str, Any]:
        pid = str(uuid.uuid4())
        values = [str(data.get(k) or "") for k in PROJECT_FIELDS]
        self._exec(f"INSERT INTO projects (id, {', '.join(PROJECT_FIELDS)}, created_at) VALUES (?, {', '.join('?' * len(PROJECT_FIELDS))}, ?)",
                   (pid, *values, now()))
        project = self.get_project(pid)
        assert project is not None
        return project

    def update_project(self, pid: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        fields = [k for k in PROJECT_FIELDS if k in data]
        if fields:
            self._exec(f"UPDATE projects SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?",
                       (*[str(data[k] or "") for k in fields], pid))
        return self.get_project(pid)

    def get_project(self, pid: str) -> Optional[Dict[str, Any]]:
        rows = self._all("SELECT * FROM projects WHERE id=?", (pid,))
        return rows[0] if rows else None

    def list_projects(self) -> List[Dict[str, Any]]:
        return self._all("""
            SELECT p.*, s.verdict AS last_verdict, s.score AS last_score, s.finished_at AS last_scan
            FROM projects p LEFT JOIN scans s ON s.id = (
                SELECT id FROM scans WHERE project_id = p.id AND status = 'done' ORDER BY started_at DESC LIMIT 1)
            ORDER BY p.created_at""")

    def delete_project(self, pid: str) -> None:
        for table in ("scans", "suppressions"):
            self._exec(f"DELETE FROM {table} WHERE project_id=?", (pid,))
        self._exec("DELETE FROM projects WHERE id=?", (pid,))

    # scans ------------------------------------------------------------------ #
    def start_scan(self, project_id: str) -> str:
        sid = str(uuid.uuid4())
        self._exec("INSERT INTO scans (id, project_id, status, started_at) VALUES (?, ?, 'running', ?)",
                   (sid, project_id, now()))
        return sid

    def finish_scan(self, sid: str, result: Dict[str, Any]) -> None:
        health = result.get("health") or {}
        self._exec("UPDATE scans SET status='done', finished_at=?, verdict=?, score=?, grade=?, result_json=? WHERE id=?",
                   (now(), result.get("verdict"), health.get("score"), health.get("grade"), json.dumps(result), sid))

    def update_result(self, sid: str, result: Dict[str, Any]) -> None:
        health = result.get("health") or {}
        self._exec("UPDATE scans SET verdict=?, score=?, grade=?, result_json=? WHERE id=?",
                   (result.get("verdict"), health.get("score"), health.get("grade"), json.dumps(result), sid))

    def fail_scan(self, sid: str, error: str) -> None:
        self._exec("UPDATE scans SET status='error', finished_at=?, error=? WHERE id=?", (now(), error[:4000], sid))

    def get_scan(self, sid: str, with_result: bool = True) -> Optional[Dict[str, Any]]:
        rows = self._all("SELECT * FROM scans WHERE id=?", (sid,))
        if not rows:
            return None
        scan = rows[0]
        raw = scan.pop("result_json", None)
        if with_result and raw:
            scan["result"] = json.loads(raw)
        return scan

    def latest_scan(self, project_id: str) -> Optional[Dict[str, Any]]:
        rows = self._all("SELECT id FROM scans WHERE project_id=? ORDER BY started_at DESC LIMIT 1", (project_id,))
        return self.get_scan(rows[0]["id"]) if rows else None

    def history(self, project_id: str, limit: int = 30) -> List[Dict[str, Any]]:
        rows = self._all("""SELECT id, status, started_at, finished_at, verdict, score, grade FROM scans
                            WHERE project_id=? AND status='done' ORDER BY started_at DESC LIMIT ?""", (project_id, limit))
        return list(reversed(rows))

    # suppressions and baselines ---------------------------------------------- #
    def add_suppression(self, project_id: str, fingerprint: str, kind: str, reason: str = "") -> None:
        self._exec("INSERT OR REPLACE INTO suppressions VALUES (?, ?, ?, ?, ?)",
                   (project_id, fingerprint, kind, reason, now()))

    def remove_suppression(self, project_id: str, fingerprint: str) -> None:
        self._exec("DELETE FROM suppressions WHERE project_id=? AND fingerprint=?", (project_id, fingerprint))

    def suppressions(self, project_id: str) -> Dict[str, str]:
        rows = self._all("SELECT fingerprint, kind, reason FROM suppressions WHERE project_id=?", (project_id,))
        labels = {"false_positive": "marked false positive", "ignore": "ignored"}
        return {r["fingerprint"]: f"{labels.get(r['kind'], r['kind'])}{': ' + r['reason'] if r['reason'] else ''}" for r in rows}

    # AI cache ------------------------------------------------------------------ #
    def cache_get(self, key: str) -> Optional[str]:
        rows = self._all("SELECT value FROM ai_cache WHERE key=?", (key,))
        return rows[0]["value"] if rows else None

    def cache_set(self, key: str, value: str) -> None:
        self._exec("INSERT OR REPLACE INTO ai_cache VALUES (?, ?, ?)", (key, value, now()))
