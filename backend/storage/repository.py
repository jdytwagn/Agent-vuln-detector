from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 2


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TaskRepository:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = Path(db_path or os.environ.get("AGENT_DETECTOR_DB_PATH", "storage/app.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    source_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    model_backend TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    summary_json TEXT,
                    report_json_path TEXT,
                    report_md_path TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluations (
                    id TEXT PRIMARY KEY,
                    manifest_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    model_backend TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    metrics_json TEXT,
                    output_path TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evaluations_created_at ON evaluations(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evaluations_status ON evaluations(status)")
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, utc_now()),
            )

    def schema_info(self) -> dict[str, Any]:
        with self._connect() as conn:
            version = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0]
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall()
            ]
        return {"backend": "sqlite", "db_path": str(self.db_path.resolve()), "schema_version": int(version), "tables": tables}

    def create_scan(self, source_path: str, model_backend: str) -> dict[str, Any]:
        task_id = str(uuid.uuid4())
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (id, source_path, status, model_backend, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (task_id, source_path, "pending", model_backend, now, now),
            )
        return self.get_scan(task_id)

    def update_scan(self, task_id: str, **fields: Any) -> None:
        self._update("scans", task_id, fields)

    def list_scans(self) -> list[dict[str, Any]]:
        return self._list("scans")

    def get_scan(self, task_id: str) -> dict[str, Any]:
        return self._get("scans", task_id)

    def create_evaluation(self, manifest_path: str, model_backend: str) -> dict[str, Any]:
        task_id = str(uuid.uuid4())
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO evaluations (id, manifest_path, status, model_backend, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (task_id, manifest_path, "pending", model_backend, now, now),
            )
        return self.get_evaluation(task_id)

    def update_evaluation(self, task_id: str, **fields: Any) -> None:
        self._update("evaluations", task_id, fields)

    def list_evaluations(self) -> list[dict[str, Any]]:
        return self._list("evaluations")

    def get_evaluation(self, task_id: str) -> dict[str, Any]:
        return self._get("evaluations", task_id)

    def _update(self, table: str, task_id: str, fields: dict[str, Any]) -> None:
        if not fields:
            return
        fields["updated_at"] = utc_now()
        encoded = {key: json.dumps(value, ensure_ascii=False) if key.endswith("_json") and not isinstance(value, str) else value for key, value in fields.items()}
        columns = ", ".join(f"{key} = ?" for key in encoded)
        values = list(encoded.values()) + [task_id]
        with self._connect() as conn:
            conn.execute(f"UPDATE {table} SET {columns} WHERE id = ?", values)

    def _list(self, table: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY created_at DESC").fetchall()
        return [self._row_to_dict(row) for row in rows]

    def _get(self, table: str, task_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(task_id)
        return self._row_to_dict(row)

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for key in ("summary_json", "metrics_json"):
            if data.get(key):
                data[key] = json.loads(data[key])
        return data
