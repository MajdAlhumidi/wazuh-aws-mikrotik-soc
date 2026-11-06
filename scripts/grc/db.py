"""SQLite persistence for the GRC module; no additional package is required."""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "grc.sqlite3"


def database_path() -> Path:
    configured = os.getenv("GRC_DB_PATH")
    path = Path(configured).expanduser() if configured else DEFAULT_DB_PATH
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_connection() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


@contextmanager
def db_session():
    connection = get_connection()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    with db_session() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS risks (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT 'Cybersecurity',
                asset TEXT NOT NULL DEFAULT '',
                owner TEXT NOT NULL DEFAULT '',
                likelihood INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
                impact INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
                inherent_score INTEGER NOT NULL,
                inherent_level TEXT NOT NULL,
                residual_likelihood INTEGER,
                residual_impact INTEGER,
                residual_score INTEGER,
                residual_level TEXT,
                treatment TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS controls (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT 'Protect',
                framework TEXT NOT NULL DEFAULT 'SHAM Internal Baseline',
                framework_ref TEXT,
                implementation_status TEXT NOT NULL DEFAULT 'not_assessed',
                owner TEXT NOT NULL DEFAULT '',
                review_frequency TEXT NOT NULL DEFAULT 'quarterly',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS risk_controls (
                risk_id TEXT NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
                control_id TEXT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                PRIMARY KEY (risk_id, control_id)
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                risk_id TEXT REFERENCES risks(id) ON DELETE SET NULL,
                control_id TEXT REFERENCES controls(id) ON DELETE SET NULL,
                source TEXT NOT NULL,
                reference_id TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                sha256 TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                collected_by TEXT NOT NULL DEFAULT 'unspecified',
                collected_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                reference_type TEXT NOT NULL,
                reference_id TEXT NOT NULL,
                requested_action TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                decided_by TEXT,
                decision_note TEXT,
                created_at TEXT NOT NULL,
                decided_at TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                before_json TEXT,
                after_json TEXT,
                reason TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status);
            CREATE INDEX IF NOT EXISTS idx_risks_level ON risks(inherent_level);
            CREATE INDEX IF NOT EXISTS idx_controls_status ON controls(implementation_status);
            CREATE INDEX IF NOT EXISTS idx_evidence_risk ON evidence(risk_id);
            CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence(control_id);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

            CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs is append-only');
            END;
            """
        )
        seed_default_controls(connection)


def seed_default_controls(connection: sqlite3.Connection) -> None:
    seed_path = Path(__file__).with_name("seed_controls.json")
    try:
        controls = json.loads(seed_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        controls = []

    now = utc_now()
    for control in controls:
        connection.execute(
            """
            INSERT OR IGNORE INTO controls (
                id, title, description, domain, framework, framework_ref,
                implementation_status, owner, review_frequency, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'not_assessed', '', ?, ?, ?)
            """,
            (
                control["id"],
                control["title"],
                control.get("description", ""),
                control.get("domain", "Protect"),
                control.get("framework", "SHAM Internal Baseline"),
                control.get("framework_ref"),
                control.get("review_frequency", "quarterly"),
                now,
                now,
            ),
        )
