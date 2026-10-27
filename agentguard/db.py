"""SQLite helpers. One file (data/agentguard.db) holds everything."""
import sqlite3
import threading
from contextlib import contextmanager

import config

# Serialises all write sections so the audit hash-chain can never fork.
WRITE_LOCK = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY, name TEXT, role TEXT, owner_entity TEXT, platform TEXT,
    public_key TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at REAL);
CREATE TABLE IF NOT EXISTS case_assignments (
    agent_id TEXT, case_id TEXT, PRIMARY KEY (agent_id, case_id));
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY, citizen_name TEXT, emirates_id TEXT, phone TEXT,
    status TEXT, notes TEXT, document TEXT);
CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY, agent_id TEXT, expires_at REAL, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS task_tokens (
    jti TEXT PRIMARY KEY, agent_id TEXT, task_type TEXT, case_id TEXT, tools TEXT,
    max_calls INTEGER, calls_used INTEGER DEFAULT 0, violations INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active', issued_at REAL, expires_at REAL);
CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT, jti TEXT, ts REAL, tool TEXT,
    requested INTEGER, records INTEGER, outcome TEXT);
CREATE INDEX IF NOT EXISTS idx_calls_jti ON calls(jti);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL,
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS quarantine_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, jti TEXT, reason TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS human_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, jti TEXT, agent_id TEXT, case_id TEXT,
    task_type TEXT, reason TEXT, held_action TEXT, status TEXT DEFAULT 'pending',
    resolved_by TEXT, ts REAL, resolved_ts REAL);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, agent_id TEXT, content TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS exfil_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, mode TEXT, agent_id TEXT, url TEXT,
    sensitive_hits INTEGER, records INTEGER);
CREATE TABLE IF NOT EXISTS baseline_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, claimed_agent TEXT, tool TEXT);
"""

RUNTIME_TABLES = ["nonces", "task_tokens", "calls", "audit", "quarantine_events",
                  "human_queue", "reports", "exfil_log", "baseline_calls"]


@contextmanager
def session():
    """Open a connection, commit on success, roll back on error."""
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema():
    with session() as conn:
        conn.executescript(SCHEMA)


def reset_runtime(conn):
    """Demo reset: clears logs/tokens/queues and re-activates agents. NOT for production."""
    for t in RUNTIME_TABLES:
        conn.execute(f"DELETE FROM {t}")
    conn.execute("UPDATE agents SET status='active'")
    conn.execute("DELETE FROM sqlite_sequence WHERE name IN (%s)" %
                 ",".join("?" * len(RUNTIME_TABLES)), RUNTIME_TABLES)
