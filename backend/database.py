"""
MythosShield — Database helpers
app.py handles DB creation directly via init_db().
This module provides standalone utilities for migrations, inspection,
and optional seed data — useful in CI, tests, and CLI scripts.

Usage:
    python database.py init          # create tables
    python database.py seed          # add a demo tenant
    python database.py inspect       # print row counts per table
"""

import os
import sqlite3
import sys
import bcrypt

DB_PATH = os.environ.get("DB_PATH", "mythosshield.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    bank_name     TEXT    NOT NULL,
    email         TEXT    UNIQUE NOT NULL,
    gst_number    TEXT,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id        INTEGER NOT NULL,
    source           TEXT    NOT NULL,
    sbom             JSON,
    aibom            JSON,
    vulnerabilities  JSON,
    risk_assessment  JSON,
    compliance_score REAL    DEFAULT 0,
    created_at       TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE TABLE IF NOT EXISTS webhooks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  INTEGER NOT NULL,
    url        TEXT    NOT NULL,
    active     INTEGER DEFAULT 1,
    created_at TEXT    DEFAULT (datetime('now'))
);
"""


def get_connection(path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path: str = DB_PATH) -> None:
    """Create all tables if they don't already exist."""
    conn = get_connection(path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"[database] Initialised: {path}")


def seed_demo(path: str = DB_PATH) -> None:
    """Insert a demo tenant (idempotent — skips if email already exists)."""
    pw_hash = bcrypt.hashpw(b"Demo@1234", bcrypt.gensalt()).decode()
    conn = get_connection(path)
    try:
        conn.execute(
            "INSERT INTO tenants (bank_name, email, gst_number, password_hash) VALUES (?,?,?,?)",
            ("Demo Bank Ltd", "demo@mythosshield.in", "29AABCU9603R1Z1", pw_hash),
        )
        conn.commit()
        print("[database] Demo tenant inserted  ->  demo@mythosshield.in / Demo@1234")
    except sqlite3.IntegrityError:
        print("[database] Demo tenant already exists — skipping seed.")
    finally:
        conn.close()


def inspect(path: str = DB_PATH) -> None:
    """Print row counts for every table."""
    conn = get_connection(path)
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    for (t,) in tables:
        count = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t:<20} {count} rows")
    conn.close()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "init":
        init_db()
    elif cmd == "seed":
        init_db()
        seed_demo()
    elif cmd == "inspect":
        inspect()
    else:
        print("Usage: python database.py [init|seed|inspect]")
