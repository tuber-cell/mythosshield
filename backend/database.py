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

# ── SCHEMA ────────────────────────────────────────────────────
# Fix 1: Added security_events table to persist Shadow AI findings
# Fix 2: Added custom_ai_endpoints table for dynamic endpoint rules
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

CREATE TABLE IF NOT EXISTS security_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     INTEGER NOT NULL,
    event_type    TEXT    NOT NULL,
    vendor        TEXT,
    source_ip     TEXT,
    username      TEXT,
    risk_level    TEXT,
    reason        TEXT,
    raw_finding   JSON,
    created_at    TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE TABLE IF NOT EXISTS custom_ai_endpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER NOT NULL,
    pattern     TEXT    NOT NULL,
    vendor_name TEXT    NOT NULL,
    active      INTEGER DEFAULT 1,
    created_at  TEXT    DEFAULT (datetime('now')),
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


# ── CONNECTION ────────────────────────────────────────────────
def get_connection(path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ── INIT ──────────────────────────────────────────────────────
def init_db(path: str = DB_PATH) -> None:
    """Create all tables if they don't already exist."""
    conn = get_connection(path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"[database] Initialised: {path}")


# ── SEED ──────────────────────────────────────────────────────
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


# ── SECURITY EVENTS ───────────────────────────────────────────
def save_security_events(tenant_id: int, findings: list, path: str = DB_PATH) -> int:
    """
    Persist Shadow AI findings to security_events table.
    Called after analyze_logs() returns results.
    Returns number of rows inserted.
    """
    import json
    conn = get_connection(path)
    inserted = 0
    try:
        for f in findings:
            conn.execute(
                """INSERT INTO security_events
                   (tenant_id, event_type, vendor, source_ip, username,
                    risk_level, reason, raw_finding)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    tenant_id,
                    f.get("type", "unknown"),
                    f.get("vendor"),
                    f.get("source_ip"),
                    f.get("username"),
                    f.get("risk_level", "LOW"),
                    f.get("reason", ""),
                    json.dumps(f),
                ),
            )
            inserted += 1
        conn.commit()
    finally:
        conn.close()
    return inserted


# ── CUSTOM ENDPOINTS ──────────────────────────────────────────
def get_custom_endpoints(tenant_id: int, path: str = DB_PATH) -> dict:
    """
    Load bank-defined custom AI endpoint rules from DB.
    Returns dict of {pattern: vendor_name} ready for analyze_logs().
    """
    conn = get_connection(path)
    rows = conn.execute(
        "SELECT pattern, vendor_name FROM custom_ai_endpoints WHERE tenant_id=? AND active=1",
        (tenant_id,)
    ).fetchall()
    conn.close()
    return {row["pattern"]: row["vendor_name"] for row in rows}


def add_custom_endpoint(tenant_id: int, pattern: str, vendor_name: str, path: str = DB_PATH) -> None:
    """Allow a bank to add their own AI endpoint pattern via the dashboard."""
    conn = get_connection(path)
    try:
        conn.execute(
            "INSERT INTO custom_ai_endpoints (tenant_id, pattern, vendor_name) VALUES (?,?,?)",
            (tenant_id, pattern.lower(), vendor_name)
        )
        conn.commit()
    finally:
        conn.close()


# ── INSPECT ───────────────────────────────────────────────────
def inspect(path: str = DB_PATH) -> None:
    """Print row counts for every table — SQL injection safe."""
    conn = get_connection(path)
    # Step 1: get table names using bound query (no f-string)
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()

    print(f"\n[database] Inspecting: {path}")
    print("-" * 36)
    for (t,) in tables:
        # Step 2: bracket-insulate table name to prevent syntax injection
        row_count = conn.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
        print(f"  {t:<28} {row_count} rows")
    print("-" * 36)
    conn.close()


# ── CLI ───────────────────────────────────────────────────────
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
