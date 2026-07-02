"""
MythosShield — Threat Intelligence Sharing
Peer-to-peer CVE/IOC sharing between tenants (opt-in).

Previously this module kept everything in an in-memory Python list, which
meant: (1) every report vanished on server restart, and (2) app.py seeded
the feed with 3 hardcoded fake reports on every startup so the UI never
looked empty. Both of those made the "community threats feed" fake by
construction. This version persists real submissions to SQLite via
database.py and does not fabricate any data.
"""

import os
import hashlib

from database import publish_threat_db, get_threats_db, get_threats_by_cve_db

# The anonymisation salt MUST come from the environment in production.
# A salt hardcoded in source control provides no real protection — anyone
# with repo access (or this file) could recompute every tenant's token.
PEER_SALT = os.environ.get("PEER_SALT")
if not PEER_SALT:
    PEER_SALT = "dev-only-insecure-salt-set-PEER_SALT-env-var"
    print(
        "[ThreatSharing] WARNING: PEER_SALT env var is not set. Using an "
        "insecure development default. Set a real PEER_SALT in production "
        "so anonymisation tokens can't be recomputed from this source code."
    )


def publish_threat(tenant_id, cve_id: str, component: str, notes: str = "") -> dict:
    """Persist a real, tenant-submitted threat report."""
    return publish_threat_db(tenant_id, cve_id, component, notes)


def get_community_threats(limit: int = 50) -> list:
    """Return real submitted reports, with tenant identity anonymised."""
    rows = get_threats_db(limit)
    anonymised = []
    for r in rows:
        raw_identity = f"{r['tenant_id']}_{PEER_SALT}".encode()
        secure_token = hashlib.sha256(raw_identity).hexdigest()[:16]
        anonymised.append({**r, "tenant_id": f"anon_{secure_token}"})
    return anonymised


def enrich_with_community_data(cve_id: str) -> dict:
    """Look up how many real peer reports exist for a given CVE."""
    cve_id = cve_id.strip().upper()
    matches = get_threats_by_cve_db(cve_id)
    return {
        "cve_id":            cve_id,
        "confirmed_in_wild": len(matches) > 0,
        "peer_reports":      len(matches),
        "first_seen":        matches[0]["published_at"] if matches else None,
        "last_seen":         matches[-1]["published_at"] if matches else None,
    }
