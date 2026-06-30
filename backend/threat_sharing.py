"""
MythosShield — Threat Intelligence Sharing
Peer-to-peer CVE/IOC sharing between tenants (opt-in).
"""

import hashlib
from datetime import datetime, timezone

_shared_threats: list[dict] = []

PEER_SALT = "MythosShield_Enterprise_Salt_2026"


def publish_threat(tenant_id: int, cve_id: str, component: str, notes: str = "") -> dict:
    record = {
        "id":           len(_shared_threats) + 1,
        "tenant_id":    tenant_id,
        "cve_id":       cve_id.strip().upper(),
        "component":    component.strip(),
        "notes":        notes.strip(),
        "published_at": datetime.now(timezone.utc).isoformat(),
    }
    _shared_threats.append(record)
    return record


def get_community_threats(limit: int = 50) -> list[dict]:
    results = sorted(_shared_threats, key=lambda x: x["published_at"], reverse=True)[:limit]
    anonymised = []
    for r in results:
        raw_identity = f"{r['tenant_id']}_{PEER_SALT}".encode()
        secure_token = hashlib.sha256(raw_identity).hexdigest()[:16]
        anonymised.append({**r, "tenant_id": f"anon_{secure_token}"})
    return anonymised


def enrich_with_community_data(cve_id: str) -> dict:
    cve_id  = cve_id.strip().upper()
    matches = [t for t in _shared_threats if t.get("cve_id") == cve_id]
    return {
        "cve_id":            cve_id,
        "confirmed_in_wild": len(matches) > 0,
        "peer_reports":      len(matches),
        "first_seen":        matches[0]["published_at"] if matches else None,
        "last_seen":         matches[-1]["published_at"] if matches else None,
    }