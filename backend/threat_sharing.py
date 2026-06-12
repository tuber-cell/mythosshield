"""
MythosShield — Threat Intelligence Sharing
Peer-to-peer CVE/IOC sharing between tenants (opt-in).
Placeholder for future integration with MISP / OpenCTI / STIX-TAXII.
"""

from datetime import datetime

# ---------------------------------------------------------------------------
# In-memory store (replace with DB table when scaling)
# ---------------------------------------------------------------------------
_shared_threats: list[dict] = []


def publish_threat(tenant_id: int, cve_id: str, component: str, notes: str = "") -> dict:
    """
    A tenant publishes a confirmed threat finding for the community.
    In production this would write to a threats table and push to a TAXII feed.
    """
    record = {
        "id": len(_shared_threats) + 1,
        "tenant_id": tenant_id,
        "cve_id": cve_id,
        "component": component,
        "notes": notes,
        "published_at": datetime.utcnow().isoformat(),
    }
    _shared_threats.append(record)
    return record


def get_community_threats(limit: int = 50) -> list[dict]:
    """Return the most recently shared threat records (anonymised tenant_id)."""
    results = sorted(_shared_threats, key=lambda x: x["published_at"], reverse=True)[:limit]
    # Strip raw tenant_id before returning to callers
    return [{**r, "tenant_id": f"tenant_{r['tenant_id']}"} for r in results]


def enrich_with_community_data(cve_id: str) -> dict:
    """
    Check whether any tenant has already confirmed this CVE in the wild.
    Returns a dict with confirmed (bool) and peer_reports count.
    """
    matches = [t for t in _shared_threats if t.get("cve_id") == cve_id]
    return {
        "cve_id": cve_id,
        "confirmed_in_wild": len(matches) > 0,
        "peer_reports": len(matches),
        "first_seen": matches[0]["published_at"] if matches else None,
    }
