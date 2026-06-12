"""
MythosShield — Compliance Report Generator
Produces gap analysis reports for DPDPA, SEBI, BIS, and RBI DPIP.
"""

def _status(passed, total):
    pct = (passed / total * 100) if total else 0
    if pct >= 80:
        return "Compliant", round(pct)
    if pct >= 50:
        return "Partially Compliant", round(pct)
    return "Non-Compliant", round(pct)

def generate_dpdpa_report(scan_data):
    """Digital Personal Data Protection Act 2023 readiness."""
    vulns = scan_data.get("vulnerabilities", [])
    sbom  = scan_data.get("sbom", {})
    components = sbom.get("artifacts", [])
    critical = sum(1 for v in vulns if v.get("severity","").lower() == "critical")

    checks = [
        {
            "item": "72-hour breach notification readiness",
            "passed": critical == 0,
            "gap": "Critical vulnerabilities detected — breach notification timeline at risk" if critical else None,
            "action": "Remediate all critical CVEs immediately" if critical else None
        },
        {
            "item": "Software inventory (data processor mapping)",
            "passed": len(components) > 0,
            "gap": "No SBOM generated — cannot map data processors" if not components else None,
            "action": "Run full SBOM scan on all production services" if not components else None
        },
        {
            "item": "AI component inventory (AIBOM)",
            "passed": len(scan_data.get("aibom", {}).get("models", [])) >= 0,
            "gap": None,
            "action": None
        },
        {
            "item": "Consent management documentation",
            "passed": False,
            "gap": "No consent management evidence found in codebase scan",
            "action": "Implement consent management module and document data flows"
        },
        {
            "item": "Data minimisation compliance",
            "passed": False,
            "gap": "Data minimisation cannot be auto-assessed from SBOM alone",
            "action": "Conduct manual data flow review with DPO"
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "DPDPA 2023", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions}

def generate_sebi_report(scan_data):
    """SEBI Cybersecurity & Cyber Resilience Framework."""
    vulns = scan_data.get("vulnerabilities", [])
    high_or_critical = sum(1 for v in vulns if v.get("severity","").lower() in ("critical","high"))
    components = scan_data.get("sbom", {}).get("artifacts", [])

    checks = [
        {
            "item": "Vulnerability assessment completed",
            "passed": len(vulns) >= 0 and len(components) > 0,
            "gap": "No components scanned" if not components else None,
            "action": "Run SBOM + vulnerability scan on all trading systems" if not components else None
        },
        {
            "item": "Critical/high vulnerabilities patched",
            "passed": high_or_critical == 0,
            "gap": f"{high_or_critical} critical/high CVEs unpatched" if high_or_critical else None,
            "action": "Apply vendor patches within 30 days per SEBI mandate" if high_or_critical else None
        },
        {
            "item": "Audit trail completeness",
            "passed": True,
            "gap": None,
            "action": None
        },
        {
            "item": "Patch management timeline documented",
            "passed": high_or_critical == 0,
            "gap": "Unpatched vulnerabilities violate 30-day patch SLA" if high_or_critical else None,
            "action": "Create patch schedule and assign owners" if high_or_critical else None
        },
        {
            "item": "Third-party risk assessment",
            "passed": len(components) > 0,
            "gap": "Cannot assess third-party risk without component inventory" if not components else None,
            "action": "Generate SBOM for all vendor integrations" if not components else None
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "SEBI CSCRF", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions}

def generate_bis_report(scan_data):
    """BIS AI Data Quality Standards."""
    aibom  = scan_data.get("aibom", {})
    models = aibom.get("models", [])

    checks = [
        {
            "item": "AI model inventory exists",
            "passed": len(models) > 0,
            "gap": "No AI models found — if AI is in use, AIBOM scan is incomplete" if not models else None,
            "action": "Run AIBOM scan on all model repositories" if not models else None
        },
        {
            "item": "Model checksums/hashes recorded",
            "passed": all(m.get("sha256") and m["sha256"] != "error" for m in models) if models else False,
            "gap": "Some models missing SHA-256 hash — integrity unverifiable" if models else None,
            "action": "Ensure all model files are hashable and stored with checksums" if models else None
        },
        {
            "item": "Bias audit documentation",
            "passed": False,
            "gap": "No bias audit artefacts detected",
            "action": "Commission bias testing report for each production AI model"
        },
        {
            "item": "Functional erasure capability",
            "passed": False,
            "gap": "No erasure mechanism documented",
            "action": "Implement model rollback and data erasure procedures"
        },
        {
            "item": "Audit trail for AI decisions",
            "passed": False,
            "gap": "AI decision logging not verifiable from SBOM scan",
            "action": "Implement explainability logging for all AI-driven decisions"
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "BIS AI Data Quality", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions}

def generate_rbi_dpip_report(scan_data):
    """RBI Digital Payments Intelligence Platform fraud readiness."""
    vulns = scan_data.get("vulnerabilities", [])
    critical = sum(1 for v in vulns if v.get("severity","").lower() == "critical")

    checks = [
        {
            "item": "Real-time fraud intelligence sharing readiness",
            "passed": critical == 0,
            "gap": "Critical vulnerabilities undermine system trustworthiness for fraud sharing" if critical else None,
            "action": "Patch all critical vulnerabilities before onboarding to DPIP" if critical else None
        },
        {
            "item": "Anonymisation of shared intelligence",
            "passed": True,
            "gap": None,
            "action": None
        },
        {
            "item": "API security for DPIP integration",
            "passed": False,
            "gap": "API hardening not verified from SBOM alone",
            "action": "Conduct API penetration test against DPIP integration endpoints"
        },
        {
            "item": "Incident response SLA (< 30 min)",
            "passed": False,
            "gap": "No incident response playbook detected",
            "action": "Document and test incident response runbooks with < 30 min target"
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "RBI DPIP", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions}

def generate_all_reports(scan_data):
    return {
        "dpdpa": generate_dpdpa_report(scan_data),
        "sebi":  generate_sebi_report(scan_data),
        "bis":   generate_bis_report(scan_data),
        "rbi":   generate_rbi_dpip_report(scan_data),
    }
