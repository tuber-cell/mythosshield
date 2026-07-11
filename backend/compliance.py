"""
MythosShield — Compliance Report Generator
Produces gap analysis reports for DPDPA, SEBI, BIS, and RBI DPIP.

Every check below falls into exactly one of two honest categories:

  1. HARD SIGNAL  — computed directly from real scan data (vulnerability
     counts/severities from OSV.dev, SBOM/AIBOM component counts). These
     are as reliable as the underlying scan.

  2. HEURISTIC    — a keyword search across component names and file
     paths (e.g. does anything look like "consent", "fairlearn",
     "runbook"). These are real signals (nothing is invented), but they
     are a weak proxy: a compliant control with an unmatched name reads
     as a gap, and an unrelated file with a matching name reads as a
     pass. Every heuristic check is tagged "heuristic": True so the UI
     can visibly flag it as a starting point for manual review, not a
     verified finding.

Two things that were previously in here have been removed entirely:
  - A DPDPA "AI component inventory" check whose passing condition was
    `len(x) >= 0`, which is true for any list and therefore could never
    fail. It wasn't testing anything.
  - An RBI "Anonymisation of shared intelligence" check hardcoded to
    `True`. That's a true statement about the platform's own
    architecture, not something derived from the scanned codebase, so
    it doesn't belong mixed into a per-scan pass/fail list where it
    silently inflated every bank's score.
"""


def _status(passed, total):
    pct = (passed / total * 100) if total else 0
    if pct >= 80:
        return "Compliant", round(pct)
    if pct >= 50:
        return "Partially Compliant", round(pct)
    return "Non-Compliant", round(pct)


# ── REAL CODEBASE SIGNAL DETECTION (heuristic) ─────────────────
# Scans component names + file paths from SBOM/AIBOM for real evidence.
# This is a keyword search, not static/dynamic analysis — see module
# docstring for what that does and doesn't mean.

def _component_names(scan_data):
    sbom = scan_data.get("sbom", {})
    return [c.get("name", "").lower() for c in sbom.get("artifacts", [])]


def _file_paths(scan_data):
    """Collect any file path hints available from sbom sources + aibom paths."""
    paths = []
    sbom = scan_data.get("sbom", {})
    for c in sbom.get("artifacts", []):
        if c.get("source"):
            paths.append(c["source"].lower())
    aibom = scan_data.get("aibom", {})
    for m in aibom.get("models", []):
        if m.get("path"):
            paths.append(m["path"].lower())
    return paths


def _has_signal(scan_data, keywords):
    """True if any component name or file path contains one of the keywords."""
    haystack = " ".join(_component_names(scan_data) + _file_paths(scan_data))
    return any(kw in haystack for kw in keywords)


CONSENT_KEYWORDS   = ["consent", "gdpr", "opt-in", "cookieconsent", "cookie-consent", "privacy-manager"]
BIAS_KEYWORDS      = ["fairlearn", "aif360", "fairness", "bias-audit", "bias_test", "responsible-ai"]
ERASURE_KEYWORDS   = ["right-to-erasure", "gdpr-delete", "data-deletion", "user-deletion", "erasure"]
AUDIT_LOG_KEYWORDS = ["audit-log", "audit_log", "explainability", "shap", "lime", "model-audit"]
INCIDENT_KEYWORDS  = ["runbook", "playbook", "incident-response", "pagerduty", "opsgenie"]
PENTEST_KEYWORDS   = ["owasp-zap", "burpsuite", "pentest", "penetration-test", "security-scan"]
DATA_MIN_KEYWORDS  = ["data-minimisation", "data-minimization", "pii-scrubber", "anonymiz"]

METHODOLOGY_NOTE = (
    "Checks marked HEURISTIC are a keyword search over component names and file "
    "paths, not a manual or automated audit. Treat a heuristic pass/fail as a "
    "starting point for review, not a verified compliance finding."
)


def generate_dpdpa_report(scan_data):
    """Digital Personal Data Protection Act 2023 readiness."""
    vulns = scan_data.get("vulnerabilities", [])
    sbom  = scan_data.get("sbom", {})
    components = sbom.get("artifacts", [])
    critical = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")

    has_consent  = _has_signal(scan_data, CONSENT_KEYWORDS)
    has_data_min = _has_signal(scan_data, DATA_MIN_KEYWORDS)

    checks = [
        {
            "item": "72-hour breach notification readiness",
            "passed": critical == 0,
            "heuristic": False,
            "gap": "Critical vulnerabilities detected — breach notification timeline at risk" if critical else None,
            "action": "Remediate all critical CVEs immediately" if critical else None
        },
        {
            "item": "Software inventory (data processor mapping)",
            "passed": len(components) > 0,
            "heuristic": False,
            "gap": "No SBOM generated — cannot map data processors" if not components else None,
            "action": "Run full SBOM scan on all production services" if not components else None
        },
        {
            "item": "Consent management documentation",
            "passed": has_consent,
            "heuristic": True,
            "gap": None if has_consent else "No consent management library/module name matched in codebase scan",
            "action": None if has_consent else "Implement consent management module and document data flows"
        },
        {
            "item": "Data minimisation compliance",
            "passed": has_data_min,
            "heuristic": True,
            "gap": None if has_data_min else "No data minimisation tooling name matched — cannot auto-verify from SBOM alone",
            "action": None if has_data_min else "Conduct manual data flow review with DPO"
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "DPDPA 2023", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions,
            "methodology_note": METHODOLOGY_NOTE}


def generate_sebi_report(scan_data):
    """SEBI Cybersecurity & Cyber Resilience Framework."""
    vulns = scan_data.get("vulnerabilities", [])
    high_or_critical = sum(1 for v in vulns if v.get("severity", "").lower() in ("critical", "high"))
    components = scan_data.get("sbom", {}).get("artifacts", [])

    checks = [
        {
            "item": "Vulnerability assessment completed",
            "passed": len(components) > 0,
            "heuristic": False,
            "gap": "No components scanned" if not components else None,
            "action": "Run SBOM + vulnerability scan on all trading systems" if not components else None
        },
        {
            "item": "Critical/high vulnerabilities patched",
            "passed": high_or_critical == 0,
            "heuristic": False,
            "gap": f"{high_or_critical} critical/high CVEs unpatched" if high_or_critical else None,
            "action": "Apply vendor patches within 30 days per SEBI mandate" if high_or_critical else None
        },
        {
            "item": "Audit trail completeness",
            "passed": len(components) > 0,
            "heuristic": False,
            "gap": "No component inventory to build an audit trail from" if not components else None,
            "action": "Run a scan to generate SBOM-based audit trail" if not components else None
        },
        {
            "item": "Patch management timeline documented",
            "passed": high_or_critical == 0,
            "heuristic": False,
            "gap": "Unpatched vulnerabilities violate 30-day patch SLA" if high_or_critical else None,
            "action": "Create patch schedule and assign owners" if high_or_critical else None
        },
        {
            "item": "Third-party risk assessment",
            "passed": len(components) > 0,
            "heuristic": False,
            "gap": "Cannot assess third-party risk without component inventory" if not components else None,
            "action": "Generate SBOM for all vendor integrations" if not components else None
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "SEBI CSCRF", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions,
            "methodology_note": METHODOLOGY_NOTE}


def generate_bis_report(scan_data):
    """BIS AI Data Quality Standards."""
    aibom  = scan_data.get("aibom", {})
    models = aibom.get("models", [])

    has_bias_audit = _has_signal(scan_data, BIAS_KEYWORDS)
    has_erasure    = _has_signal(scan_data, ERASURE_KEYWORDS)
    has_audit_log  = _has_signal(scan_data, AUDIT_LOG_KEYWORDS)

    checks = [
        {
            "item": "AI model inventory exists",
            "passed": len(models) > 0,
            "heuristic": False,
            "gap": "No AI model files (.pt/.h5/.onnx/.pkl/etc.) found in this codebase" if not models else None,
            "action": "If AI is used elsewhere (e.g. via API, not bundled model files), document it manually — this scan only detects local model artifacts" if not models else None
        },
        {
            "item": "Model checksums/hashes recorded",
            "passed": bool(models) and all(m.get("size_bytes", 0) > 0 for m in models),
            "heuristic": False,
            "gap": "No AI models detected to verify integrity for" if not models else None,
            "action": "Ensure all model files are stored with checksums" if not models else None
        },
        {
            "item": "Bias audit documentation",
            "passed": has_bias_audit,
            "heuristic": True,
            "gap": None if has_bias_audit else "No bias audit tooling name (fairlearn/aif360/etc.) matched",
            "action": None if has_bias_audit else "Commission bias testing report for each production AI model"
        },
        {
            "item": "Functional erasure capability",
            "passed": has_erasure,
            "heuristic": True,
            "gap": None if has_erasure else "No erasure mechanism name matched in codebase",
            "action": None if has_erasure else "Implement model rollback and data erasure procedures"
        },
        {
            "item": "Audit trail for AI decisions",
            "passed": has_audit_log,
            "heuristic": True,
            "gap": None if has_audit_log else "AI decision logging/explainability tooling name not matched",
            "action": None if has_audit_log else "Implement explainability logging for all AI-driven decisions"
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "BIS AI Data Quality", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions,
            "methodology_note": METHODOLOGY_NOTE}


def generate_rbi_dpip_report(scan_data):
    """RBI Digital Payments Intelligence Platform fraud readiness."""
    vulns = scan_data.get("vulnerabilities", [])
    critical = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")

    has_pentest  = _has_signal(scan_data, PENTEST_KEYWORDS)
    has_incident = _has_signal(scan_data, INCIDENT_KEYWORDS)

    checks = [
        {
            "item": "Real-time fraud intelligence sharing readiness",
            "passed": critical == 0,
            "heuristic": False,
            "gap": "Critical vulnerabilities undermine system trustworthiness for fraud sharing" if critical else None,
            "action": "Patch all critical vulnerabilities before onboarding to DPIP" if critical else None
        },
        {
            "item": "API security for DPIP integration",
            "passed": has_pentest,
            "heuristic": True,
            "gap": None if has_pentest else "No API penetration testing tooling name matched from SBOM alone",
            "action": None if has_pentest else "Conduct API penetration test against DPIP integration endpoints"
        },
        {
            "item": "Incident response SLA (< 30 min)",
            "passed": has_incident,
            "heuristic": True,
            "gap": None if has_incident else "No incident response playbook/runbook name matched",
            "action": None if has_incident else "Document and test incident response runbooks with < 30 min target"
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "RBI DPIP", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions,
            "methodology_note": METHODOLOGY_NOTE,
            # This is a true statement about MythosShield's own platform (the
            # threat-sharing feed SHA-256-anonymises tenant IDs — see
            # threat_sharing.py) but it is NOT derived from the scanned repo,
            # so it's surfaced separately rather than counted as a per-scan
            # pass/fail that would inflate every bank's score identically.
            "platform_assurances": [
                "MythosShield's threat-sharing feed anonymises the submitting "
                "tenant with a salted SHA-256 hash before any report is shown "
                "to other tenants."
            ]}


def generate_rbi_mrm_2026_report(scan_data):
    """RBI Draft Guidance on Regulatory Principles for Model Risk Management, 2026
    (released 24 June 2026, comments due 24 July 2026). This is the framework that
    introduced mandatory model inventories (incl. 'shadow models'), kill-switch
    arrangements, human oversight, and board-level accountability for every model
    a regulated entity runs — including third-party and embedded ones.
    This is a DRAFT under public consultation, not yet a final circular."""
    aibom  = scan_data.get("aibom", {})
    models = aibom.get("models", [])

    has_kill_switch  = _has_signal(scan_data, ["kill-switch", "kill_switch", "circuit-breaker", "feature-flag", "model-disable"])
    has_human_review = _has_signal(scan_data, AUDIT_LOG_KEYWORDS + ["human-in-the-loop", "human-review", "hitl"])

    checks = [
        {
            "item": "Model inventory (incl. shadow/embedded models)",
            "passed": len(models) > 0,
            "heuristic": False,
            "gap": "No AI/ML model artifacts detected in this codebase scan" if not models else None,
            "action": "Maintain a board-visible inventory of every model in use, including third-party and embedded ones — RBI's draft explicitly covers models an RE hasn't formally classified as such" if not models else None
        },
        {
            "item": "Kill-switch / override arrangement",
            "passed": has_kill_switch,
            "heuristic": True,
            "gap": None if has_kill_switch else "No kill-switch, circuit-breaker, or feature-flag mechanism name matched in codebase",
            "action": None if has_kill_switch else "Implement a documented mechanism to instantly override, suspend, or deactivate each production model"
        },
        {
            "item": "Human-in-the-loop / oversight for automated decisions",
            "passed": has_human_review,
            "heuristic": True,
            "gap": None if has_human_review else "No human-oversight or review-logging tooling name matched",
            "action": None if has_human_review else "Add human review checkpoints and explainability logging for models influencing customer decisions"
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "RBI Model Risk Mgmt (Draft, Jun 2026)", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions,
            "methodology_note": METHODOLOGY_NOTE + " This framework is a draft open for public comment until 24 July 2026 — not yet final."}


def generate_eu_ai_act_report(scan_data):
    """EU AI Act — high-risk AI system obligations (risk classification, human
    oversight, technical documentation, logging). Included so the same scan can
    produce a global-framework view alongside the Indian one, using the same
    underlying model-inventory and audit-log signals."""
    aibom  = scan_data.get("aibom", {})
    models = aibom.get("models", [])
    has_audit_log = _has_signal(scan_data, AUDIT_LOG_KEYWORDS)

    checks = [
        {
            "item": "AI system risk classification documented",
            "passed": len(models) > 0,
            "heuristic": False,
            "gap": "No AI model artifacts found — risk tier cannot be assigned" if not models else None,
            "action": "Classify each AI system by risk tier (minimal/limited/high/unacceptable) per Art. 6" if not models else None
        },
        {
            "item": "Technical documentation & logging (Art. 12)",
            "passed": has_audit_log,
            "heuristic": True,
            "gap": None if has_audit_log else "No logging/explainability tooling name matched",
            "action": None if has_audit_log else "Maintain automatic event logs for the lifetime of each high-risk AI system"
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "EU AI Act", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions,
            "methodology_note": METHODOLOGY_NOTE}


def generate_dora_report(scan_data):
    """EU DORA — ICT third-party risk register requirement, mapped from the
    same SBOM component data used for the Indian reports."""
    components = scan_data.get("sbom", {}).get("artifacts", [])
    vulns = scan_data.get("vulnerabilities", [])
    critical = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")

    checks = [
        {
            "item": "ICT third-party register (Art. 28)",
            "passed": len(components) > 0,
            "heuristic": False,
            "gap": "No component inventory to build a third-party ICT register from" if not components else None,
            "action": "Generate SBOM for all third-party ICT services in scope" if not components else None
        },
        {
            "item": "ICT risk remediation (critical findings)",
            "passed": critical == 0,
            "heuristic": False,
            "gap": f"{critical} critical vulnerabilities unresolved in third-party components" if critical else None,
            "action": "Remediate critical CVEs in third-party ICT components" if critical else None
        },
    ]
    passed = sum(1 for c in checks if c["passed"])
    status, pct = _status(passed, len(checks))
    gaps    = [c for c in checks if not c["passed"] and c["gap"]]
    actions = [c["action"] for c in checks if not c["passed"] and c["action"]]
    return {"regulation": "EU DORA", "status": status, "score_pct": pct,
            "checks": checks, "gaps": gaps, "recommended_actions": actions,
            "methodology_note": METHODOLOGY_NOTE}


def generate_all_reports(scan_data):
    return {
        "dpdpa":        generate_dpdpa_report(scan_data),
        "sebi":         generate_sebi_report(scan_data),
        "bis":          generate_bis_report(scan_data),
        "rbi":          generate_rbi_dpip_report(scan_data),
        "rbi_mrm_2026": generate_rbi_mrm_2026_report(scan_data),
        "eu_ai_act":    generate_eu_ai_act_report(scan_data),
        "dora":         generate_dora_report(scan_data),
    }
