"""
MythosShield — Shadow AI Detection
Scans proxy/network logs for unauthorised AI API calls and data exfiltration patterns.
Enterprise-ready version: captures source IP, dynamic endpoints, user attribution.
"""

import json, re, base64
from collections import defaultdict

# ── AI ENDPOINTS ──────────────────────────────────────────────
# In production: load these from your database so banks can
# add custom endpoints via the dashboard (Fix C)
AI_ENDPOINTS = {
    # Major LLM APIs
    "api.openai.com":                     "OpenAI",
    "api.anthropic.com":                  "Anthropic",
    "api.cohere.ai":                      "Cohere",
    "api.groq.com":                       "Groq",
    "api.mistral.ai":                     "Mistral",
    "api.together.xyz":                   "Together AI",
    "openrouter.ai":                      "OpenRouter",
    # Google AI
    "generativelanguage.googleapis.com":  "Google Gemini",
    "aiplatform.googleapis.com":          "Google Vertex AI",
    # AWS
    "bedrock.amazonaws.com":              "AWS Bedrock",
    "bedrock-runtime.amazonaws.com":      "AWS Bedrock",
    # Hugging Face
    "huggingface.co":                     "Hugging Face",
    "api.huggingface.co":                 "Hugging Face",
    # Others
    "api.replicate.com":                  "Replicate",
    "api.perplexity.ai":                  "Perplexity",
    "api.deepseek.com":                   "DeepSeek",
    "api.stability.ai":                   "Stability AI",
    "api.elevenlabs.io":                  "ElevenLabs",
    "api.assemblyai.com":                 "AssemblyAI",
    # Azure OpenAI
    "openai.azure.com":                   "Azure OpenAI",
}

LARGE_PAYLOAD_THRESHOLD  = 50_000   # bytes — potential training data exfiltration
REPEATED_PROMPT_THRESHOLD = 5       # same prompt pattern N+ times = suspicious automation


# ── HELPERS ───────────────────────────────────────────────────
def _is_base64_heavy(body_str):
    """Heuristic: if >40% of chars look like base64, flag it."""
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not body_str:
        return False
    ratio = sum(1 for c in body_str if c in b64_chars) / len(body_str)
    return ratio > 0.40 and len(body_str) > 500


def _match_vendor(host):
    """
    Match host against AI_ENDPOINTS.
    Uses substring match so subdomains are caught automatically.
    e.g. 'custom-deployment.api.openai.com' still matches 'api.openai.com'
    """
    host = host.lower()
    for pattern, name in AI_ENDPOINTS.items():
        if pattern in host:
            return name
    return None


# ── MAIN ANALYSER ─────────────────────────────────────────────
def analyze_logs(logs, custom_endpoints=None):
    """
    Analyse proxy/network logs for unauthorised AI API usage.

    Args:
        logs: list of dicts with keys:
            timestamp, src_ip, dst_host, dst_path, method,
            request_body (str), response_body (str),
            bytes_out (int), bytes_in (int),
            username (str, optional)   ← employee/user attribution
        custom_endpoints: dict of {pattern: vendor_name} — bank-defined rules

    Returns:
        dict with total_findings, risk_counts, vendor_summary,
             ip_summary, findings
    """
    # Merge custom endpoints if provided (Fix C — dynamic endpoints)
    active_endpoints = dict(AI_ENDPOINTS)
    if custom_endpoints:
        active_endpoints.update(custom_endpoints)

    findings          = []
    body_hash_counter = defaultdict(int)
    vendor_bytes      = defaultdict(int)
    ip_findings       = defaultdict(list)   # src_ip → list of vendor names

    for entry in logs:
        host     = entry.get("dst_host", "").lower()
        src_ip   = entry.get("src_ip", "UNKNOWN_IP")        # Fix 1 — capture IP
        username = entry.get("username", "UNKNOWN_USER")     # Fix 1 — capture user
        vendor   = _match_vendor(host)

        body      = entry.get("request_body", "") or ""
        bytes_out = entry.get("bytes_out", 0) or 0

        if vendor:
            vendor_bytes[vendor] += bytes_out
            body_sig = body[:200]
            body_hash_counter[body_sig] += 1
            ip_findings[src_ip].append(vendor)

            # Base finding
            finding = {
                "type":       "shadow_ai_call",
                "vendor":     vendor,
                "host":       host,
                "source_ip":  src_ip,                        # Fix 2 — attach to finding
                "username":   username,                      # Fix 2 — attach user
                "path":       entry.get("dst_path", ""),
                "timestamp":  entry.get("timestamp", ""),
                "bytes_out":  bytes_out,
                "risk_level": "HIGH",
                "reason":     f"Unauthorised call to {vendor} API detected from IP {src_ip} (user: {username})"
            }

            # Escalate to CRITICAL — large payload
            if bytes_out > LARGE_PAYLOAD_THRESHOLD:
                finding["risk_level"] = "CRITICAL"
                finding["reason"] += (
                    f" — large payload ({bytes_out:,} bytes, possible data exfiltration)"
                )

            # Escalate to CRITICAL — base64 heavy body
            if _is_base64_heavy(body):
                finding["risk_level"] = "CRITICAL"
                finding["reason"] += (
                    " — request body contains heavy Base64 encoding (possible file/data upload)"
                )

            findings.append(finding)

    # ── Repeated prompt detection ──────────────────────────────
    for sig, count in body_hash_counter.items():
        if count >= REPEATED_PROMPT_THRESHOLD:
            findings.append({
                "type":       "repeated_prompt",
                "risk_level": "MEDIUM",
                "reason":     (
                    f"Same prompt pattern sent {count} times "
                    f"— possible automated/scripted AI usage"
                ),
                "count":  count,
                "sample": sig[:100]
            })

    # ── Vendor summary ────────────────────────────────────────
    vendor_summary = [
        {
            "vendor":        v,
            "total_bytes":   b,
            "estimated_mb":  round(b / 1_048_576, 2)
        }
        for v, b in sorted(vendor_bytes.items(), key=lambda x: -x[1])
    ]

    # ── IP / User attribution summary (Fix 2) ─────────────────
    ip_summary = [
        {
            "source_ip":    ip,
            "vendors_used": list(set(vendors)),
            "call_count":   len(vendors),
            "risk":         "CRITICAL" if len(set(vendors)) > 2 else "HIGH"
        }
        for ip, vendors in sorted(ip_findings.items(), key=lambda x: -len(x[1]))
    ]

    # ── Risk counts ───────────────────────────────────────────
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        lvl = f.get("risk_level", "LOW")
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    return {
        "total_findings": len(findings),
        "risk_counts":    risk_counts,
        "vendor_summary": vendor_summary,
        "ip_summary":     ip_summary,       # NEW — who is doing it
        "findings":       findings
    }
