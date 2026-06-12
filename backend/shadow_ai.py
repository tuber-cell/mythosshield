"""
MythosShield — Shadow AI Detection
Scans proxy/network logs for unauthorised AI API calls and data exfiltration patterns.
"""

import json, re, base64
from collections import defaultdict

AI_ENDPOINTS = {
    "api.openai.com":        "OpenAI",
    "api.anthropic.com":     "Anthropic",
    "api.cohere.ai":         "Cohere",
    "huggingface.co":        "Hugging Face",
    "api.huggingface.co":    "Hugging Face",
    "api.replicate.com":     "Replicate",
    "generativelanguage.googleapis.com": "Google AI",
    "bedrock.amazonaws.com": "AWS Bedrock",
    "bedrock-runtime.amazonaws.com": "AWS Bedrock",
    "api.groq.com":          "Groq",
    "api.together.xyz":      "Together AI",
    "api.mistral.ai":        "Mistral",
    "openrouter.ai":         "OpenRouter",
}

LARGE_PAYLOAD_THRESHOLD = 50_000   # bytes — potential training data exfiltration
REPEATED_PROMPT_THRESHOLD = 5      # same request body pattern N+ times = suspicious

def _is_base64_heavy(body_str):
    """Heuristic: if >40% of chars look like base64, flag it."""
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not body_str:
        return False
    ratio = sum(1 for c in body_str if c in b64_chars) / len(body_str)
    return ratio > 0.40 and len(body_str) > 500

def analyze_logs(logs):
    """
    logs: list of dicts with keys:
        timestamp, src_ip, dst_host, dst_path, method,
        request_body (str), response_body (str),
        bytes_out (int), bytes_in (int)
    Returns list of findings.
    """
    findings = []
    body_hash_counter = defaultdict(int)
    vendor_bytes = defaultdict(int)

    for entry in logs:
        host = entry.get("dst_host", "").lower()
        vendor = None
        for pattern, name in AI_ENDPOINTS.items():
            if pattern in host:
                vendor = name
                break

        body = entry.get("request_body", "") or ""
        bytes_out = entry.get("bytes_out", 0) or 0

        if vendor:
            vendor_bytes[vendor] += bytes_out
            body_sig = body[:200]
            body_hash_counter[body_sig] += 1

            finding = {
                "type": "shadow_ai_call",
                "vendor": vendor,
                "host": host,
                "path": entry.get("dst_path", ""),
                "timestamp": entry.get("timestamp", ""),
                "bytes_out": bytes_out,
                "risk_level": "HIGH",
                "reason": f"Unauthorised call to {vendor} API detected"
            }

            if bytes_out > LARGE_PAYLOAD_THRESHOLD:
                finding["risk_level"] = "CRITICAL"
                finding["reason"] += f" — large payload ({bytes_out:,} bytes, possible data exfiltration)"

            if _is_base64_heavy(body):
                finding["risk_level"] = "CRITICAL"
                finding["reason"] += " — request body contains heavy base64 encoding (possible file/data upload)"

            findings.append(finding)

    # Flag repeated prompts
    for sig, count in body_hash_counter.items():
        if count >= REPEATED_PROMPT_THRESHOLD:
            findings.append({
                "type": "repeated_prompt",
                "risk_level": "MEDIUM",
                "reason": f"Same prompt pattern sent {count} times — possible automated/scripted AI usage",
                "count": count,
                "sample": sig[:100]
            })

    # Summarise by vendor
    vendor_summary = [
        {
            "vendor": v,
            "total_bytes": b,
            "estimated_mb": round(b / 1_048_576, 2)
        }
        for v, b in sorted(vendor_bytes.items(), key=lambda x: -x[1])
    ]

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        lvl = f.get("risk_level", "LOW")
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    return {
        "total_findings": len(findings),
        "risk_counts": risk_counts,
        "vendor_summary": vendor_summary,
        "findings": findings
    }
