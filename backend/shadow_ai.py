"""
MythosShield — Shadow AI Detection
Scans proxy/network logs for unauthorised AI API calls and data exfiltration patterns.
"""

import json, re, base64
from collections import defaultdict

AI_ENDPOINTS = {
    "api.openai.com":                     "OpenAI",
    "api.anthropic.com":                  "Anthropic",
    "api.cohere.ai":                      "Cohere",
    "api.groq.com":                       "Groq",
    "api.mistral.ai":                     "Mistral",
    "api.together.xyz":                   "Together AI",
    "openrouter.ai":                      "OpenRouter",
    "generativelanguage.googleapis.com":  "Google Gemini",
    "aiplatform.googleapis.com":          "Google Vertex AI",
    "bedrock.amazonaws.com":              "AWS Bedrock",
    "bedrock-runtime.amazonaws.com":      "AWS Bedrock",
    "huggingface.co":                     "Hugging Face",
    "api.huggingface.co":                 "Hugging Face",
    "api.replicate.com":                  "Replicate",
    "api.perplexity.ai":                  "Perplexity",
    "api.deepseek.com":                   "DeepSeek",
    "api.stability.ai":                   "Stability AI",
    "api.elevenlabs.io":                  "ElevenLabs",
    "api.assemblyai.com":                 "AssemblyAI",
    "openai.azure.com":                   "Azure OpenAI",
}

LARGE_PAYLOAD_THRESHOLD  = 50_000
REPEATED_PROMPT_THRESHOLD = 5


def _is_base64_heavy(body_str):
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not body_str:
        return False
    ratio = sum(1 for c in body_str if c in b64_chars) / len(body_str)
    return ratio > 0.40 and len(body_str) > 500


def _match_vendor(host, active_endpoints):
    host = host.lower()
    for pattern, name in active_endpoints.items():
        if pattern in host:
            return name
    return None


def analyze_logs(logs, custom_endpoints=None):
    active_endpoints = dict(AI_ENDPOINTS)
    if custom_endpoints:
        active_endpoints.update(custom_endpoints)

    findings          = []
    body_hash_counter = defaultdict(int)
    vendor_bytes      = defaultdict(int)
    ip_findings       = defaultdict(list)

    for entry in logs:
        host     = entry.get("dst_host", "").lower()
        src_ip   = entry.get("src_ip", "UNKNOWN_IP")
        username = entry.get("username", "UNKNOWN_USER")
        vendor   = _match_vendor(host, active_endpoints)

        body      = entry.get("request_body", "") or ""
        bytes_out = entry.get("bytes_out", 0) or 0

        if vendor:
            vendor_bytes[vendor] += bytes_out
            body_sig = body[:200]
            body_hash_counter[body_sig] += 1
            ip_findings[src_ip].append(vendor)

            finding = {
                "type":       "shadow_ai_call",
                "vendor":     vendor,
                "host":       host,
                "source_ip":  src_ip,
                "username":   username,
                "path":       entry.get("dst_path", ""),
                "timestamp":  entry.get("timestamp", ""),
                "bytes_out":  bytes_out,
                "risk_level": "HIGH",
                "reason":     f"Unauthorised call to {vendor} API detected from IP {src_ip} (user: {username})"
            }

            if bytes_out > LARGE_PAYLOAD_THRESHOLD:
                finding["risk_level"] = "CRITICAL"
                finding["reason"] += f" — large payload ({bytes_out:,} bytes, possible data exfiltration)"

            if _is_base64_heavy(body):
                finding["risk_level"] = "CRITICAL"
                finding["reason"] += " — request body contains heavy Base64 encoding (possible file/data upload)"

            findings.append(finding)

    for sig, count in body_hash_counter.items():
        if count >= REPEATED_PROMPT_THRESHOLD:
            findings.append({
                "type":       "repeated_prompt",
                "risk_level": "MEDIUM",
                "reason":     f"Same prompt pattern sent {count} times — possible automated/scripted AI usage",
                "count":  count,
                "sample": sig[:100]
            })

    vendor_summary = [
        {"vendor": v, "total_bytes": b, "estimated_mb": round(b / 1_048_576, 2)}
        for v, b in sorted(vendor_bytes.items(), key=lambda x: -x[1])
    ]

    ip_summary = [
        {
            "source_ip":    ip,
            "vendors_used": list(set(vendors)),
            "call_count":   len(vendors),
            "risk":         "CRITICAL" if len(set(vendors)) > 2 else "HIGH"
        }
        for ip, vendors in sorted(ip_findings.items(), key=lambda x: -len(x[1]))
    ]

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        lvl = f.get("risk_level", "LOW")
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    return {
        "total_findings": len(findings),
        "risk_counts":    risk_counts,
        "vendor_summary": vendor_summary,
        "ip_summary":     ip_summary,
        "findings":       findings
    }