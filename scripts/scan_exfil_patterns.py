#!/usr/bin/env python3
"""
scan_exfil_patterns.py — flags candidate data-exfiltration vectors: hardcoded
outbound URLs/webhooks, data concatenated into URLs, and DNS-exfil-shaped
strings. Read-only; never makes outbound calls itself.
"""
import sys, os, re, json

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build"}

PATTERNS = [
    ("hardcoded_webhook_url", r"https?://[a-zA-Z0-9.\-]*(webhook|hooks\.slack|discord\.com/api/webhooks)[^\s\"'<>]*", 55),
    ("data_in_url_query", r"https?://[^\s\"'<>]+\?[^\"'<>\s]*(token|key|secret|password|data)=", 60),
    ("suspicious_dns_exfil_shape", r"[a-f0-9]{16,}\.[a-z0-9.\-]+\.(com|net|io|xyz)", 35),
    ("base64_post_body", r"(fetch|axios\.post|requests\.post)\([^)]*btoa\(", 50),
    ("undeclared_telemetry_beacon", r"(?i)(beacon|telemetry|analytics)\.send\(", 30),
]

def scan_file(path, findings):
    try:
        lines = open(path, errors="ignore").readlines()
    except Exception:
        return
    for lineno, line in enumerate(lines, start=1):
        for rule, pattern, conf in PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "category": "data_exfiltration", "rule": rule,
                    "file": path, "line": lineno,
                    "evidence_redacted": line.strip()[:100],
                    "base_confidence": conf,
                })

def walk(repo_path):
    findings = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            if fn.endswith((".py", ".js", ".ts", ".sh", ".html")):
                scan_file(os.path.join(root, fn), findings)
    return findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
