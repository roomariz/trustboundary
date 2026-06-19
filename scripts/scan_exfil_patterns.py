#!/usr/bin/env python3
"""
scan_exfil_patterns.py — flags candidate data-exfiltration vectors: hardcoded
outbound URLs/webhooks, data concatenated into URLs, and DNS-exfil-shaped
strings. Read-only; never makes outbound calls itself.
"""
import sys, os, re, json
from pathlib import Path
from scanner_utils import iter_repo_files, relativise, is_env_file

PATTERNS = [
    ("hardcoded_webhook_url", r"https?://[a-zA-Z0-9.\-]*(webhook|hooks\.slack|discord\.com/api/webhooks)[^\s\"'<>]*", 55),
    ("data_in_url_query", r"https?://[^\s\"'<>]+\?[^\"'<>\s]*(token|key|secret|password|data)=", 60),
    ("suspicious_dns_exfil_shape", r"[a-f0-9]{16,}\.[a-z0-9.\-]+\.(com|net|io|xyz)", 35),
    ("base64_post_body", r"(fetch|axios\.post|requests\.post)\([^)]*btoa\(", 50),
    ("undeclared_telemetry_beacon", r"(?i)(beacon|telemetry|analytics)\.send\(", 30),
    ("network_client_usage", r"\b(requests\.(get|post|put|patch|delete|request|Session)|httpx\.(get|post|put|patch|delete|request|Client|AsyncClient)|aiohttp\.(ClientSession|request)|urllib\.(request|parse)|socket\.(socket|create_connection)|fetch\s*\(|axios\.(get|post|put|patch|delete|request|create))\b", 50),
    ("websocket_client_usage", r"(?i)\b(new\s+WebSocket|WebSocket\s*\(|ws\.(connect|send)|socket\.io)\b", 45),
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

def walk(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    findings = []
    repo_root = None
    for repo_root, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        if is_env_file(path) and not include_env_files:
            continue
        if path.suffix.lower() in (".py", ".js", ".ts", ".sh", ".html"):
            scan_file(str(path), findings)
    if repo_root is not None:
        for finding in findings:
            finding["file"] = relativise(repo_root, Path(finding["file"]))
    return findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
