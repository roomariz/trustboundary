#!/usr/bin/env python3
"""
scan_secrets.py — read-only secret detector.
Regex signatures for known credential formats + Shannon-entropy check on
generic string literals. Prints JSON findings to stdout. No network access.
"""
import sys, os, re, json, math, fnmatch
from pathlib import Path
from scanner_utils import iter_repo_files, relativise, is_lockfile
LOW_CONTEXT_PATTERNS = ["test", "fixture", "example", "sample", "mock", "placeholder"]

SIGNATURES = [
    ("aws_access_key_id", r"AKIA[0-9A-Z]{16}", 90),
    ("aws_secret_key_assignment", r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", 95),
    ("gcp_api_key", r"AIza[0-9A-Za-z\-_]{35}", 85),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}", 92),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z-]{10,}", 88),
    ("private_key_block", r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", 98),
    ("generic_secret_assignment", r"(?i)(secret|api[_-]?key|password|token)\s*[:=]\s*['\"][^'\"]{12,}['\"]", 55),
]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def context_discount(path: str) -> int:
    lower = path.lower()
    return -30 if any(tag in lower for tag in LOW_CONTEXT_PATTERNS) else 0

def scan_file(path: str, findings: list):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return
    for lineno, line in enumerate(lines, start=1):
        for name, pattern, base_conf in SIGNATURES:
            for m in re.finditer(pattern, line):
                conf = max(0, min(100, base_conf + context_discount(path)))
                findings.append({
                    "category": "leaked_secrets",
                    "rule": name,
                    "file": path,
                    "line": lineno,
                    "evidence_redacted": redact(m.group(0)),
                    "base_confidence": conf,
                })
        # generic high-entropy literal check (cheap heuristic, low base confidence)
        allow_entropy = not is_lockfile(Path(path))
        for m in re.finditer(r"""['"]([A-Za-z0-9+/_\-]{24,})['"]""", line):
            token = m.group(1)
            ent = shannon_entropy(token)
            if allow_entropy and ent > 4.0:
                findings.append({
                    "category": "leaked_secrets",
                    "rule": "high_entropy_literal",
                    "file": path,
                    "line": lineno,
                    "evidence_redacted": redact(token),
                    "base_confidence": max(0, min(100, 40 + context_discount(path))),
                })
            elif not allow_entropy:
                continue

def redact(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return s[:4] + "*" * (len(s) - 8) + s[-4:]

def walk(repo_path: str, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    findings = []
    repo_root = None
    for repo_root, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        if path.name.endswith((".lock",)):
            continue
        scan_file(str(path), findings)
    if repo_root is not None:
        for finding in findings:
            finding["file"] = relativise(repo_root, Path(finding["file"]))
    return findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
