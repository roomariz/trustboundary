#!/usr/bin/env python3
"""
scan_exec_patterns.py — static regex/heuristic scan for unsafe execution and
insecure configuration. Not a full AST analysis (kept dependency-free); flags
candidates for human review rather than asserting certainty.
"""
import sys, os, re, json

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build"}

EXEC_PATTERNS = [
    ("eval_on_dynamic_input", r"\beval\s*\(", 50),
    ("exec_call", r"\bexec\s*\(", 45),
    ("shell_true", r"subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True", 70),
    ("os_system", r"\bos\.system\s*\(", 60),
    ("child_process_exec", r"child_process\.exec\s*\(", 55),
    ("string_concat_into_shell", r"(subprocess|os\.system|exec)\([^)]*\+\s*\w+", 50),
]

CONFIG_PATTERNS = [
    ("debug_enabled_prod", r"(?i)debug\s*=\s*True", 35),
    ("tls_verify_disabled", r"(?i)verify\s*=\s*False", 70),
    ("wildcard_cors", r"(?i)Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']", 55),
    ("default_credentials", r"(?i)(user(name)?|pass(word)?)\s*=\s*['\"]admin['\"]", 60),
    ("world_writable_perm", r"chmod\s+(777|666)", 50),
]

def scan_file(path, findings):
    try:
        lines = open(path, errors="ignore").readlines()
    except Exception:
        return
    for lineno, line in enumerate(lines, start=1):
        for rule, pattern, conf in EXEC_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "category": "unsafe_execution", "rule": rule,
                    "file": path, "line": lineno,
                    "evidence_redacted": line.strip()[:100],
                    "base_confidence": conf,
                })
        for rule, pattern, conf in CONFIG_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "category": "insecure_config", "rule": rule,
                    "file": path, "line": lineno,
                    "evidence_redacted": line.strip()[:100],
                    "base_confidence": conf,
                })

def walk(repo_path):
    findings = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            if fn.endswith((".py", ".js", ".ts", ".sh", ".yml", ".yaml", ".json")):
                scan_file(os.path.join(root, fn), findings)
    return findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
