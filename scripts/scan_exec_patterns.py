#!/usr/bin/env python3
"""
scan_exec_patterns.py — static regex/heuristic scan for unsafe execution and
insecure configuration. Not a full AST analysis (kept dependency-free); flags
candidates for human review rather than asserting certainty.
"""
import sys, os, re, json
from pathlib import Path
from scanner_utils import iter_repo_files, relativise, is_text_scan_target, is_env_file

EXEC_PATTERNS = [
    ("eval_on_dynamic_input", r"\beval\s*\(", 50),
    ("exec_call", r"\bexec\s*\(", 45),
    ("shell_true", r"subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True", 70),
    ("os_system", r"\bos\.system\s*\(", 60),
    ("child_process_exec", r"child_process\.exec\s*\(", 55),
    ("string_concat_into_shell", r"(subprocess|os\.system|exec)\([^)]*\+\s*\w+", 50),
]

FILESYSTEM_PATTERNS = [
    ("filesystem_read_access", r"\b(open|Path\.open|read_text|read_bytes|os\.listdir|os\.scandir|os\.walk|Path\.glob|Path\.rglob|glob\.glob)\s*\(", 45),
    ("filesystem_write_access", r"\b(write_text|write_bytes|mkdir|makedirs|touch|shutil\.(copy|copytree|move))\s*\(", 55),
    ("filesystem_delete_access", r"\b(os\.remove|os\.unlink|Path\.unlink|os\.rmdir|shutil\.rmtree)\s*\(", 75),
    ("recursive_filesystem_operation", r"\b(os\.walk|Path\.rglob|Path\.glob)\s*\(", 40),
]

ENV_PATTERNS = [
    ("environment_variable_access", r"\b(os\.environ|os\.getenv|getenv\s*\(|load_dotenv\s*\(|dotenv\.load_dotenv\s*\()", 55),
    ("credential_env_passthrough", r"(?i)\b(env|environment)\b.*\b(secret|token|password|key)\b", 60),
]

PROMPT_PATTERNS = [
    ("raw_prompt_concatenation", r"(?i)\b(prompt|system_prompt|messages?)\b.*(\+|\.format\(|f[\"'])\s*(user_input|input|message|messages|content)", 70),
    ("direct_user_input_in_prompt", r"(?i)\b(prompt|system_prompt|messages?|system|user|content|message|chat|model|completion|invoke)\b.*f[\"'][^\"']*\{(?:user_input|input|message|messages|content|query|text|prompt)\}[^\"']*[\"']", 65),
    ("missing_instruction_separation", r"(?i)\b(prompt|system prompt)\b.*\b(append|concat|combine|mix)\b", 60),
]

ACCESS_PATTERNS = [
    ("missing_authentication", r"(?i)\b(skip_auth|bypass_auth|auth_disabled|allow_anonymous|anonymous_access|no_auth)\b", 75),
    ("missing_authorisation", r"(?i)\b(skip_authori[sz]ation|bypass_authori[sz]ation|authorization_disabled|authz_disabled|require_auth\s*=\s*False|authenticate\s*=\s*False)\b", 75),
    ("admin_bypass_risk", r"(?i)\b(admin|superuser|root)\b.*\b(bypass|override|elevate|escalate)\b", 70),
    ("tenant_filter_missing", r"(?i)\b(all tenants|cross[- ]tenant|tenant[- ]agnostic|global query|no tenant filter|without tenant filter)\b", 65),
    ("cross_tenant_retrieval", r"(?i)\b(cross[- ]tenant|tenant leakage|tenant isolation|tenant boundary)\b", 70),
]

CONFIG_PATTERNS = [
    ("debug_enabled_prod", r"(?i)debug\s*=\s*True", 35),
    ("tls_verify_disabled", r"(?i)verify\s*=\s*False", 70),
    ("wildcard_cors", r"(?i)Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']", 55),
    ("default_credentials", r"(?i)(user(name)?|pass(word)?)\s*=\s*['\"]admin['\"]", 60),
    ("world_writable_perm", r"chmod\s+(777|666)", 50),
]


def append_matches(path, lineno, line, findings, category, rules):
    for rule, pattern, conf in rules:
        if re.search(pattern, line):
            findings.append({
                "category": category, "rule": rule,
                "file": path, "line": lineno,
                "evidence_redacted": line.strip()[:100],
                "base_confidence": conf,
            })


def scan_file(path, findings):
    try:
        lines = open(path, errors="ignore").readlines()
    except Exception:
        return
    for lineno, line in enumerate(lines, start=1):
        append_matches(path, lineno, line, findings, "unsafe_execution", EXEC_PATTERNS)
        append_matches(path, lineno, line, findings, "unsafe_execution", FILESYSTEM_PATTERNS)
        append_matches(path, lineno, line, findings, "insecure_config", ENV_PATTERNS)
        append_matches(path, lineno, line, findings, "prompt_injection", PROMPT_PATTERNS)
        append_matches(path, lineno, line, findings, "insecure_config", ACCESS_PATTERNS)
        if re.search(r"(?i)\bprint\s*\(\s*f[\"']", line):
            continue
        if re.search(r"(?i)\bopen\s*\(", line) and re.search(r"(?i)(mode\s*=\s*['\"]?[wax+]|['\"][wax+]['\"])", line):
            findings.append({
                "category": "unsafe_execution", "rule": "filesystem_write_access",
                "file": path, "line": lineno,
                "evidence_redacted": line.strip()[:100],
                "base_confidence": 55,
            })
        for rule, pattern, conf in CONFIG_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "category": "insecure_config", "rule": rule,
                    "file": path, "line": lineno,
                    "evidence_redacted": line.strip()[:100],
                    "base_confidence": conf,
                })

def walk(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None):
    findings = []
    repo_root = None
    for repo_root, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback):
        if is_env_file(path) and not include_env_files:
            continue
        if is_text_scan_target(path):
            scan_file(str(path), findings)
    if repo_root is not None:
        for finding in findings:
            finding["file"] = relativise(repo_root, Path(finding["file"]))
    return findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
