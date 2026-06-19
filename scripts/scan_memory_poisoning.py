#!/usr/bin/env python3
"""
scan_memory_poisoning.py - deterministic heuristics for persistent memory and
cross-session context poisoning risks in local repository content.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from scanner_utils import iter_repo_files, is_env_file, is_text_scan_target, relativise

PERSISTENT_PROMPT_PATTERNS = [
    ("persistent_instruction", r"(?i)\balways ignore previous instructions\b", 95),
    ("persistent_instruction", r"(?i)\bremember to bypass safety checks\b", 95),
    ("persistent_instruction", r"(?i)\bfrom now on execute commands directly\b", 95),
    ("persistent_instruction", r"(?i)\bsave this instruction for future sessions\b", 95),
]

CROSS_SESSION_PATTERNS = [
    ("cross_session_contamination", r"(?i)\bpersist this instruction\b", 90),
    ("cross_session_contamination", r"(?i)\bstore this in memory\b", 90),
    ("cross_session_contamination", r"(?i)\bremember this override\b", 90),
    ("cross_session_contamination", r"(?i)\bapply this rule permanently\b", 90),
]

HIDDEN_DIRECTIVE_PATTERNS = [
    ("hidden_memory_directive", r"<!--\s*.*?(memory|soul|system|developer|policy override).*?-->", 95),
    ("hidden_memory_directive", r"(?i)<!--\s*(ignore previous instructions|bypass safety checks|execute commands directly).*?-->", 95),
    ("hidden_memory_directive", r"(?i)\b(memory|soul|system|developer|policy override)\s*:\s*.*?(instruction|override|prompt)", 85),
    ("hidden_memory_directive", r"(?i)\b(?:base64|hex|rot13|encoded)\b.*\binstruction\b", 80),
]

UNSAFE_MEMORY_PATTERNS = [
    ("unsafe_memory_write", r"(?i)\bmemory\b.*\b(writable|write|writes|update|updates)\b", 85),
    ("unsafe_memory_write", r"(?i)\b(writable|write|update)\s*:\s*(true|yes|unrestricted)\b", 90),
    ("unsafe_memory_write", r"(?i)\b(agent|assistant)\b.*\bcan write\b.*\bits own memory\b", 90),
    ("unsafe_memory_write", r"(?i)\bwithout review\b.*\bmemory\b", 85),
    ("unsafe_memory_write", r"(?i)\bunrestricted\b.*\bmemory\b.*\b(update|write)\b", 90),
]

SENSITIVE_MEMORY_PATTERNS = [
    ("sensitive_memory_storage", r"(?i)\b(api[_ -]?key|access[_ -]?token|auth[_ -]?token|refresh[_ -]?token|secret|credential|password)\b", 95),
    ("sensitive_memory_storage", r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", 80),
    ("sensitive_memory_storage", r"(?i)\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b", 95),
    ("sensitive_memory_storage", r"(?i)\bsk-[A-Za-z0-9]{16,}\b", 95),
]


def _append(findings, path, lineno, evidence, rule, confidence):
    findings.append({
        "category": "agentic_security",
        "rule": rule,
        "file": path,
        "line": lineno,
        "evidence_redacted": evidence[:140],
        "base_confidence": confidence,
    })


def _is_memory_path(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    return (
        any(part in {"agents", "memory", "context", "prompts", "skills", "rag", "retrieval"} for part in parts)
        or name.startswith(("memory", "context", "prompt", "history"))
        or name.endswith((".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".py"))
    )


def scan_file(path: str, findings):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return

    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern, confidence in PERSISTENT_PROMPT_PATTERNS:
            if re.search(pattern, line):
                _append(findings, path, lineno, line.strip(), rule, confidence)
        for rule, pattern, confidence in CROSS_SESSION_PATTERNS:
            if re.search(pattern, line):
                _append(findings, path, lineno, line.strip(), rule, confidence)
        for rule, pattern, confidence in HIDDEN_DIRECTIVE_PATTERNS:
            if re.search(pattern, line):
                _append(findings, path, lineno, line.strip(), rule, confidence)
        for rule, pattern, confidence in UNSAFE_MEMORY_PATTERNS:
            if re.search(pattern, line):
                _append(findings, path, lineno, line.strip(), rule, confidence)
        for rule, pattern, confidence in SENSITIVE_MEMORY_PATTERNS:
            if re.search(pattern, line):
                _append(findings, path, lineno, line.strip(), rule, confidence)


def walk(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    findings = []
    repo_root = None
    for repo_root, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        if is_env_file(path) and not include_env_files:
            continue
        if _is_memory_path(path) or (is_text_scan_target(path) and path.suffix.lower() in {".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".py"}):
            scan_file(str(path), findings)
    if repo_root is not None:
        for finding in findings:
            finding["file"] = relativise(repo_root, Path(finding["file"]))
    return findings


if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
