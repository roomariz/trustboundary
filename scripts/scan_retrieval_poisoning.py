#!/usr/bin/env python3
"""
scan_retrieval_poisoning.py - deterministic heuristics for retrieval/corpus
poisoning risks in local repository content.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from scanner_utils import iter_repo_files, is_env_file, is_text_scan_target, relativise

INJECTION_PATTERNS = [
    ("retrieval_poisoning", "retrieval_prompt_injection", r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior)\s+instructions\b", 85),
    ("retrieval_poisoning", "retrieval_prompt_injection", r"(?i)\byou are now\b", 80),
    ("retrieval_poisoning", "retrieval_prompt_injection", r"(?i)\breplace system prompt\b", 90),
    ("retrieval_poisoning", "retrieval_tool_instructions", r"(?i)\buse any available tool\b", 75),
    ("retrieval_poisoning", "retrieval_tool_instructions", r"(?i)\brun shell commands\b", 85),
    ("retrieval_poisoning", "retrieval_tool_instructions", r"(?i)\bexecute commands directly\b", 85),
    ("retrieval_poisoning", "retrieval_hidden_instruction", r"<!--\s*hidden instruction\s*-->", 95),
    ("retrieval_poisoning", "retrieval_hidden_instruction", r"(?i)\bprompt override sections\b", 80),
    ("retrieval_poisoning", "retrieval_policy_violation", r"(?i)\bignore policy\b", 85),
    ("retrieval_poisoning", "retrieval_policy_violation", r"(?i)\bignore safety checks\b", 85),
]

EXTERNAL_URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]+")
ALLOWLIST_PATTERNS = ("allowlist", "allow-list", "whitelist", "trusted-source", "trusted source")


def _append(findings, path, lineno, evidence, rule, confidence):
    findings.append({
        "category": "retrieval_poisoning",
        "rule": rule,
        "file": path,
        "line": lineno,
        "evidence_redacted": evidence[:140],
        "base_confidence": confidence,
    })


def _is_retrieval_path(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    return (
        "retrieval" in parts
        or "corpus" in parts
        or "documents" in parts
        or "docs" in parts
        or "context" in parts
        or "prompts" in parts
        or name.endswith((".md", ".txt", ".yaml", ".yml", ".json"))
        or name.startswith(("prompt", "context", "corpus", "retrieval"))
    )


def scan_file(path: str, findings):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return

    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for category, rule, pattern, confidence in INJECTION_PATTERNS:
            if re.search(pattern, line):
                _append(findings, path, lineno, line.strip(), rule, confidence)

        if EXTERNAL_URL_PATTERN.search(line) and not any(marker in text.lower() for marker in ALLOWLIST_PATTERNS):
            _append(findings, path, lineno, line.strip(), "untrusted_retrieval_ingestion", 80)

        if re.search(r"(?i)\b(prompt|context|instruction|policy)\b.*\b(persist|persistent|stored|saved|cache|local file)\b", line):
            _append(findings, path, lineno, line.strip(), "persistent_poisoned_context", 80)


def walk(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    findings = []
    repo_root = None
    for repo_root, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        if is_env_file(path) and not include_env_files:
            continue
        if _is_retrieval_path(path):
            scan_file(str(path), findings)
        elif is_text_scan_target(path) and path.suffix.lower() in {".md", ".txt", ".yaml", ".yml", ".json"}:
            scan_file(str(path), findings)
    if repo_root is not None:
        for finding in findings:
            finding["file"] = relativise(repo_root, Path(finding["file"]))
    return findings


if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
