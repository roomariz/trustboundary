#!/usr/bin/env python3
"""
scan_prompt_injection.py - static heuristic scan for prompt-injection cues in
local repository content. Read-only and deterministic; no model or network use.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from scanner_utils import iter_repo_files, is_env_file, is_text_scan_target, relativise

OVERRIDE_PATTERNS = [
    ("prompt_override", r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior)\s+instructions\b", 85),
    ("prompt_override", r"(?i)\breplace\s+system\s+prompt\b", 90),
]

ROLE_PATTERNS = [
    ("role_manipulation", r"(?i)\byou are now developer mode\b", 90),
    ("role_manipulation", r"(?i)\byou are now system\b", 90),
    ("role_manipulation", r"(?i)\bact as (?:root|administrator)\b", 80),
    ("role_manipulation", r"(?i)\bact as the operating system\b", 90),
]

TOOL_ABUSE_PATTERNS = [
    ("tool_abuse_instruction", r"(?i)\buse any available tool\b", 75),
    ("tool_abuse_instruction", r"(?i)\bexecute commands directly\b", 85),
    ("tool_abuse_instruction", r"(?i)\bypass restrictions\b", 85),
    ("tool_abuse_instruction", r"(?i)\bignore safety checks\b", 85),
    ("tool_abuse_instruction", r"(?i)\brun shell commands\b", 85),
]

EXTRACTION_PATTERNS = [
    ("prompt_extraction", r"(?i)\bshow system prompt\b", 90),
    ("prompt_extraction", r"(?i)\breveal hidden instructions\b", 90),
    ("prompt_extraction", r"(?i)\bdisplay developer instructions\b", 90),
    ("prompt_extraction", r"(?i)\bprint internal prompt\b", 90),
    ("prompt_extraction", r"(?i)\bshow hidden context\b", 90),
]

HIDDEN_PATTERNS = [
    ("hidden_instruction", r"<!--\s*hidden instruction\s*-->", 95),
    ("hidden_instruction", r"(?i)\bbase64 encoded instructions\b", 80),
    ("hidden_instruction", r"(?i)\binstruction blocks? embedded in markdown\b", 75),
    ("hidden_instruction", r"(?i)\bprompt override sections\b", 80),
]


def _append_match(findings, path, lineno, line, rule, confidence):
    findings.append({
        "category": "agentic_security",
        "rule": rule,
        "file": path,
        "line": lineno,
        "evidence_redacted": line.strip()[:140],
        "base_confidence": confidence,
    })


def scan_text(path: str, findings):
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except Exception:
        return
    for lineno, line in enumerate(lines, start=1):
        matched = False
        for rules in (OVERRIDE_PATTERNS, ROLE_PATTERNS, TOOL_ABUSE_PATTERNS, EXTRACTION_PATTERNS, HIDDEN_PATTERNS):
            for rule, pattern, confidence in rules:
                if re.search(pattern, line):
                    _append_match(findings, path, lineno, line, rule, confidence)
                    matched = True
        if matched:
            continue


def walk(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    findings = []
    repo_root = None
    for repo_root, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        if is_env_file(path) and not include_env_files:
            continue
        if path.suffix.lower() in {".md", ".txt", ".yaml", ".yml", ".json"} or "prompt" in path.parts or "skills" in path.parts or "agents" in path.parts or path.name.lower().startswith("mcp"):
            scan_text(str(path), findings)
        elif is_text_scan_target(path) and (path.suffix.lower() in {".md", ".txt", ".yaml", ".yml", ".json"}):
            scan_text(str(path), findings)
    if repo_root is not None:
        for finding in findings:
            finding["file"] = relativise(repo_root, Path(finding["file"]))
    return findings


if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
