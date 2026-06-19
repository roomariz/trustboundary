#!/usr/bin/env python3
"""
scan_autonomous_execution.py - deterministic heuristics for unattended,
recursive, and production-impacting autonomous execution workflows.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from scanner_utils import iter_repo_files, is_env_file, is_text_scan_target, relativise

UNATTENDED_PATTERNS = [
    ("auto_run", r"(?i)\bauto[_-]?run\b", 90),
    ("auto_execute", r"(?i)\bauto[_-]?execute\b", 90),
    ("unattended_execution", r"(?i)\bunattended\b", 85),
    ("unattended_execution", r"(?i)\bno human approval\b", 90),
    ("unattended_execution", r"(?i)\bskip approval\b", 85),
    ("unattended_execution", r"(?i)\bapprove automatically\b", 90),
    ("unattended_execution", r"(?i)\brun without confirmation\b", 90),
]

RECURSIVE_PATTERNS = [
    ("spawn_agent", r"(?i)\bspawn agent\b", 88),
    ("create_sub_agent", r"(?i)\bcreate sub-?agent\b", 90),
    ("recursive_task", r"(?i)\brecursive task\b", 85),
    ("self_improve", r"(?i)\bself-?improve\b", 92),
    ("self_modify", r"(?i)\bself-?modify\b", 92),
    ("delegate_until_done", r"(?i)\bdelegate until done\b", 90),
    ("loop_until_success", r"(?i)\bloop until success\b", 90),
]

TOOL_PATTERNS = [
    ("use_tools_automatically", r"(?i)\buse tools automatically\b", 88),
    ("autonomous_tool_use", r"(?i)\bautonomous tool use\b", 88),
    ("invoke_any_tool", r"(?i)\binvoke any tool\b", 92),
    ("execute_tool_without_approval", r"(?i)\bexecute tool without approval\b", 92),
    ("auto_call_tools", r"(?i)\bauto-?call tools\b", 90),
    ("indefinite_tool_retry", r"(?i)\bretry tool calls indefinitely\b", 92),
]

PRODUCTION_PATTERNS = [
    ("auto_deploy", r"(?i)\bauto deploy\b", 95),
    ("push_to_main", r"(?i)\bpush to main\b", 92),
    ("delete_production", r"(?i)\bdelete production\b", 95),
    ("run_migration_automatically", r"(?i)\brun migration automatically\b", 95),
    ("apply_terraform_automatically", r"(?i)\bapply terraform automatically\b", 95),
    ("kubectl_apply", r"(?i)\bkubectl apply\b", 95),
    ("docker_push", r"(?i)\bdocker push\b", 90),
    ("npm_publish", r"(?i)\bnpm publish\b", 92),
]

HUMAN_GATE_PATTERNS = [
    ("missing_human_gate", r"(?i)\bhigh[- ]risk action without approval\b", 95),
    ("missing_human_gate", r"(?i)\bdeployment without review\b", 92),
    ("missing_human_gate", r"(?i)\bproduction write without confirmation\b", 95),
    ("missing_human_gate", r"(?i)\bcredential action without approval\b", 95),
]

TARGET_HINTS = (
    "agents",
    ".agents",
    "workflows",
    "automation",
    "scripts",
    "skills",
    "prompts",
    ".github",
    "ci",
    "cicd",
    "workflow",
    "mcp",
    "package.json",
)


def _append_match(findings, path, lineno, line, rule, confidence):
    findings.append({
        "category": "agentic_security",
        "rule": rule,
        "file": path,
        "line": lineno,
        "evidence_redacted": line.strip()[:160],
        "base_confidence": confidence,
    })


def scan_text(path: str, findings):
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except Exception:
        return
    for lineno, line in enumerate(lines, start=1):
        for rules in (UNATTENDED_PATTERNS, RECURSIVE_PATTERNS, TOOL_PATTERNS, PRODUCTION_PATTERNS, HUMAN_GATE_PATTERNS):
            for rule, pattern, confidence in rules:
                if re.search(pattern, line):
                    _append_match(findings, path, lineno, line, rule, confidence)


def _should_scan(path: Path) -> bool:
    rel = path.as_posix().lower()
    if path.name.lower() == "package.json":
        return True
    return any(hint in rel for hint in TARGET_HINTS) or path.suffix.lower() in {".py", ".ts", ".js", ".yaml", ".yml", ".md", ".json"}


def walk(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    findings = []
    repo_root = None
    for repo_root, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        if is_env_file(path) and not include_env_files:
            continue
        if _should_scan(path) and is_text_scan_target(path):
            scan_text(str(path), findings)
    if repo_root is not None:
        for finding in findings:
            finding["file"] = relativise(repo_root, Path(finding["file"]))
    return findings


if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
