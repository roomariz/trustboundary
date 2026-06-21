#!/usr/bin/env python
"""Lightweight repository security grep helper.

Usage:
  python scripts/repo_security_grep.py /path/to/repo > security-candidates.json

This script only produces candidate locations for human review. It is not a
vulnerability scanner and must not be cited as sole evidence.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt",
    "coverage", "target", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
    ".pytest_cache", ".terraform", ".serverless", ".gradle", "out"
}

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".tgz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".jar",
    ".class", ".pyc", ".wasm", ".woff", ".woff2", ".ttf", ".mp4", ".mov"
}

PATTERNS = {
    "secrets": re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret|aws_access_key|aws_secret|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY)"),
    "execution": re.compile(r"(?i)(eval\s*\(|exec\s*\(|Function\s*\(|child_process|subprocess|os\.system|popen|spawn\s*\(|shell\s*=\s*True|docker\s+run|kubectl|terraform\s+apply)"),
    "ai_agentic": re.compile(r"(?i)(system prompt|developer message|prompt injection|function_call|tool_call|\bmcp\b|agent|planner|executor|memory|rag|retriever|vector|embedding|browser|computer_use|tool description)"),
    "authz": re.compile(r"(?i)(jwt|session|cookie|csrf|cors|is_admin|role|permission|authorize|authenticate|tenant|organization_id|user_id)"),
    "network_ssrf": re.compile(r"(?i)(fetch\s*\(|requests\.|axios\.|urlopen|http\.get|http\.post|webhook|callback_url|proxy|metadata\.google|169\.254\.169\.254)"),
    "injection": re.compile(r"(?i)(raw\(|execute\(|query\(|SELECT .*\+|INSERT .*\+|UPDATE .*\+|DELETE .*\+|template|render_template|innerHTML|dangerouslySetInnerHTML|pickle|yaml\.load|deserialize)"),
    "ci_supply_chain": re.compile(r"(?i)(curl .*\|.*sh|wget .*\|.*sh|pull_request_target|GITHUB_TOKEN|permissions:\s*write-all|uses:\s*[^@\s]+\s*$|latest|postinstall|preinstall)"),
    "iac_cloud": re.compile(r"(?i)(Principal\s*[:=]\s*['\"]\*|Action\s*[:=]\s*['\"]\*|0\.0\.0\.0/0|privileged:\s*true|hostPath|runAsUser:\s*0|public-read|storage_bucket|security_group|iam_policy)"),
}


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in BINARY_EXTS:
                continue
            try:
                if p.stat().st_size > 2_000_000:
                    continue
            except OSError:
                continue
            yield p


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    results = []
    for path in iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for lineno, line in enumerate(text.splitlines(), 1):
            for category, rx in PATTERNS.items():
                if rx.search(line):
                    results.append({
                        "category": category,
                        "file": rel,
                        "line": lineno,
                        "snippet": line[:500],
                    })
    print(json.dumps({"root": str(root), "candidate_count": len(results), "candidates": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
