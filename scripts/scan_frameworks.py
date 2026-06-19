#!/usr/bin/env python3
"""
scan_frameworks.py - lightweight framework-aware heuristics for common
pre-production security review surfaces.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from scanner_utils import iter_repo_files, relativise, is_text_scan_target, is_env_file


def scan_file(path, findings):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return

    lower = text.lower()

    if "fastapi" in lower:
        route_match = re.search(r"@app\.(get|post|put|patch|delete)\(", text)
        has_auth_guard = re.search(r"(Depends\(|oauth2|require_auth|auth|role|admin_required)", text, re.IGNORECASE)
        if route_match and not has_auth_guard:
            findings.append({
                "category": "framework_security",
                "framework": "FastAPI",
                "rule": "unauthenticated_route",
                "file": path,
                "line": None,
                "evidence_redacted": "FastAPI route without obvious auth dependency",
                "base_confidence": 70,
            })
        if re.search(r"@app\.(get|post|put|patch|delete)\(.*admin", text, re.IGNORECASE) and not has_auth_guard:
            findings.append({
                "category": "framework_security",
                "framework": "FastAPI",
                "rule": "unrestricted_admin_endpoint",
                "file": path,
                "line": None,
                "evidence_redacted": "Admin-style route without dependency-based auth",
                "base_confidence": 75,
            })
        if route_match and re.search(r"(prompt|system_prompt)\s*=\s*f?[\"'][^\"']*\{(?:user_input|input|message|content|query)\}", text, re.IGNORECASE) and not re.search(r"(validate|sanitize|delimiter|triple backticks|allowlist)", lower):
            findings.append({
                "category": "framework_security",
                "framework": "FastAPI",
                "rule": "unsafe_prompt_construction",
                "file": path,
                "line": None,
                "evidence_redacted": "Prompt construction appears to interpolate user input without clear delimiters or validation",
                "base_confidence": 72,
            })
        if route_match and re.search(r"\b(tool|tools|invoke|run_tool|execute_tool)\b", lower) and not re.search(r"(allowlist|policy|validate|check)", lower):
            findings.append({
                "category": "framework_security",
                "framework": "FastAPI",
                "rule": "unrestricted_tool_execution",
                "file": path,
                "line": None,
                "evidence_redacted": "Tool invocation appears to lack an allowlist or policy check",
                "base_confidence": 74,
            })

    if "supabase" in lower:
        service_role_literal = re.search(r"['\"][^'\"]*service[-_ ]role[^'\"]*['\"]", lower)
        service_role_assignment = re.search(r"(?m)^\s*[\w.]*service[-_ ]role[\w.]*\s*=\s*['\"]", lower)
        if (service_role_literal or service_role_assignment) and "os.getenv" not in lower and "os.environ" not in lower:
            findings.append({
                "category": "framework_security",
                "framework": "Supabase",
                "rule": "service_role_key_exposure",
                "file": path,
                "line": None,
                "evidence_redacted": "Supabase service-role key reference",
                "base_confidence": 85,
            })
        scoped_filter = (
            re.search(r"(tenant_id|user_id|org_id|workspace_id)\s*[=><]", lower)
            or re.search(r"\.eq\(\s*[\"'](tenant_id|user_id|org_id|workspace_id)[\"']", lower)
            or re.search(r"filter\(.+(tenant_id|user_id|org_id|workspace_id)", lower)
        )
        if re.search(r"(\.table\([^\)]*\)\.select\(|\.from\([^\)]*\)\.select\()", lower) and not scoped_filter:
            findings.append({
                "category": "framework_security",
                "framework": "Supabase",
                "rule": "missing_tenant_filters",
                "file": path,
                "line": None,
                "evidence_redacted": "Supabase query without obvious tenant filter",
                "base_confidence": 70,
            })

    if "langgraph" in lower:
        if re.search(r"add_node|add_edge|compile\(", lower) and re.search(r"(tool|tools)", lower) and not re.search(r"(allowlist|validate|policy)", lower):
            findings.append({
                "category": "framework_security",
                "framework": "LangGraph",
                "rule": "unrestricted_tool_routing",
                "file": path,
                "line": None,
                "evidence_redacted": "LangGraph tool routing without validation",
                "base_confidence": 70,
            })
        if re.search(r"state\s*\[.*\]\s*=", text) and re.search(r"graph", lower):
            findings.append({
                "category": "framework_security",
                "framework": "LangGraph",
                "rule": "unsafe_state_mutation",
                "file": path,
                "line": None,
                "evidence_redacted": "Potential unsafe graph state mutation",
                "base_confidence": 60,
            })

    if "openai" in lower and "agents" in lower:
        if re.search(r"(tools?|tool_nodes?)\s*=\s*\[", text) and not re.search(r"(validate|allowlist|policy)", lower):
            findings.append({
                "category": "framework_security",
                "framework": "OpenAI Agents SDK",
                "rule": "unrestricted_tools",
                "file": path,
                "line": None,
                "evidence_redacted": "Agents SDK tools list without validation",
                "base_confidence": 75,
            })
        if re.search(r"tool", lower) and not re.search(r"(validate|check|schema|allowlist)", lower):
            findings.append({
                "category": "framework_security",
                "framework": "OpenAI Agents SDK",
                "rule": "missing_tool_validation",
                "file": path,
                "line": None,
                "evidence_redacted": "Agents SDK tool usage without validation",
                "base_confidence": 65,
            })


def walk(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    findings = []
    repo_root = None
    for repo_root, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
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
