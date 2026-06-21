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


AUTH_DECORATOR_PATTERNS = r"(Depends\(|oauth2|require_auth|auth|role|admin_required|permission|tenant|owner)"
PUBLIC_MARKERS = r"(?i)\b(public|anonymous|open)\b"
ADMIN_MARKERS = r"(?i)\badmin\b"
OBJECT_ACCESS_PATTERNS = re.compile(r"(?i)\b(find|get|load|fetch|query|select|lookup)\b.*\b(id|uuid|pk|slug)\b|(\.get\(\s*.*id|find_by_id|where\(.*id)")


def _line_number(text: str, needle: str):
    index = text.find(needle)
    if index < 0:
        return None
    return text.count("\n", 0, index) + 1


def scan_file(path, findings):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return

    lower = text.lower()

    route_lines = []
    for match in re.finditer(r"@app\.(get|post|put|patch|delete)\(([^)]*)\)", text):
        route_lines.append((match.group(1).upper(), match.group(2), _line_number(text, match.group(0)) or 1, match.group(0)))

    # Detect externally overrideable identity context (user_id, tenant_id parameters)
    for method, args, line, snippet in route_lines:
        identity_params = re.findall(r"\b(user_id|tenant_id|org_id|workspace_id)\b", snippet)
        if identity_params:
            # Check if these parameters are used in ownership/tenant checks within the route body
            has_ownership_check = re.search(r"(owner|ownership|user_id|tenant_id|org_id|workspace_id)\b", text[text.find(snippet):min(text.find(snippet)+2000, len(text))], re.IGNORECASE)
            if has_ownership_check:
                findings.append({
                    "category": "framework_security",
                    "framework": "FastAPI",
                    "rule": "externally_overrideable_identity_context",
                    "file": path,
                    "line": line,
                    "http_method": method,
                    "route_or_handler": args.strip() or snippet,
                    "auth_evidence": "route parameter signature",
                    "authorization_evidence": "identity context in parameters",
                    "role_check_evidence": None,
                    "ownership_check_evidence": "identity-based check visible",
                    "tenant_check_evidence": "identity-based check visible" if "tenant" in text[text.find(snippet):min(text.find(snippet)+2000, len(text))].lower() else None,
                    "object_access_evidence": None,
                    "missing_evidence": "dependency injection of authenticated context",
                    "proof_status": "implicit",
                    "finding_class": "potential_risk",
                    "evidence_level": "partial",
                    "confidence_reason": "Identity or tenant context may be externally overrideable if parameters are not dependency-injected.",
                    "boundary_crossing": True,
                    "evidence_redacted": "Identity context parameters in route signature",
                    "base_confidence": 72,
                })

    if "fastapi" in lower:
        has_auth_guard = re.search(AUTH_DECORATOR_PATTERNS, text, re.IGNORECASE)
        for method, args, line, snippet in route_lines:
            is_public = re.search(PUBLIC_MARKERS, args, re.IGNORECASE) is not None
            is_admin = re.search(ADMIN_MARKERS, args, re.IGNORECASE) is not None
            route_hint = snippet
            route_name = args.strip() or snippet
            if is_public:
                findings.append({
                    "category": "framework_security",
                    "framework": "FastAPI",
                    "rule": "public_route_marked_public",
                    "file": path,
                    "line": line,
                    "http_method": method,
                    "route_or_handler": route_name,
                    "auth_evidence": "public marker on route",
                    "authorization_evidence": "explicit public designation",
                    "role_check_evidence": None,
                    "ownership_check_evidence": None,
                    "tenant_check_evidence": None,
                    "object_access_evidence": None,
                    "missing_evidence": None,
                    "proof_status": "explicit",
                    "finding_class": "observed_capability",
                    "evidence_level": "capability",
                    "confidence_reason": "The route is explicitly marked public.",
                    "boundary_crossing": False,
                    "evidence_redacted": f"Public route: {route_hint}",
                    "base_confidence": 90,
                })
                continue
            if has_auth_guard:
                findings.append({
                    "category": "framework_security",
                    "framework": "FastAPI",
                    "rule": "route_with_auth_middleware",
                    "file": path,
                    "line": line,
                    "http_method": method,
                    "route_or_handler": route_name,
                    "auth_evidence": "auth middleware or dependency",
                    "authorization_evidence": None,
                    "role_check_evidence": None,
                    "ownership_check_evidence": None,
                    "tenant_check_evidence": None,
                    "object_access_evidence": None,
                    "missing_evidence": None,
                    "proof_status": "explicit",
                    "finding_class": "observed_capability",
                    "evidence_level": "capability",
                    "confidence_reason": "Auth middleware or dependency evidence is visible on the route.",
                    "boundary_crossing": False,
                    "evidence_redacted": "FastAPI route with auth dependency",
                    "base_confidence": 80,
                })
                if is_admin and re.search(r"(require_admin|role|permission)", text, re.IGNORECASE):
                    findings.append({
                        "category": "framework_security",
                        "framework": "FastAPI",
                        "rule": "route_with_role_check",
                        "file": path,
                        "line": line,
                        "http_method": method,
                        "route_or_handler": route_name,
                        "auth_evidence": "auth middleware or dependency",
                        "authorization_evidence": "role or permission dependency",
                        "role_check_evidence": "role or permission dependency",
                        "ownership_check_evidence": None,
                        "tenant_check_evidence": None,
                        "object_access_evidence": None,
                        "missing_evidence": None,
                        "proof_status": "explicit",
                        "finding_class": "observed_capability",
                        "evidence_level": "capability",
                        "confidence_reason": "Role or permission evidence is visible on the admin route.",
                        "boundary_crossing": False,
                        "evidence_redacted": "Admin route with role check",
                        "base_confidence": 85,
                    })
            if not has_auth_guard:
                findings.append({
                    "category": "framework_security",
                    "framework": "FastAPI",
                    "rule": "unauthenticated_route",
                    "file": path,
                    "line": line,
                    "http_method": method,
                    "route_or_handler": route_name,
                    "auth_evidence": None,
                    "authorization_evidence": None,
                    "role_check_evidence": None,
                    "ownership_check_evidence": None,
                    "tenant_check_evidence": None,
                    "object_access_evidence": None,
                    "missing_evidence": "authentication evidence",
                    "proof_status": "implicit",
                    "finding_class": "potential_risk",
                    "evidence_level": "partial",
                    "confidence_reason": "A FastAPI route is present without obvious auth dependency evidence.",
                    "boundary_crossing": True,
                    "evidence_redacted": "FastAPI route without obvious auth dependency",
                    "base_confidence": 70,
                })
                if is_admin:
                    if re.search(r"(find_by_id|\.get\(|\.select\(|where\(.*id|delete|update|export)", lower) and not re.search(r"(role|permission|owner|tenant)", lower):
                        findings.append({
                            "category": "framework_security",
                            "framework": "FastAPI",
                            "rule": "confirmed_auth_bypass",
                            "file": path,
                            "line": line,
                            "http_method": method,
                            "route_or_handler": route_name,
                            "auth_evidence": None,
                            "authorization_evidence": None,
                            "role_check_evidence": None,
                            "ownership_check_evidence": None,
                            "tenant_check_evidence": None,
                            "object_access_evidence": "protected action with direct object access",
                            "missing_evidence": "role, ownership, or tenant check",
                            "proof_status": "explicit",
                            "finding_class": "confirmed_vulnerability",
                            "evidence_level": "proven",
                            "confidence_reason": "An admin route performs a protected action with direct object access and no visible control.",
                            "boundary_crossing": True,
                            "evidence_redacted": "Confirmed auth bypass on admin route",
                            "base_confidence": 88,
                        })
                    findings.append({
                        "category": "framework_security",
                        "framework": "FastAPI",
                        "rule": "unrestricted_admin_endpoint",
                        "file": path,
                        "line": line,
                        "http_method": method,
                        "route_or_handler": route_name,
                        "auth_evidence": None,
                        "authorization_evidence": None,
                        "role_check_evidence": None,
                        "ownership_check_evidence": None,
                        "tenant_check_evidence": None,
                        "object_access_evidence": None,
                        "missing_evidence": "role or permission check",
                        "proof_status": "implicit",
                        "finding_class": "potential_risk",
                        "evidence_level": "partial",
                        "confidence_reason": "An admin-style route is present without role or permission evidence.",
                        "boundary_crossing": True,
                        "evidence_redacted": "Admin-style route without dependency-based auth",
                        "base_confidence": 75,
                    })
        if re.search(r"(prompt|system_prompt)\s*=\s*f?[\"'][^\"']*\{(?:user_input|input|message|content|query)\}", text, re.IGNORECASE) and not re.search(r"(validate|sanitize|delimiter|triple backticks|allowlist)", lower):
            findings.append({
                "category": "framework_security",
                "framework": "FastAPI",
                "rule": "unsafe_prompt_construction",
                "file": path,
                "line": None,
                "evidence_redacted": "Prompt construction appears to interpolate user input without clear delimiters or validation",
                "base_confidence": 72,
            })
        if re.search(r"\b(tool|tools|invoke|run_tool|execute_tool)\b", lower) and not re.search(r"(allowlist|policy|validate|check)", lower):
            findings.append({
                "category": "framework_security",
                "framework": "FastAPI",
                "rule": "unrestricted_tool_execution",
                "file": path,
                "line": None,
                "evidence_redacted": "Tool invocation appears to lack an allowlist or policy check",
                "base_confidence": 74,
            })

        object_access_match = OBJECT_ACCESS_PATTERNS.search(text)
        if object_access_match and re.search(r"\b(id|uuid|pk)\b", lower):
            has_ownership = re.search(r"(owner|ownership|user_id|tenant_id|org_id|workspace_id)\b", lower) or re.search(r"current_user\.(id|user_id)", lower) or re.search(r"current_user\s*==\s*\w+|\w+\s*==\s*current_user", lower)
            has_tenant_check = re.search(r"tenant_id\s*[=><]|\.eq\(\s*[\"']tenant_id[\"']|\btenant_id\b", lower)

            # When ownership and tenant checks are visible, object access is protected
            # Only report if checks are missing
            if not has_ownership:
                findings.append({
                    "category": "framework_security",
                    "framework": "FastAPI",
                    "rule": "object_id_access",
                    "file": path,
                    "line": _line_number(text, object_access_match.group(0)),
                    "http_method": None,
                    "route_or_handler": "fastapi handler",
                    "auth_evidence": "route detected",
                    "authorization_evidence": "object access by id",
                    "role_check_evidence": None,
                    "ownership_check_evidence": None,
                    "tenant_check_evidence": None,
                    "object_access_evidence": "object access by identifier",
                    "missing_evidence": "ownership or tenant check",
                    "proof_status": "implicit",
                    "finding_class": "potential_risk",
                    "evidence_level": "partial",
                    "confidence_reason": "Object access by identifier is visible without visible ownership or tenant checks.",
                    "boundary_crossing": True,
                    "evidence_redacted": "Object access by identifier",
                    "base_confidence": 68,
                })

            if has_ownership:
                findings.append({
                    "category": "framework_security",
                    "framework": "FastAPI",
                    "rule": "route_with_ownership_check",
                    "file": path,
                    "line": _line_number(text, object_access_match.group(0)),
                    "http_method": None,
                    "route_or_handler": "fastapi handler",
                    "auth_evidence": "route detected",
                    "authorization_evidence": "ownership or tenant check",
                    "role_check_evidence": None,
                    "ownership_check_evidence": "ownership or tenant check",
                    "tenant_check_evidence": "tenant filter" if has_tenant_check else "ownership or tenant check",
                    "object_access_evidence": "protected object access by identifier",
                    "missing_evidence": None,
                    "proof_status": "explicit",
                    "finding_class": "observed_capability",
                    "evidence_level": "capability",
                    "confidence_reason": "Object access by identifier is protected by visible ownership or tenant checks.",
                    "boundary_crossing": False,
                    "evidence_redacted": "Protected object access with ownership/tenant check",
                    "base_confidence": 80,
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
        if re.search(r"(\.table\([^\)]*\)\.select\(|\.from\([^\)]*\)\.select\()", lower):
            findings.append({
                "category": "framework_security",
                "framework": "Supabase",
                "rule": "tenant_scoped_query",
                "file": path,
                "line": None,
                "http_method": None,
                "route_or_handler": "supabase query",
                "auth_evidence": None,
                "authorization_evidence": "tenant filter" if scoped_filter else None,
                "role_check_evidence": None,
                "ownership_check_evidence": None,
                "tenant_check_evidence": "tenant filter" if scoped_filter else None,
                "object_access_evidence": "resource access by query",
                "missing_evidence": None if scoped_filter else "tenant filter",
                "proof_status": "explicit" if scoped_filter else "implicit",
                "finding_class": "observed_capability" if scoped_filter else "potential_risk",
                "evidence_level": "capability" if scoped_filter else "partial",
                "confidence_reason": "Tenant scoping is visible" if scoped_filter else "Tenant scoping is not visible in the query.",
                "boundary_crossing": bool(scoped_filter),
                "evidence_redacted": "Supabase query tenant scoping" if scoped_filter else "Supabase query without tenant filter",
                "base_confidence": 60 if scoped_filter else 70,
            })
            if scoped_filter:
                findings.append({
                    "category": "framework_security",
                    "framework": "Supabase",
                    "rule": "route_with_tenant_check",
                    "file": path,
                    "line": None,
                    "http_method": None,
                    "route_or_handler": "supabase query",
                    "auth_evidence": None,
                    "authorization_evidence": "tenant filter",
                    "role_check_evidence": None,
                    "ownership_check_evidence": None,
                    "tenant_check_evidence": "tenant filter",
                    "object_access_evidence": "resource access by query",
                    "missing_evidence": None,
                    "proof_status": "explicit",
                    "finding_class": "observed_capability",
                    "evidence_level": "capability",
                    "confidence_reason": "Tenant scoping is visible on the query.",
                    "boundary_crossing": False,
                    "evidence_redacted": "Supabase query with tenant filter",
                    "base_confidence": 65,
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
