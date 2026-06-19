#!/usr/bin/env python3
"""
score.py - aggregates raw findings into deduplicated, evidence-rich findings.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from scanner_utils import path_scope_tags

SEVERITY_BY_RULE = {
    "aws_secret_key_assignment": "Critical",
    "private_key_block": "Critical",
    "aws_access_key_id": "Critical",
    "gcp_api_key": "High",
    "github_token": "High",
    "slack_token": "High",
    "generic_secret_assignment": "High",
    "high_entropy_literal": "Low",
    "high_entropy_lockfile_literal": "Low",
    "install_time_script": "High",
    "possible_typosquat": "High",
    "internal_name_public_registry_risk": "High",
    "unpinned_version": "Low",
    "unscoped_bash_tool": "Medium",
    "dynamic_context_pre_review_exec": "High",
    "injection_phrase_in_skill": "High",
    "suspicious_mcp_tool_description": "Critical",
    "unpinned_mcp_server_version": "Medium",
    "eval_on_dynamic_input": "High",
    "exec_call": "Medium",
    "shell_true": "High",
    "os_system": "Medium",
    "child_process_exec": "Medium",
    "string_concat_into_shell": "High",
    "environment_variable_access": "Low",
    "credential_env_passthrough": "Low",
    "debug_enabled_prod": "Low",
    "tls_verify_disabled": "High",
    "wildcard_cors": "Medium",
    "default_credentials": "High",
    "world_writable_perm": "Medium",
    "hardcoded_webhook_url": "Medium",
    "data_in_url_query": "High",
    "suspicious_dns_exfil_shape": "Medium",
    "base64_post_body": "Medium",
    "undeclared_telemetry_beacon": "Low",
    "network_client_usage": "Low",
    "websocket_client_usage": "Low",
    "unauthenticated_route": "High",
    "unrestricted_admin_endpoint": "High",
    "public_route_marked_public": "Low",
    "route_with_auth_middleware": "Low",
    "route_with_role_check": "Low",
    "route_with_permission_check": "Low",
    "route_with_ownership_check": "Low",
    "route_with_tenant_check": "Low",
    "object_id_access": "High",
    "confirmed_auth_bypass": "Critical",
    "tenant_scoped_query": "Medium",
    "service_role_key_exposure": "Critical",
    "missing_tenant_filters": "High",
    "unrestricted_tool_routing": "High",
    "unsafe_state_mutation": "Medium",
    "unrestricted_tools": "High",
    "missing_tool_validation": "Medium",
    "unsafe_prompt_construction": "Medium",
    "unrestricted_tool_execution": "Medium",
    "wildcard_allowed_tools": "High",
    "missing_tool_allowlist": "Medium",
    "unrestricted_bash_shell_tool": "High",
    "unrestricted_filesystem_tool": "High",
    "unrestricted_network_tool": "High",
    "mcp_server_command_execution_surface": "High",
    "mcp_env_credentials_exposure": "Critical",
    "prompt_override": "High",
    "role_manipulation": "High",
    "tool_abuse_instruction": "High",
    "prompt_extraction": "High",
    "hidden_instruction": "Medium",
    "auto_run": "Medium",
    "auto_execute": "Medium",
    "unattended_execution": "High",
    "spawn_agent": "High",
    "create_sub_agent": "High",
    "recursive_task": "High",
    "self_improve": "High",
    "self_modify": "High",
    "delegate_until_done": "High",
    "loop_until_success": "High",
    "use_tools_automatically": "High",
    "autonomous_tool_use": "High",
    "invoke_any_tool": "High",
    "execute_tool_without_approval": "High",
    "auto_call_tools": "High",
    "indefinite_tool_retry": "High",
    "auto_deploy": "Critical",
    "push_to_main": "High",
    "delete_production": "Critical",
    "run_migration_automatically": "Critical",
    "apply_terraform_automatically": "Critical",
    "kubectl_apply": "Critical",
    "docker_push": "High",
    "npm_publish": "High",
    "missing_human_gate": "High",
    "retrieval_prompt_injection": "High",
    "retrieval_tool_instructions": "High",
    "retrieval_hidden_instruction": "Medium",
    "retrieval_policy_violation": "High",
    "untrusted_retrieval_ingestion": "High",
    "persistent_poisoned_context": "Medium",
    "npm_audit_vulnerability": "High",
    "pip_audit_vulnerability": "High",
    "semgrep_finding": "Medium",
    "gitleaks_secret": "Critical",
    "trivy_vulnerability": "High",
    "trivy_secret": "Critical",
    "trivy_container_vulnerability": "High",
    "trivy_iac_issue": "Medium",
    "codeql_finding": "High",
}

OBSERVED_CAPABILITY_RULES = {
    "network_client_usage",
    "websocket_client_usage",
    "environment_variable_access",
    "credential_env_passthrough",
    "filesystem_read_access",
    "recursive_filesystem_operation",
}

POTENTIAL_RISK_CATEGORIES = {
    "retrieval_poisoning",
    "data_exfiltration",
}

CONFIRMED_VULNERABILITY_RULES = {
    "shell_true",
    "eval_on_dynamic_input",
    "string_concat_into_shell",
    "exec_call",
    "os_system",
    "child_process_exec",
    "unrestricted_network_tool",
    "missing_tenant_filters",
    "object_id_access",
    "confirmed_auth_bypass",
}

SOURCE_RULES = {
    "network_client_usage": "http_request",
    "websocket_client_usage": "http_request",
    "environment_variable_access": "environment_variable",
    "credential_env_passthrough": "secret",
    "filesystem_read_access": "file_contents",
    "recursive_filesystem_operation": "file_contents",
}

SINK_RULES = {
    "network_client_usage": "network",
    "websocket_client_usage": "network",
    "shell_true": "execution",
    "eval_on_dynamic_input": "execution",
    "string_concat_into_shell": "execution",
    "exec_call": "execution",
    "os_system": "execution",
    "child_process_exec": "execution",
}

LOW_CONTEXT_TAGS = ["test", "fixture", "example", "sample", "mock"]
AGGREGATED_RULES = {"environment_variable_access", "unpinned_version", "high_entropy_literal"}
AGGREGATED_CATEGORIES = {"supply_chain", "insecure_config"}
HIGH_RISK_PATH_MARKERS = ("secret", "credential", "token", "key", "passwd", "shadow", ".env", "private")
NETWORK_RISK_MARKERS = ("webhook", "callback", "http://", "https://", "url", "endpoint")
EXECUTION_RISK_MARKERS = ("shell", "subprocess", "exec", "eval", "system")
MCP_RISK_MARKERS = ("mcp", "skill", "tool", "allowed-tools")


def confidence_level(score):
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def confidence_bucket(score):
    if score >= 80:
        return "Confirmed"
    if score >= 50:
        return "Likely"
    if score >= 25:
        return "Possible"
    return "Speculative"


def evidence_level_for_finding(finding):
    if finding.get("finding_class") == "confirmed_vulnerability":
        return "proven"
    if finding.get("finding_class") == "potential_risk":
        return "partial"
    return "capability"


def _source_class_for_finding(finding):
    rule = finding.get("rule")
    category = finding.get("category")
    evidence = (finding.get("evidence_redacted") or finding.get("evidence") or "").lower()
    if any(marker in evidence for marker in ("user_input", "request", "query", "param", "prompt", "content")):
        return "untrusted_input"
    if category == "retrieval_poisoning":
        return "retrieved_document"
    if category == "agentic_security":
        return "prompt_content"
    if category == "mcp_tool_abuse":
        return "mcp_response"
    if rule in {"environment_variable_access", "credential_env_passthrough"}:
        return "environment_variable"
    if rule == "filesystem_read_access":
        return "file_contents"
    return None


def _sink_class_for_finding(finding):
    rule = finding.get("rule")
    category = finding.get("category")
    if category == "retrieval_poisoning":
        return "prompt_construction"
    if category == "agentic_security":
        return "agent_tool_invocation"
    if category == "mcp_tool_abuse":
        return "mcp_tool_exposure"
    if rule in {"shell_true", "eval_on_dynamic_input", "string_concat_into_shell", "exec_call", "os_system", "child_process_exec"}:
        return "execution"
    if rule in {"network_client_usage", "websocket_client_usage"}:
        return "network"
    return None


def _flow_path_for_finding(finding):
    source = _source_class_for_finding(finding)
    sink = _sink_class_for_finding(finding)
    if source and sink:
        return [source, sink]
    if source:
        return [source]
    if sink:
        return [sink]
    return []


def _has_explicit_control(text: str):
    text = text.lower()
    return any(token in text for token in ("sanitize", "allowlist", "whitelist", "validate", "escape", "strip()", "json.dumps", "html.escape"))


def _flow_confidence_reason(finding, confidence):
    if finding.get("rule") in OBSERVED_CAPABILITY_RULES:
        return "This finding only shows a security-relevant source or sink capability."
    if confidence >= 80:
        return "The evidence text explicitly connects a source value to a sink with no effective control."
    return "The evidence suggests a source and sink are present, but the data-flow path is not explicit enough to confirm impact."


def enrich_flow_evidence(finding, confidence=None):
    if finding.get("category") == "framework_security":
        finding_class = finding.get("finding_class", "potential_risk")
        evidence_level = finding.get("evidence_level") or evidence_level_for_finding({"finding_class": finding_class})
        return {
            "source": None,
            "sink": None,
            "flow_path": [],
            "boundary_crossing": bool(finding.get("boundary_crossing")),
            "controls_observed": [],
            "controls_missing": [],
            "proof_status": finding.get("proof_status", "unsupported"),
            "evidence_level": evidence_level,
            "finding_class": finding_class,
            "confidence_reason": finding.get("confidence_reason") or "Framework security evidence was observed.",
        }
    evidence = (finding.get("evidence_redacted") or finding.get("evidence") or "")
    source = _source_class_for_finding(finding)
    sink = _sink_class_for_finding(finding)
    flow_path = _flow_path_for_finding(finding)
    controls_observed = []
    controls_missing = []
    proof_status = "unsupported"
    evidence_level = "capability"
    finding_class = "observed_capability"

    if source and not sink:
        proof_status = "source_only"
        evidence_level = "capability"
        if finding.get("rule") not in OBSERVED_CAPABILITY_RULES:
            finding_class = finding_class_for_finding(finding, confidence if confidence is not None else finding.get("base_confidence", 40))
    elif sink and not source:
        proof_status = "sink_only"
        evidence_level = "capability"
        if finding.get("rule") in OBSERVED_CAPABILITY_RULES:
            finding_class = "observed_capability"
        elif finding.get("rule") in CONFIRMED_VULNERABILITY_RULES:
            finding_class = finding_class_for_finding(finding, confidence if confidence is not None else finding.get("base_confidence", 40))
            evidence_level = "proven" if finding_class == "confirmed_vulnerability" else "partial"
    elif source and sink:
        if finding.get("rule") in OBSERVED_CAPABILITY_RULES and not any(marker in evidence.lower() for marker in ("user_input", "request", "query", "param", "prompt", "content")):
            return {
                "source": source,
                "sink": sink,
                "flow_path": flow_path,
                "boundary_crossing": False,
                "controls_observed": [],
                "controls_missing": [],
                "proof_status": "capability",
                "evidence_level": "capability",
                "finding_class": "observed_capability",
                "confidence_reason": _flow_confidence_reason(finding, confidence if confidence is not None else finding.get("base_confidence", 40)),
            }
        proof_status = "explicit" if re.search(r"\b(return|=|\.|f['\"]|f\")", evidence) else "implicit"
        if _has_explicit_control(evidence):
            controls_observed.append("sanitization_or_allowlist")
            finding_class = "potential_risk"
            proof_status = "controlled"
            evidence_level = "partial"
        elif proof_status == "explicit":
            finding_class = "confirmed_vulnerability"
            evidence_level = "proven"
        else:
            finding_class = "potential_risk"
            evidence_level = "partial"
        if finding.get("rule") in OBSERVED_CAPABILITY_RULES:
            finding_class = "observed_capability"
            evidence_level = "capability"
    else:
        proof_status = "unsupported"
    if finding_class == "confirmed_vulnerability":
        controls_missing.append("effective_sanitization_or_allowlist")
    return {
        "source": source,
        "sink": sink,
        "flow_path": flow_path,
        "boundary_crossing": bool(source and sink),
        "controls_observed": controls_observed,
        "controls_missing": controls_missing,
        "proof_status": proof_status,
        "evidence_level": evidence_level,
        "finding_class": finding_class,
        "confidence_reason": _flow_confidence_reason(finding, confidence if confidence is not None else finding.get("base_confidence", 40)),
    }


def finding_class_for_finding(finding, confidence):
    if finding.get("rule") == "public_route_marked_public":
        return "observed_capability"
    if finding.get("rule") in {"route_with_auth_middleware", "route_with_role_check", "route_with_permission_check", "route_with_ownership_check", "route_with_tenant_check", "tenant_scoped_query"}:
        return "observed_capability"
    if finding.get("rule") == "confirmed_auth_bypass":
        return "confirmed_vulnerability"
    if finding.get("category") == "retrieval_poisoning" or finding.get("rule") in POTENTIAL_RISK_RULES:
        return "potential_risk"
    if finding.get("category") == "leaked_secrets" and finding.get("rule") not in {"high_entropy_literal", "generic_secret_assignment"}:
        return "confirmed_vulnerability"
    if finding.get("category") == "secret_leakage" and confidence >= 80:
        return "confirmed_vulnerability"
    if finding.get("category") == "container_security" and confidence >= 80:
        return "confirmed_vulnerability"
    if finding.get("rule") == "service_role_key_exposure":
        return "confirmed_vulnerability"
    if finding.get("rule") in CONFIRMED_VULNERABILITY_RULES:
        evidence = (finding.get("evidence_redacted") or finding.get("evidence") or "").lower()
        if any(marker in evidence for marker in ("user_input", "input", "request", "param", "query", "filename", "filepath")) or confidence >= 80:
            return "confirmed_vulnerability"
    if finding.get("rule") in OBSERVED_CAPABILITY_RULES:
        return "observed_capability"
    if finding.get("category") == "unsafe_execution":
        return "confirmed_vulnerability" if confidence >= 80 else "potential_risk"
    return "potential_risk" if confidence >= 50 else "observed_capability"


def adjust_confidence(finding):
    score = finding.get("base_confidence", 40)
    path = (finding.get("file") or "").lower()
    evidence = (finding.get("evidence_redacted") or finding.get("evidence") or "").lower()
    scope_tags = set(finding.get("scope_tags") or [])
    if any(tag in path for tag in LOW_CONTEXT_TAGS):
        score -= 30
    if finding.get("rule") == "high_entropy_literal":
        score = min(score, 24)
    if finding.get("rule") == "environment_variable_access":
        score = min(score, 45)
    if finding.get("category") == "prompt_injection":
        score = min(score, 70)
    if finding.get("rule") == "filesystem_read_access":
        if any(marker in path or marker in evidence for marker in HIGH_RISK_PATH_MARKERS):
            score += 20
        elif any(marker in path or marker in evidence for marker in ("config", "settings", "readme", "docs")):
            score -= 10
        else:
            score -= 5
    if finding.get("rule") == "high_entropy_literal":
        score = min(score, 24)
    if finding.get("category") == "insecure_config":
        if any(marker in path or marker in evidence for marker in ("debug", "tls", "cors", "credential", "default")):
            score += 10
    if finding.get("category") == "data_exfiltration":
        if any(marker in path or marker in evidence for marker in NETWORK_RISK_MARKERS):
            score += 10
    if finding.get("category") == "unsafe_execution":
        if any(marker in path or marker in evidence for marker in EXECUTION_RISK_MARKERS):
            score += 10
    if finding.get("category") == "mcp_tool_abuse":
        if any(marker in path or marker in evidence for marker in MCP_RISK_MARKERS):
            score += 10
        if finding.get("rule") == "mcp_env_credentials_exposure":
            score = min(100, score + 15)
    if "documentation" in scope_tags:
        score = min(score, 55 if finding.get("category") == "leaked_secrets" else 40)
    if "generated" in scope_tags:
        score = min(score, 45 if finding.get("category") == "leaked_secrets" else 35)
    if finding.get("category") == "prompt_injection":
        score = min(score, 70)
    if finding.get("category") == "agentic_security":
        score = min(score, 85)
    if finding.get("category") == "retrieval_poisoning":
        score = min(score, 90)
    if finding.get("category") == "agentic_security" and finding.get("rule") in {"persistent_instruction", "cross_session_contamination", "hidden_memory_directive", "unsafe_memory_write", "sensitive_memory_storage"}:
        score = min(score, 90)
    return max(0, min(100, score))


POTENTIAL_RISK_RULES = {
    "hardcoded_webhook_url",
    "data_in_url_query",
    "suspicious_dns_exfil_shape",
    "base64_post_body",
    "undeclared_telemetry_beacon",
    "retrieval_prompt_injection",
    "retrieval_tool_instructions",
    "retrieval_hidden_instruction",
    "retrieval_policy_violation",
    "untrusted_retrieval_ingestion",
    "persistent_poisoned_context",
}


def severity_for_finding(finding):
    severity = SEVERITY_BY_RULE.get(finding["rule"], "Medium")
    confidence = finding.get("base_confidence", 40)
    path = (finding.get("file") or "").lower()
    evidence = (finding.get("evidence_redacted") or finding.get("evidence") or "").lower()
    scope_tags = set(finding.get("scope_tags") or [])

    if finding["rule"] == "high_entropy_literal":
        return "Low" if confidence <= 24 else severity

    if finding["rule"] == "filesystem_read_access":
        if confidence >= 80 or any(
            marker in path or marker in evidence
            for marker in ("../", "..\\", "/etc/", "\\windows\\", "id_rsa", "passwd", "shadow", ".env", "credentials", "secret")
        ):
            return "High"
        if any(marker in path or marker in evidence for marker in ("user", "input", "args", "request", "query", "param", "filename", "filepath")):
            return "Medium"
        return "Low"

    if finding["rule"] == "environment_variable_access":
        if any(marker in path or marker in evidence for marker in ("key", "token", "secret", "credential", "password")):
            return "Medium"
        return "Low"

    if finding["category"] == "insecure_config":
        if any(marker in path or marker in evidence for marker in ("tls", "debug", "cors", "credential", "default")):
            return "High"
        return "Medium"

    if finding["category"] == "data_exfiltration":
        if any(marker in path or marker in evidence for marker in ("webhook", "callback", "token", "credential", "secret")):
            return "High"
        return "Medium"

    if finding["category"] == "mcp_tool_abuse":
        if finding["rule"] in {"suspicious_mcp_tool_description", "mcp_env_credentials_exposure"}:
            return "Critical"
        if finding["rule"] in {"dynamic_context_pre_review_exec", "wildcard_allowed_tools", "unrestricted_bash_shell_tool", "unrestricted_filesystem_tool", "unrestricted_network_tool", "mcp_server_command_execution_surface"}:
            return "High"
        return "High" if any(tag in scope_tags for tag in {"agent", "mcp"}) else severity

    if finding["category"] == "unsafe_execution":
        if finding["rule"] in {"shell_true", "eval_on_dynamic_input", "string_concat_into_shell"}:
            return "High"
        if finding["rule"] in {"exec_call", "os_system", "child_process_exec"}:
            return "Medium"

    if finding["category"] == "agentic_security":
        if finding["rule"] in {"prompt_override", "role_manipulation", "tool_abuse_instruction", "prompt_extraction"}:
            return "High"
        if finding["rule"] in {"auto_deploy", "delete_production", "run_migration_automatically", "apply_terraform_automatically", "kubectl_apply"}:
            return "Critical"
        if finding["rule"] in {"auto_run", "auto_execute", "unattended_execution", "spawn_agent", "create_sub_agent", "recursive_task", "self_improve", "self_modify", "delegate_until_done", "loop_until_success", "use_tools_automatically", "invoke_any_tool", "execute_tool_without_approval", "auto_call_tools", "indefinite_tool_retry", "push_to_main", "docker_push", "npm_publish", "missing_human_gate"}:
            return "High"
        return "Medium"

    if finding["category"] == "retrieval_poisoning":
        if finding["rule"] in {"retrieval_prompt_injection", "retrieval_tool_instructions", "retrieval_policy_violation", "untrusted_retrieval_ingestion"}:
            return "High"
        return "Medium"
    if finding["category"] == "agentic_security" and finding["rule"] in {"persistent_instruction", "cross_session_contamination", "hidden_memory_directive", "unsafe_memory_write", "sensitive_memory_storage"}:
        if finding["rule"] == "sensitive_memory_storage":
            return "High"
        if finding["rule"] == "persistent_instruction":
            return "High"
        if finding["rule"] == "unsafe_memory_write":
            return "Medium"
        return "Medium"

    return severity


def _location_key(finding):
    return (finding.get("file"), finding.get("line"))


def _location_sort_key(finding):
    return (finding.get("file") or "", finding.get("line") or 0)


def _dedupe_key(finding):
    return (finding.get("rule_id") or finding.get("rule"), finding.get("severity"), finding.get("confidence_level"))


def _row_sort_key(item):
    return (
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(item["severity"], 9),
        -int(item["confidence"]),
        item.get("scope") or "",
        item.get("file") or "",
        item.get("line") or 0,
        item.get("rule") or "",
    )


def _evidence_snippet(finding):
    evidence = finding.get("evidence_redacted") or finding.get("evidence") or "-"
    location = finding.get("file") or "-"
    if finding.get("line"):
        location = f"{location}:{finding['line']}"
    return f"{location} {evidence}"


def _aggregate_group(group_id, items):
    representative = sorted(items, key=_location_sort_key)[0]
    files = sorted({item.get("file") for item in items if item.get("file")})
    scopes = sorted({item.get("scope") for item in items if item.get("scope")})
    scope_tags = sorted({tag for item in items for tag in item.get("scope_tags", [])})
    locations = []
    seen = set()
    for item in sorted(items, key=_location_sort_key):
        key = _location_key(item)
        if key in seen:
            continue
        seen.add(key)
        locations.append({"file": item.get("file"), "line": item.get("line")})
    severity = representative.get("severity") or SEVERITY_BY_RULE.get(representative["rule"], "Medium")
    confidence = max(item["confidence"] for item in items)
    return {
        "id": group_id,
        "category": representative["category"],
        "rule": representative["rule"],
        "rule_id": representative["rule"],
        "severity": severity,
        "confidence": confidence,
        "confidence_level": confidence_level(confidence),
        "confidence_bucket": confidence_bucket(confidence),
        "file": representative.get("file"),
        "line": representative.get("line"),
        "scope": representative.get("scope"),
        "scope_tags": scope_tags or scopes,
        "evidence_redacted": representative.get("evidence_redacted"),
        "evidence_snippet": _evidence_snippet(representative),
        "occurrences": len(items),
        "files_affected": len(files),
        "files": files,
        "representative_locations": locations[:3],
        "status": "open",
        "source": representative.get("source"),
        "sink": representative.get("sink"),
        "flow_path": representative.get("flow_path", []),
        "boundary_crossing": representative.get("boundary_crossing", False),
        "controls_observed": representative.get("controls_observed", []),
        "controls_missing": representative.get("controls_missing", []),
        "proof_status": representative.get("proof_status", "unsupported"),
        "finding_class": representative.get("finding_class", "potential_risk"),
        "confidence_reason": representative.get("confidence_reason"),
        "route_or_handler": representative.get("route_or_handler"),
        "http_method": representative.get("http_method"),
        "auth_evidence": representative.get("auth_evidence"),
        "authorization_evidence": representative.get("authorization_evidence"),
        "role_check_evidence": representative.get("role_check_evidence"),
        "ownership_check_evidence": representative.get("ownership_check_evidence"),
        "tenant_check_evidence": representative.get("tenant_check_evidence"),
        "object_access_evidence": representative.get("object_access_evidence"),
        "missing_evidence": representative.get("missing_evidence"),
    }


def correlate(findings):
    by_file = defaultdict(list)
    for finding in findings:
        by_file[finding.get("file")].append(finding)
    correlations = []
    for file, items in by_file.items():
        cats = {f["category"] for f in items}
        ids = sorted({f["id"] for f in items})
        if "unsafe_execution" in cats and "data_exfiltration" in cats:
            correlations.append({
                "type": "exec_plus_exfil_chain",
                "file": file,
                "finding_ids": ids,
                "note": "Unsafe execution and outbound data patterns co-occur in the same file.",
            })
        if "mcp_tool_abuse" in cats and "prompt_injection" in cats:
            correlations.append({
                "type": "tool_abuse_plus_injection",
                "file": file,
                "finding_ids": ids,
                "note": "Tool/MCP config combined with injection-shaped phrasing suggests tool poisoning risk.",
            })
    return correlations


def score_findings(raw_findings, include_dependencies: bool = False, include_tests: bool = False):
    grouped = defaultdict(list)
    dedupe_groups = defaultdict(list)
    scored_rows = []
    counter = itertools.count(1)
    for finding in raw_findings:
        scope_tags = path_scope_tags(Path(finding.get("file") or ""))
        scope = scope_tags[0]
        confidence = adjust_confidence(finding)
        severity = severity_for_finding(finding)
        finding_class = finding_class_for_finding(finding, confidence)
        row = {
            "id": f"{finding['category'].upper()}-{next(counter):04d}",
            "category": finding["category"],
            "rule": finding["rule"],
            "rule_id": finding["rule"],
            "severity": severity,
            "confidence": confidence,
            "confidence_level": confidence_level(confidence),
            "confidence_bucket": confidence_bucket(confidence),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "scope": scope,
            "scope_tags": list(scope_tags),
            "evidence_redacted": finding.get("evidence_redacted"),
            "evidence_snippet": _evidence_snippet(finding),
            "status": "open",
            "base_confidence": finding.get("base_confidence", 40),
            "finding_class": finding_class,
            "evidence_level": evidence_level_for_finding({"finding_class": finding_class}),
            **enrich_flow_evidence(finding, confidence),
        }
        scored_rows.append(row)
        dedupe_groups[_dedupe_key(row)].append(row)

    deduped_rows = []
    for rows in dedupe_groups.values():
        representative = sorted(rows, key=_row_sort_key)[0]
        files = sorted({row.get("file") for row in rows if row.get("file")})
        scope_tags = sorted({tag for row in rows for tag in row.get("scope_tags", [])})
        occurrences = len(rows)
        deduped_row = dict(representative)
        deduped_row["occurrences"] = occurrences
        deduped_row["files_affected"] = len(files) or 1
        deduped_row["files"] = files or [representative.get("file")]
        deduped_row["scope_tags"] = scope_tags or list(representative.get("scope_tags", []))
        deduped_row["representative_locations"] = [{"file": row.get("file"), "line": row.get("line")} for row in sorted(rows, key=_row_sort_key)[:3]]
        deduped_row["source"] = representative.get("source")
        deduped_row["sink"] = representative.get("sink")
        deduped_row["flow_path"] = representative.get("flow_path", [])
        deduped_row["boundary_crossing"] = representative.get("boundary_crossing", False)
        deduped_row["controls_observed"] = representative.get("controls_observed", [])
        deduped_row["controls_missing"] = representative.get("controls_missing", [])
        deduped_row["proof_status"] = representative.get("proof_status", "unsupported")
        deduped_row["confidence_reason"] = representative.get("confidence_reason")
        for key in [
            "route_or_handler",
            "http_method",
            "auth_evidence",
            "authorization_evidence",
            "role_check_evidence",
            "ownership_check_evidence",
            "tenant_check_evidence",
            "object_access_evidence",
            "missing_evidence",
        ]:
            deduped_row[key] = representative.get(key)
        deduped_rows.append(deduped_row)
        if representative["rule"] in AGGREGATED_RULES or representative["category"] in AGGREGATED_CATEGORIES:
            grouped[(representative["category"], representative["rule"], representative.get("scope"))].extend(rows)

    aggregated = []
    emitted = set()
    for key, items in grouped.items():
        aggregated.append(_aggregate_group(f"{key[0].upper()}-{key[1].upper()}", items))
        emitted.add(key)

    for row in deduped_rows:
        key = (row["category"], row["rule"], row.get("scope"))
        if key not in emitted:
            aggregated.append(row)

    sort_key = lambda item: (
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(item["severity"], 9),
        -int(item["confidence"]),
        item.get("scope") or "",
        item.get("file") or "",
        item.get("line") or 0,
        item.get("rule") or "",
    )
    aggregated.sort(key=sort_key)
    deduped_rows.sort(key=sort_key)
    return {"findings": aggregated, "correlations": correlate(aggregated), "raw_findings": deduped_rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", default=None)
    ap.add_argument("--out", dest="outfile", default=None)
    args = ap.parse_args()

    raw = json.load(open(args.infile)) if args.infile else json.load(sys.stdin)
    scored = score_findings(raw)
    text = json.dumps({"findings": scored["raw_findings"], "correlations": scored["correlations"]}, indent=2)
    if args.outfile:
        open(args.outfile, "w").write(text)
    else:
        print(text)


if __name__ == "__main__":
    main()
