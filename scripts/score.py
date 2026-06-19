#!/usr/bin/env python3
"""
score.py - aggregates raw findings into deduplicated, evidence-rich findings.
"""

from __future__ import annotations

import argparse
import itertools
import json
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
    return max(0, min(100, score))


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
