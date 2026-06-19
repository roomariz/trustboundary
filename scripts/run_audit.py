#!/usr/bin/env python3
"""
run_audit.py - orchestrate the offline repository security audit.

Runs the existing scanners, scores their combined findings, and writes:
- security-audit-findings.json
- SECURITY_AUDIT_REPORT.md

This script is read-only with respect to the scanned repository. It only writes
the audit outputs in the current working directory.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import time
import sys
from scanner_utils import load_ignore_patterns, load_trustboundary_config, path_scope_tags


ROOT = Path(__file__).resolve().parent
SKIP_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", "coverage"}
MAX_FILE_SIZE = 1024 * 1024
SCANNER_MODULES = [
    "scan_secrets",
    "scan_dependencies",
    "scan_exec_patterns",
    "scan_exfil_patterns",
    "scan_skills_and_mcp",
    "scan_frameworks",
]

CATEGORY_METADATA = {
    "leaked_secrets": {
        "impact": "Credentials or secret material may be exposed to anyone who can read the repository or its logs.",
        "recommendation": "Remove the secret from the tree, rotate the credential, and move the value into a secrets manager.",
        "trust_boundary": ["filesystem", "credentials"],
    },
    "supply_chain": {
        "impact": "A dependency may be unpinned or suspicious, increasing supply-chain compromise risk.",
        "recommendation": "Pin the version, verify provenance, and review the lockfile before release.",
        "trust_boundary": ["dependency", "network"],
    },
    "dependency_confusion": {
        "impact": "A private-looking package name may resolve to a public package unexpectedly.",
        "recommendation": "Scope registries and rename or reserve the internal package name.",
        "trust_boundary": ["dependency", "network"],
    },
    "malicious_packages": {
        "impact": "Install-time code can execute during dependency installation.",
        "recommendation": "Remove or replace the package and inspect install scripts before trusting the dependency.",
        "trust_boundary": ["execution", "network"],
    },
    "unsafe_execution": {
        "impact": "Repository code can execute shell commands or dynamic code paths.",
        "recommendation": "Replace shell and eval usage with explicit execution APIs, argument lists, and input validation.",
        "trust_boundary": ["execution", "filesystem"],
    },
    "insecure_config": {
        "impact": "Configuration weakens production security posture or access controls.",
        "recommendation": "Tighten defaults, disable debug helpers, and restore secure configuration values.",
        "trust_boundary": ["configuration"],
    },
    "data_exfiltration": {
        "impact": "Repository code may send data to external destinations.",
        "recommendation": "Remove undeclared egress, allowlist destinations, and avoid embedding sensitive data in requests.",
        "trust_boundary": ["network", "external_communication"],
    },
    "mcp_tool_abuse": {
        "impact": "Agent or tool configuration may expand trust boundaries or allow unsafe tool use.",
        "recommendation": "Scope tools narrowly, pin versions, and review tool descriptions for poisoning or over-broad grants.",
        "trust_boundary": ["agent", "mcp", "execution"],
    },
    "prompt_injection": {
        "impact": "Repository content may influence an agent as instructions instead of data.",
        "recommendation": "Untrusted instructions can alter model behavior. Separate content from prompts and sanitize injected text. Prefer structured templates and quoted user content.",
        "trust_boundary": ["agent", "prompt"],
    },
    "framework_security": {
        "impact": "Framework configuration may expose routes, tools, or data without the expected guardrails.",
        "recommendation": "Add the missing dependency, allowlist, or tenant guard before exposing the path to production. Prefer framework-native auth and validation hooks.",
        "trust_boundary": ["framework"],
    },
}

RULE_RECOMMENDATIONS = {
    "filesystem_read_access": "Review each read path and restrict filesystem access to allowlisted files and directories.",
    "filesystem_write_access": "Use filesystem-specific allowlists, write only to expected locations, and validate any user-controlled filenames.",
    "filesystem_delete_access": "Guard destructive file operations with explicit allowlists and verify targets before deletion.",
    "recursive_filesystem_operation": "Avoid broad recursive filesystem traversal unless the scope is explicitly bounded.",
    "eval_on_dynamic_input": "Replace eval with explicit execution-safe parsing or dispatch logic and never evaluate user-controlled text.",
    "exec_call": "Use structured process execution instead of exec so arguments are not interpreted as code.",
    "shell_true": "Remove shell=True and pass arguments as a list to a bounded execution API.",
    "os_system": "Replace os.system with a structured process API and explicit argument handling.",
    "env_access": "Read configuration from the environment intentionally, validate missing values, and keep secrets out of source files.",
    "dotenv_usage": "Use dotenv only for local development and avoid treating .env as a production secret source.",
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
BLOCKING_SEVERITIES = {"Critical", "High"}
BLOCKING_CONFIDENCE = "HIGH"
REMEDIATION_PRIORITY = {"Critical": "REQUIRED", "High": "REQUIRED", "Medium": "RECOMMENDED", "Low": "OPTIONAL", "Info": "OPTIONAL"}
ICON_SUCCESS = "✓"
ICON_WARNING = "!"
ICON_ERROR = "x"
ICON_INFO = "i"

SUPPRESSION_FIELDS = ("rule", "path", "reason", "author", "expires")

ANSI_RESET = "\x1b[0m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_RED = "\x1b[31m"
ANSI_CYAN = "\x1b[36m"


def supports_color(stream, no_colour: bool) -> bool:
    return not no_colour and hasattr(stream, "isatty") and stream.isatty()


def colourize(text: str, colour: str, enabled: bool) -> str:
    return f"{colour}{text}{ANSI_RESET}" if enabled else text


def icon_prefix(kind: str, use_icons: bool) -> str:
    if not use_icons:
        return ""
    icons = {"success": ICON_SUCCESS, "warning": ICON_WARNING, "error": ICON_ERROR, "info": ICON_INFO}
    return f"{icons.get(kind, ICON_INFO)} "


def styled_line(text: str, kind: str = "info", colour_enabled: bool = False, use_icons: bool = True) -> str:
    colour_map = {
        "success": ANSI_GREEN,
        "warning": ANSI_YELLOW,
        "error": ANSI_RED,
        "info": ANSI_CYAN,
    }
    return f"{colourize(icon_prefix(kind, use_icons) + text, colour_map.get(kind, ANSI_CYAN), colour_enabled)}"


def log_line(text: str, kind: str = "info", quiet: bool = False, colour_enabled: bool = False, use_icons: bool = True):
    if not quiet:
        print(styled_line(text, kind=kind, colour_enabled=colour_enabled, use_icons=use_icons))


def load_module(name: str):
    path = ROOT / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load scanner module: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def emit(message: str, quiet: bool = False):
    if not quiet:
        print(message)


def _parse_date(value: str):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


def _suppression_is_expired(suppression):
    expires = suppression.get("expires")
    expiry = _parse_date(str(expires)) if expires else None
    return expiry is None or expiry < datetime.now().date()


def _suppression_matches(finding, suppression):
    rule = str(suppression.get("rule") or "")
    path = str(suppression.get("path") or "")
    finding_rule = finding.get("rule") or finding.get("rule_id")
    if rule and rule != finding_rule:
        return False
    finding_path = str(finding.get("file") or "")
    if path and not Path(finding_path).match(path):
        return False
    return True


def apply_suppressions(findings, suppressions):
    active = []
    expired = []
    ignored = []
    for suppression in suppressions or ():
        if not all(str(suppression.get(field) or "").strip() for field in SUPPRESSION_FIELDS):
            expired.append({**suppression, "status": "invalid", "reason": suppression.get("reason") or "Missing required suppression fields"})
            continue
        bucket = expired if _suppression_is_expired(suppression) else active
        bucket.append({**suppression, "status": "expired" if bucket is expired else "active"})

    kept = []
    for finding in findings:
        matched = next((suppression for suppression in active if _suppression_matches(finding, suppression)), None)
        if matched:
            ignored.append({**finding, "suppressed_by": matched})
            continue
        kept.append(finding)
    return kept, active, expired, ignored


def _finding_evidence_summary(finding):
    snippet = finding.get("evidence_snippet") or finding.get("evidence_redacted") or "-"
    return {
        "why_detected": finding.get("evidence_snippet") or finding.get("evidence_redacted") or "Pattern matched by scanner heuristic.",
        "impacted_trust_boundary": finding.get("trust_boundary", ["unknown"]),
        "confidence_bucket": finding.get("confidence_bucket") or "Unknown",
        "remediation": finding.get("recommendation"),
        "evidence_snippet": snippet,
    }


def _path_classes(finding):
    source_class = None
    sink_class = None
    if finding["category"] == "prompt_injection" or finding["rule"] in {"raw_prompt_concatenation", "direct_user_input_in_prompt", "missing_instruction_separation", "unsafe_prompt_construction"}:
        source_class = "prompt"
    elif finding["rule"] in {"environment_variable_access", "credential_env_passthrough"}:
        source_class = "environment"
    elif finding["rule"] in {"filesystem_read_access", "recursive_filesystem_operation"}:
        source_class = "file"
    elif finding["category"] == "data_exfiltration":
        source_class = "retrieval"
    elif finding["category"] == "mcp_tool_abuse":
        source_class = "tool"

    if finding["rule"] in {"shell_true", "exec_call", "os_system", "child_process_exec", "string_concat_into_shell"}:
        sink_class = "execution"
    elif finding["rule"] in {"filesystem_write_access", "filesystem_delete_access"} or finding["category"] == "framework_security" and finding["rule"] in {"missing_tenant_filters", "unsafe_state_mutation"}:
        sink_class = "filesystem"
    elif finding["category"] == "data_exfiltration":
        sink_class = "network"
    elif finding["category"] == "leaked_secrets" or finding["rule"] == "high_entropy_literal":
        sink_class = "credential"
    elif finding["category"] == "mcp_tool_abuse":
        sink_class = "tool"
    return source_class, sink_class


def _trust_boundary_label(source_class: str, sink_class: str) -> str:
    labels = {
        ("prompt", "execution"): "Prompt -> Tool",
        ("prompt", "filesystem"): "Prompt -> Filesystem",
        ("prompt", "network"): "Prompt -> Network",
        ("environment", "execution"): "Environment -> Execution",
        ("environment", "network"): "Environment -> Network",
        ("file", "execution"): "File -> Execution",
        ("file", "network"): "File -> Network",
        ("retrieval", "network"): "Retrieval -> Network",
        ("tool", "execution"): "Tool -> Execution",
        ("tool", "filesystem"): "Tool -> Filesystem",
        ("tool", "credential"): "Tool -> Credential",
    }
    return labels.get((source_class, sink_class), f"{source_class.title()} -> {sink_class.title()}")


def score_findings(raw_findings, include_dependencies: bool = False, include_tests: bool = False, repo_config=None):
    score_module = load_module("score")
    scored = score_module.score_findings(raw_findings, include_dependencies=include_dependencies, include_tests=include_tests)
    findings = []
    for finding in scored["findings"]:
        metadata = CATEGORY_METADATA.get(finding["category"], {})
        path = Path(finding.get("file") or "")
        scope_tags = sorted(set(finding.get("scope_tags") or []) | set(path_scope_tags(path, repo_config)))
        production_blocker = finding["severity"] == "Critical" or (finding["severity"] == "High" and finding["confidence_level"] == BLOCKING_CONFIDENCE)
        if finding["rule"] == "high_entropy_literal":
            production_blocker = False
        if any(tag in {"documentation", "generated"} for tag in scope_tags) and finding["category"] != "leaked_secrets":
            production_blocker = False
        if "test" in scope_tags and not include_tests:
            production_blocker = False
        if "dependency" in scope_tags and not include_dependencies:
            production_blocker = False
        findings.append({
            **finding,
            "scope": scope_tags[0],
            "scope_tags": list(scope_tags),
            "impact": metadata.get("impact", "Review the finding and validate whether it is a real risk."),
            "recommendation": RULE_RECOMMENDATIONS.get(finding["rule"], metadata.get("recommendation", "Review the flagged code or configuration and reduce the risky pattern.")),
            "remediation_priority": REMEDIATION_PRIORITY.get(finding["severity"], "RECOMMENDED"),
            "trust_boundary": metadata.get("trust_boundary", ["unknown"]),
            "production_blocker": production_blocker,
            **_finding_evidence_summary(finding),
        })
    return {"findings": findings, "correlations": scored["correlations"]}


def _should_count_for_production_signal(finding):
    scope_tags = set(finding.get("scope_tags", []))
    if "documentation" in scope_tags and finding.get("category") not in {"leaked_secrets"} and finding.get("severity") != "Critical":
        return False
    return True


def scan_repo(target_repo: Path, quiet: bool = False, include_dependencies: bool = False, include_tests: bool = False, include_env_files: bool = False, colour_enabled: bool = False, use_icons: bool = True, ignore_patterns: tuple[str, ...] = (), config=None):
    all_findings = []
    audit_warnings = []
    total = len(SCANNER_MODULES)
    files_checked = 0
    labels = {
        "scan_secrets": "Scanning secrets",
        "scan_dependencies": "Scanning dependencies",
        "scan_exec_patterns": "Scanning execution patterns",
        "scan_exfil_patterns": "Scanning exfiltration patterns",
        "scan_skills_and_mcp": "Scanning skills, plugins and MCP",
        "scan_frameworks": "Scanning frameworks",
    }
    def heartbeat(count, _path):
        nonlocal files_checked
        files_checked = max(files_checked, count)
        if count and count % 250 == 0:
            log_line(f"Scanning... {count} files checked", kind="info", quiet=quiet, colour_enabled=colour_enabled, use_icons=use_icons)
    for index, module_name in enumerate(SCANNER_MODULES, start=1):
        if config and config.enabled_scanners and module_name not in config.enabled_scanners:
            continue
        emit(f"[{index}/{total}] {labels.get(module_name, f'Scanning {module_name}') }...", quiet)
        started = time.perf_counter()
        scanner_failed = False
        try:
            scanner = load_module(module_name)
            try:
                module_findings = scanner.walk(
                    str(target_repo),
                    include_tests=include_tests,
                    include_dependencies=include_dependencies,
                    include_env_files=include_env_files,
                    ignore_patterns=ignore_patterns,
                    progress_callback=heartbeat,
                )
            except TypeError:
                module_findings = scanner.walk(str(target_repo))
            all_findings.extend(module_findings)
        except Exception as exc:
            scanner_failed = True
            audit_warnings.append({
                "rule": "scanner_failed",
                "scanner": module_name,
                "message": str(exc),
            })
        elapsed = time.perf_counter() - started
        log_line(
            f"{labels.get(module_name, module_name)} completed in {elapsed:.1f}s",
            kind="warning" if scanner_failed else "success",
            quiet=quiet,
            colour_enabled=colour_enabled,
            use_icons=use_icons,
        )
    return all_findings, audit_warnings, files_checked


def risk_counts(findings):
    counts = Counter(f["severity"] for f in findings)
    return {level: counts.get(level, 0) for level in ["Critical", "High", "Medium", "Low", "Info"]}


def posture_label(counts):
    if counts["Critical"] or counts["High"]:
        return "Not Ready"
    if counts["Medium"]:
        return "Needs Attention"
    if counts["Low"] or counts["Info"]:
        return "Acceptable"
    return "Healthy"


def is_documentation_finding(finding):
    scope_tags = set(finding.get("scope_tags", []))
    return "documentation" in scope_tags and finding.get("category") not in {"leaked_secrets"} and finding.get("severity") != "Critical"


def decision_inputs(findings):
    production_findings = [finding for finding in findings if not is_documentation_finding(finding)]
    blockers = [
        finding
        for finding in production_findings
        if finding.get("production_blocker")
        or finding.get("severity") == "Critical"
    ]
    review_items = [
        finding
        for finding in production_findings
        if finding not in blockers and (finding.get("severity") in {"High", "Medium"} or finding.get("remediation_priority") == "RECOMMENDED")
    ]
    return production_findings, blockers, review_items


def release_decision(findings, audit_warnings=None):
    production_findings, blockers, review_items = decision_inputs(findings)
    if audit_warnings:
        return "REVIEW_REQUIRED"
    if blockers:
        return "NOT_READY_FOR_PRODUCTION"
    if review_items:
        return "REVIEW_REQUIRED"
    if production_findings:
        return "READY_WITH_REVIEW"
    return "READY_FOR_PRODUCTION"


def boundary_summary(findings):
    boundaries = {
        "filesystem_access": ["filesystem"],
        "network_access": ["network", "external_communication"],
        "environment_access": ["credentials", "environment"],
        "execution_access": ["execution", "agent", "mcp"],
    }
    summary = {}
    for key, tags in boundaries.items():
        matched = [finding for finding in findings if any(tag in finding.get("trust_boundary", []) for tag in tags)]
        highest = None
        if matched:
            highest = min((finding["severity"] for finding in matched), key=lambda sev: SEVERITY_ORDER.get(sev, 9))
        summary[key] = {
            "label": key.replace("_", " ").title(),
            "finding_count": len(matched),
            "highest_severity": highest,
            "production_blocker_count": sum(1 for finding in matched if finding.get("production_blocker")),
            "status": "observed" if matched else "not_observed",
        }
    return summary


def attack_surface_summary(findings):
    categories = Counter(f["category"] for f in findings)
    scopes = Counter(f.get("scope", "production") for f in findings)
    return {
        "findings_by_category": dict(categories),
        "findings_by_scope": dict(scopes),
        "top_rules": [finding["rule"] for finding in findings[:10]],
        "high_risk_paths": len([finding for finding in findings if finding.get("production_blocker")]),
    }


def top_risks(findings, repo_config=None):
    eligible = [
        finding
        for finding in findings
        if (
            path_scope_tags(Path(finding.get("file") or ""), repo_config) == ("production",)
            or finding.get("category") == "leaked_secrets"
            or (finding.get("severity") == "Critical" and "documentation" in path_scope_tags(Path(finding.get("file") or ""), repo_config))
        )
    ]
    return sorted(
        eligible,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding["severity"], 9),
            -int(finding.get("confidence", 0)),
            -(finding.get("occurrences", 1)),
            finding.get("file") or "",
            finding.get("line") or 0,
        ),
    )[:10]


def trust_paths(findings):
    sources = {
        "prompt": [f for f in findings if _path_classes(f)[0] == "prompt"],
        "environment": [f for f in findings if _path_classes(f)[0] == "environment"],
        "file": [f for f in findings if _path_classes(f)[0] == "file"],
        "retrieval": [f for f in findings if _path_classes(f)[0] == "retrieval"],
        "tool": [f for f in findings if _path_classes(f)[0] == "tool"],
    }
    sinks = {
        "execution": [f for f in findings if _path_classes(f)[1] == "execution"],
        "filesystem": [f for f in findings if _path_classes(f)[1] == "filesystem"],
        "network": [f for f in findings if _path_classes(f)[1] == "network"],
        "credential": [f for f in findings if _path_classes(f)[1] == "credential"],
        "tool": [f for f in findings if _path_classes(f)[1] == "tool"],
    }
    path_source_labels = {
        "prompt": "Prompt Input",
        "environment": "Environment Variable",
        "file": "File Input",
        "retrieval": "Retrieval Output",
        "tool": "MCP Tool Input",
    }
    path_sink_labels = {
        "execution": "Execution Sink",
        "filesystem": "Filesystem Sink",
        "network": "Network Sink",
        "credential": "Credential Sink",
        "tool": "Tool Sink",
    }
    paths = []
    class_pairs = [
        ("prompt", "execution", "High", "Prompt data can reach command execution."),
        ("prompt", "filesystem", "Medium", "Prompt data can reach filesystem mutation."),
        ("prompt", "network", "High", "Prompt data can reach outbound requests."),
        ("environment", "execution", "Medium", "Environment values can influence execution paths."),
        ("environment", "network", "Medium", "Environment values can flow into outbound requests."),
        ("file", "execution", "Medium", "File-controlled data can reach execution sinks."),
        ("file", "network", "Medium", "File-controlled data can reach outbound requests."),
        ("retrieval", "network", "High", "Retrieved content can be reused in network requests."),
        ("tool", "execution", "High", "Tool-originated input can reach execution sinks."),
        ("tool", "filesystem", "Medium", "Tool-originated input can reach filesystem mutation."),
        ("tool", "credential", "High", "Tool-originated input can reach credential exposure."),
    ]
    for source_key, sink_key, risk, summary in class_pairs:
        source_items = sources.get(source_key) or []
        sink_items = sinks.get(sink_key) or []
        if not source_items or not sink_items:
            continue
        same_file = any(src.get("file") and src.get("file") == sink.get("file") for src in source_items for sink in sink_items)
        cross_file = any((src.get("file") or "") != (sink.get("file") or "") for src in source_items for sink in sink_items)
        source_item = source_items[0]
        sink_item = sink_items[0]
        confidence = "High" if same_file else "Medium" if cross_file else "Low"
        confidence_score = 85 if same_file else 65 if cross_file else 45
        reason = summary
        if same_file:
            reason += " Source and sink findings appear in the same file."
        elif cross_file:
            reason += " Source and sink findings span multiple files."
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if same_file else "cross_file",
            "boundary": _trust_boundary_label(source_key, sink_key),
            "source": path_source_labels[source_key],
            "source_class": source_key,
            "sink": path_sink_labels[sink_key],
            "sink_class": sink_key,
            "risk": risk,
            "confidence": confidence,
            "confidence_score": confidence_score,
            "evidence": [source_item["id"], sink_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                },
                {
                    "finding_id": sink_item["id"],
                    "file": sink_item.get("file"),
                    "line": sink_item.get("line"),
                    "role": "sink",
                },
            ],
            "data_flow_summary": reason,
        })
    if any(f["category"] == "framework_security" for f in findings):
        paths.append({
            "path_type": "source_to_sink",
            "boundary": "Framework -> Privileged Tool",
            "source": "Framework Entry Point",
            "sink": "Privileged Tool or Route",
            "risk": "Low",
            "confidence": "Low",
            "confidence_score": 35,
            "evidence": [f["id"] for f in findings if f["category"] == "framework_security"][:2],
            "evidence_details": [
                {
                    "finding_id": f["id"],
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "role": "framework",
                }
                for f in findings if f["category"] == "framework_security"
            ][:2],
            "data_flow_summary": "Framework-specific entry points may lack authentication, tenant, or tool validation.",
        })
    return paths


def attack_chains(trust_paths_items):
    chains = []
    source_classes = {path.get("source_class") for path in trust_paths_items if path.get("source_class")}
    sink_classes = {path.get("sink_class") for path in trust_paths_items if path.get("sink_class")}
    boundary_names = {path.get("boundary") for path in trust_paths_items if path.get("boundary")}

    def has_source(source):
        return source in source_classes

    def has_sink(sink):
        return sink in sink_classes

    if has_source("prompt") and has_sink("execution") and has_sink("network") and (has_sink("tool") or has_sink("filesystem")):
        chains.append({
            "name": "Prompt -> Tool -> Execution -> Network",
            "risk": "Critical",
            "reason": "Prompt-controlled input can reach tool execution and then outbound communication.",
            "confidence_score": 90,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Prompt ->")),
        })
    if has_source("prompt") and has_sink("execution"):
        chains.append({
            "name": "Prompt -> Execution",
            "risk": "High",
            "reason": "Prompt-controlled input can reach execution sinks.",
            "confidence_score": 80,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Prompt ->")),
        })
    if has_source("prompt") and has_sink("credential") or has_source("tool") and has_sink("credential"):
        chains.append({
            "name": "Prompt -> Credential",
            "risk": "Critical",
            "reason": "Prompt-controlled input can reach credential exposure.",
            "confidence_score": 92,
            "supporting_boundaries": sorted(name for name in boundary_names if name and ("Prompt ->" in name or "Tool ->" in name)),
        })
    if has_source("retrieval") and has_sink("network"):
        chains.append({
            "name": "Retrieval -> Network",
            "risk": "High",
            "reason": "Retrieved content can flow into outbound requests.",
            "confidence_score": 84,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Retrieval ->")),
        })
    if has_source("tool") and has_sink("filesystem") and has_sink("execution"):
        chains.append({
            "name": "Tool -> Filesystem -> Execution",
            "risk": "High",
            "reason": "Tool-originated input can touch files and later influence execution.",
            "confidence_score": 83,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Tool ->")),
        })
    if has_source("environment") and has_sink("network"):
        chains.append({
            "name": "Environment -> Network",
            "risk": "Medium",
            "reason": "Environment-sourced values can influence outbound requests.",
            "confidence_score": 72,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Environment ->")),
        })
    return chains


def required_fixes(findings):
    _, blockers, _ = decision_inputs(findings)
    items = blockers
    return sorted(items, key=severity_sort_key)


def recommended_fixes(findings):
    _, blockers, review_items = decision_inputs(findings)
    items = review_items
    return sorted(items, key=severity_sort_key)


def framework_findings(findings):
    return sorted([
        finding
        for finding in findings
        if finding.get("category") == "framework_security"
        and (
            "documentation" not in set(finding.get("scope_tags", []))
            or finding.get("severity") == "Critical"
            or finding.get("category") == "leaked_secrets"
        )
    ], key=severity_sort_key)


def severity_sort_key(finding):
    return (SEVERITY_ORDER.get(finding["severity"], 9), -int(finding.get("confidence", 0)), finding.get("file") or "", finding.get("line") or 0)


def format_location(finding):
    if finding.get("line"):
        return f"{finding['file']}:{finding['line']}"
    return finding["file"] or "-"


def render_report(repo_path: Path, scored, scope_summary, audit_warnings=None, repo_config=None):
    findings = sorted(scored["findings"], key=severity_sort_key)
    suppressions = apply_suppressions(findings, getattr(repo_config, "suppressions", ()))
    findings, active_suppressions, expired_suppressions, ignored_findings = suppressions
    counts = risk_counts(findings)
    decision = release_decision(findings, audit_warnings=audit_warnings)
    trust_profile = boundary_summary(findings)
    attack_surface = attack_surface_summary(findings)
    paths = trust_paths(findings)
    chains = attack_chains(paths)
    required = required_fixes(findings)
    recommended = recommended_fixes(findings)
    framework_items = framework_findings(findings)
    risks = top_risks(findings, repo_config=repo_config)

    blockers_exist = bool(required)
    blocker_label = "Production Blockers" if decision == "NOT_READY_FOR_PRODUCTION" else "Blocking Review"
    if audit_warnings:
        required_reason = "One or more scanners failed, so the audit is incomplete and requires manual review"
    elif decision == "NOT_READY_FOR_PRODUCTION":
        required_reason = "Critical finding or High finding with high confidence requires production blocking remediation"
    elif decision == "REVIEW_REQUIRED":
        if blockers_exist:
            required_reason = "Critical finding or High finding with high confidence requires blocking review"
        else:
            required_reason = "Findings exist, but none meet the production blocker threshold"
    elif decision == "READY_WITH_REVIEW":
        required_reason = "Findings exist, but none meet the production blocker threshold"
    else:
        required_reason = "No blockers or unresolved trust-boundary risks were found"
    lines = [
        f"# Repo Security Audit - {repo_path.name or repo_path} - {datetime.now().date().isoformat()}",
        "",
        "## Executive Summary",
        f"- Total findings: {len(findings)} (Critical: {counts['Critical']}, High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}, Info: {counts['Info']})",
        f"- Overall posture: {posture_label(counts)}",
        f"- Release decision: {decision}",
        "- Network verification pass: skipped (offline scanner only)",
        f"- Scanner failures: {len(audit_warnings or [])}",
        "",
        "## Release Decision",
        f"- {decision}",
        f"- Reason: {required_reason}",
        "",
        "## Top Risks",
    ]
    if risks:
        for index, finding in enumerate(risks, start=1):
            lines.append(f"{index}. {finding['rule']} ({finding['severity']}, {finding['confidence_level']}) - {finding.get('evidence_snippet')}")
    else:
        lines.append("No risks identified.")

    lines.extend([
        "",
        "## Trust Boundary Assessment",
    ])
    if paths:
        for path in paths:
            lines.extend([
                f"- **{path.get('boundary') or (path['source'] + ' -> ' + path['sink'])}**",
                f"  - Evidence: {', '.join(path['evidence'])}",
                f"  - Confidence: {path['confidence']}",
                f"  - Confidence score: {path.get('confidence_score', '-')}",
                f"  - Data flow: {path['data_flow_summary']}",
            ])
    else:
        lines.append("- No supported trust paths were inferred.")

    lines.extend([
        "",
        "## Attack Chains",
    ])
    if chains:
        for chain in chains:
            lines.append(f"- **{chain['name']}** ({chain['risk']}, confidence {chain.get('confidence_score', '-')}) - {chain['reason']}")
    else:
        lines.append("- No attack chains inferred.")

    lines.extend([
        "",
        f"## {blocker_label}",
    ])
    if required:
        for finding in required[:10]:
            lines.append(f"- {finding['id']} ({finding['severity']}, {finding['confidence_level']}) {finding['rule']} - {finding.get('recommendation')}")
        if len(required) > 10:
            lines.append(f"- ... and {len(required) - 10} more in JSON")
    else:
        lines.append(f"No {blocker_label.lower()} identified.")

    lines.extend([
        "",
        "## Review Items",
    ])
    if recommended:
        for finding in recommended[:10]:
            lines.append(f"- {finding['id']} ({finding['severity']}, {finding['confidence_level']}) {finding['rule']} - {finding.get('recommendation')}")
    else:
        lines.append("No review items identified.")

    documentation_notes = [finding for finding in findings if is_documentation_finding(finding)]
    lines.extend([
        "",
        "## Documentation Notes",
    ])
    if documentation_notes:
        for finding in documentation_notes[:10]:
            lines.append(f"- {finding['id']} ({finding['severity']}, {finding['confidence_level']}) {finding['rule']} - {finding.get('recommendation')}")
    else:
        lines.append("No documentation notes identified.")

    lines.extend([
        "",
        "## Suppressions",
    ])
    if active_suppressions:
        lines.append("Active")
        for suppression in active_suppressions:
            lines.append(f"- {suppression['rule']} | {suppression['path']} | {suppression['reason']} | {suppression['author']} | {suppression['expires']}")
    else:
        lines.append("No active suppressions.")
    if expired_suppressions:
        lines.append("Expired")
        for suppression in expired_suppressions:
            lines.append(f"- {suppression['rule']} | {suppression['path']} | {suppression['reason']} | {suppression['author']} | {suppression['expires']}")
    if ignored_findings:
        lines.append("Ignored findings")
        for finding in ignored_findings[:10]:
            lines.append(f"- {finding['id']} ({finding['severity']}, {finding['confidence_level']}) {finding['rule']} - suppressed")

    lines.extend([
        "",
        "## Aggregated Findings",
    ])
    high_critical = [f for f in findings if f["severity"] in {"Critical", "High"} and not is_documentation_finding(f)]
    medium = [f for f in findings if f["severity"] == "Medium"][:10]
    low = [f for f in findings if f["severity"] == "Low"]
    for finding in high_critical + medium:
        lines.append(f"- {finding['id']} | {finding['rule_id']} | {finding['severity']} | {finding['confidence_level']} | {finding.get('occurrences', 1)} occurrence(s)")
    if low:
        lines.append(f"- Low findings: {len(low)} total, summarized in JSON")

    lines.extend([
        "",
        "## Trust Boundary Profile",
    ])
    for key in ["filesystem_access", "network_access", "environment_access", "execution_access"]:
        item = trust_profile[key]
        lines.append(f"- {item['label']}: {item['finding_count']} finding(s), highest severity {item['highest_severity'] or '-'}, status {item['status']}")

    lines.extend([
        "",
        "## Attack Surface Summary",
        f"- Categories observed: {', '.join(sorted(attack_surface['findings_by_category'])) if attack_surface['findings_by_category'] else 'None'}",
        f"- High risk paths: {attack_surface['high_risk_paths']}",
        "",
        "## Scope Breakdown",
    ])
    for scope_name in ["production", "test", "dependency", "generated", "documentation"]:
        lines.append(f"- {scope_name.title()}: {attack_surface['findings_by_scope'].get(scope_name, 0)}")

    lines.extend([
        "",
        "## Scan Scope",
        f"- Target: `{repo_path}`",
        "- Mode: application source scan",
        f"- Files scanned: `{scope_summary['files_scanned']}`",
        f"- Files skipped: `{scope_summary['files_skipped']}`",
        f"- Excluded directories: `{scope_summary['excluded_dir_count']}`",
        "",
        "## Excluded Paths",
    ])
    for item in scope_summary["excluded_directories"]:
        lines.append(f"- `{item}`")

    lines.extend([
        "",
        "## Limitations",
        "- This audit is heuristic and read-only.",
        "- Regex patterns can miss context-sensitive bugs and can produce false positives.",
        "- No network verification or live registry checking is performed.",
        "- Findings should be treated as leads for human review, not as proof of compromise.",
    ])
    if audit_warnings:
        lines.extend([
            "",
            "## Audit Warnings",
        ])
        for warning in audit_warnings:
            lines.append(f"- {warning.get('rule', 'scanner_failed')} - {warning.get('scanner', '-')}: {warning.get('message', '-')}")
    lines.extend([
        "",
        "## Framework-Specific Findings",
    ])
    if framework_items:
        framework_groups = defaultdict(list)
        for finding in framework_items:
            framework_groups[finding.get("framework") or "Unknown"].append(finding)
        for framework_name in sorted(framework_groups):
            lines.append(f"### {framework_name}")
            for finding in framework_groups[framework_name]:
                lines.append(f"- {finding['id']} ({finding['severity']}, {finding['confidence_level']}) {finding['rule']} - {finding.get('file') or '-'}")
    else:
        lines.append("No framework-specific findings identified.")

    if scored["correlations"]:
        lines.extend(["", "## Cross-Category Correlations"])
        for correlation in scored["correlations"]:
            lines.append(f"- {correlation['note']} ({correlation['file']})")

    lines.extend(["", "Full finding details are available in `security-audit-findings.json`."])
    return "\n".join(lines) + "\n"


def render_audit_warnings(warnings):
    if not warnings:
        return ""
    lines = ["## Audit Warnings"]
    for warning in warnings:
        lines.append(f"- {warning.get('rule', 'scanner_failed')} - {warning.get('scanner', '-')}: {warning.get('message', '-')}")
    return "\n".join(lines) + "\n"


def build_json_output(repo_path: Path, scored, scope_summary, audit_warnings=None, repo_config=None):
    findings = list(scored["findings"])
    findings, active_suppressions, expired_suppressions, ignored_findings = apply_suppressions(findings, getattr(repo_config, "suppressions", ()))
    counts = risk_counts(findings)
    decision = release_decision(findings, audit_warnings=audit_warnings)
    surface = attack_surface_summary(findings)
    scope_counts = {
        scope: sum(1 for finding in findings if scope in set(finding.get("scope_tags", [])))
        for scope in ["production", "test", "dependency", "generated", "documentation"]
    }
    return {
        "schema_version": 2,
        "repo": {
            "name": repo_path.name or str(repo_path),
            "path": str(repo_path),
        },
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
            "overall_posture": posture_label(counts),
            "release_decision": decision,
            "production_blockers": sum(1 for finding in findings if finding.get("production_blocker")),
            "scanner_failures": len(audit_warnings or []),
            "scope_counts": scope_counts,
        },
        "suppressions": {
            "active": active_suppressions,
            "expired": expired_suppressions,
            "ignored_findings": ignored_findings,
        },
        "scope": scope_summary,
        "trust_boundary": boundary_summary(findings),
        "top_risks": top_risks(findings, repo_config=repo_config),
        "attack_surface": surface,
        "trust_paths": trust_paths(findings),
        "attack_chains": attack_chains(trust_paths(findings)),
        "framework_specific_findings": [
            {
                "id": finding["id"],
                "framework": finding.get("framework"),
                "rule": finding["rule"],
                "severity": finding["severity"],
                "confidence_level": finding.get("confidence_level"),
                "file": finding.get("file"),
                "line": finding.get("line"),
            }
            for finding in framework_findings(findings)
        ],
        "findings": findings,
        "correlations": scored["correlations"],
        "audit_warnings": list(audit_warnings or []),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", nargs="?", default=".")
    parser.add_argument("subcommand", nargs="?", default=None)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--no-colour", action="store_true")
    parser.add_argument("--no-icons", action="store_true")
    parser.add_argument("--include-dependencies", action="store_true")
    parser.add_argument("--include-tests", action="store_true")
    parser.add_argument("--include-env-files", action="store_true")
    args = parser.parse_args(argv)

    if args.repo == "scan" and args.subcommand:
        args.repo, args.subcommand = args.subcommand, None

    target_repo = Path(args.repo).resolve()
    if not target_repo.exists():
        print(f"Target repository does not exist: {target_repo}", file=sys.stderr)
        return 1

    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        started = time.perf_counter()
        colour_enabled = supports_color(sys.stdout, args.no_colour)
        use_icons = not args.no_icons
        emit("Repository Trust Boundary Auditor", args.quiet)
        emit(f"Target: {target_repo}", args.quiet)
        excluded_directories = [".git", "node_modules", "dist", "build", ".venv", "venv", "env", ".tox", ".mypy_cache", ".pytest_cache", "__pycache__", "coverage", ".next", "out", "target", "vendor", "site-packages", ".venv-windows"]
        emit("Mode: application source scan", args.quiet)
        log_line(f"Excluded directories: {len(excluded_directories)}", kind="info", quiet=args.quiet, colour_enabled=colour_enabled, use_icons=use_icons)
        log_line("Scanning source files...", kind="info", quiet=args.quiet, colour_enabled=colour_enabled, use_icons=use_icons)
        repo_config = load_trustboundary_config(target_repo)
        ignore_patterns = load_ignore_patterns(target_repo)
        raw_findings, audit_warnings, files_checked = scan_repo(
            target_repo,
            args.quiet,
            args.include_dependencies,
            args.include_tests,
            args.include_env_files,
            colour_enabled=colour_enabled,
            use_icons=use_icons,
            ignore_patterns=ignore_patterns + tuple(repo_config.exclusions) + tuple(repo_config.ignore_patterns),
            config=repo_config,
        )
        emit("Scoring findings...", args.quiet)
        scored = score_findings(raw_findings, args.include_dependencies, args.include_tests, repo_config=repo_config)
        scope_summary = {
            "files_scanned": files_checked,
            "files_skipped": max(0, files_checked - len(raw_findings)),
            "excluded_dir_count": len(excluded_directories),
            "excluded_directories": excluded_directories,
        }
        findings_path = Path.cwd() / "security-audit-findings.json"
        report_path = Path.cwd() / "SECURITY_AUDIT_REPORT.md"
        emit("Generating reports...", args.quiet)
        json_output = build_json_output(target_repo, scored, scope_summary, audit_warnings=audit_warnings, repo_config=repo_config)
        findings_path.write_text(json.dumps(json_output, indent=2), encoding="utf-8")
        report = render_report(target_repo, scored, scope_summary, audit_warnings=audit_warnings, repo_config=repo_config)
        warnings_block = render_audit_warnings(audit_warnings)
        if warnings_block:
            report += "\n" + warnings_block
        report_path.write_text(report, encoding="utf-8")
        emit("")
        log_line("Done.", kind="success", quiet=args.quiet, colour_enabled=colour_enabled, use_icons=use_icons)
        emit(f"Total elapsed: {time.perf_counter() - started:.1f}s", args.quiet)
        emit(f"Files scanned: {scope_summary['files_scanned']}", args.quiet)
        emit(f"Files skipped: {scope_summary['files_skipped']}", args.quiet)
        decision = release_decision(scored["findings"], audit_warnings=audit_warnings)
        decision_kind = "success" if decision in {"READY_FOR_PRODUCTION", "READY_WITH_REVIEW"} else "warning" if decision == "REVIEW_REQUIRED" else "error"
        log_line(f"Release Decision: {decision}", kind=decision_kind, quiet=args.quiet, colour_enabled=colour_enabled, use_icons=use_icons)
        emit(f"Findings: {len(scored['findings'])}", args.quiet)
        if audit_warnings:
            emit(f"Audit warnings: {len(audit_warnings)}", args.quiet)
        emit(f"Report: {report_path.name}", args.quiet)
        emit(f"JSON: {findings_path.name}", args.quiet)
        return 0
    except Exception as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
