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
import sys


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
        "recommendation": "Replace shell and eval usage with explicit APIs and input validation.",
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

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
BLOCKING_SEVERITIES = {"Critical", "High"}
REMEDIATION_PRIORITY = {"Critical": "REQUIRED", "High": "REQUIRED", "Medium": "RECOMMENDED", "Low": "OPTIONAL", "Info": "OPTIONAL"}


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


def score_findings(raw_findings):
    score_module = load_module("score")
    scored = []
    counter = 1
    for finding in raw_findings:
        confidence = score_module.adjust_confidence(finding)
        severity = score_module.SEVERITY_BY_RULE.get(finding["rule"], "Medium")
        metadata = CATEGORY_METADATA.get(finding["category"], {})
        evidence_locations = finding.get("evidence_locations") or [{"file": finding.get("file"), "line": finding.get("line")}]
        evidence_count = finding.get("evidence_count") or len([item for item in evidence_locations if item.get("file")])
        scored.append({
            "id": f"{finding['category'].upper()}-{counter:04d}",
            "category": finding["category"],
            "rule": finding["rule"],
            "severity": severity,
            "confidence": confidence,
            "confidence_bucket": score_module.confidence_bucket(confidence),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "evidence_redacted": finding.get("evidence_redacted"),
            "evidence_count": evidence_count,
            "evidence_locations": evidence_locations,
            "confidence_level": score_module.confidence_level(confidence),
            "impact": metadata.get("impact", "Review the finding and validate whether it is a real risk."),
            "recommendation": metadata.get("recommendation", "Review the flagged code or configuration and reduce the risky pattern."),
            "remediation_priority": REMEDIATION_PRIORITY.get(severity, "RECOMMENDED"),
            "trust_boundary": metadata.get("trust_boundary", ["unknown"]),
            "production_blocker": severity in BLOCKING_SEVERITIES,
            "status": "open",
        })
        counter += 1
    return {"findings": scored, "correlations": score_module.correlate(scored)}


def scan_repo(target_repo: Path, quiet: bool = False):
    all_findings = []
    total = len(SCANNER_MODULES)
    labels = {
        "scan_secrets": "Scanning secrets",
        "scan_dependencies": "Scanning dependencies",
        "scan_exec_patterns": "Scanning execution patterns",
        "scan_exfil_patterns": "Scanning exfiltration patterns",
        "scan_skills_and_mcp": "Scanning skills, plugins and MCP",
        "scan_frameworks": "Scanning frameworks",
    }
    for index, module_name in enumerate(SCANNER_MODULES, start=1):
        scanner = load_module(module_name)
        emit(f"[{index}/{total}] {labels.get(module_name, f'Scanning {module_name}') }...", quiet)
        module_findings = scanner.walk(str(target_repo))
        all_findings.extend(module_findings)
        emit(f"[{index}/{total}] Done {labels.get(module_name, module_name)}.", quiet)
    return all_findings


def risk_counts(findings):
    counts = Counter(f["severity"] for f in findings)
    return {level: counts.get(level, 0) for level in ["Critical", "High", "Medium", "Low", "Info"]}


def posture_label(counts):
    if counts["Critical"]:
        return "Critical"
    if counts["High"]:
        return "Needs Attention"
    if counts["Medium"]:
        return "Acceptable"
    return "Strong"


def release_decision(findings):
    if any(f.get("severity") == "Critical" for f in findings):
        return "NOT_READY_FOR_PRODUCTION"
    if any(f.get("rule") == "aws_access_key_id" for f in findings):
        return "NOT_READY_FOR_PRODUCTION"
    if any(f.get("category") == "prompt_injection" and f.get("severity") == "High" for f in findings):
        return "NOT_READY_FOR_PRODUCTION"
    if any(f.get("category") == "unsafe_execution" and f.get("severity") == "High" for f in findings):
        return "NOT_READY_FOR_PRODUCTION"
    if any(f.get("rule") == "missing_tenant_filters" and f.get("severity") == "High" for f in findings):
        return "NOT_READY_FOR_PRODUCTION"
    if any(f.get("rule") == "unrestricted_tools" and f.get("severity") == "High" for f in findings):
        return "NOT_READY_FOR_PRODUCTION"
    if any(f.get("production_blocker") for f in findings):
        return "NOT_READY_FOR_PRODUCTION"
    if any(f.get("severity") == "High" for f in findings):
        return "REVIEW_REQUIRED"
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
    return {
        "findings_by_category": dict(categories),
        "top_rules": [finding["rule"] for finding in findings[:10]],
        "high_risk_paths": len([finding for finding in findings if finding.get("production_blocker")]),
    }


def trust_paths(findings):
    paths = []
    has_prompt = any(f["category"] == "prompt_injection" for f in findings)
    has_tool = any(f["category"] == "mcp_tool_abuse" for f in findings)
    has_exec = any(f["category"] == "unsafe_execution" for f in findings)
    has_exfil = any(f["category"] == "data_exfiltration" for f in findings)
    if has_prompt and has_tool and has_exec:
        paths.append({
            "name": "Prompt-to-Shell",
            "attack_path": ["User Input", "Prompt Construction", "Tool Invocation", "Shell Execution"],
            "trust_path": ["User Input", "Prompt Template", "Validated Tool", "Restricted Execution"],
            "data_flow_summary": "Untrusted input can move from prompt construction into a tool call and reach shell execution.",
        })
    if has_exfil:
        paths.append({
            "name": "Retrieval-to-External-Request",
            "attack_path": ["User Input", "Retrieval Layer", "External Request"],
            "trust_path": ["User Input", "Retrieval Guard", "Allowlisted Request"],
            "data_flow_summary": "Repository code may pass retrieved or user-controlled data into outbound requests.",
        })
    if any(f["category"] == "framework_security" for f in findings):
        paths.append({
            "name": "Framework Surface",
            "attack_path": ["Framework Entry Point", "Missing Guard", "Sensitive Action"],
            "trust_path": ["Framework Entry Point", "Auth / Validation", "Sensitive Action"],
            "data_flow_summary": "Framework-specific entry points may lack the expected authentication, tenant, or tool validation.",
        })
    return paths


def required_fixes(findings):
    items = [f for f in findings if f.get("remediation_priority") == "REQUIRED" or f.get("production_blocker")]
    return sorted(items, key=severity_sort_key)


def recommended_fixes(findings):
    items = [f for f in findings if f.get("remediation_priority") in {"RECOMMENDED", "OPTIONAL"}]
    return sorted(items, key=severity_sort_key)


def framework_findings(findings):
    return sorted([finding for finding in findings if finding.get("category") == "framework_security"], key=severity_sort_key)


def severity_sort_key(finding):
    return (SEVERITY_ORDER.get(finding["severity"], 9), -int(finding.get("confidence", 0)), finding.get("file") or "", finding.get("line") or 0)


def format_location(finding):
    if finding.get("line"):
        return f"{finding['file']}:{finding['line']}"
    return finding["file"] or "-"


def render_report(repo_path: Path, scored):
    findings = sorted(scored["findings"], key=severity_sort_key)
    counts = risk_counts(findings)
    decision = release_decision(findings)
    trust_profile = boundary_summary(findings)
    attack_surface = attack_surface_summary(findings)
    paths = trust_paths(findings)
    required = required_fixes(findings)
    recommended = recommended_fixes(findings)
    framework_items = framework_findings(findings)
    by_category = defaultdict(list)
    for finding in findings:
        by_category[finding["category"]].append(finding)

    category_titles = {
        "leaked_secrets": "Leaked Secrets",
        "supply_chain": "Supply-Chain Risk",
        "dependency_confusion": "Dependency Confusion",
        "malicious_packages": "Malicious Packages",
        "unsafe_execution": "Unsafe Execution",
        "insecure_config": "Insecure Config",
        "data_exfiltration": "Data Exfiltration",
        "mcp_tool_abuse": "MCP / Tool Abuse",
        "prompt_injection": "Prompt Injection",
    }

    lines = [
        f"# Repo Security Audit - {repo_path.name or repo_path} - {datetime.now().date().isoformat()}",
        "",
        "## Executive Summary",
        f"- Total findings: {len(findings)} (Critical: {counts['Critical']}, High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}, Info: {counts['Info']})",
        f"- Overall posture: {posture_label(counts)}",
        f"- Release decision: {decision}",
        "- Network verification pass: skipped (offline scanner only)",
        "",
        "## Trust Boundary Profile",
    ]
    for key in ["filesystem_access", "network_access", "environment_access", "execution_access"]:
        item = trust_profile[key]
        lines.append(
            f"- {item['label']}: {item['finding_count']} finding(s), highest severity {item['highest_severity'] or '-'}, status {item['status']}"
        )

    lines.extend([
        "## Risk Counts by Severity",
        f"- Critical: {counts['Critical']}",
        f"- High: {counts['High']}",
        f"- Medium: {counts['Medium']}",
        f"- Low: {counts['Low']}",
        f"- Info: {counts['Info']}",
        "",
        "## Production Readiness Assessment",
        f"- Production blockers: {sum(1 for finding in findings if finding.get('production_blocker'))}",
        f"- Ready for production: {decision == 'READY_FOR_PRODUCTION'}",
        f"- Review required: {decision == 'REVIEW_REQUIRED'}",
        f"- Not ready for production: {decision == 'NOT_READY_FOR_PRODUCTION'}",
        "",
        "## Release Decision",
        f"- {decision}",
        "",
        "## Attack Surface Summary",
        f"- Categories observed: {', '.join(sorted(attack_surface['findings_by_category'])) if attack_surface['findings_by_category'] else 'None'}",
        f"- High risk paths: {attack_surface['high_risk_paths']}",
        "",
        "## Trust Paths",
    ])
    if paths:
        for path in paths:
            lines.extend([
                f"- **{path['name']}**",
                f"  - Attack path: {' -> '.join(path['attack_path'])}",
                f"  - Trust path: {' -> '.join(path['trust_path'])}",
                f"  - Data flow: {path['data_flow_summary']}",
            ])
    else:
        lines.append("- No multi-step trust paths were inferred.")

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
                lines.append(f"- {finding['id']} ({finding['severity']}) {finding['rule']} - {finding.get('file') or '-'}")
    else:
        lines.append("No framework-specific findings identified.")

    lines.extend([
        "",
        "## Required Fixes",
    ])
    if required:
        for finding in required:
            lines.append(f"- {finding['id']} ({finding['severity']}) {finding['rule']} - {finding.get('recommendation')}")
    else:
        lines.append("No required fixes identified.")

    lines.extend([
        "",
        "## Recommended Fixes",
    ])
    if recommended:
        for finding in recommended:
            lines.append(f"- {finding['id']} ({finding['severity']}) {finding['rule']} - {finding.get('recommendation')}")
    else:
        lines.append("No recommended fixes identified.")

    lines.extend([
        "## Findings Table",
        "| ID | Severity | Confidence | Evidence Count | Location(s) | Trust Boundary | Production Blocker | Rule | Impact | Recommendation | Evidence |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ])
    for finding in findings:
        trust_boundary = ", ".join(finding.get("trust_boundary") or ["unknown"])
        evidence_locations = ", ".join(
            f"{item.get('file') or '-'}:{item.get('line') or '-'}" for item in finding.get("evidence_locations") or []
        ) or "-"
        lines.append(
            f"| {finding['id']} | {finding['severity']} | {finding.get('confidence_level') or finding['confidence_bucket']} | {finding.get('evidence_count') or 0} | {evidence_locations} | {trust_boundary} | {str(bool(finding.get('production_blocker'))).lower()} | {finding['rule']} | {finding.get('impact') or '-'} | {finding.get('recommendation') or '-'} | {finding.get('evidence_redacted') or '-'} |"
        )

    lines.extend(["", "## Detailed Findings"])
    for category, title in category_titles.items():
        items = by_category.get(category, [])
        lines.append(f"### {title}")
        if not items:
            lines.append("No findings in this category.")
        for finding in items:
            evidence_locations = ", ".join(
                f"{item.get('file') or '-'}:{item.get('line') or '-'}" for item in finding.get("evidence_locations") or []
            ) or "-"
            lines.extend([
                f"- **{finding['id']}**",
                f"  - File: `{finding.get('file') or '-'}`",
                f"  - Line: `{finding.get('line') or '-'}`",
                f"  - Rule ID: `{finding['rule']}`",
                f"  - Severity: `{finding['severity']}`",
                f"  - Confidence: `{finding.get('confidence_level') or finding['confidence_bucket']}`",
                f"  - Evidence count: `{finding.get('evidence_count') or 0}`",
                f"  - Evidence locations: `{evidence_locations}`",
                f"  - Trust boundary: `{', '.join(finding.get('trust_boundary') or ['unknown'])}`",
                f"  - Production blocker: `{str(bool(finding.get('production_blocker'))).lower()}`",
                f"  - Remediation priority: `{finding.get('remediation_priority') or 'RECOMMENDED'}`",
                f"  - Impact: {finding.get('impact') or '-'}",
                f"  - Recommendation: {finding.get('recommendation') or '-'}",
                f"  - Evidence: `{finding.get('evidence_redacted') or '-'}`",
            ])

    lines.extend([
        "",
        "## Limitations of Regex/Static Scanning",
        "- This audit is heuristic and read-only.",
        "- Regex patterns can miss context-sensitive bugs and can produce false positives.",
        "- No network verification or live registry checking is performed.",
        "- Findings should be treated as leads for human review, not as proof of compromise.",
    ])

    if scored["correlations"]:
        lines.extend(["", "## Cross-Category Correlations"])
        for correlation in scored["correlations"]:
            lines.append(f"- {correlation['note']} ({correlation['file']})")

    return "\n".join(lines) + "\n"


def build_json_output(repo_path: Path, scored):
    findings = list(scored["findings"])
    counts = risk_counts(findings)
    decision = release_decision(findings)
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
        },
        "trust_boundary": boundary_summary(findings),
        "attack_surface": attack_surface_summary(findings),
        "trust_paths": trust_paths(findings),
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
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", nargs="?", default=".")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    target_repo = Path(args.repo).resolve()
    if not target_repo.exists():
        print(f"Target repository does not exist: {target_repo}", file=sys.stderr)
        return 1

    try:
        emit("Repository Trust Boundary Auditor", args.quiet)
        emit(f"Target: {target_repo}", args.quiet)
        raw_findings = scan_repo(target_repo, args.quiet)
        emit("Scoring findings...", args.quiet)
        scored = score_findings(raw_findings)
        findings_path = Path.cwd() / "security-audit-findings.json"
        report_path = Path.cwd() / "SECURITY_AUDIT_REPORT.md"
        emit("Generating reports...", args.quiet)
        findings_path.write_text(json.dumps(build_json_output(target_repo, scored), indent=2), encoding="utf-8")
        report_path.write_text(render_report(target_repo, scored), encoding="utf-8")
        emit("")
        emit("Done.", args.quiet)
        emit(f"Release Decision: {release_decision(scored['findings'])}", args.quiet)
        emit(f"Findings: {len(scored['findings'])}", args.quiet)
        emit(f"Report: {report_path.name}", args.quiet)
        emit(f"JSON: {findings_path.name}", args.quiet)
        return 0
    except Exception as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
