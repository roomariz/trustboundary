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
import shutil
import subprocess
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
    "scan_autonomous_execution",
    "scan_exfil_patterns",
    "scan_prompt_injection",
    "scan_memory_poisoning",
    "scan_retrieval_poisoning",
    "scan_skills_and_mcp",
    "scan_frameworks",
    "scan_infrastructure",
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
    "agentic_security": {
        "impact": "Repository content may instruct an agent to override prompts, abuse tools, extract hidden context, or poison persistent memory.",
        "recommendation": "Treat prompt-bearing and memory-bearing content as untrusted data, quote it explicitly, and separate instructions from inputs. Keep secrets out of long-lived agent state.",
        "trust_boundary": ["agent", "prompt", "memory"],
    },
    "retrieval_poisoning": {
        "impact": "Retrieved corpus content may alter agent behavior, inject instructions, or poison downstream prompts and tools.",
        "recommendation": "Treat retrieved content as untrusted data, validate ingestion sources, and isolate persistent prompt/context files.",
        "trust_boundary": ["retrieval", "prompt", "agent"],
    },
    "framework_security": {
        "impact": "Framework configuration may expose routes, tools, or data without the expected guardrails.",
        "recommendation": "Add the missing dependency, allowlist, or tenant guard before exposing the path to production. Prefer framework-native auth and validation hooks.",
        "trust_boundary": ["framework"],
    },
    "dependency_vulnerability": {
        "impact": "A dependency or package ecosystem issue may expose the repository to known exploits or malicious code paths.",
        "recommendation": "Upgrade, pin, or remove the affected dependency and verify the lockfile before release.",
        "trust_boundary": ["dependency"],
    },
    "static_code_security": {
        "impact": "Static analysis identified code patterns that may enable security issues.",
        "recommendation": "Review the flagged code path and remediate the insecure pattern before release.",
        "trust_boundary": ["execution", "filesystem", "network"],
    },
    "secret_leakage": {
        "impact": "Secret material appears to be committed or exposed in the repository.",
        "recommendation": "Remove the secret, rotate the credential, and move it to a secrets manager.",
        "trust_boundary": ["credentials", "filesystem"],
    },
    "container_security": {
        "impact": "Container image or container configuration may include known security issues.",
        "recommendation": "Update the image base, dependencies, or runtime configuration before shipping.",
        "trust_boundary": ["container", "execution"],
    },
    "infrastructure_as_code": {
        "impact": "Infrastructure-as-code configuration may expose cloud or deployment resources to risk.",
        "recommendation": "Tighten the infrastructure policy, module versions, and resource access controls.",
        "trust_boundary": ["configuration", "deployment"],
    },
    "ci_cd_security": {
        "impact": "CI/CD configuration may allow unsafe pipeline execution or secret exposure.",
        "recommendation": "Lock down workflow permissions, secret handling, and pipeline triggers before release.",
        "trust_boundary": ["deployment", "execution", "credentials"],
    },
    "infrastructure_security": {
        "impact": "Infrastructure and deployment configuration may expose hosts, cloud resources, or tenant data.",
        "recommendation": "Tighten infrastructure defaults, pin deployment behavior, and remove risky runtime privileges before release.",
        "trust_boundary": ["container", "deployment", "configuration"],
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
    "docker_socket_mount": "Avoid mounting the Docker socket into containers unless the workflow is explicitly trusted and isolated.",
    "host_filesystem_mount": "Avoid bind-mounting host paths into containers unless the path is explicitly allowlisted and necessary.",
    "privileged_container": "Drop privileged mode and the Docker default capabilities unless there is a tightly controlled exception.",
    "container_root_user": "Run containers as a non-root user and set a read-only filesystem where possible.",
    "missing_read_only_rootfs": "Enable a read-only root filesystem for containers unless write access is strictly required.",
    "untrusted_deploy_command": "Avoid shelling deployment commands from untrusted workflow inputs; use allowlists and explicit arguments.",
    "unpinned_action": "Pin GitHub Actions by commit SHA so upstream changes cannot silently alter workflow behavior.",
    "broad_iam_permissions": "Scope cloud and IAM permissions to the minimum required actions and resources.",
    "public_database_storage": "Require authentication and tenant scoping before exposing database or storage resources.",
    "missing_rls_indicator": "Enable and document row-level security for multi-tenant Supabase data access.",
    "k8s_privileged_pod": "Remove privileged pod settings and tighten the pod security context.",
    "k8s_hostpath_mount": "Replace hostPath mounts with safer volume types unless host access is explicitly required.",
    "k8s_host_networking": "Disable hostNetwork, hostPID, and hostIPC unless the workload absolutely requires them.",
    "k8s_missing_resource_limits": "Set CPU and memory requests and limits for production workloads.",
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
BLOCKING_SEVERITIES = {"Critical", "High"}
BLOCKING_CONFIDENCE = "HIGH"
REMEDIATION_PRIORITY = {"Critical": "REQUIRED", "High": "REQUIRED", "Medium": "RECOMMENDED", "Low": "OPTIONAL", "Info": "OPTIONAL"}
SARIF_SEVERITY_MAP = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
ICON_SUCCESS = "✓"
ICON_WARNING = "!"
ICON_ERROR = "x"
ICON_INFO = "i"

SUPPRESSION_FIELDS = ("rule", "path", "reason", "author", "expires")
RISK_ACCEPTANCE_FIELDS = ("rule", "path", "reason", "owner", "expires")

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


def tool_available(command: str) -> bool:
    return shutil.which(command) is not None


def run_optional_tool(command, cwd: Path):
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    except FileNotFoundError:
        return None


def external_engine_statuses():
    return [
        {"name": "npm audit", "tool": "npm audit"},
        {"name": "pip-audit", "tool": "pip-audit"},
        {"name": "semgrep", "tool": "semgrep"},
        {"name": "gitleaks", "tool": "gitleaks"},
        {"name": "trivy", "tool": "trivy"},
        {"name": "codeql", "tool": "codeql"},
    ]


def _external_finding(tool: str, category: str, rule: str, severity: str, confidence: str, file=None, line=None, evidence=None, impact=None, recommendation=None, trust_boundary=None, production_blocker=False, extra=None):
    finding = {
        "tool": tool,
        "category": category,
        "rule": rule,
        "rule_id": rule,
        "file": file,
        "line": line,
        "evidence": evidence,
        "evidence_redacted": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "trust_boundary": trust_boundary or CATEGORY_METADATA.get(category, {}).get("trust_boundary", ["unknown"]),
        "production_blocker": production_blocker,
        "base_confidence": {"HIGH": 85, "MEDIUM": 65, "LOW": 35}.get(confidence, 50),
        "external_source": tool,
        "external_severity": severity,
    }
    if extra:
        finding.update(extra)
    return finding


def _load_json(text: str):
    text = text.strip()
    if not text:
        return None
    return json.loads(text)


def parse_npm_audit(output: str, repo_path: Path):
    data = _load_json(output)
    if not data:
        return []
    findings = []
    advisories = data.get("vulnerabilities") or {}
    for package_name, vuln in advisories.items():
        sev = (vuln.get("severity") or "high").lower()
        severity = "Critical" if sev == "critical" else "High" if sev == "high" else "Medium" if sev == "moderate" else "Low"
        recommendations = vuln.get("fixAvailable")
        evidence = json.dumps({"package": package_name, "severity": vuln.get("severity"), "via": vuln.get("via")}, ensure_ascii=False)
        findings.append(_external_finding("npm audit", "dependency_vulnerability", "npm_audit_vulnerability", severity, "HIGH" if severity in {"Critical", "High"} else "MEDIUM", file=str(repo_path / "package.json"), evidence=evidence, impact="npm audit reported a vulnerable dependency.", recommendation=f"Update {package_name}." if package_name else "Update the vulnerable dependency.", production_blocker=severity in {"Critical", "High"} and (vuln.get("isDirect") or vuln.get("via")), extra={"package": package_name, "fix_available": recommendations}))
    return findings


def parse_pip_audit(output: str, repo_path: Path):
    data = _load_json(output)
    if not data:
        return []
    findings = []
    for dep in data.get("dependencies", []):
        name = dep.get("name")
        for vuln in dep.get("vulns", []):
            findings.append(_external_finding("pip-audit", "dependency_vulnerability", "pip_audit_vulnerability", "High", "HIGH", file=str(repo_path / "requirements.txt"), evidence=json.dumps(vuln, ensure_ascii=False), impact="pip-audit reported a vulnerable Python dependency.", recommendation=f"Upgrade {name} to a secure version.", production_blocker=True, extra={"package": name, "vulnerability_id": vuln.get("id"), "aliases": vuln.get("aliases", [])}))
    return findings


def parse_semgrep(output: str):
    data = _load_json(output)
    if not data:
        return []
    findings = []
    for result in data.get("results", []):
        path = result.get("path")
        extra = {"semgrep_id": result.get("check_id"), "metadata": result.get("extra", {})}
        findings.append(_external_finding("semgrep", "static_code_security", "semgrep_finding", "High" if result.get("extra", {}).get("severity") in {"ERROR", "WARNING"} else "Medium", "HIGH" if result.get("extra", {}).get("confidence", "HIGH").upper() == "HIGH" else "MEDIUM", file=path, line=result.get("start", {}).get("line"), evidence=result.get("extra", {}).get("message"), impact="Semgrep identified a security-sensitive code pattern.", recommendation=result.get("extra", {}).get("fix", "Review and remediate the flagged code path."), extra=extra))
    return findings


def parse_gitleaks(output: str):
    data = _load_json(output)
    if not data:
        return []
    findings = []
    for item in data if isinstance(data, list) else data.get("leaks", []):
        findings.append(_external_finding("gitleaks", "secret_leakage", "gitleaks_secret", "Critical", "HIGH", file=item.get("File"), line=item.get("StartLine"), evidence=item.get("Match"), impact="Gitleaks identified a committed secret.", recommendation="Remove the secret and rotate the credential.", production_blocker=True, extra={"rule": item.get("RuleID"), "secret": item.get("Secret")}))
    return findings


def parse_trivy(output: str):
    data = _load_json(output)
    if not data:
        return []
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        vuln_type = (result.get("Type") or "").lower()
        category = "container_security" if "container" in vuln_type or target.startswith("docker://") else "dependency_vulnerability" if "package" in vuln_type or "library" in vuln_type else "infrastructure_as_code" if vuln_type in {"terraform", "cloudformation", "kubernetes"} else "secret_leakage" if vuln_type == "secret" else "dependency_vulnerability"
        rule = "trivy_container_vulnerability" if category == "container_security" else "trivy_secret" if category == "secret_leakage" else "trivy_iac_issue" if category == "infrastructure_as_code" else "trivy_vulnerability"
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "MEDIUM").title()
            findings.append(_external_finding("trivy", category, rule, severity, "HIGH" if severity in {"Critical", "High"} else "MEDIUM", file=target, evidence=json.dumps(vuln, ensure_ascii=False), impact="Trivy reported a security issue.", recommendation=vuln.get("PrimaryURL") or "Review the Trivy finding and remediate the underlying issue.", production_blocker=severity == "Critical" or (severity == "High" and category in {"container_security", "dependency_vulnerability"}), extra={"vulnerability_id": vuln.get("VulnerabilityID"), "title": vuln.get("Title")}))
    return findings


def parse_codeql(output: str):
    data = _load_json(output)
    if not data:
        return []
    findings = []
    for item in data.get("runs", [{}])[0].get("results", []):
        loc = (item.get("locations") or [{}])[0].get("physicalLocation", {})
        findings.append(_external_finding("codeql", "static_code_security", "codeql_finding", "High", "HIGH", file=loc.get("artifactLocation", {}).get("uri"), line=loc.get("region", {}).get("startLine"), evidence=item.get("message", {}).get("text"), impact="CodeQL identified a security query result.", recommendation="Review the CodeQL alert and remediate the code path.", production_blocker=True, extra={"rule": item.get("ruleId")}))
    return findings


def run_external_engines(target_repo: Path, quiet: bool = False):
    findings = []
    warnings = []
    statuses = []
    commands = [
        ("npm audit", ["npm", "audit", "--json"], parse_npm_audit),
        ("pip-audit", ["pip-audit", "--format", "json"], parse_pip_audit),
        ("semgrep", ["semgrep", "--json", "--quiet", "--config", "auto"], parse_semgrep),
        ("gitleaks", ["gitleaks", "detect", "--report-format", "json", "--no-banner"], parse_gitleaks),
        ("trivy", ["trivy", "fs", "--format", "json", "--quiet"], parse_trivy),
        ("codeql", ["codeql", "database", "analyze", "--format=json"], parse_codeql),
    ]
    for label, command, parser in commands:
        engine_status = {"name": label, "tool": label, "status": "completed", "finding_count": 0, "message": ""}
        if not tool_available(command[0]):
            engine_status["status"] = "skipped"
            engine_status["message"] = f"{label} is not installed."
            warnings.append({"rule": "scanner_unavailable", "scanner": label, "message": f"{label} is not installed."})
            log_line(f"{label} unavailable; skipping.", kind="warning", quiet=quiet)
            statuses.append(engine_status)
            continue
        result = run_optional_tool(command, target_repo)
        if result is None:
            engine_status["status"] = "failed"
            engine_status["message"] = f"{label} could not be started."
            warnings.append({"rule": "scanner_failed", "scanner": label, "message": f"{label} could not be started."})
            statuses.append(engine_status)
            continue
        if result.returncode not in {0, 1}:
            engine_status["status"] = "failed"
            engine_status["message"] = f"{label} exited with code {result.returncode}."
            warnings.append({"rule": "scanner_failed", "scanner": label, "message": f"{label} exited with code {result.returncode}."})
            log_line(f"{label} failed; continuing.", kind="warning", quiet=quiet)
            statuses.append(engine_status)
            continue
        try:
            parsed = parser(result.stdout or "")
        except Exception as exc:
            engine_status["status"] = "failed"
            engine_status["message"] = f"{label} output could not be parsed: {exc}"
            warnings.append({"rule": "scanner_failed", "scanner": label, "message": f"{label} output could not be parsed: {exc}"})
            log_line(f"{label} output parse failed; continuing.", kind="warning", quiet=quiet)
            statuses.append(engine_status)
            continue
        engine_status["finding_count"] = len(parsed)
        findings.extend(parsed)
        statuses.append(engine_status)
    return findings, warnings, statuses


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


def _risk_acceptance_is_expired(risk_acceptance):
    expires = risk_acceptance.get("expires")
    expiry = _parse_date(str(expires)) if expires else None
    return expiry is None or expiry < datetime.now().date()


def _risk_acceptance_matches(finding, risk_acceptance):
    rule = str(risk_acceptance.get("rule") or "")
    path = str(risk_acceptance.get("path") or "")
    finding_rule = finding.get("rule") or finding.get("rule_id")
    if rule and rule != finding_rule:
        return False
    finding_path = str(finding.get("file") or "")
    if path and not Path(finding_path).match(path):
        return False
    return True


def apply_risk_acceptance(findings, risk_acceptances):
    active = []
    expired = []
    invalid = []
    accepted = []
    for acceptance in risk_acceptances or ():
        if not all(str(acceptance.get(field) or "").strip() for field in RISK_ACCEPTANCE_FIELDS):
            invalid.append({**acceptance, "status": "invalid", "reason": acceptance.get("reason") or "Missing required risk acceptance fields"})
            continue
        bucket = expired if _risk_acceptance_is_expired(acceptance) else active
        bucket.append({**acceptance, "status": "expired" if bucket is expired else "active"})

    updated = []
    for finding in findings:
        matched = next((acceptance for acceptance in active if _risk_acceptance_matches(finding, acceptance)), None)
        if matched and finding.get("severity") not in {"Critical"} and finding.get("category") != "leaked_secrets":
            accepted_finding = dict(finding)
            accepted_finding["status"] = "accepted_risk"
            accepted_finding["accepted_risk"] = matched
            accepted.append(accepted_finding)
            updated.append(accepted_finding)
            continue
        updated.append(finding)
    return updated, active, expired, invalid, accepted


def risk_acceptance_state(findings, risk_acceptances):
    updated, active, expired, invalid, accepted = apply_risk_acceptance(findings, risk_acceptances)
    return {
        "findings": updated,
        "active": active,
        "expired": expired,
        "invalid": invalid,
        "accepted_findings": accepted,
    }


def risk_acceptance_warnings(risk_acceptances):
    warnings = []
    for acceptance in risk_acceptances or ():
        if not all(str(acceptance.get(field) or "").strip() for field in RISK_ACCEPTANCE_FIELDS):
            warnings.append({
                "rule": "risk_acceptance_invalid",
                "message": "Invalid risk acceptance entry missing required fields.",
                "entry": acceptance,
            })
    return warnings


def _finding_evidence_summary(finding):
    snippet = finding.get("evidence_snippet") or finding.get("evidence_redacted") or "-"
    summary = {
        "why_detected": finding.get("evidence_snippet") or finding.get("evidence_redacted") or "Pattern matched by scanner heuristic.",
        "impacted_trust_boundary": finding.get("trust_boundary", ["unknown"]),
        "confidence_bucket": finding.get("confidence_bucket") or "Unknown",
        "confidence_score": finding.get("confidence_score"),
        "confidence_band": finding.get("confidence_band") or finding.get("confidence_level"),
        "remediation": finding.get("recommendation"),
        "evidence_snippet": snippet,
    }
    summary.update({
        "route_or_handler": finding.get("route_or_handler"),
        "http_method": finding.get("http_method"),
        "auth_evidence": finding.get("auth_evidence"),
        "authorization_evidence": finding.get("authorization_evidence"),
        "role_check_evidence": finding.get("role_check_evidence"),
        "ownership_check_evidence": finding.get("ownership_check_evidence"),
        "tenant_check_evidence": finding.get("tenant_check_evidence"),
        "object_access_evidence": finding.get("object_access_evidence"),
        "missing_evidence": finding.get("missing_evidence"),
        "proof_status": finding.get("proof_status"),
        "boundary_crossing": finding.get("boundary_crossing"),
        "agent_surface": finding.get("agent_surface"),
        "prompt_evidence": finding.get("prompt_evidence"),
        "retrieval_evidence": finding.get("retrieval_evidence"),
        "memory_evidence": finding.get("memory_evidence"),
        "tool_evidence": finding.get("tool_evidence"),
        "mcp_evidence": finding.get("mcp_evidence"),
        "execution_evidence": finding.get("execution_evidence"),
        "filesystem_evidence": finding.get("filesystem_evidence"),
        "network_egress_evidence": finding.get("network_egress_evidence"),
        "sensitive_data_evidence": finding.get("sensitive_data_evidence"),
        "tenant_data_evidence": finding.get("tenant_data_evidence"),
        "controls_observed": finding.get("controls_observed"),
        "controls_missing": finding.get("controls_missing"),
        "attack_path": finding.get("attack_path"),
        "proof_status": finding.get("proof_status"),
        "finding_class": finding.get("finding_class"),
        "evidence_level": finding.get("evidence_level"),
        "confidence_reason": finding.get("confidence_reason"),
        "boundary_crossing": finding.get("boundary_crossing"),
        "evidence_components": finding.get("evidence_components"),
        "missing_evidence": finding.get("missing_evidence"),
    })
    return summary


def _redact_sensitive_text(text):
    if not text:
        return text
    redacted = str(text)
    replacements = [
        ("AKIA", "AKIA[REDACTED]"),
        ("sk-", "sk-[REDACTED]"),
        ("service-role", "[REDACTED]"),
        ("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\n[REDACTED]"),
    ]
    for needle, replacement in replacements:
        if needle in redacted:
            redacted = redacted.replace(needle, replacement)
    return redacted


def _exposure_what(finding):
    if finding.get("category") == "leaked_secrets":
        return "Secret material appears to be committed in the repository."
    if finding.get("category") == "data_exfiltration":
        return "Repository code may send data to an external destination."
    if finding.get("category") == "retrieval_poisoning":
        return "Retrieved content may override instructions or steer downstream behavior."
    if finding.get("category") == "agentic_security":
        return "Agent instructions or tool policy may expand privileges without a human gate."
    if finding.get("category") == "framework_security":
        return "Framework code may expose data or privileged actions without a guard."
    if finding.get("category") == "unsafe_execution":
        return "Code may execute shell commands or dynamic input."
    return finding.get("impact") or "Security-sensitive code or configuration was detected."


def _exposure_where(finding):
    location = format_location(finding)
    return location if location and location != "-" else finding.get("file") or "-"


def _exposure_attack_entry(finding):
    source_class, sink_class = _path_classes(finding)
    if source_class == "prompt":
        return "Untrusted prompt text or user input influences a privileged action."
    if source_class == "retrieval":
        return "Retrieved content is treated as instruction instead of data."
    if source_class == "memory":
        return "Persistent context or memory is reused without review."
    if source_class == "tool":
        return "Tool configuration or tool output can reach a privileged sink."
    if source_class == "environment":
        return "Environment-driven values can steer the sink."
    if sink_class == "network":
        return "User-controlled data reaches an outbound request."
    if sink_class == "execution":
        return "User-controlled data reaches command execution."
    if sink_class == "credential":
        return "Sensitive values are read or emitted without sufficient boundary checks."
    return "A repository-controlled value reaches a security-sensitive sink."


def _exposure_attack_path(finding):
    source_class, sink_class = _path_classes(finding)
    if source_class and sink_class:
        return f"{source_class.title()} -> {sink_class.title()}"
    if finding.get("category") == "retrieval_poisoning":
        return "Retrieval -> Prompt -> Tool"
    if finding.get("category") == "data_exfiltration":
        return "Input -> Network request -> External destination"
    return "Repository input -> Sensitive sink"


def _exposure_impact(finding):
    return finding.get("impact") or "This may expose sensitive data, enable unsafe execution, or weaken production controls."


def _exposure_recommended_fix(finding):
    return finding.get("recommendation") or "Review the flagged code path and narrow the trust boundary."


def build_exposure(finding):
    return {
        "what": _exposure_what(finding),
        "where": _exposure_where(finding),
        "attack_entry": _exposure_attack_entry(finding),
        "attack_path": _exposure_attack_path(finding),
        "impact": _exposure_impact(finding),
        "recommended_fix": _exposure_recommended_fix(finding),
    }


def _path_classes(finding):
    source_class = None
    sink_class = None
    if finding.get("category") == "framework_security":
        rule = finding.get("rule")
        if rule == "public_route_marked_public":
            source_class = "unauthenticated_user"
        elif rule in {"route_with_auth_middleware", "route_with_role_check", "route_with_permission_check", "route_with_ownership_check", "route_with_tenant_check"}:
            source_class = "authenticated_session"
        elif rule in {"route_with_tenant_check", "tenant_scoped_query"}:
            source_class = "tenant_context"
        elif rule in {"unauthenticated_route", "unrestricted_admin_endpoint", "object_id_access", "missing_tenant_filters"}:
            source_class = "route_handler"
        if rule in {"object_id_access", "route_with_ownership_check"}:
            sink_class = "object_resource"
        elif rule in {"missing_tenant_filters", "tenant_scoped_query", "route_with_tenant_check"}:
            sink_class = "tenant_data"
        elif rule == "unrestricted_admin_endpoint":
            sink_class = "admin_action"
        elif rule in {"unauthenticated_route", "public_route_marked_public"}:
            sink_class = "route_handler"
    if finding["category"] in {"prompt_injection", "agentic_security"} or finding["rule"] in {"raw_prompt_concatenation", "direct_user_input_in_prompt", "missing_instruction_separation", "unsafe_prompt_construction"}:
        source_class = "prompt"
    elif finding["category"] == "retrieval_poisoning":
        source_class = "retrieval"
    elif finding["category"] == "agentic_security" and finding["rule"] in {"persistent_instruction", "cross_session_contamination", "hidden_memory_directive", "unsafe_memory_write", "sensitive_memory_storage"}:
        source_class = "memory"
    elif finding["category"] == "agentic_security" and finding["rule"] in {"auto_run", "auto_execute", "unattended_execution", "spawn_agent", "create_sub_agent", "recursive_task", "self_improve", "self_modify", "delegate_until_done", "loop_until_success", "use_tools_automatically", "invoke_any_tool", "execute_tool_without_approval", "auto_call_tools", "indefinite_tool_retry", "auto_deploy", "push_to_main", "delete_production", "run_migration_automatically", "apply_terraform_automatically", "kubectl_apply", "docker_push", "npm_publish", "missing_human_gate"}:
        source_class = "agent"
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
    elif finding["category"] in {"data_exfiltration", "retrieval_poisoning"} or finding["rule"] == "unrestricted_network_tool":
        sink_class = "network"
    elif finding["category"] == "leaked_secrets" or finding["rule"] in {"high_entropy_literal", "mcp_env_credentials_exposure"}:
        sink_class = "credential"
    elif finding["category"] == "mcp_tool_abuse":
        sink_class = "tool"
    elif finding["category"] == "agentic_security" and finding["rule"] in {"auto_deploy", "push_to_main", "delete_production", "run_migration_automatically", "apply_terraform_automatically", "kubectl_apply", "docker_push", "npm_publish"}:
        sink_class = "deployment"
    return source_class, sink_class


def _trust_boundary_label(source_class: str, sink_class: str) -> str:
    labels = {
        ("prompt", "execution"): "Prompt -> Tool",
        ("prompt", "filesystem"): "Prompt -> Filesystem",
        ("prompt", "network"): "Prompt -> Network",
        ("prompt", "tool"): "Prompt -> Privileged Action",
        ("environment", "execution"): "Environment -> Execution",
        ("environment", "network"): "Environment -> Network",
        ("file", "execution"): "File -> Execution",
        ("file", "network"): "File -> Network",
        ("retrieval", "network"): "Retrieval -> Network",
        ("retrieval", "prompt"): "Retrieval -> Prompt",
        ("retrieval", "tool"): "Retrieval -> Tool",
        ("retrieval", "execution"): "Retrieval -> Execution",
        ("memory", "prompt"): "Memory -> Prompt",
        ("memory", "tool"): "Memory -> Tool",
        ("memory", "credential"): "Memory -> Credential",
        ("memory", "network"): "Memory -> Network",
        ("memory", "execution"): "Memory -> Execution",
        ("tool", "execution"): "Tool -> Execution",
        ("tool", "filesystem"): "Tool -> Filesystem",
        ("tool", "credential"): "Tool -> Credential",
        ("tool", "deployment"): "Tool -> Deployment",
        ("prompt", "deployment"): "Prompt -> Deployment",
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
        finding_class = finding.get("finding_class", "potential_risk")
        evidence_level = finding.get("evidence_level") or ("proven" if finding_class == "confirmed_vulnerability" else "partial" if finding_class == "potential_risk" else "capability")
        infra_confirmed = finding.get("category") in {"container_security", "ci_cd_security", "infrastructure_as_code"} and finding.get("confidence_score", 0) >= 80
        if finding.get("rule") in {"network_client_usage", "websocket_client_usage", "environment_variable_access", "credential_env_passthrough", "filesystem_read_access", "recursive_filesystem_operation"} and finding.get("proof_status") in {"source_only", "sink_only"}:
            finding_class = "observed_capability"
            evidence_level = "capability"
        elif finding.get("proof_status") in {"implicit", "controlled"} and finding_class != "confirmed_vulnerability":
            finding_class = "potential_risk"
            evidence_level = "partial"
        elif infra_confirmed:
            finding_class = "confirmed_vulnerability"
            evidence_level = "proven"
        elif finding.get("proof_status") == "explicit" and finding_class != "observed_capability":
            finding_class = "confirmed_vulnerability"
            evidence_level = "proven"
        trust_score_penalty = {"observed_capability": 0, "potential_risk": 1, "confirmed_vulnerability": 1}[finding_class]
        production_blocker = finding["severity"] == "Critical" or (finding["severity"] == "High" and finding.get("confidence_band") == "HIGH")
        if finding_class != "confirmed_vulnerability":
            production_blocker = False
        if finding["rule"] == "shell_true":
            production_blocker = True
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
            "finding_class": "confirmed_vulnerability" if infra_confirmed else finding_class,
            "evidence_level": evidence_level,
            "trust_score_penalty": trust_score_penalty,
            "evidence_redacted": _redact_sensitive_text(finding.get("evidence_redacted") or finding.get("evidence")),
            "exposure": build_exposure({
                **finding,
                "impact": metadata.get("impact", "Review the finding and validate whether it is a real risk."),
                "recommendation": RULE_RECOMMENDATIONS.get(finding["rule"], metadata.get("recommendation", "Review the flagged code or configuration and reduce the risky pattern.")),
            }),
            "infrastructure_surface": finding.get("infrastructure_surface"),
            "config_file": finding.get("config_file"),
            "config_key": finding.get("config_key"),
            "observed_evidence": finding.get("observed_evidence"),
            "missing_evidence": finding.get("missing_evidence"),
            "controls_observed": finding.get("controls_observed"),
            "controls_missing": finding.get("controls_missing"),
            "boundary_crossing": finding.get("boundary_crossing") or infra_confirmed,
            "proof_status": finding.get("proof_status"),
            "confidence_score": finding.get("confidence_score"),
            "confidence_band": finding.get("confidence_band"),
            "confidence_reason": finding.get("confidence_reason"),
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
    def _confidence_band(finding):
        return finding.get("confidence_band") or finding.get("confidence_level")
    production_findings = [finding for finding in findings if finding.get("finding_class") != "observed_capability" and not is_documentation_finding(finding)]
    accepted = [finding for finding in production_findings if finding.get("status") == "accepted_risk" and finding.get("severity") != "Critical" and finding.get("category") != "leaked_secrets"]
    production_findings = [finding for finding in production_findings if finding not in accepted]
    blockers = [
        finding
        for finding in production_findings
        if (
            finding.get("production_blocker")
            or (
                finding.get("finding_class") == "confirmed_vulnerability"
                and (
                    finding.get("severity") == "Critical"
                or (finding.get("severity") == "High" and _confidence_band(finding) in {"MEDIUM", "HIGH"})
                )
            )
            or (finding.get("category") == "leaked_secrets" and finding.get("severity") == "Critical")
        )
    ]
    review_items = [
        finding
        for finding in production_findings
        if finding not in blockers
        and (
            finding.get("finding_class") == "potential_risk"
            and (
                finding.get("severity") in {"High", "Critical"}
                or _confidence_band(finding) in {"MEDIUM", "HIGH"}
                or finding.get("category") in {"unsafe_execution", "leaked_secrets", "agentic_security", "mcp_tool_abuse", "retrieval_poisoning", "data_exfiltration"}
            )
            or (finding.get("finding_class") == "confirmed_vulnerability" and _confidence_band(finding) == "LOW")
        )
    ]
    return production_findings, blockers, review_items


def readiness_decision(findings, audit_warnings=None):
    production_findings, blockers, review_items = decision_inputs(findings)
    decision_reasons = []
    def finding_id(finding):
        return finding.get("id") or finding.get("rule") or finding.get("rule_id") or "unknown"
    if audit_warnings:
        decision_reasons.append("Scanner failures prevent a complete production assessment.")
        return {
            "readiness": "NOT_READY_FOR_PRODUCTION",
            "production_blockers": [finding_id(finding) for finding in blockers[:10]] + [f"scanner:{warning.get('scanner', 'unknown')}" for warning in audit_warnings],
            "required_reviews": [finding_id(finding) for finding in review_items[:10]],
            "decision_reasons": decision_reasons,
        }
    if blockers:
        decision_reasons.append("Critical confirmed vulnerabilities remain unresolved.")
        return {
            "readiness": "NOT_READY_FOR_PRODUCTION",
            "production_blockers": [finding_id(finding) for finding in blockers[:10]],
            "required_reviews": [finding_id(finding) for finding in review_items[:10]],
            "decision_reasons": decision_reasons,
        }
    if review_items:
        if any(finding.get("severity") in {"High", "Critical"} and finding.get("confidence_band") in {"MEDIUM", "HIGH"} for finding in review_items):
            decision_reasons.append("High-confidence production risks require review before release.")
        else:
            decision_reasons.append("Production review items remain.")
        return {
            "readiness": "REVIEW_REQUIRED",
            "production_blockers": [],
            "required_reviews": [finding["id"] for finding in review_items[:10]],
            "decision_reasons": decision_reasons,
        }
    if production_findings:
        decision_reasons.append("Only informational production findings remain.")
        return {
            "readiness": "READY_WITH_REVIEW",
            "production_blockers": [],
            "required_reviews": [],
            "decision_reasons": decision_reasons,
        }
    decision_reasons.append("No relevant production findings remain.")
    return {
        "readiness": "READY_FOR_PRODUCTION",
        "production_blockers": [],
        "required_reviews": [],
        "decision_reasons": decision_reasons,
    }


def release_decision(findings, audit_warnings=None):
    return readiness_decision(findings, audit_warnings=audit_warnings)["readiness"]


def boundary_summary(findings):
    boundaries = {
        "filesystem_access": ["filesystem"],
        "network_access": ["network", "external_communication"],
        "environment_access": ["credentials", "environment"],
        "execution_access": ["execution", "agent", "mcp"],
        "deployment_access": ["deployment"],
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


def auth_review_summary(findings):
    auth_findings = [finding for finding in findings if finding.get("category") == "framework_security"]
    protected = [finding for finding in auth_findings if finding.get("auth_evidence") or finding.get("authorization_evidence") or finding.get("role_check_evidence") or finding.get("tenant_check_evidence") or finding.get("ownership_check_evidence")]
    public = [finding for finding in auth_findings if finding.get("rule") == "public_route_marked_public"]
    review_required = [
        finding for finding in auth_findings
        if finding.get("rule") in {"unauthenticated_route", "unrestricted_admin_endpoint", "object_id_access", "missing_tenant_filters", "tenant_scoped_query"}
    ]
    admin_review = [finding for finding in review_required if finding.get("rule") == "unrestricted_admin_endpoint"]
    object_tenant_review = [finding for finding in review_required if finding.get("rule") in {"object_id_access", "missing_tenant_filters", "tenant_scoped_query"}]
    return {
        "protected_routes": len(protected),
        "public_routes": len(public),
        "routes_requiring_review": len(review_required),
        "admin_routes_requiring_review": len(admin_review),
        "object_tenant_routes_requiring_review": len(object_tenant_review),
    }


def _map_entry(component, evidence, confidence_score, partial_evidence=False, inferred=False, related_findings=None, confidence_band_override=None):
    band = confidence_band_override or ("HIGH" if confidence_score >= 80 else "MEDIUM" if confidence_score >= 50 else "LOW")
    return {
        "component": component,
        "evidence": evidence,
        "confidence_score": confidence_score,
        "confidence_band": band,
        "partial_evidence": partial_evidence,
        "inferred": inferred,
        "related_findings": related_findings or [],
    }


def _unknown_map_entry(component, related_findings=None):
    return _map_entry(
        component,
        "No direct evidence observed in the scanned repository.",
        0,
        partial_evidence=True,
        inferred=False,
        related_findings=related_findings or [],
        confidence_band_override="UNKNOWN",
    )


def _build_repository_map(findings, matcher, unknown_component):
    matched = [finding for finding in findings if matcher(finding)]
    if not matched:
        return [_unknown_map_entry(unknown_component)]

    entries = []
    for finding in matched:
        evidence = (
            finding.get("evidence_redacted")
            or finding.get("evidence_snippet")
            or finding.get("observed_evidence")
            or finding.get("evidence")
            or "Observed repository evidence."
        )
        entries.append(_map_entry(
            finding.get("route_or_handler") or finding.get("framework") or finding.get("rule"),
            evidence,
            finding.get("confidence_score") or finding.get("confidence", 0) or 0,
            partial_evidence=finding.get("proof_status") in {"implicit", "source_only", "sink_only", "partial"},
            inferred=finding.get("proof_status") in {"implicit", "source_only", "sink_only"} or finding.get("finding_class") == "potential_risk",
            related_findings=[finding.get("id")] if finding.get("id") else [],
        ))
    return entries


def repository_understanding_summary(findings):
    auth_findings = [finding for finding in findings if finding.get("category") == "framework_security"]
    agent_findings = [finding for finding in findings if finding.get("category") in {"prompt_injection", "retrieval_poisoning", "mcp_tool_abuse", "agentic_security"}]
    infra_findings = [finding for finding in findings if finding.get("category") in {"container_security", "ci_cd_security", "infrastructure_as_code"}]
    auth_review = auth_review_summary(findings)
    tenant_review = tenant_isolation_review_summary(findings)

    return {
        "authentication_map": _build_repository_map(
            auth_findings,
            lambda finding: finding.get("rule") in {"route_with_auth_middleware", "public_route_marked_public", "unauthenticated_route"},
            "authentication",
        ),
        "authorisation_map": _build_repository_map(
            auth_findings,
            lambda finding: finding.get("rule") in {"route_with_role_check", "route_with_ownership_check", "route_with_tenant_check", "object_id_access", "unrestricted_admin_endpoint", "confirmed_auth_bypass", "missing_tenant_filters", "tenant_scoped_query"},
            "authorisation",
        ),
        "data_flow_map": _build_repository_map(
            findings,
            lambda finding: bool(finding.get("source") or finding.get("sink") or finding.get("flow_path")),
            "data flow",
        ),
        "trust_boundary_map": _build_repository_map(
            findings,
            lambda finding: bool(finding.get("boundary_crossing") or finding.get("trust_boundary") or finding.get("boundary")),
            "trust boundary",
        ),
        "agent_map": _build_repository_map(
            agent_findings,
            lambda finding: True,
            "agent",
        ),
        "infrastructure_map": _build_repository_map(
            infra_findings,
            lambda finding: True,
            "infrastructure",
        ),
        "repository_understanding": [
            _map_entry(
                "authentication",
                "Observed from framework, route, and dependency evidence where available.",
                auth_review["protected_routes"] + auth_review["routes_requiring_review"],
                partial_evidence=auth_review["public_routes"] == 0 or auth_review["routes_requiring_review"] > 0,
                inferred=auth_review["routes_requiring_review"] > 0,
                related_findings=[finding.get("id") for finding in auth_findings if finding.get("id")][:10],
            ),
            _map_entry(
                "authorisation",
                "Observed from role, ownership, tenant, and object-access evidence where available.",
                tenant_review["tenant_controls_detected"] + tenant_review["confirmed_cross_tenant_findings"],
                partial_evidence=tenant_review["tenant_review_count"] > 0,
                inferred=tenant_review["confirmed_cross_tenant_findings"] > 0,
                related_findings=[finding.get("id") for finding in auth_findings if finding.get("id")][:10],
            ),
            _map_entry(
                "data flow",
                "Observed from source, sink, and flow-path evidence where available.",
                sum(1 for finding in findings if finding.get("source") or finding.get("sink") or finding.get("flow_path")),
                partial_evidence=True,
                inferred=any(finding.get("finding_class") == "potential_risk" for finding in findings),
                related_findings=[finding.get("id") for finding in findings if finding.get("id")][:10],
            ),
            _map_entry(
                "trust boundaries",
                "Observed from boundary-crossing evidence and trust-zone relationships where available.",
                sum(1 for finding in findings if finding.get("boundary_crossing")),
                partial_evidence=any(finding.get("proof_status") in {"implicit", "source_only", "sink_only"} for finding in findings),
                inferred=any(finding.get("finding_class") == "potential_risk" for finding in findings),
                related_findings=[finding.get("id") for finding in findings if finding.get("boundary_crossing")][:10],
            ),
            _map_entry(
                "agent surfaces",
                "Observed from prompts, retrieval, memory, tools, MCP, and execution evidence where available.",
                len(agent_findings),
                partial_evidence=any(finding.get("proof_status") in {"implicit", "partial"} for finding in agent_findings),
                inferred=bool(agent_findings),
                related_findings=[finding.get("id") for finding in agent_findings if finding.get("id")][:10],
            ),
            _map_entry(
                "infrastructure",
                "Observed from CI/CD, containers, Kubernetes, Terraform, and Supabase evidence where available.",
                len(infra_findings),
                partial_evidence=any(finding.get("proof_status") in {"implicit", "partial"} for finding in infra_findings),
                inferred=bool(infra_findings),
                related_findings=[finding.get("id") for finding in infra_findings if finding.get("id")][:10],
            ),
        ],
    }


def tenant_isolation_review_summary(findings):
    tenant_findings = [finding for finding in findings if any(
        finding.get(field) for field in (
            "tenant_identifier",
            "tenant_evidence",
            "tenant_propagation_evidence",
            "query_scope_evidence",
            "retrieval_scope_evidence",
            "ownership_scope_evidence",
            "tenant_control_evidence",
        )
    ) or finding.get("rule") in {"route_with_tenant_check", "tenant_scoped_query", "missing_tenant_filters"}]
    confirmed = [finding for finding in tenant_findings if finding.get("finding_class") == "confirmed_vulnerability"]
    review = [finding for finding in tenant_findings if finding.get("finding_class") in {"potential_risk", "observed_capability"}]
    controls = [finding for finding in tenant_findings if finding.get("tenant_control_evidence") or finding.get("tenant_evidence") or finding.get("query_scope_evidence") or finding.get("ownership_scope_evidence")]
    return {
        "tenant_controls_detected": len(controls),
        "tenant_review_count": len(review),
        "confirmed_cross_tenant_findings": len(confirmed),
        "tenant_findings": tenant_findings,
    }


def attack_surface_summary(findings):
    categories = Counter(f["category"] for f in findings)
    scopes = Counter(f.get("scope", "production") for f in findings)
    return {
        "findings_by_category": dict(categories),
        "findings_by_scope": dict(scopes),
        "top_rules": [finding["rule"] for finding in findings[:10]],
        "high_risk_paths": len([finding for finding in findings if finding.get("production_blocker")]),
    }


def trust_grade(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _trust_score_deductions(findings):
    deductions = []
    severity_weights = {"Critical": 24, "High": 14, "Medium": 8, "Low": 3, "Info": 1}
    confidence_weights = {"HIGH": 6, "MEDIUM": 3, "LOW": 1}
    doc_weight = {"Critical": 14, "High": 7, "Medium": 3, "Low": 1, "Info": 0}
    for finding in findings:
        severity = finding.get("severity", "Medium")
        confidence = finding.get("confidence_level", "MEDIUM")
        base = severity_weights.get(severity, 8) + confidence_weights.get(confidence, 3)
        category = finding.get("category")
        if finding.get("finding_class") == "observed_capability":
            base = 0
        elif finding.get("finding_class") == "potential_risk":
            base = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(severity, 2)
        else:
            if finding.get("production_blocker"):
                base += 6
            if category == "agentic_security":
                base += 6
            if category == "retrieval_poisoning":
                base += 5
            if category == "mcp_tool_abuse":
                base += 4
            if category == "leaked_secrets":
                base += 12
            if is_documentation_finding(finding):
                base = doc_weight.get(severity, 2) + (1 if confidence == "HIGH" else 0)
        deductions.append({
            "finding": finding,
            "points": base,
        })
    return deductions


def calculate_trust_score(findings, trust_paths_items, attack_chains_items, active_suppressions=None, expired_suppressions=None, audit_warnings=None, unsuppressed_findings=None):
    active_suppressions = list(active_suppressions or [])
    expired_suppressions = list(expired_suppressions or [])
    audit_warnings = list(audit_warnings or [])
    unsuppressed_findings = list(unsuppressed_findings or findings)

    suppressed = list(findings)
    active_suppression_count = len(active_suppressions)
    expired_suppression_count = len(expired_suppressions)
    potential_findings = [finding for finding in suppressed if finding.get("finding_class") == "potential_risk"]
    confirmed_findings = [finding for finding in suppressed if finding.get("finding_class") == "confirmed_vulnerability"]
    blocked_findings = sum(1 for finding in confirmed_findings if finding.get("production_blocker"))
    doc_findings = [finding for finding in confirmed_findings if is_documentation_finding(finding)]
    prod_findings = [finding for finding in confirmed_findings if not is_documentation_finding(finding) and (finding.get("scope") == "production" or "production" in set(finding.get("scope_tags", [])))]
    agentic_findings = [finding for finding in confirmed_findings if finding.get("category") == "agentic_security"]
    confirmed_trust_paths = trust_paths(confirmed_findings)
    trust_path_count = len(confirmed_trust_paths)
    attack_chain_count = len(attack_chains(confirmed_trust_paths))
    baseline_potential_findings = [finding for finding in unsuppressed_findings if finding.get("finding_class") == "potential_risk"]
    baseline_confirmed_findings = [finding for finding in unsuppressed_findings if finding.get("finding_class") == "confirmed_vulnerability"]
    baseline_trust_paths = trust_paths(baseline_confirmed_findings)
    baseline_trust_path_count = len(baseline_trust_paths)
    baseline_attack_chain_count = len(attack_chains(baseline_trust_paths))

    deductions = []
    total = 0

    def add(label, points, evidence):
        nonlocal total
        if points <= 0:
            return
        total += points
        deductions.append({"driver": label, "points": points, "evidence": evidence})

    for entry in _trust_score_deductions(confirmed_findings):
        finding = entry["finding"]
        add(
            f"{finding.get('severity', 'Medium')} {finding.get('confidence_level', 'MEDIUM')} finding",
            entry["points"],
            finding.get("id"),
        )

    potential_points = min(10, sum(entry["points"] for entry in _trust_score_deductions(potential_findings)))
    add("potential risks", potential_points, len(potential_findings))
    add("production-scope findings", min(12, len(prod_findings) * 2), len(prod_findings))
    add("documentation findings", min(6, len(doc_findings)), len(doc_findings))
    add("production blockers", min(18, blocked_findings * 6), blocked_findings)
    add("trust paths", min(24, trust_path_count * 4), trust_path_count)
    add("attack chains", min(28, attack_chain_count * 6), attack_chain_count)
    add("expired suppressions", min(12, expired_suppression_count * 4), expired_suppression_count)
    add("scanner failures", min(18, len(audit_warnings) * 6), len(audit_warnings))
    add("agentic security findings", min(16, len(agentic_findings) * 3), len(agentic_findings))

    raw_score = max(0, 100 - total)
    baseline_deductions = 0
    for entry in _trust_score_deductions(baseline_confirmed_findings):
        baseline_deductions += entry["points"]
    baseline_deductions += min(10, sum(entry["points"] for entry in _trust_score_deductions(baseline_potential_findings)))
    baseline_deductions += min(12, sum(1 for finding in baseline_confirmed_findings if not is_documentation_finding(finding) and (finding.get("scope") == "production" or "production" in set(finding.get("scope_tags", [])))) * 2)
    baseline_deductions += min(6, sum(1 for finding in baseline_confirmed_findings if is_documentation_finding(finding)))
    baseline_deductions += min(18, sum(1 for finding in baseline_confirmed_findings if finding.get("production_blocker")) * 6)
    baseline_deductions += min(24, baseline_trust_path_count * 4)
    baseline_deductions += min(28, baseline_attack_chain_count * 6)
    baseline_deductions += min(12, expired_suppression_count * 4)
    baseline_deductions += min(18, len(audit_warnings) * 6)
    baseline_deductions += min(16, len([finding for finding in baseline_confirmed_findings if finding.get("category") == "agentic_security"]) * 3)
    baseline_score = max(0, 100 - baseline_deductions)

    final_score = min(raw_score, baseline_score)
    final_score = max(0, min(100, final_score))

    reasoning = [
        f"Start at 100; observed capabilities do not reduce the score, potential risks are capped at 10 points, and confirmed vulnerabilities retain normal penalties.",
        f"Classified findings: {len(confirmed_findings)} confirmed, {len(potential_findings)} potential, {len(suppressed) - len(confirmed_findings) - len(potential_findings)} observed.",
        f"Production-scope findings: {len(prod_findings)}.",
        f"Documentation findings: {len(doc_findings)}.",
        f"Production blockers: {blocked_findings}.",
        f"Expired suppressions: {expired_suppression_count}.",
        f"Scanner failures: {len(audit_warnings)}.",
    ]
    if active_suppression_count:
        reasoning.append("Active suppressions may reduce the visible findings list, but the score is capped at the unsuppressed baseline.")

    top_drivers = sorted(deductions, key=lambda item: item["points"], reverse=True)[:5]
    return {
        "trust_score": final_score,
        "trust_grade": trust_grade(final_score),
        "trust_score_reasoning": reasoning,
        "top_drivers": top_drivers,
        "baseline_score": baseline_score,
    }


def production_readiness(findings, trust_paths_items, attack_chains_items, active_suppressions=None, expired_suppressions=None, audit_warnings=None, trust_score_info=None, unsuppressed_findings=None):
    active_suppressions = list(active_suppressions or [])
    expired_suppressions = list(expired_suppressions or [])
    audit_warnings = list(audit_warnings or [])
    unsuppressed_findings = list(unsuppressed_findings or findings)
    trust_score_info = trust_score_info or calculate_trust_score(findings, trust_paths_items, attack_chains_items, active_suppressions=active_suppressions, expired_suppressions=expired_suppressions, audit_warnings=audit_warnings, unsuppressed_findings=unsuppressed_findings)

    def critical_expired_suppressions():
        critical_rules = {finding.get("rule") for finding in unsuppressed_findings if finding.get("severity") == "Critical"}
        return [
            suppression
            for suppression in expired_suppressions
            if suppression.get("rule") in critical_rules
        ]

    production_findings = [
        finding
        for finding in findings
        if finding.get("finding_class") != "observed_capability"
        and not is_documentation_finding(finding)
        and (
            finding.get("scope") == "production"
            or "production" in set(finding.get("scope_tags", []))
            or finding.get("category") == "framework_security"
        )
    ]
    pressure_findings = [finding for finding in production_findings if not (finding.get("status") == "accepted_risk" and finding.get("severity") != "Critical" and finding.get("category") != "leaked_secrets")]
    gate = readiness_decision(pressure_findings, audit_warnings=audit_warnings)
    blockers = [finding for finding in pressure_findings if finding["id"] in set(gate["production_blockers"])]
    review_items = [finding for finding in pressure_findings if finding["id"] in set(gate["required_reviews"])]
    decision_paths = trust_paths(production_findings)
    decision_chains = attack_chains(decision_paths)
    risky_paths = [path for path in decision_paths if path.get("risk") in {"High", "Critical"} and path.get("confidence") in {"High", "Medium"}]
    high_confidence_chains = [chain for chain in decision_chains if chain.get("confidence_score", 0) >= 90]
    unresolved_agentic_chains = [chain for chain in decision_chains if any("Agent" in boundary for boundary in chain.get("supporting_boundaries", [])) or "Agent" in chain.get("name", "")]

    scanner_issue = any(warning.get("rule") in {"scanner_failed", "scanner_unavailable"} for warning in audit_warnings)
    if scanner_issue or critical_expired_suppressions():
        status = "NOT_READY_FOR_PRODUCTION"
        reason = gate["decision_reasons"][0] if gate["decision_reasons"] else "Scanner failures prevent a complete production assessment."
    elif gate["readiness"] == "NOT_READY_FOR_PRODUCTION":
        status = "NOT_READY_FOR_PRODUCTION"
        reason = gate["decision_reasons"][0] if gate["decision_reasons"] else "Critical production risk remains unresolved."
    elif gate["readiness"] == "REVIEW_REQUIRED" or any(finding.get("severity") == "High" and finding.get("finding_class") == "confirmed_vulnerability" for finding in pressure_findings) or high_confidence_chains or unresolved_agentic_chains or risky_paths:
        status = "REVIEW_REQUIRED"
        reason = gate["decision_reasons"][0] if gate["decision_reasons"] else "High-confidence production risk paths or chains still need review."
    elif trust_score_info.get("trust_score", 0) >= 90:
        status = "READY_FOR_PRODUCTION"
        reason = gate["decision_reasons"][0] if gate["decision_reasons"] else "No meaningful production findings remain and trust score is high."
    else:
        status = "READY_WITH_REVIEW"
        reason = gate["decision_reasons"][0] if gate["decision_reasons"] else "Residual production evidence remains, but it is limited to review items."

    next_steps = []
    if status == "NOT_READY_FOR_PRODUCTION":
        next_steps = [
            "Fix all critical production findings.",
            "Resolve scanner failures before release.",
            "Re-run the audit after remediation.",
        ]
    elif status == "REVIEW_REQUIRED":
        next_steps = [
            "Review high-confidence attack chains and risky trust paths.",
            "Tighten agentic or tool-mediated production flows.",
            "Re-run the audit after review.",
        ]
    elif status == "READY_WITH_REVIEW":
        next_steps = [
            "Address the remaining medium and low production items.",
            "Document any accepted residual risk.",
            "Re-run the audit before production release.",
        ]
    else:
        next_steps = [
            "Proceed with production release controls.",
            "Keep the current audit output as the release evidence.",
        ]

    blockers_list = [finding["id"] for finding in blockers[:10]]
    if critical_expired_suppressions():
        blockers_list.extend([f"suppression:{suppression['rule']}" for suppression in critical_expired_suppressions()])
    if audit_warnings:
        blockers_list.extend([f"scanner:{warning.get('scanner', 'unknown')}" for warning in audit_warnings])

    review_item_ids = [finding["id"] for finding in review_items[:10]]
    return {
        "status": status,
        "reason": reason,
        "blockers": blockers_list,
        "review_items": review_item_ids,
        "recommended_next_steps": next_steps,
        "decision_reasons": gate["decision_reasons"],
        "production_blockers": gate["production_blockers"],
        "required_reviews": gate["required_reviews"],
    }


def top_risks(findings, repo_config=None):
    findings = [normalize_emitted_finding(finding) for finding in findings]
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
        "deployment": [f for f in findings if _path_classes(f)[1] == "deployment"],
    }
    path_source_labels = {
        "prompt": "Prompt Input",
        "agent": "Agent",
        "environment": "Environment Variable",
        "file": "File Input",
        "retrieval": "Retrieval Output",
        "tool": "MCP Tool Input",
        "deployment": "Deployment Target",
    }
    path_sink_labels = {
        "execution": "Execution Sink",
        "filesystem": "Filesystem Sink",
        "network": "Network Sink",
        "credential": "Credential Sink",
        "tool": "Tool Sink",
        "network": "Network Sink",
        "privileged_action": "Privileged Action Sink",
        "deployment": "Deployment Target",
    }
    paths = []
    class_pairs = [
        ("prompt", "execution", "High", "Prompt data can reach command execution."),
        ("prompt", "filesystem", "Medium", "Prompt data can reach filesystem mutation."),
        ("prompt", "network", "High", "Prompt data can reach outbound requests."),
        ("prompt", "tool", "High", "Prompt data can reach privileged tool use."),
        ("prompt", "privileged_action", "High", "Prompt data can reach privileged action paths."),
        ("agent", "execution", "High", "Agent instructions can reach command execution."),
        ("agent", "filesystem", "High", "Agent instructions can reach filesystem mutation."),
        ("agent", "credential", "High", "Agent instructions can reach credential exposure."),
        ("agent", "deployment", "Critical", "Agent instructions can reach deployment actions."),
        ("agent", "tool", "High", "Agent instructions can reach privileged tool use."),
        ("environment", "execution", "Medium", "Environment values can influence execution paths."),
        ("environment", "network", "Medium", "Environment values can flow into outbound requests."),
        ("file", "execution", "Medium", "File-controlled data can reach execution sinks."),
        ("file", "network", "Medium", "File-controlled data can reach outbound requests."),
        ("retrieval", "network", "High", "Retrieved content can be reused in network requests."),
        ("retrieval", "prompt", "High", "Retrieved content can influence prompt construction."),
        ("retrieval", "tool", "High", "Retrieved content can influence tool use."),
        ("retrieval", "execution", "High", "Retrieved content can influence execution paths."),
        ("tenant_context", "query", "High", "Tenant context can influence database queries."),
        ("tenant_context", "retrieval", "High", "Tenant context can influence retrieval scoping."),
        ("tenant_context", "repository", "High", "Tenant context can influence repository access."),
        ("tenant_data", "prompt", "High", "Tenant data can influence prompt construction."),
        ("tenant_data", "tool", "High", "Tenant data can influence agent tool use."),
        ("tenant_data", "network", "High", "Tenant data can influence external requests."),
        ("tool", "execution", "High", "Tool-originated input can reach execution sinks."),
        ("tool", "filesystem", "Medium", "Tool-originated input can reach filesystem mutation."),
        ("tool", "credential", "High", "Tool-originated input can reach credential exposure."),
        ("tool", "network", "High", "Tool-originated input can reach outbound requests."),
        ("tool", "deployment", "High", "Tool-originated input can reach deployment actions."),
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
    agentic_sources = [f for f in findings if f.get("category") == "agentic_security"]
    if agentic_sources:
        source_item = agentic_sources[0]
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if len({f.get("file") for f in agentic_sources if f.get("file")}) == 1 else "cross_file",
            "boundary": "Prompt -> Tool",
            "source": "Prompt Input",
            "source_class": "prompt",
            "sink": "Tool Sink",
            "sink_class": "tool",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in agentic_sources) else "Medium",
            "confidence_score": 86,
            "evidence": [source_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                }
            ],
            "data_flow_summary": "Prompt-like instructions can steer tool use.",
        })
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if len({f.get("file") for f in agentic_sources if f.get("file")}) == 1 else "cross_file",
            "boundary": "Prompt -> Privileged Action",
            "source": "Prompt Input",
            "source_class": "prompt",
            "sink": "Privileged Action Sink",
            "sink_class": "privileged_action",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in agentic_sources) else "Medium",
            "confidence_score": 88,
            "evidence": [source_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                }
            ],
            "data_flow_summary": "Prompt-like instructions can be treated as privileged action requests.",
        })
    agentic_execution_sources = [f for f in findings if f.get("category") == "agentic_security" and f.get("rule") in {"auto_run", "auto_execute", "unattended_execution", "spawn_agent", "create_sub_agent", "recursive_task", "self_improve", "self_modify", "delegate_until_done", "loop_until_success", "use_tools_automatically", "invoke_any_tool", "execute_tool_without_approval", "auto_call_tools", "indefinite_tool_retry", "auto_deploy", "push_to_main", "delete_production", "run_migration_automatically", "apply_terraform_automatically", "kubectl_apply", "docker_push", "npm_publish", "missing_human_gate"}]
    if agentic_execution_sources:
        source_item = agentic_execution_sources[0]
        same_file = len({f.get("file") for f in agentic_execution_sources if f.get("file")}) == 1
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if same_file else "cross_file",
            "boundary": "Agent -> Tool",
            "source": "Agent",
            "source_class": "agent",
            "sink": "Tool Sink",
            "sink_class": "tool",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in agentic_execution_sources) else "Medium",
            "confidence_score": 88,
            "evidence": [source_item["id"]],
            "evidence_details": [{
                "finding_id": source_item["id"],
                "file": source_item.get("file"),
                "line": source_item.get("line"),
                "role": "source",
            }],
            "data_flow_summary": "Autonomous agent instructions can reach tool use without a human gate.",
        })
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if same_file else "cross_file",
            "boundary": "Agent -> Execution",
            "source": "Agent",
            "source_class": "agent",
            "sink": "Execution Sink",
            "sink_class": "execution",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in agentic_execution_sources) else "Medium",
            "confidence_score": 89,
            "evidence": [source_item["id"]],
            "evidence_details": [{
                "finding_id": source_item["id"],
                "file": source_item.get("file"),
                "line": source_item.get("line"),
                "role": "source",
            }],
            "data_flow_summary": "Autonomous agent instructions can reach execution sinks.",
        })
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if same_file else "cross_file",
            "boundary": "Agent -> Filesystem",
            "source": "Agent",
            "source_class": "agent",
            "sink": "Filesystem Sink",
            "sink_class": "filesystem",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in agentic_execution_sources) else "Medium",
            "confidence_score": 87,
            "evidence": [source_item["id"]],
            "evidence_details": [{
                "finding_id": source_item["id"],
                "file": source_item.get("file"),
                "line": source_item.get("line"),
                "role": "source",
            }],
            "data_flow_summary": "Autonomous agent instructions can reach filesystem mutation.",
        })
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if same_file else "cross_file",
            "boundary": "Agent -> Deployment",
            "source": "Agent",
            "source_class": "agent",
            "sink": "Deployment Target",
            "sink_class": "deployment",
            "risk": "Critical",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in agentic_execution_sources) else "Medium",
            "confidence_score": 92,
            "evidence": [source_item["id"]],
            "evidence_details": [{
                "finding_id": source_item["id"],
                "file": source_item.get("file"),
                "line": source_item.get("line"),
                "role": "source",
            }],
            "data_flow_summary": "Autonomous agent instructions can directly reach deployment actions.",
        })
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if same_file else "cross_file",
            "boundary": "Agent -> Credential",
            "source": "Agent",
            "source_class": "agent",
            "sink": "Credential Sink",
            "sink_class": "credential",
            "risk": "High",
            "confidence": "Medium",
            "confidence_score": 84,
            "evidence": [source_item["id"]],
            "evidence_details": [{
                "finding_id": source_item["id"],
                "file": source_item.get("file"),
                "line": source_item.get("line"),
                "role": "source",
            }],
            "data_flow_summary": "Autonomous agent instructions can reach credential-handling paths.",
        })
    retrieval_poisoning_findings = [f for f in findings if f.get("category") == "retrieval_poisoning"]
    if retrieval_poisoning_findings:
        source_item = retrieval_poisoning_findings[0]
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if len({f.get("file") for f in retrieval_poisoning_findings if f.get("file")}) == 1 else "cross_file",
            "boundary": "Retrieval -> Prompt",
            "source": "Retrieved Content",
            "source_class": "retrieval",
            "sink": "Prompt Sink",
            "sink_class": "prompt",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in retrieval_poisoning_findings) else "Medium",
            "confidence_score": 89,
            "evidence": [source_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                }
            ],
            "data_flow_summary": "Retrieved corpus content can influence prompt construction.",
        })
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if len({f.get("file") for f in retrieval_poisoning_findings if f.get("file")}) == 1 else "cross_file",
            "boundary": "Retrieval -> Tool",
            "source": "Retrieved Content",
            "source_class": "retrieval",
            "sink": "Tool Sink",
            "sink_class": "tool",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in retrieval_poisoning_findings) else "Medium",
            "confidence_score": 88,
            "evidence": [source_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                }
            ],
            "data_flow_summary": "Retrieved corpus content can influence tool use.",
        })
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if len({f.get("file") for f in retrieval_poisoning_findings if f.get("file")}) == 1 else "cross_file",
            "boundary": "Retrieval -> Execution",
            "source": "Retrieved Content",
            "source_class": "retrieval",
            "sink": "Execution Sink",
            "sink_class": "execution",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in retrieval_poisoning_findings) else "Medium",
            "confidence_score": 87,
            "evidence": [source_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                }
            ],
            "data_flow_summary": "Retrieved corpus content can influence execution paths.",
        })
    mcp_tool_findings = [f for f in findings if f.get("category") == "mcp_tool_abuse"]
    mcp_credential_findings = [f for f in mcp_tool_findings if f.get("rule") == "mcp_env_credentials_exposure"]
    if mcp_tool_findings:
        source_item = mcp_tool_findings[0]
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if len({f.get("file") for f in mcp_tool_findings if f.get("file")}) == 1 else "cross_file",
            "boundary": "Tool -> Execution",
            "source": "MCP Tool Configuration",
            "source_class": "tool",
            "sink": "Execution Sink",
            "sink_class": "execution",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in mcp_tool_findings) else "Medium",
            "confidence_score": 84,
            "evidence": [source_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                }
            ],
            "data_flow_summary": "MCP tool configuration can expose direct execution surface.",
        })
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if len({f.get("file") for f in mcp_tool_findings if f.get("file")}) == 1 else "cross_file",
            "boundary": "Tool -> Filesystem",
            "source": "MCP Tool Configuration",
            "source_class": "tool",
            "sink": "Filesystem Sink",
            "sink_class": "filesystem",
            "risk": "High",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in mcp_tool_findings) else "Medium",
            "confidence_score": 82,
            "evidence": [source_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                }
            ],
            "data_flow_summary": "MCP tool configuration can expose filesystem access surface.",
        })
    if mcp_tool_findings and any(f.get("rule") == "unrestricted_network_tool" for f in mcp_tool_findings):
        source_item = next(f for f in mcp_tool_findings if f.get("rule") == "unrestricted_network_tool")
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if len({f.get("file") for f in mcp_tool_findings if f.get("file")}) == 1 else "cross_file",
            "boundary": "Tool -> Network",
            "source": "MCP Tool Configuration",
            "source_class": "tool",
            "sink": "Network Sink",
            "sink_class": "network",
            "risk": "High",
            "confidence": "High" if source_item.get("confidence_level") == "HIGH" else "Medium",
            "confidence_score": 83,
            "evidence": [source_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                }
            ],
            "data_flow_summary": "MCP tool configuration can expose outbound network access surface.",
        })
    if mcp_credential_findings:
        source_item = mcp_credential_findings[0]
        paths.append({
            "path_type": "source_to_sink",
            "correlation_type": "same_file" if len({f.get("file") for f in mcp_credential_findings if f.get("file")}) == 1 else "cross_file",
            "boundary": "Tool -> Credential",
            "source": "MCP Credential Fields",
            "source_class": "tool",
            "sink": "Credential Sink",
            "sink_class": "credential",
            "risk": "Critical",
            "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in mcp_credential_findings) else "Medium",
            "confidence_score": 92,
            "evidence": [source_item["id"]],
            "evidence_details": [
                {
                    "finding_id": source_item["id"],
                    "file": source_item.get("file"),
                    "line": source_item.get("line"),
                    "role": "source",
                }
            ],
            "data_flow_summary": "MCP environment fields can expose credential material.",
        })
    memory_findings = [f for f in findings if f.get("category") == "agentic_security" and f.get("rule") in {"persistent_instruction", "cross_session_contamination", "hidden_memory_directive", "unsafe_memory_write", "sensitive_memory_storage"}]
    if memory_findings:
        source_item = memory_findings[0]
        paths.extend([
            {
                "path_type": "source_to_sink",
                "correlation_type": "same_file" if len({f.get("file") for f in memory_findings if f.get("file")}) == 1 else "cross_file",
                "boundary": "Memory -> Prompt",
                "source": "Persistent Memory",
                "source_class": "memory",
                "sink": "Prompt Sink",
                "sink_class": "prompt",
                "risk": "High",
                "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in memory_findings) else "Medium",
                "confidence_score": 90,
                "evidence": [source_item["id"]],
                "evidence_details": [{"finding_id": source_item["id"], "file": source_item.get("file"), "line": source_item.get("line"), "role": "source"}],
                "data_flow_summary": "Persistent memory can influence future prompt construction.",
            },
            {
                "path_type": "source_to_sink",
                "correlation_type": "same_file" if len({f.get("file") for f in memory_findings if f.get("file")}) == 1 else "cross_file",
                "boundary": "Memory -> Tool",
                "source": "Persistent Memory",
                "source_class": "memory",
                "sink": "Tool Sink",
                "sink_class": "tool",
                "risk": "High",
                "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in memory_findings) else "Medium",
                "confidence_score": 89,
                "evidence": [source_item["id"]],
                "evidence_details": [{"finding_id": source_item["id"], "file": source_item.get("file"), "line": source_item.get("line"), "role": "source"}],
                "data_flow_summary": "Persistent memory can influence tool selection and invocation.",
            },
            {
                "path_type": "source_to_sink",
                "correlation_type": "same_file" if len({f.get("file") for f in memory_findings if f.get("file")}) == 1 else "cross_file",
                "boundary": "Memory -> Credential",
                "source": "Persistent Memory",
                "source_class": "memory",
                "sink": "Credential Sink",
                "sink_class": "credential",
                "risk": "Critical",
                "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in memory_findings) else "Medium",
                "confidence_score": 92,
                "evidence": [source_item["id"]],
                "evidence_details": [{"finding_id": source_item["id"], "file": source_item.get("file"), "line": source_item.get("line"), "role": "source"}],
                "data_flow_summary": "Persistent memory can retain and expose credentials or secrets.",
            },
            {
                "path_type": "source_to_sink",
                "correlation_type": "same_file" if len({f.get("file") for f in memory_findings if f.get("file")}) == 1 else "cross_file",
                "boundary": "Memory -> Execution",
                "source": "Persistent Memory",
                "source_class": "memory",
                "sink": "Execution Sink",
                "sink_class": "execution",
                "risk": "High",
                "confidence": "High" if any(f.get("confidence_level") == "HIGH" for f in memory_findings) else "Medium",
                "confidence_score": 91,
                "evidence": [source_item["id"]],
                "evidence_details": [{"finding_id": source_item["id"], "file": source_item.get("file"), "line": source_item.get("line"), "role": "source"}],
                "data_flow_summary": "Persistent memory can drive future execution behavior.",
            },
        ])
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


def _graph_trust_zone(label: str):
    zone_map = {
        "untrusted_input": "untrusted_user_input",
        "prompt_content": "llm_prompt_context",
        "retrieved_document": "retrieval_context",
        "environment_variable": "secrets_environment",
        "file_contents": "local_filesystem",
        "mcp_response": "agent_tool_runtime",
        "tenant_context": "tenant_context",
        "tenant_data": "tenant_data",
        "agent": "application_code",
    }
    return zone_map.get(label, "application_code")


def _graph_node(node_id: str, node_type: str, label: str, finding=None, evidence=None, trust_zone=None):
    return {
        "node_id": node_id,
        "node_type": node_type,
        "label": label,
        "file": (finding or {}).get("file"),
        "line": (finding or {}).get("line"),
        "evidence": evidence or (finding or {}).get("evidence_redacted") or (finding or {}).get("evidence_snippet") or (finding or {}).get("evidence"),
        "trust_zone": trust_zone or "application_code",
    }


def build_trust_boundary_graph(findings, trust_paths_items=None):
    trust_paths_items = list(trust_paths_items or trust_paths(findings))
    nodes = {}
    edges = []

    def add_node(node_id, node_type, label, finding=None, evidence=None, trust_zone=None):
        if node_id not in nodes:
            nodes[node_id] = _graph_node(node_id, node_type, label, finding=finding, evidence=evidence, trust_zone=trust_zone)
        return nodes[node_id]

    def make_edge(edge_id, source_id, target_id, edge_type, boundary_crossing, from_zone, to_zone, finding=None, partial_evidence=False, evidence=None, trust_boundary=None):
        edges.append({
            "edge_id": edge_id,
            "source": source_id,
            "target": target_id,
            "edge_type": edge_type,
            "boundary_crossing": boundary_crossing,
            "trust_zone_from": from_zone,
            "trust_zone_to": to_zone,
            "partial_evidence": partial_evidence,
            "file": (finding or {}).get("file"),
            "line": (finding or {}).get("line"),
            "evidence": evidence or (finding or {}).get("evidence_redacted") or (finding or {}).get("evidence_snippet"),
            "trust_boundary": trust_boundary,
        })

    for finding in findings:
        node_type = {
            "prompt_injection": "llm_prompt_component",
            "retrieval_poisoning": "entry_point",
            "mcp_tool_abuse": "agent_tool",
            "unsafe_execution": "shell_sink",
            "data_exfiltration": "network_sink",
            "secret_leakage": "data_store",
            "leaked_secrets": "data_store",
            "agentic_security": "internal_component",
        }.get(finding.get("category"), "internal_component")
        trust_zone = {
            "prompt_injection": "llm_prompt_context",
            "retrieval_poisoning": "retrieval_context",
            "mcp_tool_abuse": "agent_tool_runtime",
            "unsafe_execution": "shell_runtime",
            "data_exfiltration": "external_network",
            "secret_leakage": "tenant_data",
            "leaked_secrets": "tenant_data",
            "agentic_security": "application_code",
            "container_security": "container_runtime",
            "ci_cd_security": "ci_workflow",
            "infrastructure_as_code": "cloud_control_plane",
        }.get(finding.get("category"), "application_code")
        add_node(finding["id"], node_type, finding.get("rule") or finding["category"], finding=finding, trust_zone=trust_zone)
        if finding.get("category") == "ci_cd_security":
            if finding.get("rule") in {"pull_request_target_secret_exposure", "secret_environment_use"}:
                add_node("secrets_environment", "context", "Secrets Environment", trust_zone="secrets_environment")
                make_edge(
                    f"{finding['id']}:secrets",
                    finding["id"],
                    "secrets_environment",
                    "ci_workflow -> secrets_environment",
                    True,
                    "ci_workflow",
                    "secrets_environment",
                    finding=finding,
                    partial_evidence=finding.get("finding_class") != "confirmed_vulnerability",
                    evidence=finding.get("observed_evidence") or finding.get("evidence_redacted"),
                    trust_boundary="secrets_environment",
                )
            if finding.get("rule") in {"dangerous_ci_command", "untrusted_input_deploy"}:
                add_node("deployment_target", "deployment", "Deployment Target", trust_zone="deployment")
                make_edge(
                    f"{finding['id']}:deploy",
                    finding["id"],
                    "deployment_target",
                    "ci_workflow -> deployment_target",
                    True,
                    "ci_workflow",
                    "deployment",
                    finding=finding,
                    partial_evidence=finding.get("finding_class") != "confirmed_vulnerability",
                    evidence=finding.get("observed_evidence") or finding.get("evidence_redacted"),
                    trust_boundary="deployment_target",
                )
            add_node("shell_runtime", "runtime", "Shell Runtime", trust_zone="shell_runtime")
            make_edge(
                f"{finding['id']}:shell",
                finding["id"],
                "shell_runtime",
                "ci_workflow -> shell_runtime",
                finding.get("rule") in {"dangerous_ci_command", "untrusted_input_deploy"},
                "ci_workflow",
                "shell_runtime",
                finding=finding,
                partial_evidence=finding.get("finding_class") != "confirmed_vulnerability",
                evidence=finding.get("observed_evidence") or finding.get("evidence_redacted"),
                trust_boundary="shell_runtime",
            )
        if finding.get("category") == "container_security":
            add_node("host_filesystem", "host", "Host Filesystem", trust_zone="host_filesystem")
            add_node("external_network", "network", "External Network", trust_zone="external_network")
            make_edge(
                f"{finding['id']}:hostfs",
                finding["id"],
                "host_filesystem",
                "container_runtime -> host_filesystem",
                finding.get("rule") in {"docker_socket_mount", "k8s_hostpath_mount"},
                "container_runtime",
                "host_filesystem",
                finding=finding,
                partial_evidence=finding.get("finding_class") != "confirmed_vulnerability",
                evidence=finding.get("observed_evidence") or finding.get("evidence_redacted"),
                trust_boundary="host_filesystem",
            )
            make_edge(
                f"{finding['id']}:network",
                finding["id"],
                "external_network",
                "container_runtime -> external_network",
                True,
                "container_runtime",
                "external_network",
                finding=finding,
                partial_evidence=finding.get("finding_class") != "confirmed_vulnerability",
                evidence=finding.get("observed_evidence") or finding.get("evidence_redacted"),
                trust_boundary="external_network",
            )
        if finding.get("category") == "infrastructure_as_code":
            add_node("cloud_resource", "resource", "Cloud Resource", trust_zone="cloud_resource")
            make_edge(
                f"{finding['id']}:cloud",
                finding["id"],
                "cloud_resource",
                "terraform_config -> cloud_resource",
                True,
                "cloud_control_plane",
                "cloud_resource",
                finding=finding,
                partial_evidence=finding.get("finding_class") != "confirmed_vulnerability",
                evidence=finding.get("observed_evidence") or finding.get("evidence_redacted"),
                trust_boundary="cloud_resource",
            )
        if finding.get("category") == "infrastructure_as_code" and finding.get("infrastructure_surface") == "Supabase":
            add_node("tenant_data", "data_store", "Tenant Data", trust_zone="tenant_data")
            make_edge(
                f"{finding['id']}:tenant",
                finding["id"],
                "tenant_data",
                "supabase_config -> tenant_data",
                True,
                "cloud_control_plane",
                "tenant_data",
                finding=finding,
                partial_evidence=finding.get("finding_class") != "confirmed_vulnerability",
                evidence=finding.get("observed_evidence") or finding.get("evidence_redacted"),
                trust_boundary="tenant_data",
            )
        if finding.get("category") == "framework_security":
            rule = finding.get("rule")
            if rule == "public_route_marked_public":
                add_node("unauthenticated_user", "actor", "Unauthenticated User", trust_zone="external_user")
                make_edge(
                    f"{finding['id']}:public",
                    "unauthenticated_user",
                    finding["id"],
                    "public_route",
                    False,
                    "external_user",
                    "application_code",
                    finding=finding,
                    partial_evidence=False,
                    evidence=finding.get("auth_evidence") or finding.get("evidence_redacted"),
                    trust_boundary="public_route",
                )
            elif rule in {"route_with_auth_middleware", "route_with_role_check", "route_with_permission_check", "route_with_ownership_check", "route_with_tenant_check"}:
                add_node("authenticated_session", "actor", "Authenticated Session", trust_zone="trusted_session")
                make_edge(
                    f"{finding['id']}:auth",
                    "authenticated_session",
                    finding["id"],
                    "authenticated_route",
                    True,
                    "trusted_session",
                    "application_code",
                    finding=finding,
                    partial_evidence=False,
                    evidence=finding.get("auth_evidence") or finding.get("authorization_evidence") or finding.get("evidence_redacted"),
                    trust_boundary="authenticated_route",
                )
            elif rule in {"unauthenticated_route", "unrestricted_admin_endpoint", "object_id_access", "missing_tenant_filters", "tenant_scoped_query"}:
                add_node("route_handler", "entry_point", "Route Handler", trust_zone="application_code")
                make_edge(
                    f"{finding['id']}:route",
                    "route_handler",
                    finding["id"],
                    "route_handler",
                    False,
                    "application_code",
                    "application_code",
                    finding=finding,
                    partial_evidence=True,
                    evidence=finding.get("route_or_handler") or finding.get("evidence_redacted"),
                    trust_boundary="route_handler",
                )
                if rule == "object_id_access":
                    add_node("object_resource", "data_store", "Object Resource", trust_zone="tenant_data")
                    make_edge(
                        f"{finding['id']}:object",
                        finding["id"],
                        "object_resource",
                        "object_resource",
                        True,
                        "application_code",
                        "tenant_data",
                        finding=finding,
                        partial_evidence=not finding.get("ownership_check_evidence"),
                        evidence=finding.get("object_access_evidence") or finding.get("evidence_redacted"),
                        trust_boundary="object_resource",
                    )
                if rule in {"missing_tenant_filters", "tenant_scoped_query", "route_with_tenant_check"}:
                    add_node("tenant_data", "data_store", "Tenant Data", trust_zone="tenant_data")
                    make_edge(
                        f"{finding['id']}:tenant",
                        finding["id"],
                        "tenant_data",
                        "tenant_data",
                        bool(finding.get("tenant_check_evidence")),
                        "application_code",
                        "tenant_data",
                        finding=finding,
                        partial_evidence=not finding.get("tenant_check_evidence"),
                        evidence=finding.get("tenant_check_evidence") or finding.get("evidence_redacted"),
                        trust_boundary="tenant_data",
                    )
                    add_node("tenant_context", "context", "Tenant Context", trust_zone="tenant_context")
                    make_edge(
                        f"{finding['id']}:tenant_context",
                        "tenant_context",
                        finding["id"],
                        "tenant_context",
                        bool(finding.get("tenant_check_evidence")),
                        "tenant_context",
                        "application_code",
                        finding=finding,
                        partial_evidence=not finding.get("tenant_check_evidence"),
                        evidence=finding.get("tenant_check_evidence") or finding.get("evidence_redacted"),
                        trust_boundary="tenant_context",
                    )
                    if rule in {"tenant_scoped_query", "missing_tenant_filters"}:
                        add_node("repository", "data_store", "Repository", trust_zone="tenant_data")
                        make_edge(
                            f"{finding['id']}:repo",
                            "tenant_context",
                            "repository",
                            "tenant_context -> repository",
                            bool(finding.get("tenant_check_evidence")),
                            "tenant_context",
                            "tenant_data",
                            finding=finding,
                            partial_evidence=not finding.get("tenant_check_evidence"),
                            evidence=finding.get("tenant_check_evidence") or finding.get("evidence_redacted"),
                            trust_boundary="repository",
                        )
                        add_node("query", "data_flow", "Query", trust_zone="tenant_data")
                        make_edge(
                            f"{finding['id']}:query",
                            "tenant_context",
                            "query",
                            "tenant_context -> query",
                            bool(finding.get("tenant_check_evidence")),
                            "tenant_context",
                            "tenant_data",
                            finding=finding,
                            partial_evidence=not finding.get("tenant_check_evidence"),
                            evidence=finding.get("tenant_check_evidence") or finding.get("evidence_redacted"),
                            trust_boundary="query",
                        )
                tenant_evidence = finding.get("tenant_check_evidence") or finding.get("tenant_evidence") or finding.get("ownership_check_evidence") or finding.get("authorization_evidence")
                if tenant_evidence and finding.get("category") in {"retrieval_poisoning", "data_exfiltration", "agentic_security"}:
                    add_node("tenant_data", "data_store", "Tenant Data", trust_zone="tenant_data")
                    if finding.get("category") in {"retrieval_poisoning", "agentic_security"}:
                        add_node("prompt_context", "context", "Prompt Context", trust_zone="llm_prompt_context")
                        make_edge(
                            f"{finding['id']}:prompt_context",
                            "tenant_data",
                            "prompt_context",
                            "tenant_data -> prompt_context",
                            True,
                            "tenant_data",
                            "llm_prompt_context",
                            finding=finding,
                            partial_evidence=False,
                            evidence=tenant_evidence,
                            trust_boundary="prompt_context",
                        )
                        add_node("agent_tool", "agent", "Agent Tool", trust_zone="agent_tool_runtime")
                        make_edge(
                            f"{finding['id']}:agent_tool",
                            "tenant_data",
                            "agent_tool",
                            "tenant_data -> agent_tool",
                            True,
                            "tenant_data",
                            "agent_tool_runtime",
                            finding=finding,
                            partial_evidence=False,
                            evidence=tenant_evidence,
                            trust_boundary="agent_tool",
                        )
                    if finding.get("category") == "data_exfiltration":
                        add_node("external_network", "network", "External Network", trust_zone="external_network")
                        make_edge(
                            f"{finding['id']}:network",
                            "tenant_data",
                            "external_network",
                            "tenant_data -> external_network",
                            True,
                            "tenant_data",
                            "external_network",
                            finding=finding,
                            partial_evidence=False,
                            evidence=tenant_evidence,
                            trust_boundary="external_network",
                        )
                if rule == "unrestricted_admin_endpoint":
                    add_node("admin_user", "actor", "Admin User", trust_zone="trusted_session")
                    add_node("admin_action", "privileged_action", "Admin Action", trust_zone="application_code")
                    make_edge(
                        f"{finding['id']}:admin",
                        "admin_user",
                        "admin_action",
                        "admin_action",
                        True,
                        "trusted_session",
                        "application_code",
                        finding=finding,
                        partial_evidence=not finding.get("role_check_evidence"),
                        evidence=finding.get("role_check_evidence") or finding.get("authorization_evidence") or finding.get("evidence_redacted"),
                        trust_boundary="admin_action",
                    )

    for path in trust_paths_items:
        source_class = path.get("source_class")
        sink_class = path.get("sink_class")
        source_id = f"{path.get('boundary', 'boundary')}:source"
        target_id = f"{path.get('boundary', 'boundary')}:sink"
        if source_class:
            add_node(source_id, "entry_point" if source_class in {"prompt", "retrieval", "tool", "environment"} else "internal_component", path.get("source"), trust_zone=_graph_trust_zone(source_class))
        if sink_class:
            add_node(target_id, "internal_component", path.get("sink"), trust_zone=_graph_trust_zone(sink_class))
        make_edge(
            f"{path.get('boundary', 'boundary')}:{path.get('risk', 'Medium')}",
            source_id,
            target_id,
            path.get("boundary", "Unknown"),
            True,
            _graph_trust_zone(source_class or "agent"),
            _graph_trust_zone(sink_class or "application_code"),
            finding=None,
            partial_evidence=not source_class or not sink_class,
            evidence=path.get("data_flow_summary"),
            trust_boundary=path.get("boundary"),
        )

    return {
        "nodes": sorted(nodes.values(), key=lambda item: (item["node_type"], item["label"], item["node_id"])),
        "edges": edges,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "partial_edge_count": sum(1 for edge in edges if edge.get("partial_evidence")),
            "boundary_crossing_count": sum(1 for edge in edges if edge.get("boundary_crossing")),
        },
    }


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
    if has_source("prompt") and has_sink("tool") and has_sink("execution"):
        chains.append({
            "name": "Prompt -> Tool -> Execution",
            "risk": "Critical",
            "reason": "Prompt-controlled input can influence tool use and reach execution sinks.",
            "confidence_score": 91,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Prompt ->")),
        })
    if has_source("agent") and has_sink("tool") and has_sink("deployment"):
        chains.append({
            "name": "Agent -> Tool -> Deployment",
            "risk": "Critical",
            "reason": "Agent-controlled instructions can steer tool use into deployment actions.",
            "confidence_score": 93,
            "supporting_boundaries": sorted(name for name in boundary_names if name and ("Deployment" in name or "Tool" in name)),
        })
    if has_source("agent") and has_sink("execution") and has_sink("deployment"):
        chains.append({
            "name": "Agent -> Tool -> Execution",
            "risk": "Critical",
            "reason": "Agent-controlled instructions can steer tools into execution sinks.",
            "confidence_score": 92,
            "supporting_boundaries": sorted(name for name in boundary_names if name and ("Tool" in name or "Execution" in name)),
        })
    if has_source("prompt") and has_sink("tool") and has_sink("filesystem"):
        chains.append({
            "name": "Prompt -> Tool -> Filesystem",
            "risk": "High",
            "reason": "Prompt-controlled input can influence tool use and reach filesystem mutation.",
            "confidence_score": 88,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Prompt ->")),
        })
    if has_source("retrieval") and has_sink("prompt") and has_sink("tool"):
        chains.append({
            "name": "Retrieval -> Prompt -> Tool",
            "risk": "High",
            "reason": "Retrieved content can shape prompts and then influence tool use.",
            "confidence_score": 89,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Retrieval ->")),
        })
    if has_source("memory") and has_sink("prompt") and has_sink("tool"):
        chains.append({
            "name": "Memory -> Prompt -> Tool",
            "risk": "Critical",
            "reason": "Persistent memory can shape prompts and then influence tool use.",
            "confidence_score": 91,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Memory ->")),
        })
    if has_source("memory") and has_sink("credential") and has_sink("network"):
        chains.append({
            "name": "Memory -> Credential -> Network",
            "risk": "Critical",
            "reason": "Persistent memory can retain secrets that later flow into outbound requests.",
            "confidence_score": 92,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Memory ->")),
        })
    if has_source("memory") and has_sink("prompt") and has_sink("execution"):
        chains.append({
            "name": "Memory -> Prompt -> Execution",
            "risk": "High",
            "reason": "Persistent memory can shape prompts and then reach execution sinks.",
            "confidence_score": 90,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Memory ->")),
        })
    if has_source("prompt") and has_sink("execution"):
        chains.append({
            "name": "Prompt -> Execution",
            "risk": "High",
            "reason": "Prompt-controlled input can reach execution sinks.",
            "confidence_score": 80,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Prompt ->")),
        })
    if has_source("prompt") and has_sink("tool"):
        chains.append({
            "name": "Prompt -> Tool",
            "risk": "High",
            "reason": "Prompt-controlled input can influence privileged tool selection or invocation.",
            "confidence_score": 86,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Prompt ->")),
        })
    if has_source("prompt") and has_sink("privileged_action"):
        chains.append({
            "name": "Prompt -> Privileged Action",
            "risk": "High",
            "reason": "Prompt-controlled input can reach privileged action boundaries.",
            "confidence_score": 87,
            "supporting_boundaries": sorted(name for name in boundary_names if name and "Prompt ->" in name),
        })
    if has_source("prompt") and has_sink("credential") or has_source("tool") and has_sink("credential"):
        chains.append({
            "name": "Prompt -> Credential",
            "risk": "Critical",
            "reason": "Prompt-controlled input can reach credential exposure.",
            "confidence_score": 92,
            "supporting_boundaries": sorted(name for name in boundary_names if name and ("Prompt ->" in name or "Tool ->" in name)),
        })
    if has_source("tool") and has_sink("credential") and has_sink("network"):
        chains.append({
            "name": "Tool -> Credential -> Network",
            "risk": "Critical",
            "reason": "Tool-originated input can expose credentials and then reach outbound requests.",
            "confidence_score": 91,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Tool ->")),
        })
    if has_source("retrieval") and has_sink("tool") and has_sink("network"):
        chains.append({
            "name": "Retrieval -> Tool -> Network",
            "risk": "High",
            "reason": "Retrieved content can influence tools and then reach outbound requests.",
            "confidence_score": 88,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Retrieval ->")),
        })
    if has_source("retrieval") and has_sink("prompt") and has_sink("execution"):
        chains.append({
            "name": "Retrieval -> Prompt -> Execution",
            "risk": "High",
            "reason": "Retrieved content can shape prompts and then reach execution sinks.",
            "confidence_score": 87,
            "supporting_boundaries": sorted(name for name in boundary_names if name and name.startswith("Retrieval ->")),
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


def _attack_path_status(finding):
    finding_class = finding.get("finding_class")
    evidence_level = (finding.get("evidence_level") or "").lower()
    if finding_class == "confirmed_vulnerability":
        return "confirmed"
    if evidence_level == "partial" and finding.get("category") in {"retrieval_poisoning", "mcp_tool_abuse"}:
        return "partial_evidence"
    if finding_class == "potential_risk" and finding.get("boundary_crossing"):
        return "review_required"
    if evidence_level in {"partial", "capability"}:
        return "partial_evidence"
    return None


def _attack_path_category(finding):
    category = finding.get("category")
    rule = finding.get("rule")
    mapping = {
        "data_exfiltration": "data_exfiltration",
        "unsafe_execution": "command_execution",
        "filesystem_mutation": "filesystem_write",
        "prompt_injection": "prompt_injection",
        "retrieval_poisoning": "retrieval_poisoning",
        "agentic_security": "agent_tool_misuse",
        "mcp_tool_abuse": "mcp_tool_abuse",
        "framework_security": "auth_bypass" if rule in {"confirmed_auth_bypass", "unauthenticated_route", "unrestricted_admin_endpoint"} else None,
        "tenant_isolation": "cross_tenant_access",
        "leaked_secrets": "secrets_exposure",
        "secret_leakage": "secrets_exposure",
        "supply_chain": "supply_chain_execution",
    }
    if category == "framework_security" and rule in {"object_id_access"}:
        return "object_access_bypass"
    if category == "framework_security" and rule in {"missing_tenant_filters", "tenant_scoped_query"}:
        return "cross_tenant_access"
    return mapping.get(category)


def _secret_material_is_direct(finding):
    if finding.get("severity") != "Critical":
        return False
    if finding.get("category") not in {"leaked_secrets", "secret_leakage"}:
        return False
    evidence = (finding.get("evidence_redacted") or finding.get("evidence") or finding.get("observed_evidence") or "").lower()
    secret_value = str(finding.get("secret") or finding.get("match") or finding.get("secret_value") or "").lower()
    if not evidence and not secret_value:
        return False
    redacted_markers = ("redacted", "example", "sample", "placeholder", "scanner source", "detector", "regex", "pattern")
    if any(marker in evidence for marker in redacted_markers):
        return False
    if any(marker in secret_value for marker in redacted_markers):
        return False
    return True


def _emission_confidence_band(finding):
    return (finding.get("confidence_band") or finding.get("confidence_level") or "").upper()


def _satisfies_confirmed_invariant(finding):
    if finding.get("finding_class") != "confirmed_vulnerability":
        return False
    if _secret_material_is_direct(finding):
        return True
    if _emission_confidence_band(finding) != "HIGH" and int(finding.get("confidence_score") or 0) < 80:
        return False
    return all([
        finding.get("source"),
        finding.get("sink"),
        finding.get("flow_path"),
        finding.get("missing_evidence"),
        finding.get("impact"),
    ])


def normalize_emitted_finding(finding):
    normalized = dict(finding)
    has_path = bool(normalized.get("source") or normalized.get("sink") or normalized.get("flow_path"))
    if normalized.get("finding_class") == "confirmed_vulnerability" and not _satisfies_confirmed_invariant(normalized):
        normalized["finding_class"] = "potential_risk" if has_path else "observed_capability"
        if normalized.get("evidence_level") == "proven":
            normalized["evidence_level"] = "partial" if has_path else "capability"
        if normalized.get("proof_status") == "explicit" and normalized["finding_class"] != "confirmed_vulnerability":
            normalized["proof_status"] = "implicit" if has_path else "capability"
        normalized["production_blocker"] = False
    return normalized


def attack_paths(findings, trust_paths_items=None, trust_boundary_graph=None, auth_review=None, tenant_review=None):
    findings = [normalize_emitted_finding(finding) for finding in findings]
    trust_paths_items = list(trust_paths_items or trust_paths(findings))
    trust_boundary_graph = trust_boundary_graph or build_trust_boundary_graph(findings, trust_paths_items)
    auth_review = auth_review or auth_review_summary(findings)
    tenant_review = tenant_review or tenant_isolation_review_summary(findings)

    eligible = []
    for finding in findings:
        status = _attack_path_status(finding)
        category = _attack_path_category(finding)
        if not status or not category:
            continue
        if finding.get("finding_class") == "observed_capability":
            continue
        if finding.get("finding_class") == "potential_risk" and not finding.get("boundary_crossing"):
            continue
        eligible.append((finding, status, category))

    paths = []
    for finding, status, category in eligible:
        path_id = f"AP-{finding['id']}"
        entry_point = finding.get("source") or finding.get("file") or "observed evidence"
        sink = finding.get("sink") or finding.get("rule")
        related_findings = [finding["id"]]
        related_findings = sorted({item for item in related_findings if item})
        path_steps = [finding.get("source") or "observed source"]
        if finding.get("flow_path"):
            path_steps = list(finding["flow_path"])
        elif finding.get("boundary_crossing"):
            path_steps.append(finding.get("sink") or "observed sink")
        attack_boundary = finding.get("trust_boundary") or finding.get("boundary") or (trust_paths_items[0]["boundary"] if trust_paths_items else "Observed boundary")
        missing_evidence = list(dict.fromkeys((finding.get("missing_evidence") or []) + ([] if status == "confirmed" else ["full end-to-end exploit proof"])))
        remediation_summary = finding.get("recommendation") or finding.get("impact") or "Review and narrow the exposed trust boundary."
        paths.append({
            "attack_path_id": path_id,
            "status": status,
            "category": category,
            "entry_point": entry_point,
            "trust_boundary": attack_boundary,
            "path_steps": path_steps,
            "sink": sink,
            "impact": finding.get("impact") or finding.get("recommendation") or "Potential security impact identified.",
            "prerequisites": [finding.get("proof_status") or "observed evidence"],
            "evidence": {
                "source": finding.get("source"),
                "sink": finding.get("sink"),
                "flow_path": finding.get("flow_path"),
                "boundary_crossing": finding.get("boundary_crossing"),
                "evidence_level": finding.get("evidence_level"),
                "finding_class": finding.get("finding_class"),
                "confidence_score": finding.get("confidence_score"),
                "trust_boundary_graph": {
                    "node_count": len(trust_boundary_graph.get("nodes", [])),
                    "edge_count": len(trust_boundary_graph.get("edges", [])),
                    "boundary_crossing_count": trust_boundary_graph.get("summary", {}).get("boundary_crossing_count", 0),
                },
            },
            "missing_evidence": missing_evidence,
            "confidence_score": finding.get("confidence_score"),
            "confidence_band": finding.get("confidence_band") or finding.get("confidence_level"),
            "related_findings": related_findings,
            "remediation_summary": remediation_summary,
        })

    paths.sort(key=lambda item: (0 if item["status"] == "confirmed" else 1 if item["status"] == "review_required" else 2, -int(item.get("confidence_score") or 0), item["attack_path_id"]))
    summary = {
        "confirmed": sum(1 for item in paths if item["status"] == "confirmed"),
        "review_required": sum(1 for item in paths if item["status"] == "review_required"),
        "partial_evidence": sum(1 for item in paths if item["status"] == "partial_evidence"),
        "total": len(paths),
    }
    return {"paths": paths, "summary": summary}


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


def finding_heading(finding):
    bucket = (finding.get("confidence_bucket") or "Unknown").strip() or "Unknown"
    return f"[{bucket}] {finding['id']}"


def external_assessment_incomplete(external_summary) -> bool:
    engines = (external_summary or {}).get("engines", [])
    return any(engine.get("status") in {"skipped", "failed"} for engine in engines)


def render_report(repo_path: Path, scored, scope_summary, audit_warnings=None, repo_config=None, external_summary=None, explain: bool = False):
    findings = [normalize_emitted_finding(finding) for finding in scored["findings"]]
    findings = sorted(findings, key=severity_sort_key)
    unsuppressed_findings = list(findings)
    findings, active_suppressions, expired_suppressions, ignored_findings = apply_suppressions(findings, getattr(repo_config, "suppressions", ()))
    risk_state = risk_acceptance_state(findings, getattr(repo_config, "risk_acceptance", ()))
    findings = sorted(risk_state["findings"], key=severity_sort_key)
    counts = risk_counts(findings)
    decision = release_decision(findings, audit_warnings=audit_warnings)
    trust_profile = boundary_summary(findings)
    attack_surface = attack_surface_summary(findings)
    paths = trust_paths(findings)
    chains = attack_chains(paths)
    attack_path_info = attack_paths(findings, trust_paths_items=paths, trust_boundary_graph=build_trust_boundary_graph(findings, paths), auth_review=auth_review_summary(findings), tenant_review=tenant_isolation_review_summary(findings))
    required = required_fixes(findings)
    recommended = recommended_fixes(findings)
    framework_items = framework_findings(findings)
    risks = top_risks(findings, repo_config=repo_config)
    trust_score_info = calculate_trust_score(findings, paths, chains, active_suppressions=active_suppressions, expired_suppressions=expired_suppressions, audit_warnings=audit_warnings, unsuppressed_findings=unsuppressed_findings)
    readiness = production_readiness(findings, paths, chains, active_suppressions=active_suppressions, expired_suppressions=expired_suppressions, audit_warnings=audit_warnings, trust_score_info=trust_score_info, unsuppressed_findings=unsuppressed_findings)
    audit_trail = build_audit_trail(repo_path, findings, audit_warnings, active_suppressions, risk_state, trust_score_info, readiness, decision, repo_config=repo_config)
    trust_boundary_graph = build_trust_boundary_graph(findings, paths)
    auth_review = auth_review_summary(findings)
    incomplete_external_assessment = external_assessment_incomplete(external_summary)

    required_reason = readiness["reason"]
    lines = [
        f"# Repo Security Audit - {repo_path.name or repo_path} - {datetime.now().date().isoformat()}",
        "",
        "## Executive Summary",
    ]
    if incomplete_external_assessment:
        lines.append("- Full assessment incomplete: one or more optional external cybersecurity engines did not run. This does not mean those areas are clean.")
    lines.extend([
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
        "## Trust Score",
        f"- Score: {trust_score_info['trust_score']}/100",
        f"- Grade: {trust_score_info['trust_grade']}",
        "- Top score drivers:",
    ])
    if trust_score_info["top_drivers"]:
        for driver in trust_score_info["top_drivers"]:
            lines.append(f"  - {driver['driver']}: -{driver['points']} ({driver['evidence']})")
    else:
        lines.append("  - None")

    lines.extend([
        "",
        "## Confidence Legend",
        "- HIGH means strong evidence supports the finding, usually including source, sink, path, missing control, and plausible impact.",
        "- MEDIUM means meaningful risk indicators are present, but some proof is incomplete.",
        "- LOW means capability or weak evidence was observed, but exploitability is not proven.",
        "- Partial or inferred evidence cannot produce HIGH confidence.",
        "- Observed controls reduce confidence.",
        "- Confirmed critical secret exposure may still be HIGH where secret material is directly present.",
    ])

    def _finding_block(finding):
        exposure = finding.get("exposure") or build_exposure(finding)
        lines_block = [
            f"### {finding_heading(finding)}",
            f"- Rule: {finding['rule']}",
            f"- Category: {finding['category']}",
            f"- Severity: {finding['severity']}",
            f"- Confidence: {finding.get('confidence_band') or finding.get('confidence_level') or 'LOW'} ({finding.get('confidence_score', 0)}/100)",
            f"- Confidence bucket: {finding.get('confidence_bucket') or 'Unknown'}",
            f"- Finding class: {finding.get('finding_class') or '-'}",
            f"- Evidence level: {finding.get('evidence_level') or '-'}",
            f"- File path: {finding.get('file') or '-'}",
            f"- Line number: {finding.get('line') or '-'}",
            f"- Evidence snippet: {finding.get('evidence_redacted') or finding.get('evidence_snippet') or '-'}",
            f"- What is exposed or at risk: {exposure['what']}",
            f"- Where the exposure happens: {exposure['where']}",
            f"- Possible attack scenario: {exposure['attack_entry']}",
            f"- Why it matters: {exposure['impact']}",
            f"- Recommended fix: {exposure['recommended_fix']}",
            f"- Safer code or configuration pattern: {finding.get('recommendation')}",
            f"- Production impact: {'Blocks production' if finding.get('production_blocker') else 'Review required before production'}",
            f"- Blocks production: {'Yes' if finding.get('production_blocker') else 'No'}",
        ]
        if explain:
            lines_block.extend([
                f"- Attack path: {exposure['attack_path']}",
                f"- Exposure summary: {exposure['what']} at {exposure['where']}.",
            ])
        return lines_block

    lines.extend([
        "",
        "## Production Readiness",
    ])
    if incomplete_external_assessment:
        lines.append("- Full assessment incomplete: one or more optional external cybersecurity engines did not run. This does not mean those areas are clean.")
    lines.extend([
        f"- Status: {readiness['status']}",
        f"- Reason: {readiness['reason']}",
        f"- Blockers: {', '.join(readiness['blockers']) if readiness['blockers'] else 'None'}",
        f"- Review items: {', '.join(readiness['review_items']) if readiness['review_items'] else 'None'}",
        "- Recommended next steps:",
    ])
    for step in readiness["recommended_next_steps"]:
        lines.append(f"  - {step}")

    lines.extend([
        "",
        "## Authentication and Authorisation Review",
        f"- Protected routes detected: {auth_review['protected_routes']}",
        f"- Public routes detected: {auth_review['public_routes']}",
        f"- Routes requiring review: {auth_review['routes_requiring_review']}",
        f"- Admin routes requiring review: {auth_review['admin_routes_requiring_review']}",
        f"- Object/tenant access requiring review: {auth_review['object_tenant_routes_requiring_review']}",
    ])
    if auth_review["routes_requiring_review"]:
        routes = [finding for finding in findings if finding.get("category") == "framework_security" and finding.get("rule") in {"unauthenticated_route", "unrestricted_admin_endpoint", "object_id_access", "missing_tenant_filters", "tenant_scoped_query"}]
        for finding in routes[:10]:
            lines.append(f"- {finding.get('http_method') or '-'} {finding.get('route_or_handler') or finding.get('rule')} - {finding.get('rule')}")

    repository_maps = repository_understanding_summary(findings)
    lines.extend([
        "",
        "## Repository Understanding",
        "This section is evidence-only. Unknown areas, partial evidence, and inferred relationships are marked explicitly.",
        "",
        "### Authentication Map",
    ])
    for entry in repository_maps["authentication_map"]:
        lines.append(f"- {entry['component']}: {entry['evidence']} [confidence {entry['confidence_band']} ({entry['confidence_score']}/100)]")
        if entry["partial_evidence"] or entry["inferred"]:
            markers = [label for label, enabled in (("partial evidence", entry["partial_evidence"]), ("inferred", entry["inferred"])) if enabled]
            lines.append(f"  - Markers: {', '.join(markers)}")
    lines.append("")
    lines.append("### Authorisation Map")
    for entry in repository_maps["authorisation_map"]:
        lines.append(f"- {entry['component']}: {entry['evidence']} [confidence {entry['confidence_band']} ({entry['confidence_score']}/100)]")
        if entry["partial_evidence"] or entry["inferred"]:
            markers = [label for label, enabled in (("partial evidence", entry["partial_evidence"]), ("inferred", entry["inferred"])) if enabled]
            lines.append(f"  - Markers: {', '.join(markers)}")
    lines.append("")
    lines.append("### Data Flow Map")
    for entry in repository_maps["data_flow_map"]:
        lines.append(f"- {entry['component']}: {entry['evidence']} [confidence {entry['confidence_band']} ({entry['confidence_score']}/100)]")
        if entry["partial_evidence"] or entry["inferred"]:
            markers = [label for label, enabled in (("partial evidence", entry["partial_evidence"]), ("inferred", entry["inferred"])) if enabled]
            lines.append(f"  - Markers: {', '.join(markers)}")
    lines.append("")
    lines.append("### Trust Boundary Map")
    for entry in repository_maps["trust_boundary_map"]:
        lines.append(f"- {entry['component']}: {entry['evidence']} [confidence {entry['confidence_band']} ({entry['confidence_score']}/100)]")
        if entry["partial_evidence"] or entry["inferred"]:
            markers = [label for label, enabled in (("partial evidence", entry["partial_evidence"]), ("inferred", entry["inferred"])) if enabled]
            lines.append(f"  - Markers: {', '.join(markers)}")
    lines.append("")
    lines.append("### Agent Map")
    for entry in repository_maps["agent_map"]:
        lines.append(f"- {entry['component']}: {entry['evidence']} [confidence {entry['confidence_band']} ({entry['confidence_score']}/100)]")
        if entry["partial_evidence"] or entry["inferred"]:
            markers = [label for label, enabled in (("partial evidence", entry["partial_evidence"]), ("inferred", entry["inferred"])) if enabled]
            lines.append(f"  - Markers: {', '.join(markers)}")
    lines.append("")
    lines.append("### Infrastructure Map")
    for entry in repository_maps["infrastructure_map"]:
        lines.append(f"- {entry['component']}: {entry['evidence']} [confidence {entry['confidence_band']} ({entry['confidence_score']}/100)]")
        if entry["partial_evidence"] or entry["inferred"]:
            markers = [label for label, enabled in (("partial evidence", entry["partial_evidence"]), ("inferred", entry["inferred"])) if enabled]
            lines.append(f"  - Markers: {', '.join(markers)}")

    tenant_review = tenant_isolation_review_summary(findings)
    lines.extend([
        "",
        "## Multi-Tenant Isolation Review",
        f"- Tenant controls detected: {tenant_review['tenant_controls_detected']}",
        f"- Tenant-scoped queries detected: {sum(1 for finding in tenant_review['tenant_findings'] if finding.get('rule') == 'tenant_scoped_query')}",
        f"- Unscoped queries requiring review: {sum(1 for finding in tenant_review['tenant_findings'] if finding.get('rule') == 'missing_tenant_filters')}",
        f"- Retrieval isolation concerns: {sum(1 for finding in tenant_review['tenant_findings'] if finding.get('retrieval_scope_evidence') or finding.get('category') == 'retrieval_poisoning')}",
        f"- Prompt isolation concerns: {sum(1 for finding in tenant_review['tenant_findings'] if finding.get('category') in {'retrieval_poisoning', 'agentic_security'} and finding.get('tenant_evidence'))}",
        f"- Confirmed cross-tenant risks: {tenant_review['confirmed_cross_tenant_findings']}",
    ])

    infrastructure_findings = [finding for finding in findings if finding.get("category") in {"container_security", "ci_cd_security", "infrastructure_as_code"}]
    confirmed_infra = [finding for finding in infrastructure_findings if finding.get("finding_class") == "confirmed_vulnerability"]
    blockers = [finding for finding in infrastructure_findings if finding.get("production_blocker")]
    lines.extend([
        "",
        "## Infrastructure Security Review",
        f"- Infrastructure files detected: {scope_summary.get('infrastructure_files_detected', 0)}",
        f"- Container risks: {sum(1 for finding in infrastructure_findings if finding.get('category') == 'container_security')}",
        f"- CI/CD risks: {sum(1 for finding in infrastructure_findings if finding.get('category') == 'ci_cd_security')}",
        f"- Kubernetes/Helm risks: {sum(1 for finding in infrastructure_findings if finding.get('infrastructure_surface') in {'Kubernetes', 'Helm'})}",
        f"- Terraform/cloud risks: {sum(1 for finding in infrastructure_findings if finding.get('infrastructure_surface') == 'Terraform')}",
        f"- Supabase risks: {sum(1 for finding in infrastructure_findings if finding.get('infrastructure_surface') == 'Supabase')}",
        f"- Confirmed infrastructure blockers: {len(blockers)}",
    ])
    if confirmed_infra:
        for finding in confirmed_infra[:10]:
            lines.append(f"- {finding['id']} - {finding['rule']} ({finding['severity']}, {finding['confidence_level']})")
    else:
        lines.append("- None")

    lines.extend([
        "",
        render_audit_trail(audit_trail),
        "",
        "## Trust Boundary Graph",
        f"- Nodes: {trust_boundary_graph['summary']['node_count']}",
        f"- Edges: {trust_boundary_graph['summary']['edge_count']}",
        f"- Boundary crossings: {trust_boundary_graph['summary']['boundary_crossing_count']}",
        f"- Partial evidence edges: {trust_boundary_graph['summary']['partial_edge_count']}",
        "- Highest-risk crossings:",
    ])
    graph_edges = [edge for edge in trust_boundary_graph["edges"] if edge.get("boundary_crossing")]
    if graph_edges:
        for edge in graph_edges[:10]:
            lines.append(
                f"  - {edge['edge_type']}: {edge['trust_zone_from']} -> {edge['trust_zone_to']} "
                f"({'partial evidence' if edge.get('partial_evidence') else 'evidenced'})"
            )
    else:
        lines.append("  - None")
    lines.extend([
        "- External egress paths:",
        "  - " + ", ".join(sorted({f"{edge['trust_zone_from']} -> {edge['trust_zone_to']}" for edge in trust_boundary_graph["edges"] if edge["trust_zone_to"] in {"external_network", "third_party_service"}}) or ["None"]),
        "- Execution paths:",
        "  - " + ", ".join(sorted({edge["edge_type"] for edge in trust_boundary_graph["edges"] if edge["trust_zone_to"] in {"shell_runtime", "external_network"}}) or ["None"]),
        "- AI/agent paths:",
        "  - " + ", ".join(sorted({edge["edge_type"] for edge in trust_boundary_graph["edges"] if edge["trust_zone_from"] in {"llm_prompt_context", "retrieval_context", "agent_tool_runtime"}}) or ["None"]),
        "- Tenant-data paths:",
        "  - " + ", ".join(sorted({edge["edge_type"] for edge in trust_boundary_graph["edges"] if edge["trust_zone_from"] == "tenant_data" or edge["trust_zone_to"] == "tenant_data"}) or ["None"]),
        "",
        "## Cybersecurity Exposure Map",
    ])
    for finding in findings[:10]:
        exposure = finding.get("exposure") or build_exposure(finding)
        lines.append(f"- {finding['id']} -> {exposure['attack_path']} ({finding.get('file') or '-'}:{finding.get('line') or '-'})")

    observed_capabilities = [finding for finding in findings if finding.get("finding_class") == "observed_capability"]
    potential_risks = [finding for finding in findings if finding.get("finding_class") == "potential_risk"]
    confirmed_vulnerabilities = [finding for finding in findings if finding.get("finding_class") == "confirmed_vulnerability"]

    lines.extend(["", "## Observed Capabilities"])
    if observed_capabilities:
        for finding in observed_capabilities[:10]:
            lines.extend(_finding_block(finding))
            lines.append("")
    else:
        lines.append("No observed capabilities identified.")

    lines.extend(["", "## Potential Risks"])
    if potential_risks:
        for finding in potential_risks[:10]:
            lines.extend(_finding_block(finding))
            lines.append("")
    else:
        lines.append("No potential risks identified.")

    lines.extend(["", "## Confirmed Vulnerabilities"])
    if confirmed_vulnerabilities:
        for finding in confirmed_vulnerabilities[:10]:
            lines.extend(_finding_block(finding))
            lines.append("")
    else:
        lines.append("No confirmed vulnerabilities identified.")

    lines.extend([
        "## Attack Paths",
    ])
    if attack_path_info["paths"]:
        for status in ["confirmed", "review_required", "partial_evidence"]:
            status_paths = [path for path in attack_path_info["paths"] if path["status"] == status]
            if not status_paths:
                continue
            lines.append(f"### {status.replace('_', ' ').title()}")
            for path in status_paths:
                lines.append(f"- {path['attack_path_id']} | {path['category']} | {path['entry_point']} -> {path['sink']} | {path['confidence_band']} ({path['confidence_score']}/100)")
                lines.append(f"  - Boundary: {path['trust_boundary']}")
                lines.append(f"  - Steps: {' -> '.join(path['path_steps']) if path['path_steps'] else '-'}")
                lines.append(f"  - Impact: {path['impact']}")
                lines.append(f"  - Prerequisites: {', '.join(path['prerequisites']) if path['prerequisites'] else 'None'}")
                lines.append(f"  - Missing evidence: {', '.join(path['missing_evidence']) if path['missing_evidence'] else 'None'}")
                lines.append(f"  - Related findings: {', '.join(path['related_findings']) if path['related_findings'] else 'None'}")
                lines.append(f"  - Remediation summary: {path['remediation_summary']}")
    else:
        lines.append("No supported attack paths were generated.")

    lines.extend([
        "",
        "## Exploitable Entry Points",
    ])
    for finding in findings[:10]:
        lines.append(f"- {format_location(finding)} - {finding['rule']} ({finding['severity']})")

    lines.extend([
        "",
        "## Affected Files and Lines",
    ])
    for finding in findings[:10]:
        lines.append(f"- {finding.get('file') or '-'}:{finding.get('line') or '-'} - {finding['id']}")

    lines.extend([
        "",
        "## Root Cause",
    ])
    for finding in findings[:10]:
        lines.append(f"- {finding['id']}: {finding.get('recommendation')}")

    lines.extend([
        "",
        "## Recommended Fixes",
    ])
    for finding in findings[:10]:
        lines.append(f"- {finding_heading(finding)}: {finding.get('recommendation')}")

    blockers = [finding for finding in findings if finding["id"] in set(readiness["production_blockers"])]
    if blockers:
        lines.extend([
            "",
            "## Production Blockers",
        ])
        for finding in blockers[:10]:
            lines.append(f"- {finding['id']} - {finding['rule']} ({finding['severity']}, {finding['confidence_level']})")
    elif readiness["review_items"]:
        lines.extend([
            "",
            "## Required Review",
        ])
        review_candidates = [finding for finding in findings if finding["id"] in set(readiness["review_items"])]
        for finding in review_candidates[:10]:
            lines.append(f"- {finding_heading(finding)} ({finding['severity']}, {finding['confidence_level']}) {finding['rule']} - {finding.get('recommendation')}")

    false_positive_notes = [finding for finding in findings if finding["confidence_level"] == "LOW" or "test" in set(finding.get("scope_tags", []))]
    lines.extend([
        "",
        "## False Positive Notes",
    ])
    if false_positive_notes:
        for finding in false_positive_notes[:10]:
            lines.append(f"- {finding['id']} - requires review; confidence {finding['confidence_level']}")
    else:
        lines.append("No false positive notes identified.")

    lines.extend([
        "",
        "## Re-scan Instructions",
        f"- Run: `trustboundary \"{repo_path}\" --sarif" + (" --explain" if explain else "") + "`",
        "- Re-run after remediation and before release approval.",
        "- If you enable `--full`, external tools may add findings when installed locally.",
        "",
        "## Top Risks",
    ])
    agentic_findings = [finding for finding in findings if finding.get("category") == "agentic_security"]
    autonomous_findings = [finding for finding in findings if finding.get("category") == "agentic_security" and finding.get("rule") in {"auto_run", "auto_execute", "unattended_execution", "spawn_agent", "create_sub_agent", "recursive_task", "self_improve", "self_modify", "delegate_until_done", "loop_until_success", "use_tools_automatically", "invoke_any_tool", "execute_tool_without_approval", "auto_call_tools", "indefinite_tool_retry", "auto_deploy", "push_to_main", "delete_production", "run_migration_automatically", "apply_terraform_automatically", "kubectl_apply", "docker_push", "npm_publish", "missing_human_gate"}]
    retrieval_findings = [finding for finding in findings if finding.get("category") == "retrieval_poisoning"]
    memory_findings = [finding for finding in findings if finding.get("category") == "agentic_security" and finding.get("rule") in {"persistent_instruction", "cross_session_contamination", "hidden_memory_directive", "unsafe_memory_write", "sensitive_memory_storage"}]
    memory_examples = ", ".join(f"{finding['rule']} ({finding.get('file')})" for finding in memory_findings[:3]) if memory_findings else "None"
    memory_highest = min((finding["severity"] for finding in memory_findings), key=lambda sev: SEVERITY_ORDER.get(sev, 9)) if memory_findings else "-"
    autonomous_examples = ", ".join(f"{finding['rule']} ({finding.get('file')})" for finding in autonomous_findings[:3]) if autonomous_findings else "None"
    autonomous_highest = min((finding["severity"] for finding in autonomous_findings), key=lambda sev: SEVERITY_ORDER.get(sev, 9)) if autonomous_findings else "-"
    lines.extend([
        "",
        "## AI Agent Security Review",
        f"- Agent surfaces detected: {', '.join(sorted({finding.get('rule') for finding in agentic_findings if finding.get('rule')})) or 'None'}",
        f"- Prompt/retrieval risks: {sum(1 for finding in findings if finding.get('category') in {'prompt_injection', 'retrieval_poisoning'})}",
        f"- Tool/MCP risks: {sum(1 for finding in findings if finding.get('category') == 'mcp_tool_abuse' or finding.get('rule') in {'tool_to_shell_path', 'tool_to_filesystem_path', 'tool_to_network_path'})}",
        f"- Memory risks: {len(memory_findings)}",
        f"- Execution and egress paths: {sum(1 for finding in findings if finding.get('rule') in {'tool_to_shell_path', 'tool_to_filesystem_path', 'tool_to_network_path', 'shell_true', 'network_client_usage'})}",
        f"- Confirmed agent attack paths: {', '.join(sorted({finding.get('attack_path') for finding in agentic_findings if finding.get('attack_path')})) or 'None'}",
        f"- Retrieval Poisoning Findings: {len(retrieval_findings)}",
        "",
        "### Memory / Persistent Context Risks",
        f"- Finding count: {len(memory_findings)}",
        f"- Highest severity: {memory_highest}",
        f"- Representative examples: {memory_examples}",
        "",
        "### Autonomous Execution Risks",
        f"- Finding count: {len(autonomous_findings)}",
        f"- Highest severity: {autonomous_highest}",
        f"- Representative examples: {autonomous_examples}",
    ])
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
        "## Risk Acceptance",
        f"- Active accepted risks: {len(risk_state['active'])}",
        f"- Expired acceptances: {len(risk_state['expired'])}",
        f"- Invalid acceptances: {len(risk_state['invalid'])}",
        f"- Accepted findings count: {len(risk_state['accepted_findings'])}",
    ])
    for acceptance in risk_state["active"][:10]:
        lines.append(f"- {acceptance['rule']} | {acceptance['path']} | {acceptance['reason']} | {acceptance['owner']} | {acceptance['expires']}")
    for acceptance in risk_state["expired"][:10]:
        lines.append(f"- expired: {acceptance['rule']} | {acceptance['path']} | {acceptance['reason']} | {acceptance['owner']} | {acceptance['expires']}")
    for acceptance in risk_state["invalid"][:10]:
        lines.append(f"- invalid: {acceptance.get('rule', '-')} | {acceptance.get('path', '-')} | {acceptance.get('reason', '-')}")

    lines.extend([
        "",
        "## Aggregated Findings",
    ])
    high_critical = [f for f in findings if f["severity"] in {"Critical", "High"} and not is_documentation_finding(f)]
    medium = [f for f in findings if f["severity"] == "Medium"][:10]
    low = [f for f in findings if f["severity"] == "Low"]
    for finding in high_critical + medium:
        lines.append(f"- {finding['id']} | {finding.get('rule_id') or finding.get('rule') or '-'} | {finding['severity']} | {finding['confidence_level']} | {finding.get('occurrences', 1)} occurrence(s)")
    if low:
        lines.append(f"- Low findings: {len(low)} total, summarized in JSON")

    lines.extend([
        "",
        "## Trust Boundary Profile",
    ])
    for key in ["filesystem_access", "network_access", "environment_access", "execution_access", "deployment_access"]:
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

    lines.extend([
        "",
        "## External Cybersecurity Engines",
    ])
    if incomplete_external_assessment:
        lines.append("- Full assessment incomplete: one or more optional external cybersecurity engines did not run. This does not mean those areas are clean.")
    if external_summary and external_summary.get("engines"):
        for engine in external_summary["engines"]:
            if engine["status"] == "completed":
                lines.append(f"- {engine['name']}: completed ({engine['finding_count']} finding(s))")
            else:
                lines.append(f"- {engine['name']}: {engine['status']} - {engine.get('message', '-')}")
        if external_summary.get("warnings"):
            lines.append("- Warnings:")
            for warning in external_summary["warnings"]:
                lines.append(f"  - {warning.get('scanner', 'unknown')}: {warning.get('message', '-')}")
    else:
        lines.append("External engines were not run.")

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
    seen = set()
    for warning in warnings:
        key = (warning.get("rule", "scanner_failed"), warning.get("scanner", "-"), warning.get("message", "-"))
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- {warning.get('rule', 'scanner_failed')} - {warning.get('scanner', '-')}: {warning.get('message', '-')}")
    return "\n".join(lines) + "\n"


def build_audit_trail(repo_path: Path, findings, audit_warnings, active_suppressions, risk_state, trust_score_info, readiness, decision, repo_config=None):
    scanners = [name for name in SCANNER_MODULES if not repo_config or not repo_config.enabled_scanners or name in repo_config.enabled_scanners]
    scanner_failures = sorted(
        (
            {
                "scanner": warning.get("scanner", "unknown"),
                "message": warning.get("message", "-"),
                "rule": warning.get("rule", "scanner_failed"),
            }
            for warning in (audit_warnings or [])
        ),
        key=lambda item: (item["scanner"], item["rule"], item["message"]),
    )
    trail = {
        "scan_timestamp": datetime.now().isoformat(timespec="seconds"),
        "repository_name": repo_path.name or str(repo_path),
        "scanners": scanners,
        "scanner_failures": scanner_failures,
        "findings_count": len(findings),
        "suppression_count": len(active_suppressions),
        "risk_acceptance_count": len(risk_state.get("active", [])),
        "trust_score": trust_score_info["trust_score"],
        "trust_grade": trust_score_info["trust_grade"],
        "production_readiness_status": readiness.get("status"),
        "release_decision": decision,
        "decision_reasons": [
            trust_score_info["trust_score_reasoning"][0] if trust_score_info.get("trust_score_reasoning") else "",
            readiness.get("reason", ""),
        ],
        "top_drivers": [
            {
                "driver": driver["driver"],
                "points": driver["points"],
                "evidence": driver["evidence"],
            }
            for driver in trust_score_info.get("top_drivers", [])
        ],
        "schema_version": 1,
    }
    return trail


def render_audit_trail(audit_trail):
    lines = [
        "## Audit Trail",
        f"- Generated at: {audit_trail['scan_timestamp']}",
        f"- Scanner count: {len(audit_trail['scanners'])}",
        f"- Findings count: {audit_trail['findings_count']}",
        f"- Trust Score: {audit_trail['trust_score']}/100 ({audit_trail['trust_grade']})",
        f"- Production Readiness: {audit_trail['production_readiness_status']}",
        f"- Release Decision: {audit_trail['release_decision']}",
        f"- Suppressions: {audit_trail['suppression_count']}",
        f"- Risk Acceptances: {audit_trail['risk_acceptance_count']}",
        f"- Scanner Failures: {len(audit_trail['scanner_failures'])}",
    ]
    return "\n".join(lines)


def build_json_output(repo_path: Path, scored, scope_summary, audit_warnings=None, repo_config=None, external_summary=None):
    findings = [normalize_emitted_finding(finding) for finding in scored["findings"]]
    unsuppressed_findings = list(findings)
    findings, active_suppressions, expired_suppressions, ignored_findings = apply_suppressions(findings, getattr(repo_config, "suppressions", ()))
    risk_state = risk_acceptance_state(findings, getattr(repo_config, "risk_acceptance", ()))
    findings = list(risk_state["findings"])
    counts = risk_counts(findings)
    decision = release_decision(findings, audit_warnings=audit_warnings)
    surface = attack_surface_summary(findings)
    trust_score_info = calculate_trust_score(findings, trust_paths(findings), attack_chains(trust_paths(findings)), active_suppressions=active_suppressions, expired_suppressions=expired_suppressions, audit_warnings=audit_warnings, unsuppressed_findings=unsuppressed_findings)
    readiness = production_readiness(findings, trust_paths(findings), attack_chains(trust_paths(findings)), active_suppressions=active_suppressions, expired_suppressions=expired_suppressions, audit_warnings=audit_warnings, trust_score_info=trust_score_info, unsuppressed_findings=unsuppressed_findings)
    audit_trail = build_audit_trail(repo_path, findings, audit_warnings, active_suppressions, risk_state, trust_score_info, readiness, decision, repo_config=repo_config)
    scope_counts = {
        scope: sum(1 for finding in findings if scope in set(finding.get("scope_tags", [])))
        for scope in ["production", "test", "dependency", "generated", "documentation"]
    }
    trust_paths_items = trust_paths(findings)
    trust_boundary_graph = build_trust_boundary_graph(findings, trust_paths_items)
    auth_review = auth_review_summary(findings)
    tenant_review = tenant_isolation_review_summary(findings)
    attack_path_info = attack_paths(findings, trust_paths_items=trust_paths_items, trust_boundary_graph=trust_boundary_graph, auth_review=auth_review, tenant_review=tenant_review)
    repository_maps = repository_understanding_summary(findings)
    agent_findings = [finding for finding in findings if finding.get("category") == "agentic_security"]
    agent_attack_paths = sorted({finding.get("attack_path") for finding in agent_findings if finding.get("attack_path")})
    confirmed_agent_findings = [finding for finding in agent_findings if finding.get("finding_class") == "confirmed_vulnerability"]
    infrastructure_findings = [finding for finding in findings if finding.get("category") in {"container_security", "ci_cd_security", "infrastructure_as_code"}]
    confirmed_infrastructure_findings = [
        finding
        for finding in infrastructure_findings
        if finding.get("finding_class") == "confirmed_vulnerability" or finding.get("confidence_score", 0) >= 80
    ]
    infrastructure_files_detected = len({finding.get("file") for finding in infrastructure_findings if finding.get("file")})
    return {
        "schema_version": 3,
        "repo": {
            "name": repo_path.name or str(repo_path),
            "path": str(repo_path),
        },
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "audit_trail": audit_trail,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
            "overall_posture": posture_label(counts),
            "release_decision": decision,
            "production_blockers": len(readiness["production_blockers"]),
            "decision_reasons": readiness["decision_reasons"],
            "scanner_failures": len(audit_warnings or []),
            "trust_score": trust_score_info["trust_score"],
            "trust_grade": trust_score_info["trust_grade"],
            "trust_score_reasoning": trust_score_info["trust_score_reasoning"],
            "production_readiness": {
                "status": readiness["status"],
                "reason": readiness["reason"],
                "blockers": readiness["blockers"],
                "review_items": readiness["review_items"],
                "recommended_next_steps": readiness["recommended_next_steps"],
                "decision_reasons": readiness["decision_reasons"],
                "production_blockers": readiness["production_blockers"],
                "required_reviews": readiness["required_reviews"],
            },
            "scope_counts": scope_counts,
            "tenant_controls_detected": tenant_review["tenant_controls_detected"],
            "tenant_review_count": tenant_review["tenant_review_count"],
            "confirmed_cross_tenant_findings": tenant_review["confirmed_cross_tenant_findings"],
            "agent_surfaces_detected": sorted({finding.get("rule") for finding in agent_findings if finding.get("rule")}),
            "agent_review_count": len(agent_findings),
            "confirmed_agent_findings": len(confirmed_agent_findings),
            "agent_attack_paths": agent_attack_paths,
            "infrastructure_files_detected": infrastructure_files_detected,
            "infrastructure_review_count": len(infrastructure_findings),
            "confirmed_infrastructure_findings": len(confirmed_infrastructure_findings),
        },
        "suppressions": {
            "active": active_suppressions,
            "expired": expired_suppressions,
            "ignored_findings": ignored_findings,
        },
        "risk_acceptance": {
            "active": risk_state["active"],
            "expired": risk_state["expired"],
            "invalid": risk_state["invalid"],
            "accepted_findings": risk_state["accepted_findings"],
        },
        "scope": scope_summary,
        "external_cybersecurity_engines": external_summary or {"engines": [], "warnings": [], "findings": [], "assessment_complete": True},
        "trust_boundary": boundary_summary(findings),
        "top_risks": top_risks(findings, repo_config=repo_config),
        "attack_surface": surface,
        "trust_paths": trust_paths_items,
        "attack_chains": attack_chains(trust_paths_items),
        "attack_paths": attack_path_info["paths"],
        "attack_path_summary": attack_path_info["summary"],
        "trust_boundary_graph": trust_boundary_graph,
        "auth_review": auth_review,
        "multi_tenant_isolation_review": tenant_review,
        "repository_understanding": repository_maps["repository_understanding"],
        "authentication_map": repository_maps["authentication_map"],
        "authorisation_map": repository_maps["authorisation_map"],
        "data_flow_map": repository_maps["data_flow_map"],
        "trust_boundary_map": repository_maps["trust_boundary_map"],
        "agent_map": repository_maps["agent_map"],
        "infrastructure_map": repository_maps["infrastructure_map"],
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


def _sarif_level(severity: str) -> str:
    return SARIF_SEVERITY_MAP.get(severity, "warning")


def build_sarif_output(repo_path: Path, findings, repo_config=None, explain: bool = False, external_summary=None, readiness=None):
    findings = [normalize_emitted_finding(finding) for finding in findings]
    def _rule_sort_key(rule):
        return (
            rule.get("fullDescription", {}).get("text", ""),
            rule["id"],
        )

    def _result_sort_key(result):
        location = result.get("locations", [{}])[0].get("physicalLocation", {})
        artifact = location.get("artifactLocation", {}).get("uri", "")
        region = location.get("region", {})
        return (
            result.get("ruleId", ""),
            result.get("level", ""),
            artifact,
            region.get("startLine") or 0,
            result.get("message", {}).get("text", ""),
        )

    rule_map = {}
    for finding in findings:
        attack_path_ids = [f"AP-{finding['id']}"] if _attack_path_status(finding) and _attack_path_category(finding) else []
        rule_id = finding.get("rule_id") or finding.get("rule")
        if not rule_id or rule_id in rule_map:
            continue
        help_text = finding.get("recommendation") or finding.get("impact") or "Review this finding."
        rule_map[rule_id] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding.get("rule", rule_id)},
            "fullDescription": {"text": finding.get("impact") or finding.get("recommendation") or "TrustBoundary finding."},
            "help": {"text": help_text},
                "properties": {
                    "category": finding.get("category"),
                    "severity": finding.get("severity"),
                    "confidence_level": finding.get("confidence_level"),
                    "scope": finding.get("scope"),
                    "trust_boundary": finding.get("trust_boundary"),
                    "production_blocker": finding.get("production_blocker"),
                    "status": finding.get("status"),
                    "exposure": finding.get("exposure"),
                    "finding_class": finding.get("finding_class"),
                    "evidence_level": finding.get("evidence_level") or "capability",
                    "confidence_score": finding.get("confidence_score"),
                    "confidence_band": finding.get("confidence_band"),
                    "confidence_reason": finding.get("confidence_reason"),
                    "evidence_components": finding.get("evidence_components"),
                    "missing_evidence": finding.get("missing_evidence"),
                    "agent_surface": finding.get("agent_surface"),
                    "prompt_evidence": finding.get("prompt_evidence"),
                    "retrieval_evidence": finding.get("retrieval_evidence"),
                    "memory_evidence": finding.get("memory_evidence"),
                    "tool_evidence": finding.get("tool_evidence"),
                    "mcp_evidence": finding.get("mcp_evidence"),
                    "execution_evidence": finding.get("execution_evidence"),
                    "filesystem_evidence": finding.get("filesystem_evidence"),
                    "network_egress_evidence": finding.get("network_egress_evidence"),
                    "sensitive_data_evidence": finding.get("sensitive_data_evidence"),
                    "tenant_data_evidence": finding.get("tenant_data_evidence"),
                    "controls_observed": finding.get("controls_observed"),
                    "controls_missing": finding.get("controls_missing"),
                    "attack_path": finding.get("attack_path"),
                    "attack_path_ids": attack_path_ids,
                    "proof_status": finding.get("proof_status"),
                    "boundary_crossing": finding.get("boundary_crossing"),
                    "infrastructure_surface": finding.get("infrastructure_surface"),
                    "config_file": finding.get("config_file"),
                    "config_key": finding.get("config_key"),
                    "observed_evidence": finding.get("observed_evidence"),
                },
            }

    rules = sorted(rule_map.values(), key=_rule_sort_key)
    results = []
    for finding in findings:
        attack_path_ids = [f"AP-{finding['id']}"] if _attack_path_status(finding) and _attack_path_category(finding) else []
        rule_id = finding.get("rule_id") or finding.get("rule")
        if not rule_id:
            continue
        result = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.get("severity", "Medium")),
            "message": {"text": finding.get("impact") or finding.get("recommendation") or finding.get("evidence_snippet") or finding.get("rule") or rule_id},
            "properties": {
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "confidence_level": finding.get("confidence_level"),
                "scope": finding.get("scope"),
                "trust_boundary": finding.get("trust_boundary"),
                "production_blocker": finding.get("production_blocker"),
                "status": finding.get("status"),
                "exposure": finding.get("exposure"),
                "finding_class": finding.get("finding_class"),
                "evidence_level": finding.get("evidence_level") or "capability",
                "confidence_score": finding.get("confidence_score"),
                "confidence_band": finding.get("confidence_band"),
                "confidence_reason": finding.get("confidence_reason"),
                "evidence_components": finding.get("evidence_components"),
                "missing_evidence": finding.get("missing_evidence"),
                "agent_surface": finding.get("agent_surface"),
                "prompt_evidence": finding.get("prompt_evidence"),
                "retrieval_evidence": finding.get("retrieval_evidence"),
                "memory_evidence": finding.get("memory_evidence"),
                "tool_evidence": finding.get("tool_evidence"),
                "mcp_evidence": finding.get("mcp_evidence"),
                "execution_evidence": finding.get("execution_evidence"),
                "filesystem_evidence": finding.get("filesystem_evidence"),
                "network_egress_evidence": finding.get("network_egress_evidence"),
                "sensitive_data_evidence": finding.get("sensitive_data_evidence"),
                "tenant_data_evidence": finding.get("tenant_data_evidence"),
                "controls_observed": finding.get("controls_observed"),
                "controls_missing": finding.get("controls_missing"),
                "attack_path": finding.get("attack_path"),
                "attack_path_ids": attack_path_ids,
                "proof_status": finding.get("proof_status"),
                "boundary_crossing": finding.get("boundary_crossing"),
                "infrastructure_surface": finding.get("infrastructure_surface"),
                "config_file": finding.get("config_file"),
                "config_key": finding.get("config_key"),
                "observed_evidence": finding.get("observed_evidence"),
            },
        }
        if explain and finding.get("exposure"):
            result["message"] = {"text": f"{result['message']['text']} Exposure path: {finding['exposure'].get('attack_path')}."}
        if finding.get("file"):
            physical_location = {
                "artifactLocation": {"uri": Path(finding["file"]).as_posix()},
            }
            if finding.get("line"):
                physical_location["region"] = {"startLine": finding["line"]}
            result["locations"] = [{"physicalLocation": physical_location}]
        results.append(result)

    results.sort(key=_result_sort_key)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TrustBoundary",
                        "informationUri": "https://github.com/openai/trustboundary",
                        "rules": rules,
                    }
                },
                "properties": {
                    "external_cybersecurity_engines": external_summary or {"engines": [], "warnings": [], "findings": [], "assessment_complete": True},
                    "production_readiness": {
                        "status": (readiness or {}).get("status"),
                        "decision_reasons": (readiness or {}).get("decision_reasons", []),
                        "production_blockers": (readiness or {}).get("production_blockers", []),
                        "required_reviews": (readiness or {}).get("required_reviews", []),
                    },
                    "trust_boundary_graph": {
                        "node_count": len(build_trust_boundary_graph(findings)["nodes"]),
                        "edge_count": len(build_trust_boundary_graph(findings)["edges"]),
                    },
                },
                "results": results,
            }
        ],
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
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--sarif", action="store_true")
    parser.add_argument("--explain", action="store_true")
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
        emit("Mode: application source scan" + (" + external engines" if args.full else ""), args.quiet)
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
        external_summary = {"engines": [], "warnings": [], "findings": []}
        if args.full:
            emit("Running external cybersecurity engines...", args.quiet)
            external_findings, external_warnings, external_statuses = run_external_engines(target_repo, quiet=args.quiet)
            audit_warnings.extend(external_warnings)
            external_summary = {
                "engines": external_statuses,
                "warnings": list(external_warnings),
                "findings": list(external_findings),
                "assessment_complete": all(engine["status"] == "completed" for engine in external_statuses),
            }
            raw_findings.extend(external_findings)
        audit_warnings = list(audit_warnings or []) + risk_acceptance_warnings(getattr(repo_config, "risk_acceptance", ()))
        emit("Scoring findings...", args.quiet)
        scored = score_findings(raw_findings, args.include_dependencies, args.include_tests, repo_config=repo_config)
        infrastructure_findings = [finding for finding in scored["findings"] if finding.get("category") in {"container_security", "ci_cd_security", "infrastructure_as_code"}]
        scope_summary = {
            "files_scanned": files_checked,
            "files_skipped": max(0, files_checked - len(raw_findings)),
            "excluded_dir_count": len(excluded_directories),
            "excluded_directories": excluded_directories,
            "infrastructure_files_detected": len({finding.get("file") for finding in infrastructure_findings if finding.get("file")}),
        }
        findings_path = Path.cwd() / "security-audit-findings.json"
        report_path = Path.cwd() / "SECURITY_AUDIT_REPORT.md"
        sarif_path = Path.cwd() / "security-audit-findings.sarif"
        emit("Generating reports...", args.quiet)
        json_output = build_json_output(target_repo, scored, scope_summary, audit_warnings=audit_warnings, repo_config=repo_config, external_summary=external_summary)
        findings_path.write_text(json.dumps(json_output, indent=2), encoding="utf-8")
        report = render_report(target_repo, scored, scope_summary, audit_warnings=audit_warnings, repo_config=repo_config, external_summary=external_summary, explain=args.explain)
        warnings_block = render_audit_warnings(audit_warnings)
        if warnings_block:
            report += "\n" + warnings_block
        report_path.write_text(report, encoding="utf-8")
        if args.sarif:
            sarif_output = build_sarif_output(target_repo, json_output["findings"], repo_config=repo_config, explain=args.explain, external_summary=external_summary, readiness=json_output["summary"]["production_readiness"])
            sarif_path.write_text(json.dumps(sarif_output, indent=2), encoding="utf-8")
        emit("")
        log_line("Done.", kind="success", quiet=args.quiet, colour_enabled=colour_enabled, use_icons=use_icons)
        emit(f"Total elapsed: {time.perf_counter() - started:.1f}s", args.quiet)
        emit(f"Files scanned: {scope_summary['files_scanned']}", args.quiet)
        emit(f"Files skipped: {scope_summary['files_skipped']}", args.quiet)
        decision = release_decision(scored["findings"], audit_warnings=audit_warnings)
        decision_kind = "success" if decision in {"READY_FOR_PRODUCTION", "READY_WITH_REVIEW"} else "warning" if decision == "REVIEW_REQUIRED" else "error"
        log_line(f"Release Decision: {decision}", kind=decision_kind, quiet=args.quiet, colour_enabled=colour_enabled, use_icons=use_icons)
        log_line(f"Trust Score: {json_output['summary']['trust_score']}/100 ({json_output['summary']['trust_grade']})", kind="info", quiet=args.quiet, colour_enabled=colour_enabled, use_icons=use_icons)
        emit(f"Findings: {len(scored['findings'])}", args.quiet)
        if audit_warnings:
            emit(f"Audit warnings: {len(audit_warnings)}", args.quiet)
        emit(f"Report: {report_path.name}", args.quiet)
        emit(f"JSON: {findings_path.name}", args.quiet)
        if args.sarif:
            emit(f"SARIF: {sarif_path.name}", args.quiet)
        return 0
    except Exception as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
