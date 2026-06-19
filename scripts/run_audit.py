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
    return {
        "why_detected": finding.get("evidence_snippet") or finding.get("evidence_redacted") or "Pattern matched by scanner heuristic.",
        "impacted_trust_boundary": finding.get("trust_boundary", ["unknown"]),
        "confidence_bucket": finding.get("confidence_bucket") or "Unknown",
        "remediation": finding.get("recommendation"),
        "evidence_snippet": snippet,
    }


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
            "evidence_redacted": _redact_sensitive_text(finding.get("evidence_redacted") or finding.get("evidence")),
            "exposure": build_exposure({
                **finding,
                "impact": metadata.get("impact", "Review the finding and validate whether it is a real risk."),
                "recommendation": RULE_RECOMMENDATIONS.get(finding["rule"], metadata.get("recommendation", "Review the flagged code or configuration and reduce the risky pattern.")),
            }),
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
    accepted = [finding for finding in production_findings if finding.get("status") == "accepted_risk" and finding.get("severity") != "Critical" and finding.get("category") != "leaked_secrets"]
    production_findings = [finding for finding in production_findings if finding not in accepted]
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
        if finding.get("production_blocker"):
            base += 6
        if category == "agentic_security":
            base += 6
        if category == "retrieval_poisoning":
            base += 5
        if category == "mcp_tool_abuse":
            base += 4
        if category == "leaked_secrets":
            base += 8
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
    blocked_findings = sum(1 for finding in suppressed if finding.get("production_blocker"))
    doc_findings = [finding for finding in suppressed if is_documentation_finding(finding)]
    prod_findings = [finding for finding in suppressed if not is_documentation_finding(finding) and (finding.get("scope") == "production" or "production" in set(finding.get("scope_tags", [])))]
    agentic_findings = [finding for finding in suppressed if finding.get("category") == "agentic_security"]
    trust_path_count = len(trust_paths_items or [])
    attack_chain_count = len(attack_chains_items or [])
    baseline_trust_path_count = len(trust_paths(unsuppressed_findings))
    baseline_attack_chain_count = len(attack_chains(trust_paths(unsuppressed_findings)))

    deductions = []
    total = 0

    def add(label, points, evidence):
        nonlocal total
        if points <= 0:
            return
        total += points
        deductions.append({"driver": label, "points": points, "evidence": evidence})

    for entry in _trust_score_deductions(suppressed):
        finding = entry["finding"]
        add(
            f"{finding.get('severity', 'Medium')} {finding.get('confidence_level', 'MEDIUM')} finding",
            entry["points"],
            finding.get("id"),
        )

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
    for entry in _trust_score_deductions(unsuppressed_findings):
        baseline_deductions += entry["points"]
    baseline_deductions += min(12, sum(1 for finding in unsuppressed_findings if not is_documentation_finding(finding) and (finding.get("scope") == "production" or "production" in set(finding.get("scope_tags", [])))) * 2)
    baseline_deductions += min(6, sum(1 for finding in unsuppressed_findings if is_documentation_finding(finding)))
    baseline_deductions += min(18, sum(1 for finding in unsuppressed_findings if finding.get("production_blocker")) * 6)
    baseline_deductions += min(24, baseline_trust_path_count * 4)
    baseline_deductions += min(28, baseline_attack_chain_count * 6)
    baseline_deductions += min(12, expired_suppression_count * 4)
    baseline_deductions += min(18, len(audit_warnings) * 6)
    baseline_deductions += min(16, len([finding for finding in unsuppressed_findings if finding.get("category") == "agentic_security"]) * 3)
    baseline_score = max(0, 100 - baseline_deductions)

    final_score = min(raw_score, baseline_score)
    final_score = max(0, min(100, final_score))

    reasoning = [
        f"Start at 100 and deduct for {len(suppressed)} finding(s), {trust_path_count} trust path(s), and {attack_chain_count} attack chain(s).",
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

    production_findings = [finding for finding in findings if not is_documentation_finding(finding) and (finding.get("scope") == "production" or "production" in set(finding.get("scope_tags", [])))]
    pressure_findings = [finding for finding in production_findings if not (finding.get("status") == "accepted_risk" and finding.get("severity") != "Critical" and finding.get("category") != "leaked_secrets")]
    blockers = [finding for finding in pressure_findings if finding.get("production_blocker") or finding.get("severity") == "Critical"]
    review_items = [finding for finding in pressure_findings if finding not in blockers and finding.get("severity") in {"High", "Medium", "Low"}]
    risky_paths = [path for path in trust_paths_items if path.get("risk") in {"High", "Critical"} and path.get("confidence") in {"High", "Medium"}]
    high_confidence_chains = [chain for chain in attack_chains_items if chain.get("confidence_score", 0) >= 90]
    unresolved_agentic_chains = [chain for chain in attack_chains_items if any("Agent" in boundary for boundary in chain.get("supporting_boundaries", [])) or "Agent" in chain.get("name", "")]

    scanner_issue = any(warning.get("rule") in {"scanner_failed", "scanner_unavailable"} for warning in audit_warnings)
    if scanner_issue:
        status = "NOT_READY_FOR_PRODUCTION"
        reason = "Scanner failures prevent a complete production assessment."
    elif blockers or critical_expired_suppressions():
        status = "NOT_READY_FOR_PRODUCTION"
        reason = "Critical production risk remains unresolved."
    elif any(finding.get("severity") == "High" for finding in pressure_findings) or high_confidence_chains or unresolved_agentic_chains or risky_paths:
        status = "REVIEW_REQUIRED"
        reason = "High-confidence production risk paths or chains still need review."
    elif review_items:
        status = "READY_WITH_REVIEW"
        reason = "Only medium or low production review items remain."
    elif trust_score_info.get("trust_score", 0) >= 90:
        status = "READY_FOR_PRODUCTION"
        reason = "No meaningful production findings remain and trust score is high."
    else:
        status = "READY_WITH_REVIEW"
        reason = "Residual production evidence remains, but it is limited to review items."

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
    findings = sorted(scored["findings"], key=severity_sort_key)
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
    required = required_fixes(findings)
    recommended = recommended_fixes(findings)
    framework_items = framework_findings(findings)
    risks = top_risks(findings, repo_config=repo_config)
    trust_score_info = calculate_trust_score(findings, paths, chains, active_suppressions=active_suppressions, expired_suppressions=expired_suppressions, audit_warnings=audit_warnings, unsuppressed_findings=unsuppressed_findings)
    readiness = production_readiness(findings, paths, chains, active_suppressions=active_suppressions, expired_suppressions=expired_suppressions, audit_warnings=audit_warnings, trust_score_info=trust_score_info, unsuppressed_findings=unsuppressed_findings)
    audit_trail = build_audit_trail(repo_path, findings, audit_warnings, active_suppressions, risk_state, trust_score_info, readiness, decision, repo_config=repo_config)
    incomplete_external_assessment = external_assessment_incomplete(external_summary)

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

    def _finding_block(finding):
        exposure = finding.get("exposure") or build_exposure(finding)
        lines_block = [
            f"### {finding_heading(finding)}",
            f"- Rule: {finding['rule']}",
            f"- Category: {finding['category']}",
            f"- Severity: {finding['severity']}",
            f"- Confidence: {finding['confidence_level']}",
            f"- Confidence bucket: {finding.get('confidence_bucket') or 'Unknown'}",
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
        render_audit_trail(audit_trail),
        "",
        "## Cybersecurity Exposure Map",
    ])
    for finding in findings[:10]:
        exposure = finding.get("exposure") or build_exposure(finding)
        lines.append(f"- {finding['id']} -> {exposure['attack_path']} ({finding.get('file') or '-'}:{finding.get('line') or '-'})")

    lines.extend([
        "",
        "## Leakage Findings",
    ])
    if findings:
        for finding in findings[:10]:
            lines.extend(_finding_block(finding))
            lines.append("")
    else:
        lines.append("No leakage findings identified.")

    lines.extend([
        "## Attack Paths",
    ])
    if paths:
        for path in paths:
            related_findings = [finding for finding in findings if finding["id"] in set(path.get("evidence", []))]
            heading = finding_heading(related_findings[0]) if related_findings else f"[{path.get('risk', 'Unknown')}] {path['boundary']}"
            lines.append(f"- {heading}: {path['source']} -> {path['sink']} ({path['risk']}, confidence {path.get('confidence_score', '-')})")
            if explain:
                lines.append(f"  - Source: {path['source']}")
                lines.append(f"  - Boundary crossed: {path['boundary']}")
                lines.append(f"  - Sink: {path['sink']}")
                lines.append(f"  - Trigger condition: {path['data_flow_summary']}")
                lines.append("  - Likely attacker action: Poison input or steer repository-controlled data into the sink.")
                lines.append("  - Business impact: Data exfiltration, unsafe execution, or privilege expansion.")
                lines.append("  - Recommended mitigation: Use allowlists, validation, and human approval gates.")
    else:
        lines.append("No supported attack paths were inferred.")

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

    lines.extend([
        "",
        "## Production Blockers",
    ])
    blockers = [finding for finding in findings if finding.get("production_blocker")]
    if blockers:
        for finding in blockers[:10]:
            lines.append(f"- {finding['id']} - {finding['rule']} ({finding['severity']}, {finding['confidence_level']})")
    else:
        lines.append("No production blockers identified.")

    lines.extend([
        "",
        "## Review Items",
    ])
    if recommended:
        for finding in recommended[:10]:
            lines.append(f"- {finding_heading(finding)} ({finding['severity']}, {finding['confidence_level']}) {finding['rule']} - {finding.get('recommendation')}")
    else:
        lines.append("No review items identified.")

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
        "## Agentic AI Security",
        f"- Prompt Injection Findings: {sum(1 for finding in agentic_findings if finding.get('rule') in {'prompt_override', 'role_manipulation', 'hidden_instruction'})}",
        f"- Tool Abuse Findings: {sum(1 for finding in agentic_findings if finding.get('rule') == 'tool_abuse_instruction')}",
        f"- Prompt Extraction Findings: {sum(1 for finding in agentic_findings if finding.get('rule') == 'prompt_extraction')}",
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
        lines.append(f"- {finding['id']} | {finding['rule_id']} | {finding['severity']} | {finding['confidence_level']} | {finding.get('occurrences', 1)} occurrence(s)")
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
    findings = list(scored["findings"])
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
            "production_blockers": sum(1 for finding in findings if finding.get("production_blocker")),
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
            },
            "scope_counts": scope_counts,
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


def _sarif_level(severity: str) -> str:
    return SARIF_SEVERITY_MAP.get(severity, "warning")


def build_sarif_output(repo_path: Path, findings, repo_config=None, explain: bool = False, external_summary=None):
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
            },
        }

    rules = sorted(rule_map.values(), key=_rule_sort_key)
    results = []
    for finding in findings:
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
        scope_summary = {
            "files_scanned": files_checked,
            "files_skipped": max(0, files_checked - len(raw_findings)),
            "excluded_dir_count": len(excluded_directories),
            "excluded_directories": excluded_directories,
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
            sarif_output = build_sarif_output(target_repo, json_output["findings"], repo_config=repo_config, explain=args.explain, external_summary=external_summary)
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
