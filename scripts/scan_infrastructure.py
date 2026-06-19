#!/usr/bin/env python3
"""
scan_infrastructure.py - local read-only heuristics for infrastructure and
deployment configuration security review.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from scanner_utils import iter_repo_files, relativise


def _add(findings, path, line, category, rule, evidence, base_confidence, **extra):
    finding = {
        "category": category,
        "rule": rule,
        "file": path,
        "line": line,
        "evidence_redacted": evidence,
        "base_confidence": base_confidence,
        **extra,
    }
    findings.append(finding)


def _line_number(text: str, needle: str):
    idx = text.find(needle)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def _is_dockerfile(path: Path) -> bool:
    return path.name == "Dockerfile" or path.name.startswith("Dockerfile.")


def _is_compose(path: Path) -> bool:
    return path.name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


def _is_github_workflow(path: Path) -> bool:
    return ".github" in path.parts and "workflows" in path.parts and path.suffix.lower() in {".yml", ".yaml"}


def _is_terraform(path: Path) -> bool:
    return path.suffix.lower() == ".tf" or path.name in {"terraform.tfvars", "terraform.tfvars.json"}


def _is_kubernetes_manifest(path: Path, text: str) -> bool:
    lower = path.name.lower()
    if lower in {"kustomization.yaml", "kustomization.yml"}:
        return True
    if path.suffix.lower() not in {".yml", ".yaml"}:
        return False
    if any(part.lower() in {"k8s", "kubernetes", "manifests"} for part in path.parts):
        return True
    return bool(re.search(r"(?m)^(apiVersion|kind):\s*", text))


def _is_helm_chart(path: Path) -> bool:
    return path.name == "Chart.yaml" or "templates" in [part.lower() for part in path.parts]


def _is_supabase_config(path: Path, text: str) -> bool:
    lower = path.as_posix().lower()
    if "supabase" in lower:
        return True
    return bool(re.search(r"(?im)^\s*\[.*supabase|^\s*project_id\s*=", text))


def _is_env_template(path: Path) -> bool:
    name = path.name.lower()
    return name.startswith(".env.") or name in {".env.example", ".env.sample", "env.example", "env.sample"}


def _scan_dockerfile(path: Path, text: str, findings: list):
    lines = text.splitlines()
    joined = "\n".join(lines)
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if re.search(r"(?i)^\s*USER\s+0\b|^\s*USER\s+root\b", stripped):
            _add(findings, path, lineno, "container_security", "container_root_user", stripped, 92, infrastructure_surface="Dockerfile", config_file=path.name, config_key="USER", observed_evidence=stripped, missing_evidence="non-root runtime user", controls_observed=[], controls_missing=["USER non-root"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
        if re.search(r"(?i)^\s*CMD\s+\[?.*(bash|sh)\b", stripped):
            _add(findings, path, lineno, "container_security", "dangerous_shell_command", stripped, 55, infrastructure_surface="Dockerfile", config_file=path.name, config_key="CMD", observed_evidence=stripped, missing_evidence="explicit argument allowlist", controls_observed=[], controls_missing=["bounded entrypoint"], boundary_crossing=False, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
    if re.search(r"(?i)^\s*VOLUME\s+/.+", joined, re.M) and re.search(r"(?i)^\s*USER\s+root\b|^\s*USER\s+0\b", joined, re.M):
        _add(findings, path, _line_number(text, "VOLUME") or 1, "container_security", "container_root_user", "root user with writable volume", 80, infrastructure_surface="Dockerfile", config_file=path.name, config_key="VOLUME", observed_evidence="root user with writable volume", missing_evidence="non-root runtime user", controls_observed=[], controls_missing=["USER non-root"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")


def _scan_compose(path: Path, text: str, findings: list):
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if "docker.sock" in line:
            _add(findings, path, lineno, "container_security", "docker_socket_mount", line.strip(), 95, infrastructure_surface="docker-compose", config_file=path.name, config_key="volumes", observed_evidence=line.strip(), missing_evidence="socket isolation", controls_observed=[], controls_missing=["no docker socket mount"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
        if re.search(r"(?i)\bprivileged:\s*true\b", line):
            _add(findings, path, lineno, "container_security", "privileged_container", line.strip(), 95, infrastructure_surface="docker-compose", config_file=path.name, config_key="privileged", observed_evidence=line.strip(), missing_evidence="least-privilege container runtime", controls_observed=[], controls_missing=["privileged: false"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
        if re.search(r"(?i)\buser:\s*root\b", line):
            _add(findings, path, lineno, "container_security", "container_root_user", line.strip(), 90, infrastructure_surface="docker-compose", config_file=path.name, config_key="user", observed_evidence=line.strip(), missing_evidence="non-root runtime user", controls_observed=[], controls_missing=["user: non-root"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
        if re.search(r"(?i)\bread_only:\s*false\b", line):
            _add(findings, path, lineno, "container_security", "missing_read_only_rootfs", line.strip(), 75, infrastructure_surface="docker-compose", config_file=path.name, config_key="read_only", observed_evidence=line.strip(), missing_evidence="read_only: true", controls_observed=[], controls_missing=["read_only: true"], boundary_crossing=False, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
        if re.search(r"(?i)\bports:\s*$", line):
            _add(findings, path, lineno, "container_security", "broad_network_exposure", line.strip(), 50, infrastructure_surface="docker-compose", config_file=path.name, config_key="ports", observed_evidence=line.strip(), missing_evidence="bind address scope", controls_observed=[], controls_missing=["loopback or narrow port binding"], boundary_crossing=True, proof_status="implicit", finding_class="observed_capability", evidence_level="capability")


def _scan_workflow(path: Path, text: str, findings: list):
    lines = text.splitlines()
    if "pull_request_target" in text:
        for lineno, line in enumerate(lines, start=1):
            if re.search(r"(?i)\bsecrets\.", line):
                _add(findings, path, lineno, "ci_cd_security", "pull_request_target_secret_exposure", line.strip(), 95, infrastructure_surface="GitHub Actions", config_file=path.name, config_key="on.pull_request_target", observed_evidence=line.strip(), missing_evidence="trusted PR boundary", controls_observed=[], controls_missing=["avoid secrets in pull_request_target"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
            if re.search(r"(?i)\brun:\s*.*(curl|wget|bash|sh)\b", line):
                _add(findings, path, lineno, "ci_cd_security", "dangerous_ci_command", line.strip(), 70, infrastructure_surface="GitHub Actions", config_file=path.name, config_key="jobs.*.steps.run", observed_evidence=line.strip(), missing_evidence="command allowlist", controls_observed=[], controls_missing=["trusted command set"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
    for lineno, line in enumerate(lines, start=1):
        if "uses:" in line and "@" in line:
            ref = line.split("uses:", 1)[1].strip()
            if "@" in ref and not re.search(r"@[0-9a-fA-F]{40}\b", ref):
                _add(findings, path, lineno, "ci_cd_security", "unpinned_action", line.strip(), 75, infrastructure_surface="GitHub Actions", config_file=path.name, config_key="uses", observed_evidence=ref, missing_evidence="commit SHA pinning", controls_observed=[], controls_missing=["pin action by SHA"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
        if re.search(r"(?i)\bpermissions:\s*\{?\s*.*\b(write-all|contents:\s*write|id-token:\s*write)\b", line):
            _add(findings, path, lineno, "ci_cd_security", "broad_ci_permissions", line.strip(), 72, infrastructure_surface="GitHub Actions", config_file=path.name, config_key="permissions", observed_evidence=line.strip(), missing_evidence="least-privilege permissions", controls_observed=[], controls_missing=["narrow workflow permissions"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
        if re.search(r"(?i)\b(run|shell):\s*.*\b(git push|kubectl apply|terraform apply|helm upgrade|docker push)\b", line):
            _add(findings, path, lineno, "ci_cd_security", "dangerous_ci_command", line.strip(), 78, infrastructure_surface="GitHub Actions", config_file=path.name, config_key="jobs.*.steps.run", observed_evidence=line.strip(), missing_evidence="review gate for deployment", controls_observed=[], controls_missing=["trusted deployment boundary"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
        if re.search(r"(?i)\$\{\{\s*github\.(event|head_ref|ref|actor|repository_owner)", line) and re.search(r"(?i)\brun:", line):
            _add(findings, path, lineno, "ci_cd_security", "untrusted_input_deploy", line.strip(), 88, infrastructure_surface="GitHub Actions", config_file=path.name, config_key="jobs.*.steps.run", observed_evidence=line.strip(), missing_evidence="trusted input validation", controls_observed=[], controls_missing=["no deployment from untrusted input"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
        if "secrets." in line and "if:" not in line:
            _add(findings, path, lineno, "ci_cd_security", "secret_environment_use", line.strip(), 60, infrastructure_surface="GitHub Actions", config_file=path.name, config_key="secrets", observed_evidence=line.strip(), missing_evidence="secret scoping guard", controls_observed=[], controls_missing=["limit secret exposure"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")


def _scan_terraform(path: Path, text: str, findings: list):
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if re.search(r'(?i)\b(effect|action)\s*=\s*"allow"', line) and "*" in text:
            _add(findings, path, lineno, "infrastructure_as_code", "broad_iam_permissions", line.strip(), 85, infrastructure_surface="Terraform", config_file=path.name, config_key="policy", observed_evidence="allow with wildcard resource or action", missing_evidence="least privilege scope", controls_observed=[], controls_missing=["scope IAM actions/resources"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
        if re.search(r"(?i)\bpublic(_|-)?(read|write|access)\s*=\s*true\b", line):
            _add(findings, path, lineno, "infrastructure_as_code", "public_database_storage", line.strip(), 88, infrastructure_surface="Terraform", config_file=path.name, config_key="public", observed_evidence=line.strip(), missing_evidence="private access controls", controls_observed=[], controls_missing=["restrict public access"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
        if re.search(r"(?i)\b0\.0\.0\.0/0\b", line):
            _add(findings, path, lineno, "infrastructure_as_code", "broad_network_exposure", line.strip(), 70, infrastructure_surface="Terraform", config_file=path.name, config_key="cidr_blocks", observed_evidence=line.strip(), missing_evidence="narrow CIDR allowlist", controls_observed=[], controls_missing=["restrict network exposure"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
        if re.search(r"(?i)\b(var|local|data)\.", line) and re.search(r"(?i)\bapply|destroy|replace\b", line):
            _add(findings, path, lineno, "infrastructure_as_code", "untrusted_input_deploy", line.strip(), 80, infrastructure_surface="Terraform", config_file=path.name, config_key="resource", observed_evidence=line.strip(), missing_evidence="trusted deployment inputs", controls_observed=[], controls_missing=["no deployment from untrusted input"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
        if re.search(r"(?i)\b(module|resource)\b.*\b\"[^\"]*\"\s*\{\s*$", line):
            continue
    if re.search(r"(?im)^\s*resource\s+\".*\".*\{\s*$", text) and re.search(r"(?im)^\s*#\s*public\b", text):
        _add(findings, path, 1, "infrastructure_as_code", "public_database_storage", "public resource comment", 55, infrastructure_surface="Terraform", config_file=path.name, config_key="resource", observed_evidence="public resource comment", missing_evidence="private access controls", controls_observed=[], controls_missing=["restrict public access"], boundary_crossing=True, proof_status="implicit", finding_class="observed_capability", evidence_level="capability")


def _scan_kubernetes(path: Path, text: str, findings: list):
    lines = text.splitlines()
    lower = text.lower()
    for lineno, line in enumerate(lines, start=1):
        if re.search(r"(?i)\bprivileged:\s*true\b", line):
            _add(findings, path, lineno, "container_security", "k8s_privileged_pod", line.strip(), 95, infrastructure_surface="Kubernetes", config_file=path.name, config_key="securityContext.privileged", observed_evidence=line.strip(), missing_evidence="privileged: false", controls_observed=[], controls_missing=["drop privileged pod mode"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
        if re.search(r"(?i)\bhostPath:\s*$", line):
            _add(findings, path, lineno, "container_security", "k8s_hostpath_mount", line.strip(), 93, infrastructure_surface="Kubernetes", config_file=path.name, config_key="volumes.hostPath", observed_evidence=line.strip(), missing_evidence="safer volume type", controls_observed=[], controls_missing=["avoid hostPath"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
        if re.search(r"(?i)\bhost(Network|PID|IPC):\s*true\b", line):
            _add(findings, path, lineno, "container_security", "k8s_host_networking", line.strip(), 90, infrastructure_surface="Kubernetes", config_file=path.name, config_key="host*", observed_evidence=line.strip(), missing_evidence="isolated pod namespaces", controls_observed=[], controls_missing=["disable host namespace sharing"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
        if re.search(r"(?i)\bresources:\s*$", line):
            if "limits" not in lower:
                _add(findings, path, lineno, "container_security", "k8s_missing_resource_limits", line.strip(), 65, infrastructure_surface="Kubernetes", config_file=path.name, config_key="resources", observed_evidence="resources block without visible limits", missing_evidence="resource limits", controls_observed=[], controls_missing=["cpu and memory limits"], boundary_crossing=False, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
        if re.search(r"(?i)\bsecurityContext:\s*$", line) and not re.search(r"(?i)\brunAsNonRoot:\s*true\b", lower):
            _add(findings, path, lineno, "container_security", "missing_read_only_rootfs", line.strip(), 50, infrastructure_surface="Kubernetes", config_file=path.name, config_key="securityContext", observed_evidence="securityContext without non-root evidence", missing_evidence="runAsNonRoot/readOnlyRootFilesystem", controls_observed=[], controls_missing=["non-root and read-only rootfs"], boundary_crossing=False, proof_status="implicit", finding_class="observed_capability", evidence_level="capability")


def _scan_helm(path: Path, text: str, findings: list):
    if re.search(r"(?i)\bprivileged:\s*true\b", text):
        _add(findings, path, 1, "container_security", "k8s_privileged_pod", "privileged template value", 90, infrastructure_surface="Helm", config_file=path.name, config_key="values", observed_evidence="privileged template value", missing_evidence="privileged: false", controls_observed=[], controls_missing=["remove privileged template"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
    if re.search(r"(?i)\bhostPath:\s*", text):
        _add(findings, path, 1, "container_security", "k8s_hostpath_mount", "hostPath template value", 88, infrastructure_surface="Helm", config_file=path.name, config_key="values", observed_evidence="hostPath template value", missing_evidence="safer volume type", controls_observed=[], controls_missing=["remove hostPath template"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")
    if re.search(r"(?i)\bhost(Network|PID|IPC):\s*true\b", text):
        _add(findings, path, 1, "container_security", "k8s_host_networking", "host namespace template value", 88, infrastructure_surface="Helm", config_file=path.name, config_key="values", observed_evidence="host namespace template value", missing_evidence="isolated pod namespaces", controls_observed=[], controls_missing=["remove host namespace sharing"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")


def _scan_supabase(path: Path, text: str, findings: list):
    lower = text.lower()
    if re.search(r"(?i)\brls\s*=\s*true\b|\benable_row_level_security\b", text):
        _add(findings, path, 1, "infrastructure_as_code", "supabase_rls_enabled", "Supabase RLS indicator present", 85, infrastructure_surface="Supabase", config_file=path.name, config_key="rls", observed_evidence="RLS indicator present", missing_evidence=None, controls_observed=["row level security"], controls_missing=[], boundary_crossing=False, proof_status="explicit", finding_class="observed_capability", evidence_level="capability")
    else:
        _add(findings, path, 1, "infrastructure_as_code", "missing_rls_indicator", "No Supabase RLS indicator found", 65, infrastructure_surface="Supabase", config_file=path.name, config_key="rls", observed_evidence="no visible RLS indicator", missing_evidence="row level security indicator", controls_observed=[], controls_missing=["document RLS on multi-tenant tables"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")
    if "service_role" in lower or "service-role" in lower:
        _add(findings, path, 1, "secret_leakage", "supabase_service_role_exposure", "Supabase service role material detected", 92, infrastructure_surface="Supabase", config_file=path.name, config_key="service_role", observed_evidence="service role material detected", missing_evidence="environment secret sourcing", controls_observed=[], controls_missing=["remove service-role material from config"], boundary_crossing=True, proof_status="explicit", finding_class="confirmed_vulnerability", evidence_level="proven")


def _scan_env_template(path: Path, text: str, findings: list):
    if re.search(r"(?i)\b(secret|password|token|key)\s*=\s*.+", text) and not re.search(r"(?i)\b(example|sample|placeholder|changeme|dummy)\b", text):
        _add(findings, path, 1, "secret_leakage", "env_template_secret", "Environment template contains credential-like value", 88, infrastructure_surface="Environment Template", config_file=path.name, config_key="env", observed_evidence="credential-like value in template", missing_evidence="placeholder-only template values", controls_observed=[], controls_missing=["use placeholders instead of secrets"], boundary_crossing=True, proof_status="implicit", finding_class="potential_risk", evidence_level="partial")


def scan_file(path: Path, findings: list):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return
    if _is_dockerfile(path):
        _scan_dockerfile(path, text, findings)
    if _is_compose(path):
        _scan_compose(path, text, findings)
    if _is_github_workflow(path):
        _scan_workflow(path, text, findings)
    if _is_terraform(path):
        _scan_terraform(path, text, findings)
    if _is_kubernetes_manifest(path, text):
        _scan_kubernetes(path, text, findings)
    if _is_helm_chart(path):
        _scan_helm(path, text, findings)
    if _is_supabase_config(path, text):
        _scan_supabase(path, text, findings)
    if _is_env_template(path):
        _scan_env_template(path, text, findings)


def walk(repo_path: str, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    findings = []
    repo_root = None
    for repo_root, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        scan_file(path, findings)
    if repo_root is not None:
        for finding in findings:
            finding["file"] = relativise(repo_root, Path(finding["file"]))
    return findings


if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
