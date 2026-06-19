# Changelog

## 2.0.2 - Phase 7: Infrastructure Security Analysis

- Phase 7 adds a new local, read-only infrastructure security scanner.
- Supported surfaces now include `Dockerfile`, `docker-compose.yml` / `docker-compose.yaml`, GitHub Actions workflows, Terraform, Kubernetes manifests, Helm charts, Supabase config, and `.env` template files.
- Infrastructure findings preserve evidence fields for `infrastructure_surface`, `config_file`, `config_key`, `observed_evidence`, `missing_evidence`, `controls_observed`, `controls_missing`, `boundary_crossing`, `proof_status`, `finding_class`, `evidence_level`, `confidence_score`, `confidence_band`, and `confidence_reason`.
- The trust-boundary graph now includes infrastructure edges for `ci_workflow -> shell_runtime`, `ci_workflow -> secrets_environment`, `ci_workflow -> deployment_target`, `container_runtime -> host_filesystem`, `container_runtime -> external_network`, `kubernetes_workload -> host_runtime`, `supabase_config -> tenant_data`, and `terraform_config -> cloud_resource`.
- JSON output now includes `infrastructure_files_detected`, `infrastructure_review_count`, and `confirmed_infrastructure_findings`.
- Markdown output now includes `## Infrastructure Security Review`.
- Readiness behavior remains conservative: observed infrastructure capability stays informational, material infrastructure risks require review, and confirmed secret exposure, privileged host access, or dangerous deployment paths block production.
- Validation: `python scripts/validate_plugin.py` and `pytest -q` (`132 passed`).

## 2.0.1 - Phase 5: Multi-Tenant Isolation Analysis

- Phase 5 adds Multi-Tenant Isolation Analysis.
- The scanner now reports tenant evidence, tenant propagation, query scope, retrieval scope, ownership scope, and missing tenant controls.
- The trust-boundary graph now includes tenant-context, repository, query, retrieval, prompt, agent-tool, and external-network tenant paths.
- JSON output includes `tenant_controls_detected`, `tenant_review_count`, and `confirmed_cross_tenant_findings`.
- Markdown output includes `## Multi-Tenant Isolation Review`.
- Readiness behavior keeps tenant capability evidence informational, requires review for material tenant-isolation gaps, and blocks production on confirmed cross-tenant exposure.
- Validation: `python scripts/validate_plugin.py` and `pytest -q` (`124 passed`).

## 2.0.0 - v2 Baseline Release

- Added the Production Security Gate and report decision flow.
- Added the Windows npm wrapper for smoother local installs.
- Tightened scan scope exclusions for repos, dependencies, and generated paths.
- Added visual CLI status output for progress, warnings, and release decisions.
- Expanded the confidence and evidence engine for deduped, evidence-rich findings.
- Deduplicated repeated findings into aggregated records with occurrence tracking.
- Added the Top Risks section for the most important review items.
- Added the Trust-Boundary Assessment summary for cross-boundary risk paths.
- Fixed production gate wording so review findings and true blockers are reported distinctly.

## 1.0.0 - Initial release

- Added the `repo-security-audit` CLI entry point.
- Added offline scanners, scoring, and report generation.
- Added Codex and OpenCode command wiring.
- Added release-readiness validation and tests.
