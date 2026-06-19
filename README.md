# Trustboundary

`repo-security-audit` is a read-only security audit plugin and CLI for repositories, skills, plugins and MCP-style tooling.

## Problem

Developers and AI-agent users need a quick way to audit unfamiliar code before trusting or using it. This matters for repositories, plugins, skills and MCP-style tooling, where security risks can hide in secrets, dependencies, execution paths and configuration.

## Solution

This package provides a read-only, CLI-backed security audit plugin. It scans a target repository with local static checks and produces structured JSON plus a Markdown report for review.

The report includes a production security gate, Top Risks, Trust Boundary Assessment, aggregated findings summary, and Infrastructure Security Review. The release decision distinguishes `REVIEW_REQUIRED` from `NOT_READY_FOR_PRODUCTION`.

## What It Checks

- Secrets and credentials
- Risky dependency indicators
- Dangerous execution patterns
- Possible exfiltration patterns
- Risky plugin, skill and MCP configuration patterns
- Infrastructure and deployment review surfaces, including Dockerfiles, compose files, GitHub Actions workflows, Terraform, Kubernetes manifests, Helm charts, Supabase config, and `.env` template files

## What It Outputs

- `security-audit-findings.json`
- `SECURITY_AUDIT_REPORT.md`
- `security-audit-findings.sarif` when `--sarif` is used

## Sample Report Excerpt

```md
## Leakage Findings

### DATA_EXFILTRATION-0090: Network client usage
- What is exposed or at risk: Request payloads may leave the repository boundary through outbound network calls.
- Where: apps/matter-portal/app/api-utils.ts:12
- Attack path: Prompt -> Network
- Recommended fix: Use an allowlist of approved outbound hosts and validate URLs before fetch.
- Release decision: REVIEW_REQUIRED
```

## What TrustBoundary does and does not do

- TrustBoundary performs local, read-only cybersecurity and trust-boundary scanning.
- TrustBoundary helps developers review repositories before production.
- TrustBoundary does not certify that a repository is secure.
- Findings are evidence-based review leads unless marked confirmed.

## Supported Usage

Python 3 is required for the audit engine. On Windows, the npm global install uses a Node wrapper which locates Python automatically.

CLI:

```bash
repo-security-audit /path/to/repo
```

Codex slash command:

```text
/repo-security-audit
```

OpenCode command:

```text
repo-security-audit .
```

GitHub Actions:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: "20"
- run: npm install
- run: npx trustboundary scan . --sarif
```

The repository includes a ready-to-use workflow at `.github/workflows/trustboundary.yml` that runs the scan and uploads the Markdown, JSON, and SARIF outputs as artifacts. If the repository grants `security-events: write`, the workflow also uploads SARIF to GitHub code scanning on push.

Skill usage:

- `skills/repo-security-audit/SKILL.md`

## Safety Model

- Read-only scanning
- No network calls
- No auto-remediation
- Does not modify target repositories except for the generated audit outputs in the current working directory

## Limitations

This is heuristic static scanning. It is not a full SAST platform, a penetration test, a dependency intelligence system, or a guarantee that code is safe. It can miss issues and it can produce false positives.

## Release Readiness

Run `python scripts/validate_plugin.py` and `pytest -q` before release to confirm the bundle and CLI wiring are intact.

### Phase 5 Release Note

Phase 5 adds Multi-Tenant Isolation Analysis.

- The scanner now reports tenant evidence, tenant propagation, query scope, retrieval scope, ownership scope, and missing tenant controls.
- The trust-boundary graph now includes tenant-context, repository, query, retrieval, prompt, agent-tool, and external-network tenant paths.
- JSON output includes `tenant_controls_detected`, `tenant_review_count`, and `confirmed_cross_tenant_findings`.
- Markdown output includes `## Multi-Tenant Isolation Review`.
- Readiness behavior keeps tenant capability evidence informational, requires review for material tenant-isolation gaps, and blocks production on confirmed cross-tenant exposure.

Validation:

- `python scripts/validate_plugin.py`
- `pytest -q`
- `124 passed`

### Phase 7 Release Note

Phase 7 adds Infrastructure Security Analysis.

- The scanner stays local and read-only while reviewing Dockerfiles, compose files, GitHub Actions workflows, Terraform, Kubernetes manifests, Helm charts, Supabase config, and `.env` template files.
- Infrastructure findings preserve evidence fields such as `infrastructure_surface`, `config_file`, `config_key`, `observed_evidence`, `missing_evidence`, `controls_observed`, `controls_missing`, `boundary_crossing`, `proof_status`, `finding_class`, `evidence_level`, `confidence_score`, `confidence_band`, and `confidence_reason`.
- The trust-boundary graph now includes infrastructure edges for CI workflows, deployment targets, container host access, external network access, Kubernetes host/runtime access, Supabase tenant data, and Terraform cloud resources.
- JSON output includes `infrastructure_files_detected`, `infrastructure_review_count`, and `confirmed_infrastructure_findings`.
- Markdown output now includes `## Infrastructure Security Review`.
- Readiness remains conservative: observed capability is informational, material infrastructure risks require review, and confirmed secret exposure, privileged host access, or dangerous deployment paths block production.

Validation:

- `python scripts/validate_plugin.py`
- `pytest -q`
- `132 passed`
