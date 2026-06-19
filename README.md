# TrustBoundary

TrustBoundary is a local, deterministic, read-only repository trust-boundary auditor.

It reviews repositories, AI-generated code, MCP servers, agent systems, plugins and skills.

## Naming

- The project is TrustBoundary.
- The npm package may be published as `repo-security-audit`.
- The CLI exposes both `trustboundary` and `repo-security-audit`.
- The recommended command for users is `trustboundary`.

## Installation

### Install from GitHub

```powershell
npm uninstall -g trustboundary
npm install -g github:roomariz/trustboundary
```

## Quick Start

```powershell
cd D:\path\to\target\repository
trustboundary scan "." --full --sarif --explain
```

## Problem

Developers and AI-agent users need a quick way to audit unfamiliar code before trusting or using it. This matters for repositories, plugins, skills and MCP-style tooling, where security risks can hide in secrets, dependencies, execution paths and configuration.

## Solution

This package provides a read-only, CLI-backed security audit plugin. It scans a target repository with local static checks and produces structured JSON plus a Markdown report for review.

The report includes a production security gate, Top Risks, Trust Boundary Assessment, aggregated findings summary, and Infrastructure Security Review. The release decision distinguishes `REVIEW_REQUIRED` from `NOT_READY_FOR_PRODUCTION`.

## Evidence Classification

TrustBoundary classifies findings by evidence strength:

- `OBSERVED_CAPABILITY`: a security-relevant capability exists, but exploitability is not proven.
- `POTENTIAL_RISK`: a dangerous capability appears with contextual risk indicators, but no complete exploit path is proven.
- `CONFIRMED_VULNERABILITY`: source, sink, path, missing or ineffective control, and plausible impact are all evidenced.

Examples:

- `fetch()` alone is `OBSERVED_CAPABILITY`.
- `fetch()` near sensitive data or untrusted input is `POTENTIAL_RISK`.
- Sensitive data flowing to an uncontrolled external endpoint without an effective control is `CONFIRMED_VULNERABILITY`.

Evidence determines classification.

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

Reports are written to the current working directory.

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
- TrustBoundary is not a penetration-testing tool, runtime exploit framework, certification system, or guarantee of safety.
- Dangerous primitives are not automatically vulnerabilities.
- Findings are evidence-based review leads unless marked confirmed.

## Design Principles

- Local-first
- Read-only
- Deterministic
- Evidence-based
- No automatic remediation
- No source-code upload during analysis

## Release Decisions

### READY_FOR_PRODUCTION

No material findings requiring review.

### REVIEW_REQUIRED

Security-relevant findings require human review before deployment.

### NOT_READY_FOR_PRODUCTION

Confirmed vulnerabilities or production-blocking findings were detected.

## Supported Usage

Python 3 is required for the audit engine. On Windows, the npm global install uses a Node wrapper which locates Python automatically.

CLI:

```bash
trustboundary scan "." --full --sarif --explain
```

Legacy CLI example:

```bash
repo-security-audit /path/to/repo
```

Codex slash command:

```text
/trustboundary scan "." --full --sarif --explain
```

OpenCode command:

```text
trustboundary scan . --full --sarif --explain
```

Legacy package command:

```bash
repo-security-audit scan "." --full --sarif --explain
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
- The scan does not intentionally call external services or upload source code during analysis.
- Installation and package updates may require network access.
- No auto-remediation
- Does not modify target repositories except for the generated audit outputs in the current working directory

## Limitations

This is heuristic static scanning. It is not a full SAST platform, a penetration test, a dependency intelligence system, a runtime exploit framework, or a guarantee that code is safe. It can miss issues and it can produce false positives.

## Release Readiness

Run `python scripts/validate_plugin.py` and `pytest -q` before release to confirm the bundle and CLI wiring are intact.
