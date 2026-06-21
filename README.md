# TrustBoundary

TrustBoundary is a reusable security and trust-boundary review toolkit for repositories, AI-generated code, MCP servers, plugins, agents, and skills. It provides local, deterministic, read-only auditing through multiple distribution channels — npm CLI, Codex plugin, and Claude Code commands — all sharing the same audit engine and evidence-based findings model.

## Naming

- The project is TrustBoundary.
- The Codex plugin is `trustboundary`.
- The npm package is currently `repo-security-audit`.
- The CLI exposes both `trustboundary` and `repo-security-audit`.
- The recommended CLI command is `trustboundary`.

## Current Capabilities

- **Fast scanner-driven repository trust-boundary audit** — deterministic CLI scanner with evidence-based classification
- **Deep senior-auditor cybersecurity review** — manual, repository-wide assessment covering conventional and AI/agentic risks
- **AI and agentic security assessment** — prompt injection, tool abuse, agent privilege escalation, data exfiltration
- **MCP, plugin, and skill review** — configuration and execution-path analysis for extensible systems
- **Production-readiness assessment** — evidence-based release decision gates (READY_FOR_PRODUCTION, REVIEW_REQUIRED, NOT_READY_FOR_PRODUCTION)

## Installation

Install TrustBoundary once, then use the workflow you need. Choose your distribution channel based on where you work:

- **npm CLI** — use `trustboundary scan` in any terminal or CI job
- **Codex plugin** — use `$repo-security-audit` or `$cybersecurity-repository-audit` inside Codex
- **Claude Code commands** — use `/trustboundary:audit` or `/trustboundary:deep-audit` inside Claude Code

Installing one distribution channel does not install the others. The npm package does not register anything with Codex or Claude Code, and the plugin/command bundles do not put a CLI on your `PATH`.

### Distribution map

```text
TrustBoundary
├─ npm CLI
│  └─ trustboundary scan
├─ Codex Plugin
│  ├─ $repo-security-audit
│  └─ $cybersecurity-repository-audit
└─ Claude Code
   ├─ /trustboundary:audit
   └─ /trustboundary:deep-audit
```

### Install as a Codex plugin

Requires Codex CLI v0.117.0 or newer (the version that introduced the plugin system).

The `trustboundary` plugin bundles two skills, both installed together:

- `repo-security-audit` — runs the deterministic offline CLI scanner and summarises its output.
- `cybersecurity-repository-audit` — a senior-auditor manual review producing an evidence-based report.

**From GitHub (recommended for most users):**

```bash
codex plugin marketplace add roomariz/trustboundary
codex plugin add trustboundary
```

**From a local clone (for development or offline use):**

```bash
git clone https://github.com/roomariz/trustboundary.git
cd trustboundary
codex plugin marketplace add .
codex plugin add trustboundary
```

Then start a new Codex thread and invoke either skill:

- Explicitly: start a prompt with `$repo-security-audit` or `$cybersecurity-repository-audit`
- Implicitly: ask Codex to "security audit this repository"
- Browse/manage: run `/plugins` (plugins) or `/skills` (skills) inside a Codex session

If the plugin does not appear after installing, restart Codex — there is no hot reload. The CLI engine still requires Python 3 on `PATH`.

### Claude Code commands

TrustBoundary ships two Claude Code slash commands under the `trustboundary`
namespace. They live in `.claude/commands/trustboundary/` and are available in
any Claude Code session opened in this repository (or copy that directory into
another repo's `.claude/commands/` to use them there):

- `/trustboundary:audit` — a fast repository trust-boundary scan. It drives the
  `repo-security-audit` skill: runs the offline CLI scanner and summarises its
  output.
- `/trustboundary:deep-audit` — a senior-auditor-grade deep security review. It
  drives the `cybersecurity-repository-audit` skill: a manual, evidence-based,
  repository-wide assessment covering conventional and AI/agentic risks.

Both commands inspect the current repository, preserve strict evidence-based
classification, and never claim a confirmed vulnerability without file, line,
source, sink, path, trust boundary, and reachability evidence. They produce a
concise professional report unless you ask for full detail.

### Install from GitHub (npm CLI)

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

## Why TrustBoundary?

Traditional SAST tools answer:
"What vulnerabilities exist?"

TrustBoundary answers:
"Can I safely trust, execute, integrate, or deploy this repository?"

The focus is trust-boundary analysis, evidence-based classification, AI/agentic security review, and production-readiness assessment rather than vulnerability counting.

## Solution

TrustBoundary provides a local, read-only repository trust-boundary auditing platform available through three distribution channels:

- npm CLI
- Codex plugin
- Claude Code commands

The platform performs deterministic repository analysis and can also be used through bundled audit skills for deeper security review workflows. It scans a target repository with local static checks and produces structured JSON plus a Markdown report for review.

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

Confirmed vulnerabilities, production-blocking findings, or incomplete mandatory security assessment prevented a production recommendation.

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

Codex skill (after installing the `trustboundary` plugin — see Installation):

```text
$repo-security-audit
$cybersecurity-repository-audit
```

Codex does not use a `/trustboundary` slash command. Skills are invoked with `$<skill-name>`, browsed with `/skills`, or matched implicitly from a prompt such as "security audit this repository".

Claude Code commands:

```text
/trustboundary:audit
/trustboundary:deep-audit
```

The same audit is reachable three ways, depending on your tool:

- **Codex** uses `$repo-security-audit` and `$cybersecurity-repository-audit`.
- **Claude Code** uses `/trustboundary:audit` and `/trustboundary:deep-audit`.
- **npm CLI** uses `trustboundary scan "." --full --sarif --explain`.

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
    node-version: "24"
- run: npm install
- run: npx trustboundary scan . --sarif
```

The repository includes a ready-to-use workflow at `.github/workflows/trustboundary.yml` that runs the scan and uploads the Markdown, JSON, and SARIF outputs as artifacts. If the repository grants `security-events: write`, the workflow also uploads SARIF to GitHub code scanning on push.

Skill usage (both bundled in the `trustboundary` Codex plugin):

- `skills/repo-security-audit/SKILL.md` — **repo-security-audit**: a fast,
  scanner-driven trust-boundary assessment. Runs the offline CLI scanner and
  summarises its output.
- `skills/cybersecurity-repository-audit/SKILL.md` — **cybersecurity-repository-audit**:
  a deep, repository-wide security review using structured evidence, threat
  modelling, reachability analysis, and AI/agentic security assessment. Ships
  supporting `references/`, `templates/`, and `scripts/` files.

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
