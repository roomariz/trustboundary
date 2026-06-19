# Trustboundary

`repo-security-audit` is a read-only security audit plugin and CLI for repositories, skills, plugins and MCP-style tooling.

## Problem

Developers and AI-agent users need a quick way to audit unfamiliar code before trusting or using it. This matters for repositories, plugins, skills and MCP-style tooling, where security risks can hide in secrets, dependencies, execution paths and configuration.

## Solution

This package provides a read-only, CLI-backed security audit plugin. It scans a target repository with local static checks and produces structured JSON plus a Markdown report for review.

## What It Checks

- Secrets and credentials
- Risky dependency indicators
- Dangerous execution patterns
- Possible exfiltration patterns
- Risky plugin, skill and MCP configuration patterns

## What It Outputs

- `security-audit-findings.json`
- `SECURITY_AUDIT_REPORT.md`

## Supported Usage

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
