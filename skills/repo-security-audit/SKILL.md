---
name: repo-security-audit
description: Use when the user asks to audit, scan, or review a repository (or its agent skills / MCP configuration) for security risks — supply-chain, secrets, dependency confusion, malicious packages, unsafe execution, insecure config, data exfiltration, prompt injection, or MCP/tool abuse. Triggers on phrases like "security audit this repo", "scan for leaked secrets", "check for malicious dependencies", "review our skills/MCP config for risk", or "/repo-security-audit".
allowed-tools: Read, Grep, Glob, Bash(repo-security-audit:*)
version: 1.0.0
---

# Trustboundary

Identify the target repository path, then run the installed CLI:

1. `repo-security-audit <target-repo-path>`
2. Read `SECURITY_AUDIT_REPORT.md`
3. Read `security-audit-findings.json`
4. Summarise only what the scanner reported

This audit is read-only and uses local static checks only. It produces:
- `security-audit-findings.json`
- `SECURITY_AUDIT_REPORT.md`

Never invent vulnerabilities or upgrade heuristics into facts.
Do not make network calls or auto-remediate anything.
Treat the scanner as read-only and do not modify the target repository apart from the generated audit outputs.

## Workflow

1. Scope the repo path.
2. Run the offline scan CLI.
3. Review the generated JSON and Markdown outputs.
4. Report findings with the scanner's severity, confidence, file, line, rule id, and evidence.
5. Do not auto-apply changes.

## Output

Produce a security audit report with severity, confidence, concrete remediation steps, and explicit limitations of the static scan.
