---
description: Fast repository trust-boundary scan using the repo-security-audit skill
allowed-tools: Read, Grep, Glob, Bash
---

# TrustBoundary: Fast Audit

Run a fast, read-only trust-boundary scan of the current repository.

## When to use this

Use `/trustboundary:audit` for a quick first-pass security review of an
unfamiliar or recently changed repository — secrets, risky dependencies,
dangerous execution patterns, possible exfiltration, and risky plugin / skill /
MCP configuration. For a senior-auditor-grade manual review with full
attack-path evidence, use `/trustboundary:deep-audit` instead.

## What to do

1. Identify the current repository root (default to `.`).
2. Follow the skill instructions in `skills/repo-security-audit/SKILL.md`.
   The core flow is:
   - Run the offline CLI: `trustboundary scan "." --full --sarif --explain`
     (fall back to `repo-security-audit .` if `trustboundary` is unavailable).
   - Read `SECURITY_AUDIT_REPORT.md`.
   - Read `security-audit-findings.json`.
   - Summarise only what the scanner reported.

The audit is read-only and uses local static checks only. It does not call
external services or upload source code. It produces:

- `security-audit-findings.json`
- `SECURITY_AUDIT_REPORT.md`
- `security-audit-findings.sarif` (when `--sarif` is used)

## Evidence rules (strict)

- Report findings using the scanner's severity, confidence, file, line, rule id,
  and evidence. Never invent vulnerabilities or upgrade heuristics into facts.
- Preserve evidence-based classification:
  - `OBSERVED_CAPABILITY` — a security-relevant capability exists, but
    exploitability is not proven.
  - `POTENTIAL_RISK` — a dangerous capability appears with contextual risk
    indicators, but no complete exploit path is proven.
  - `CONFIRMED_VULNERABILITY` — only when file, line, source, sink, path, trust
    boundary, and reachability are all evidenced.
- Do not claim a confirmed vulnerability without that full evidence chain.
- Do not make network calls and do not auto-remediate. Do not modify the target
  repository apart from the generated audit outputs in the current directory.

## Output

Produce a concise, professional summary: the release decision, top risks, and a
short findings table with severity, confidence, location, and evidence. Include
the static-scan limitations. Expand to the full detailed report only if the user
asks for full detail.
