---
description: Senior-auditor-grade deep security review using the cybersecurity-repository-audit skill
allowed-tools: Read, Grep, Glob, Bash
---

# TrustBoundary: Deep Audit

Perform a senior-auditor-grade, evidence-based security assessment of the
current repository.

## When to use this

Use `/trustboundary:deep-audit` when you need a defensible, repository-wide
security review covering both conventional application security and AI/agentic
risks — prompt injection, indirect prompt injection, model/tool boundary
failures, MCP/tool abuse, agent privilege escalation, unsafe execution, data
exfiltration, secret leakage, authentication/authorization weaknesses, CI/CD
risk, cloud/IaC risk, supply-chain compromise, and trust-boundary violations.

For a quick first-pass CLI scan instead, use `/trustboundary:audit`.

## What to do

1. Identify the current repository root and build a repository map.
2. Follow the full skill instructions in
   `skills/cybersecurity-repository-audit/SKILL.md`. Apply its workflow:
   establish scope, build a threat model before judging code, run
   repository-wide searches and targeted inspection, trace data flow and
   authorization (not just patterns), and work through the AI/agentic and
   conventional security checklists.
3. You may run the offline CLI
   (`trustboundary scan "." --full --sarif --explain`) as one input, but never
   substitute scanner output for manual analysis.

This review is read-only. Do not make network calls beyond what is needed to run
local scanners, do not auto-remediate, and do not modify the target repository
apart from generated audit outputs.

## Evidence rules (strict)

Accuracy is more important than finding volume. A zero-finding report is
acceptable when the evidence does not support confirmed vulnerabilities.

- Do not claim a finding unless you can cite exact repository evidence: file
  path, line number(s), symbol context, and affected snippet.
- Do not claim a confirmed vulnerability without the full reachability model:
  **source, sink, path, trust boundary, and reachability evidence**, plus a
  missing or ineffective control and plausible impact.
- Every item must use exactly one classification: Confirmed Vulnerability,
  Likely Vulnerability, Architectural Risk, Governance Gap, Hardening
  Recommendation, Observation, or Positive Control. Missing controls are not
  automatically vulnerabilities.
- Apply the skill's Evidence Validation Gate and False-Positive Challenge before
  any Critical or High finding. If repository exposure cannot be proven, state
  "Repository exposure not confirmed." and downgrade.
- Verify git/source-control state before claiming source-controlled exposure.
  Treat `.env.example`, samples, tests, and templates with placeholders as not
  confirmed secret exposure.

## Output

Produce a concise, professional report by default: executive summary (overall
risk rating, trust assessment, production readiness), top risks, and a findings
summary table. Provide the skill's full detailed report format — with per-finding
reachability models, attack paths, evidence for and against, remediation, and
verification — only when the user asks for full detail.
