---
name: cybersecurity-repository-audit
description: Use when asked to scan, audit, review, or assess a code repository for traditional application security and AI/agentic security risks; produces a senior-auditor-grade report with exact file/class/function/line evidence, attack paths, severity, confidence, remediation, and production-readiness assessment.
---

# Cybersecurity Repository Audit

## Overview

Act like a senior cybersecurity auditor performing a defensible repository-wide security assessment. The output must be a complete professional report, not a loose list of concerns. Cover both conventional software-security weaknesses and AI/agentic risks: prompt injection, indirect prompt injection, model/tool boundary failures, MCP/tool abuse, agent privilege escalation, unsafe code execution, data exfiltration, secret leakage, authentication and authorization weaknesses, CI/CD risk, cloud/IaC risk, supply-chain compromise, and trust-boundary violations.

This skill is grounded in the attached reference set summarized in `references/ai-agentic-security-taxonomy.md`, including OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications / AIUC-1 crosswalk material, OWASP State of Agentic AI Security and Governance, OWASP AI Security Solutions Landscape for AI and Agentic Red Teaming, OpenSSF guidance for AI code-assistant instructions, and related LLM application security material.

## Core Principle: Accuracy Over Finding Volume

Accuracy is more important than finding vulnerabilities. A report with zero findings is acceptable if the repository evidence does not support confirmed vulnerabilities.

Do **not** infer vulnerabilities from incomplete evidence. Do **not** elevate architectural concerns, governance gaps, missing controls, or hardening recommendations into vulnerabilities. When evidence is incomplete, explicitly state uncertainty and classify the item as an Observation, Architectural Risk, Governance Gap, or Hardening Recommendation as appropriate.

**Core rule:** Do not claim an issue unless you can cite exact repository evidence: file path, line number(s), symbol context, affected snippet, repository-state evidence when relevant, and a plausible reachable attack path. If something is a design concern without direct exploitable evidence, label it as an Observation or Architectural Risk with lower confidence.

**Audit success metric:** Minimize false positives, maximize evidence quality, distinguish vulnerabilities from recommendations, and provide defensible engineering conclusions. Do not maximize finding count, speculate about missing controls, or infer compromise without evidence.

## When to Use

Use this skill when the user asks for:

- A repository security scan, security audit, red-team style review, or production-readiness assessment.
- AI/LLM/agent/MCP security review.
- Prompt injection, tool abuse, exfiltration, secret handling, sandboxing, or supply-chain assessment.
- A formal report suitable for engineering leadership, security review, or remediation planning.

Do **not** use this for:

- A quick syntax/code-style review with no security scope.
- Live exploitation of third-party systems or anything outside the user's repository/environment.
- Producing exploit payloads intended for unauthorized targets. Keep proof-of-concepts scoped to local/repository evidence and benign demonstrations.

## Audit Standard

Every finding must include all of the following fields:

1. **ID**: stable identifier, e.g. `SEC-001`.
2. **Title**: concise vulnerability name.
3. **Finding classification**: exactly one of Confirmed Vulnerability, Likely Vulnerability, Architectural Risk, Governance Gap, Hardening Recommendation, Observation, Positive Control. Do not mix categories.
4. **Severity**: Critical / High / Medium / Low / Informational.
5. **Confidence**: High / Medium / Low.
6. **Category / taxonomy mapping**: map to CWE, OWASP Web/API, OWASP LLM, OWASP Agentic, OpenSSF, or cloud/IaC control where possible.
7. **Location**: exact file path, class, function/method, and line number range.
8. **Repository state**: committed/tracked/untracked/ignored/generated/example-template/runtime-only/unknown; include git evidence when making source-controlled exposure claims.
9. **Affected code snippet**: quote the relevant code with line numbers.
10. **Reachability model**: Source, Transformation, Sink, Trust Boundary, Reachability Evidence.
11. **Evidence supporting the finding**: why the snippet is vulnerable; include data/control-flow evidence and any configuration evidence.
12. **Evidence weakening the finding**: counter-evidence, mitigating controls, uncertainty, and scope limits.
13. **Alternative explanations**: placeholder/test/generated/local-only/runtime-only/example file, unreachable path, scanner false positive, etc.
14. **Why the finding remains valid**: concise false-positive challenge conclusion.
15. **Attack path**: attacker preconditions, entry point, trust boundary crossed, vulnerable operation, and post-condition.
16. **Impact**: concrete security consequence: data exfiltration, RCE, auth bypass, privilege escalation, token theft, tenant breakout, model/tool hijack, etc.
17. **Exploit scenario / proof**: safe, repository-scoped demonstration or reasoning path; no destructive payloads.
18. **Remediation**: specific fix, including safer pattern and exact files/functions to change.
19. **Verification**: test/check that should pass after remediation.

If any required element cannot be established, say so explicitly and lower confidence. Do not report source-to-sink vulnerabilities without tracing reachability.

## Mandatory Evidence Validation Gate

Before reporting any **Critical** or **High** severity finding, all of the following must pass:

1. Confirm the file exists in the repository being audited.
2. Confirm the evidence comes from repository contents, not assumptions, scanner output alone, generated artifacts, local-only files, or runtime-only state.
3. Confirm the finding is reproducible from repository evidence.
4. Distinguish repository state: committed file, tracked file, untracked local file, ignored file, generated artifact, example/template file, runtime environment variable, or unknown.
5. If repository exposure cannot be proven, downgrade the item to Observation or Architectural Risk and state exactly: **"Repository exposure not confirmed."**

Critical and High findings must not be issued without passing this validation gate.

## Mandatory False-Positive Challenge

Before finalizing any finding, document:

- Evidence supporting the finding.
- Evidence weakening the finding.
- Alternative explanations.
- Why the finding remains valid.

If the finding cannot survive this challenge, do not report it as a vulnerability. Prefer no finding over a weak finding.

## Git Verification Requirements

When making claims about source-controlled exposure, verify repository state with:

```bash
git status --short
git ls-files -- <file>
git check-ignore -v -- <file>
git log --all -- <file>
```

Interpretation rules:

- **Committed file**: appears in `git ls-files` and has history in `git log --all -- <file>`.
- **Tracked file**: appears in `git ls-files`; may be newly added or modified.
- **Untracked local file**: appears in `git status --short` as `??`; do not claim repository exposure.
- **Ignored file**: identified by `git check-ignore -v`; do not claim repository exposure unless separately distributed.
- **Generated artifact**: build/output/cache file; treat as lower confidence unless it is intentionally shipped.
- **Example/template file**: `.example`, `.sample`, fixtures, docs, templates; inspect for placeholders before classifying.
- **Runtime environment variable**: not repository exposure unless committed configuration reveals the value.

If repository state cannot be verified, explicitly state this limitation and reduce confidence accordingly. Never claim a secret is committed unless source-control evidence confirms it. Never claim repository exposure from a local working tree alone.

## Secret Exposure Validation

A string resembling a secret is not automatically a secret. To classify as **Confirmed Secret Exposure**, all of these must be true:

- Credential format appears valid for the claimed provider/token type.
- Value is not obvious placeholder text (`changeme`, `example`, `test`, `dummy`, `xxx`, `<TOKEN>`, etc.).
- File exists within repository scope.
- File is tracked or distributed.
- Repository exposure is confirmed with git/source-control evidence or distribution evidence.

Otherwise classify it as exactly one of:

- Potential Secret
- Example Credential
- Placeholder Credential
- Local Development Secret
- Observation

`.env.example`, `.sample`, documentation, tests, and templates containing placeholders must never be reported as confirmed credential exposure.

## Mandatory Reachability Model

Every vulnerability must include:

- **Source:** attacker-controlled or untrusted input source.
- **Transformation:** parsing, concatenation, prompt assembly, authorization decision, serialization, validation, or other processing.
- **Sink:** sensitive operation, tool call, query, filesystem/network action, model prompt, credential exposure, authorization decision, etc.
- **Trust Boundary:** boundary crossed by the attacker-controlled data or capability.
- **Reachability Evidence:** code/config evidence proving the path can execute.

If any element cannot be established, confidence cannot exceed Medium and severity must be reassessed. If runtime behavior is not observed, repository state is unknown, deployment configuration is unavailable, source-to-sink path is incomplete, or exploitability is inferred rather than demonstrated, confidence must be Low (and in any case cannot exceed Medium under those conditions). High confidence requires direct repository evidence.

## Finding Classification Model

Every item in the report must belong to exactly one category:

1. **Confirmed Vulnerability** — source-to-sink path, reachability, repository evidence, and exploitability are established.
2. **Likely Vulnerability** — strong repository evidence exists but one non-critical runtime/deployment assumption remains.
3. **Architectural Risk** — design or trust-boundary concern without enough evidence for a vulnerability.
4. **Governance Gap** — missing process, policy, review, inventory, ownership, or compliance control.
5. **Hardening Recommendation** — defense-in-depth improvement without a proven exploit path.
6. **Observation** — notable fact, weak signal, local-only issue, potential secret, or item requiring follow-up.
7. **Positive Control** — security control that materially reduces risk.

Do not mix categories. Missing controls are not automatically vulnerabilities.

## Hardening Recommendation Rules

The following must not be reported as vulnerabilities unless an exploit path exists:

- Use of `latest` dependency versions.
- Missing SBOM or AI SBOM.
- Missing AI manifest/tool manifest.
- Absence of CI hardening evidence.
- Missing documentation.
- Missing governance controls.

Place these under Hardening Recommendations or Governance Gaps unless repository evidence proves an exploitable path.

## Critical and High Finding Sanity Review

Before publishing, review every Critical and High finding and ask:

- Could this be a placeholder?
- Could this be an example file?
- Could this be generated output?
- Could this be a test fixture?
- Could this be a local-only file?
- Could this be ignored by source control?
- Could this be an untracked developer artifact?

If any answer is yes, re-investigate before reporting. Severity must be based on proven exploitability, not theoretical impact. A finding cannot be Critical unless repository evidence exists, reachability is established, impact is material, and confidence is High; otherwise reduce severity.

## Required Workflow

### 1. Establish scope and repository map

- Identify repository root, language stack, package managers, frameworks, deployment targets, CI/CD systems, IaC/cloud providers, and AI/agent frameworks.
- Enumerate files; exclude only obvious generated/vendor/build artifacts. Do **not** sample only a few files.
- Identify security-relevant assets:
  - Entry points: HTTP routes, CLIs, workers, webhooks, queue consumers, scheduled jobs.
  - Authn/authz: middleware, route guards, token/session code, RBAC/ABAC checks.
  - Secret handling: env vars, config, vault/KMS clients, logs, telemetry, error reporting.
  - Dangerous sinks: shell execution, eval/deserialization, SQL/NoSQL queries, template rendering, file/path operations, SSRF-capable network calls.
  - AI/agent surfaces: prompts, system/developer instructions, RAG ingestion/retrieval, tool schemas/descriptions, MCP servers/clients, function calling, memory, planner/executor loops, browser/computer-use tools, autonomous workflows.
  - Supply chain: lockfiles, package manifests, Dockerfiles, GitHub Actions, scripts, model downloads, prompt files, MCP/tool registries, external templates.
  - Cloud/IaC: Terraform, CloudFormation, Kubernetes, Helm, Docker Compose, IAM policies, storage/network exposure.

### 2. Build a threat model before judging code

For each externally reachable or untrusted-input surface, record:

- **Actor**: anonymous user, authenticated user, tenant user, malicious dependency, compromised MCP server, malicious webpage/document, malicious model output, CI contributor, cloud principal.
- **Asset**: secrets, user data, business data, agent tools, credentials, deployment environment, model/system prompt, memory, vector store, logs.
- **Trust boundary**: browser/API boundary, tenant boundary, prompt/data boundary, model/tool boundary, local/remote MCP boundary, CI/repo boundary, cloud account boundary.
- **Attack path hypothesis**: source → transform → sink.

Use the threat model to avoid shallow pattern matching.

### 3. Run repository-wide searches and targeted inspection

Use available tools, preferring fast repository search and then exact file reads. Suggested search themes:

- Secrets: `api_key`, `token`, `secret`, `password`, `private_key`, `.env`, credentials, cloud keys.
- Execution: `eval`, `exec`, `Function(`, `child_process`, `subprocess`, `os.system`, `shell=True`, `spawn`, `docker run`, `kubectl`, `terraform apply`.
- Network/SSRF: `fetch`, `requests`, `axios`, `http`, `urlopen`, webhooks, callbacks, proxying user URLs.
- Auth: `jwt`, `session`, `cookie`, `csrf`, `cors`, `is_admin`, `role`, `permission`, route middleware.
- Injection: SQL builders, ORM raw queries, template rendering, YAML/JSON/XML parsing, pickle/deserialization.
- AI/agent: `system prompt`, `developer`, `prompt`, `tool`, `function_call`, `mcp`, `agent`, `planner`, `executor`, `memory`, `rag`, `retriever`, `vector`, `embedding`, `browser`, `computer_use`.
- CI/supply chain: package manifests/lockfiles, `curl | sh`, unpinned GitHub Actions, broad `GITHUB_TOKEN`, dependency install scripts, postinstall hooks, dynamic downloads.
- IaC/cloud: wildcard IAM, public buckets, open security groups, privileged containers, hostPath mounts, missing resource limits, plaintext secrets.

If available, run lightweight automated tools, but never substitute tool output for human analysis:

- Dependency audits: `npm audit`, `pnpm audit`, `pip-audit`, `cargo audit`, `go list -m -u -json all`, `govulncheck`, `bundler audit` as appropriate.
- Secrets: `gitleaks`, `trufflehog`, or repository grep for common patterns.
- IaC/container: `checkov`, `tfsec`, `trivy config`, `hadolint`, `kube-score` if installed.
- SAST: language-appropriate scanner if already configured.

If a scanner is missing, do not stop; document that it was unavailable and continue manual review.

### 4. Inspect data flow and authorization, not just patterns

For each candidate issue:

1. Trace untrusted source to sensitive sink.
2. Check validation, normalization, escaping, authorization, scoping, and sandbox controls.
3. Confirm whether the vulnerable path is reachable.
4. Confirm whether mitigating controls are central and consistently applied or local and bypassable.
5. Identify bypasses: alternate routes, background jobs, direct service methods, webhook paths, CLI paths, async execution after approval, cached permissions, stale tokens.

#### Object Identifier Access Evidence Rule

**Object access by identifier alone is NOT a confirmed vulnerability.** Before reporting an IDOR (Insecure Direct Object Reference):

- **Check for ownership checks**: Does the code verify `object.owner_id == current_user.id` or equivalent?
- **Check for tenant checks**: Does the code verify `object.tenant_id == current_tenant.id` or equivalent?
- **Classification:**
  - If both ownership AND tenant checks are visible in the same route/handler: classify as `observed_capability` (protected object access). This is a normal, secure pattern.
  - If checks are missing: classify as `potential_risk` or `confirmed_vulnerability` depending on reachability and evidence strength.
  - If identity context itself is externally overrideable (e.g., `user_id` and `tenant_id` come from route parameters instead of authenticated dependencies): classify as `externally_overrideable_identity_context` (potential_risk).

**Evidence supporting the finding:**
- Object retrieved by user-supplied ID without checks: ownership bypass risk.
- Checks present but bypassable through alternate code paths: still vulnerable.
- Identity context overrideable through parameters: identity context override risk.

**Evidence weakening the finding:**
- Central, well-applied ownership check visible in the same handler.
- Central, well-applied tenant scoping visible.
- Identity derived from authenticated dependency, not route parameters.
- Both user and tenant checks present and evaluated before returning sensitive data.

**Why this rule exists:** False positives on protected object access waste auditor and engineering time. Ownership and tenant checks are normal API patterns, not vulnerabilities. Accurate classification improves actionability and trust in security findings.

### 5. AI and agentic security checklist

Evaluate these categories explicitly when the repo contains AI/LLM/agent code:

- **Prompt injection and goal hijack**: untrusted content enters system/developer instructions, tool descriptions, scratchpads, memory, RAG context, or planner state without delimiting, filtering, and tool-call constraints.
- **Indirect prompt injection**: agent summarizes or browses webpages/docs/emails/issues/PRs and lets hidden instructions influence actions.
- **Tool misuse and MCP abuse**: overbroad tools, unsafe tool schemas, hidden instructions in tool metadata, untrusted MCP servers, missing allowlists, no per-tool authorization, no execution-time revalidation.
- **Identity and privilege abuse**: agent runs as a powerful service account, shares user credentials across tenants, or lacks user-bound delegated authorization.
- **Agentic supply chain**: unpinned MCP servers/actions/models, unaudited prompt/tool packages, dynamic code/model downloads, no AI SBOM/provenance, no code signing or checksums.
- **Unexpected code execution**: model-controlled shell/code/browser/computer-use tools, eval-like operations, notebook execution, plugin installation, command construction from model output.
- **Memory and context poisoning**: persistent memory/vector store accepts untrusted data without source labels, TTLs, access controls, provenance, or poisoning detection.
- **Orchestration and communication**: multi-agent messages cross trust boundaries without sender identity, integrity, policy enforcement, or transcript isolation.
- **Repudiation/accountability gaps**: no tamper-evident audit trail for prompts, retrieved context, model outputs, tool calls, approvals, and final actions.
- **Resource exhaustion / cost abuse**: unbounded loops, recursive agents, unlimited tool calls, unbounded retrieval, no rate limits, no budget caps.
- **Rogue agents**: agents can create/modify tools, spawn agents, schedule jobs, self-modify prompts, or escalate privileges without policy and approval boundaries.
- **Sensitive information disclosure**: secrets/system prompts/user data can leak into prompts, logs, telemetry, model providers, browser pages, or tool outputs.
- **Excessive agency**: high-impact actions lack human-in-the-loop gates, approval UX is spoofable, or approvals are not bound to exact action parameters.
- **Model/provider risk**: untrusted model endpoints, weak data-retention controls, cross-region data transfer, no fallback policy, no provider allowlist.

### 6. Conventional security checklist

Always assess:

- Authentication: password/session/JWT/OAuth validation, MFA assumptions, token audience/issuer/expiry, cookie flags, CSRF.
- Authorization: object-level checks, tenant isolation, admin checks, route/method consistency, background/worker paths.
- Injection: SQL/NoSQL/command/template/path/header/LDAP/XML/deserialization.
- SSRF and egress: user-controlled URLs, metadata endpoints, cloud credentials, DNS rebinding, proxy bypasses.
- File handling: path traversal, unsafe archive extraction, symlink races, upload validation, public file serving.
- Cryptography: insecure randomness, hardcoded keys, weak algorithms, missing verification, custom crypto.
- Logging/telemetry: secret/PII leakage, prompt/context leakage, model output logging, insecure debug endpoints.
- Error handling: stack traces, debug flags, verbose exceptions, fail-open auth.
- Rate limiting and abuse controls: brute force, DoS, cost abuse, account enumeration.
- CI/CD: unpinned actions, pull_request_target misuse, secrets exposed to forks, overbroad tokens, unsigned artifacts.
- Containers/IaC: privileged containers, host mounts, root users, public network exposure, permissive IAM, plaintext secrets.

## Severity and Confidence

### Severity rubric

- **Critical**: proven direct unauthenticated or low-privilege path to RCE, credential theft, cross-tenant compromise, production secret exfiltration, or agent/tool takeover with high-impact capabilities **and** repository evidence, established reachability, material impact, and High confidence. If any element is missing, reduce severity.
- **High**: proven authenticated but practical privilege escalation, sensitive data exfiltration, durable prompt/memory poisoning enabling unauthorized actions, CI/CD secret theft, or broad cloud/IAM compromise path with repository evidence and reachability. High cannot be issued if the Evidence Validation Gate fails.
- **Medium**: exploitable with constraints, meaningful data exposure, missing authorization in limited scope, unsafe agent capability requiring uncommon preconditions, supply-chain weakness without direct compromise evidence.
- **Low**: defense-in-depth gap, weak hardening, limited impact, requires strong preconditions.
- **Informational**: positive/negative observation, documentation gap, or improvement with no immediate exploit path.

### Confidence rubric

- **High**: direct repository evidence plus exact reachable source-to-sink path confirmed with code/config evidence; repository state verified where exposure is claimed.
- **Medium**: strong repository evidence but one runtime/deployment assumption remains unverified.
- **Low**: runtime behavior not observed, repository state unknown, deployment configuration unavailable, source-to-sink path incomplete, exploitability inferred rather than demonstrated, suspicious pattern, or architectural risk requiring design/runtime confirmation.

## Required Report Format

Use this structure unless the user requested a different format. A detailed template is available in `templates/security-report.md`.

```markdown
# Security Audit Report: <repository/project>

## Executive Summary
- Scope:
- Methods:
- Overall risk rating:
- Repository trust assessment:
- Production readiness:
- Top risks:

## Scope and Methodology
- Files/areas reviewed:
- Tools/commands run:
- Frameworks/taxonomies used:
- Limitations:

## Architecture and Trust Boundaries
- Entry points:
- Assets:
- Trust boundaries:
- AI/agentic components:

## Findings Summary
| ID | Classification | Severity | Confidence | Category | Title | Location | Status |

## Detailed Findings
### SEC-001: <title>
- Classification: Confirmed Vulnerability / Likely Vulnerability / Architectural Risk / Governance Gap / Hardening Recommendation / Observation / Positive Control
- Severity:
- Confidence:
- Category / taxonomy mapping:
- Location: `path:line-line`, class/function/method
- Repository state: committed/tracked/untracked/ignored/generated/example-template/runtime-only/unknown; include git evidence for exposure claims
- Affected code:
  ```<language>
  <line-numbered snippet>
  ```
- Reachability model:
  - Source:
  - Transformation:
  - Sink:
  - Trust Boundary:
  - Reachability Evidence:
- Evidence supporting the finding:
- Evidence weakening the finding:
- Alternative explanations:
- Why the finding remains valid:
- Attack path:
- Impact:
- Exploit scenario / proof:
- Recommended remediation:
- Verification:

## Positive Security Controls Observed

## Missing Controls / Architectural Risks

## AI/Agentic Security Assessment

## Supply Chain and CI/CD Assessment

## Cloud/IaC and Deployment Assessment

## Evidence Reliability Assessment

For each Critical and High finding:

| Finding | Repository Verified | Git Verified | Runtime Verified | Confidence Justification |
| ------- | ------------------- | ------------ | ---------------- | ------------------------ |

## Overall Repository Trust and Production-Readiness Assessment
- Trust rating:
- Release recommendation: Ready / Ready with conditions / Not ready
- Required fixes before production:
- Recommended next steps:
```

## Evidence Quality Rules

- Quote code snippets with line numbers. If the file is large, quote only the relevant lines plus small context.
- Prefer exact symbol names over vague module references.
- Do not cite scanner output alone. Validate findings manually in code.
- Deduplicate findings by root cause. If the same vulnerable helper affects many call sites, one finding can list multiple affected locations.
- Separate confirmed vulnerabilities from likely vulnerabilities, architectural risks, governance gaps, hardening recommendations, observations, and positive controls.
- Include positive controls when they materially reduce risk.
- If no confirmed high-severity issue exists, say so; do not inflate severity. A zero-finding report is acceptable.

## Common Pitfalls

1. **Pattern matching without reachability.** A dangerous function is not automatically exploitable. Trace source → transform → sink.
2. **Ignoring AI trust boundaries.** Treat prompts, retrieved documents, webpages, emails, tool descriptions, MCP metadata, and model outputs as untrusted inputs unless proven otherwise.
3. **Forgetting execution-time authorization.** Approval at request/planning time can go stale before asynchronous execution. Check revalidation at execution.
4. **Overlooking tool metadata poisoning.** MCP/tool descriptions and schemas can carry model-visible instructions that reviewers may ignore.
5. **Assuming service-account safety.** Agents often run with broader privileges than users. Verify delegated, user-scoped authorization.
6. **Reporting missing controls as vulnerabilities.** Missing SBOM/provenance/audit logs may be a governance risk, but severity depends on exploitability and asset exposure.
7. **Skipping CI/CD and IaC.** Supply-chain and deployment paths often provide easier compromise than application code.
8. **Not stating limitations.** If dependencies cannot be installed, scanners cannot run, git state cannot be verified, or runtime config is absent, state that clearly and reduce confidence.
9. **Calling placeholders secrets.** `.env.example`, samples, tests, and templates with placeholder values are not confirmed secret exposure.
10. **Promoting governance gaps to vulnerabilities.** Missing SBOMs, manifests, CI hardening, or documentation are Governance Gaps or Hardening Recommendations unless a concrete exploit path is proven.

## Verification Checklist

Before delivering the report:

- [ ] Repository root and scope are explicit.
- [ ] Major languages/frameworks/package managers identified.
- [ ] Entry points and trust boundaries documented.
- [ ] AI/agentic components checked, or explicitly marked not present.
- [ ] Authn/authz, secrets, execution, injection, supply chain, CI/CD, and IaC/cloud areas reviewed.
- [ ] Every confirmed vulnerability has file, class/function/method, line numbers, snippet, repository state, reachability model, false-positive challenge, attack path, impact, severity, confidence, remediation, and verification.
- [ ] Findings are deduplicated; each item has exactly one classification; severity is based on proven exploitability, not theoretical impact.
- [ ] Limitations are documented.
- [ ] Critical/High findings passed the Evidence Validation Gate and are listed in Evidence Reliability Assessment.
- [ ] Git verification was performed for source-controlled exposure claims, or limitations are explicit.
- [ ] Overall trust and production-readiness assessment is included.
