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


---

# File: references/ai-agentic-security-taxonomy.md

# AI and Agentic Security Reference Taxonomy

This reference distills the attached security material provided for the `cybersecurity-repository-audit` skill.

## Source material used

- `Cheat-Sheet-Red-Teaming-AI-Solution-Landscape-Q226.pdf` — OWASP GenAI Security Project AI Security Solutions Landscape for AI and Agentic Red Teaming, Q2 2026. Extracted text emphasizes lifecycle red/blue/purple teaming, model vulnerability scanning, agent-logic corruption testing, LLM plugin/tool/infrastructure scanning, prompt-chaining, multi-turn attacks, protocol attacks including A2A/MCP, RAG-poison scenarios, guardrail conformance, CI hooks, metrics, and release thresholds.
- `Lakera-Agentic-AI-Security-The-Enterprise-Playbook.pdf` — included as a source document. Text extraction from the local PDF yielded no readable body text in this environment, so use its title/domain as supporting context and prefer the extracted OWASP/OpenSSF sources for quotable taxonomy.
- `LLMAll_en-US_FINAL.pdf` — OWASP Top 10 for LLM Applications 2025. Extracted text identifies prompt injection, sensitive information disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weakness, misinformation, and unbounded consumption patterns.
- `OWASP-Top10-for-Agentic-Applications_AIUC-1-Crosswalk-May26_01.pdf` — OWASP AIUC-1 crosswalk for Agentic Applications, May 2026. Extracted text emphasizes strategic gaps around circuit breakers, blast-radius caps, planner-executor isolation, runtime malicious-activity monitoring, AI service entitlement controls, supply-chain attestation, tool manifests, prompt version control, agent dependency bills of materials, code signing, structured schemas at the agent-model boundary, cross-region data-use controls, tool-call governance, execution-time authorization revalidation, and third-party testing of tool calls.
- `State-of-Agentic-AI-Security-and-Governance-v2.01-1.pdf` — OWASP State of Agentic AI Security and Governance, June 2026. Extracted text emphasizes prompt injection as a foundational unsolved challenge, agentic supply chain as an active attack surface, MCP/tool registry risks, malicious MCP servers, tool poisoning attacks hidden in descriptions/metadata, agentic identity, AI SBOM/provenance, explainability, monitoring, and governance maturity.
- `security.txt` — references supplied by user:
  - `https://genai.owasp.org/llm-top-10` (the file text omitted `://`; normalize when using)
  - `https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html`
  - `https://www.paloaltonetworks.com/resources/infographics/llm-applications-owasp-10`

## OWASP LLM Top 10 assessment checklist

Use this as a repository-review checklist and map findings where applicable.

1. **Prompt Injection**
   - Direct: user text alters model/system intent.
   - Indirect: webpage, document, email, PR/issue, RAG chunk, or tool output contains hidden model instructions.
   - Evidence to seek: untrusted text concatenated into high-trust prompts; no delimiting; model output drives tools; prompt-injected retrieved content can cause actions or data leakage.

2. **Sensitive Information Disclosure**
   - Secrets, PII, system prompts, credentials, tenant data, logs, traces, or retrieved documents sent to models/providers or exposed in responses.
   - Evidence to seek: raw env/config in prompts/logs; broad context dumps; no redaction; cross-tenant retrieval; telemetry with prompts/tool outputs.

3. **Supply Chain**
   - Compromised dependencies, models, datasets, prompts, MCP servers, plugins, containers, actions, or dynamic downloads.
   - Evidence to seek: unpinned deps/actions/images; `curl | sh`; unsigned models; unaudited tool registries; missing lockfiles/checksums/SBOM.

4. **Data and Model Poisoning**
   - Training/RAG/memory/vector data can be maliciously altered to affect behavior.
   - Evidence to seek: untrusted ingestion; no provenance; weak write controls; no content moderation; no source labels; no TTL; poisoned memory accepted as trusted.

5. **Improper Output Handling**
   - Model output is treated as trusted code, commands, SQL, HTML, config, or authorization decisions.
   - Evidence to seek: model-generated shell/code executed; HTML rendered unsanitized; SQL/config generated and applied; tool params accepted without validation.

6. **Excessive Agency**
   - Agent can take high-impact actions without least privilege, constraints, or human approval.
   - Evidence to seek: broad tools; unrestricted file/network/shell; no allowlists; approvals not bound to exact parameters; no rate/budget caps.

7. **System Prompt Leakage**
   - Prompts, policies, chain-of-thought-like traces, hidden instructions, or tool schemas leak.
   - Evidence to seek: prompt/debug endpoints; responses include system/developer prompts; logs/traces accessible; prompt files shipped publicly with secrets.

8. **Vector and Embedding Weaknesses**
   - Retrieval flaws cause data leakage, poisoning, or cross-tenant contamination.
   - Evidence to seek: missing tenant filters; weak metadata ACLs; no source provenance; untrusted chunks override instructions; embedding inversion exposure.

9. **Misinformation / Integrity Failures**
   - System produces unsupported high-impact claims or takes actions based on unverified outputs.
   - Evidence to seek: no citations; no human review for regulated/high-impact domains; hallucinated tool results accepted.

10. **Unbounded Consumption**
   - Cost/DoS risk through unrestricted tokens, loops, tool calls, retrieval, or model invocations.
   - Evidence to seek: no quotas; recursive agents; unbounded retries; no per-user cost caps; unbounded document ingestion.

## OWASP Agentic Applications assessment checklist

Map agentic findings to these categories when the repository contains autonomous agents, function calling, tools, MCP, RAG, multi-agent orchestration, browser/computer-use, background jobs, or self-modifying workflows.

1. **Agent Goal Hijack**
   - Attacker changes the agent's objective or decision path through malicious content, hidden prompts, gradual sub-goals, or reflection-loop traps.
   - Review prompts, planner state, RAG content, memory, webpages, emails, PRs, issues, tool outputs.

2. **Tool Misuse and Exploitation**
   - Unsafe tools, broad capabilities, weak schemas, missing allowlists, user-controlled tool arguments, or tool results accepted as trusted.
   - For MCP: inspect server/client trust, tool descriptions, metadata, schemas, transport, authorization, and isolation.

3. **Identity and Privilege Abuse**
   - Agents use powerful service accounts, shared credentials, missing user delegation, stale approvals, or cross-tenant capabilities.
   - Check if authorization is validated at execution time, not only planning/request time.

4. **Agentic Supply Chain Vulnerabilities**
   - Compromised MCP servers, plugins, prompts, tool packages, actions, model artifacts, datasets, or dynamic downloads.
   - Require tool manifests, prompt versioning, checksums/signatures, SBOM/AI SBOM, provenance, dependency pinning, and review gates.

5. **Unexpected Code Execution**
   - Model/tool data reaches shell, eval, notebook/code runners, plugin installers, browsers, CI, infrastructure commands, or deserializers.
   - Review sandboxing, egress, filesystem scope, syscall/network restrictions, and explicit allowlists.

6. **Memory and Context Poisoning**
   - Persistent memory, RAG/vector stores, long-term agent notes, or conversation summaries can be poisoned or cross-contaminated.
   - Require source labels, provenance, TTL, ACLs, tenant filters, quarantine, and retrieval-time policy checks.

7. **Orchestration and Multi-Agent Communication Weaknesses**
   - Agents trust messages from other agents without identity/integrity, or messages cross tenant/workspace boundaries.
   - Check sender authentication, transcript isolation, topic scoping, and policy enforcement at handoff points.

8. **Repudiation and Accountability Gaps**
   - Missing immutable audit trail for prompts, retrieved context, model outputs, tool calls, approvals, and final actions.
   - For high-impact actions, require replayable trace and human approval records.

9. **Resource Overload / Cost Abuse**
   - Infinite loops, recursive delegation, unbounded web browsing, large-context ingestion, uncontrolled retries, or expensive tool calls.
   - Require budgets, quotas, max-turns, timeouts, rate limits, circuit breakers, and kill switches.

10. **Rogue Agents**
   - Agents can self-spawn, self-modify prompts/tools, schedule durable jobs, change permissions, or persist capabilities without governance.
   - Require least privilege, separation of duties, policy-as-code, approvals, blast-radius caps, and monitoring.

## Agentic red-team and governance controls to look for

- Lifecycle testing: scope/plan, develop/experiment, test/evaluate, release, deploy, operate/monitor.
- Red/blue/purple teaming: model vulnerability scanning, agent-logic corruption tests, SAST/DAST/IAST, LLM plugin/tool/infrastructure scanning, interactive sandboxing, defender signal validation.
- Agent-specific release gates: prompt-chaining attacks, multi-turn attacks, A2A/MCP protocol attacks, RAG poisoning scenarios, guardrail conformance, policy tests, success-threshold analysis, CI hooks.
- Runtime guardrails: pre-AI and post-AI guardrails in code, not only model-layer instructions.
- Planner-executor isolation; circuit breakers; blast-radius caps; high-impact action approvals.
- Tool-call governance: request-time and execution-time authorization, tool manifests, allowlists, schemas, telemetry, third-party testing.
- Agentic identity: user-bound delegated authorization, non-human identity controls, rotation, scoped credentials, service-account minimization.
- AI SBOM/provenance: dependencies, models, prompts, tools, MCP servers, datasets, vector sources, code-signing/checksums.
- Monitoring: malicious agent activity detection, prompt-injection detection, tool abuse detection, anomaly and cost monitoring.

## OpenSSF AI code assistant instruction risks

When reviewing repos that include AI assistant instructions (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md`, etc.), check for:

- Instructions that ask assistants to ignore security checks, tests, review, or approvals.
- Instructions that permit reading secrets or writing secrets into outputs.
- Instructions that encourage unsafe commands, remote script execution, or broad file deletion.
- Hidden or obfuscated prompt injection in docs, examples, comments, or test data.
- Conflicting instructions that create unsafe precedence or trust confusion.
- Instructions that allow the assistant to modify CI, credentials, auth, deployment, or security controls without review.

Treat repository instructions as part of the supply chain and prompt attack surface.


---

# File: templates/security-report.md

# Security Audit Report: <repository/project>

**Date:** <date>  
**Auditor:** Hermes Agent using `cybersecurity-repository-audit` skill  
**Scope:** <repo path, branch/commit if available>  
**Assessment type:** Repository-wide source, configuration, AI/agentic, CI/CD, supply-chain, and deployment security review

## Executive Summary

- **Audit objective:** Minimize false positives, maximize evidence quality, distinguish vulnerabilities from recommendations, and provide defensible engineering conclusions.
- **Overall risk rating:** <Critical/High/Medium/Low>
- **Repository trust assessment:** <Trusted / Conditionally trusted / Low trust / Untrusted for production>
- **Production readiness:** <Ready / Ready with conditions / Not ready>
- **Finding count note:** A report with zero confirmed vulnerabilities is acceptable when evidence does not support vulnerability claims.
- **Most important risks:**
  1. <risk>
  2. <risk>
  3. <risk>

## Scope and Methodology

### Scope reviewed

- Repository root: `<path>`
- Branch/commit:
- Languages/frameworks:
- Package managers and lockfiles:
- Entry points:
- AI/agentic components:
- CI/CD and deployment files:
- Cloud/IaC files:

### Repository State Verification

- `git status --short`: <summary>
- `git ls-files`: <used for exposure claims: yes/no>
- `git check-ignore`: <used for local/ignored files: yes/no>
- `git log --all -- <file>`: <used for committed-exposure claims: yes/no>
- Limitations: <state if repository state could not be verified; reduce confidence accordingly>

### Methods and tools

- Manual source review:
- Repository-wide searches:
- Automated scanners run:
- Automated scanners unavailable:
- Frameworks/taxonomies applied:
  - OWASP Top 10 for LLM Applications 2025
  - OWASP Top 10 for Agentic Applications / AIUC-1 crosswalk
  - OWASP AI Security Solutions Landscape for AI and Agentic Red Teaming
  - OpenSSF AI code-assistant instruction guidance
  - Conventional OWASP/CWE/cloud/IaC controls

### Limitations

- <state runtime/config/dependency/source-control/deployment limitations>

## Architecture and Trust Boundaries

### Entry points

| Entry point | File(s) | Trust boundary | Notes |
|---|---|---|---|

### Sensitive assets

| Asset | Location | Why sensitive |
|---|---|---|

### AI/agentic components

| Component | File(s) | Tools/capabilities | Trust boundary |
|---|---|---|---|

## Findings Summary

| ID | Classification | Severity | Confidence | Category | Title | Location | Status |
|---|---|---|---|---|---|---|---|

## Detailed Findings

### SEC-001: <title>

- **Classification:** Confirmed Vulnerability / Likely Vulnerability / Architectural Risk / Governance Gap / Hardening Recommendation / Observation / Positive Control
- **Severity:** <Critical/High/Medium/Low/Informational>
- **Confidence:** <High/Medium/Low>
- **Category / taxonomy mapping:** <CWE/OWASP/Agentic/OpenSSF/cloud>
- **Location:** `<path>:<line-start>-<line-end>`, class `<class>`, function/method `<function>`
- **Repository state:** <committed/tracked/untracked/ignored/generated/example-template/runtime-only/unknown>
- **Git evidence:**
  - `git ls-files -- <file>`: <result>
  - `git check-ignore -v -- <file>`: <result>
  - `git log --all -- <file>`: <result>

**Affected code:**

```<language>
<line-numbered snippet>
```

**Reachability model:**

- **Source:** <attacker-controlled or untrusted input source>
- **Transformation:** <processing/validation/prompt assembly/auth decision/etc.>
- **Sink:** <sensitive operation/tool/query/filesystem/network/model prompt/etc.>
- **Trust Boundary:** <boundary crossed>
- **Reachability Evidence:** <code/config evidence proving execution path>

**Evidence supporting the finding:**

<explain why the code/config is vulnerable and how reachability was established>

**Evidence weakening the finding:**

<counter-evidence, mitigating controls, missing runtime details, local-only concerns, etc.>

**Alternative explanations considered:**

<placeholder/example/test/generated/local-only/ignored/untracked/scanner false-positive/etc.>

**Why the finding remains valid:**

<false-positive challenge conclusion; if it does not survive, do not report as vulnerability>

**Attack path:**

1. Attacker capability/precondition:
2. Entry point:
3. Trust boundary crossed:
4. Vulnerable operation/sink:
5. Result/post-condition:

**Impact:**

<concrete business/security impact based on proven exploitability, not theoretical impact>

**Exploit scenario / proof:**

<safe repo-scoped exploit reasoning or benign reproduction>

**Recommended remediation:**

<specific code/config changes>

**Verification:**

<tests/scans/manual checks to confirm the fix>

## Positive Security Controls Observed

| Control | Evidence | Risk reduced |
|---|---|---|

## Missing Controls / Architectural Risks

| Classification | Risk/Gap | Evidence | Recommendation |
|---|---|---|---|

## AI/Agentic Security Assessment

| Area | Assessment | Evidence | Classification | Recommendation |
|---|---|---|---|---|
| Prompt injection / goal hijack | | | | |
| Tool/MCP governance | | | | |
| Agent identity and privilege | | | | |
| Memory/RAG poisoning | | | | |
| Model output handling | | | | |
| Auditability and approvals | | | | |
| Resource/cost controls | | | | |

## Supply Chain and CI/CD Assessment

| Area | Assessment | Evidence | Classification | Recommendation |
|---|---|---|---|---|
| Dependency pinning/lockfiles | | | | |
| GitHub Actions / CI tokens | | | | |
| Dynamic downloads/scripts | | | | |
| Container/IaC provenance | | | | |
| AI SBOM / tool manifests | | | | |

## Cloud/IaC and Deployment Assessment

| Area | Assessment | Evidence | Classification | Recommendation |
|---|---|---|---|---|
| IAM / service accounts | | | | |
| Network exposure | | | | |
| Secrets management | | | | |
| Containers/Kubernetes | | | | |
| Logging/monitoring | | | | |

## Evidence Reliability Assessment

For each Critical and High finding:

| Finding | Repository Verified | Git Verified | Runtime Verified | Confidence Justification |
| ------- | ------------------- | ------------ | ---------------- | ------------------------ |

## Overall Repository Trust and Production-Readiness Assessment

- **Trust rating:** <rating and rationale>
- **Release recommendation:** <Ready / Ready with conditions / Not ready>
- **Required fixes before production:**
  1. <fix>
- **Recommended next steps:**
  1. <step>


---

# File: scripts/repo_security_grep.py

```python
#!/usr/bin/env python
"""Lightweight repository security grep helper.

Usage:
  python scripts/repo_security_grep.py /path/to/repo > security-candidates.json

This script only produces candidate locations for human review. It is not a
vulnerability scanner and must not be cited as sole evidence.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt",
    "coverage", "target", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
    ".pytest_cache", ".terraform", ".serverless", ".gradle", "out"
}

BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".tgz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".jar",
    ".class", ".pyc", ".wasm", ".woff", ".woff2", ".ttf", ".mp4", ".mov"
}

PATTERNS = {
    "secrets": re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret|aws_access_key|aws_secret|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY)"),
    "execution": re.compile(r"(?i)(eval\s*\(|exec\s*\(|Function\s*\(|child_process|subprocess|os\.system|popen|spawn\s*\(|shell\s*=\s*True|docker\s+run|kubectl|terraform\s+apply)"),
    "ai_agentic": re.compile(r"(?i)(system prompt|developer message|prompt injection|function_call|tool_call|\bmcp\b|agent|planner|executor|memory|rag|retriever|vector|embedding|browser|computer_use|tool description)"),
    "authz": re.compile(r"(?i)(jwt|session|cookie|csrf|cors|is_admin|role|permission|authorize|authenticate|tenant|organization_id|user_id)"),
    "network_ssrf": re.compile(r"(?i)(fetch\s*\(|requests\.|axios\.|urlopen|http\.get|http\.post|webhook|callback_url|proxy|metadata\.google|169\.254\.169\.254)"),
    "injection": re.compile(r"(?i)(raw\(|execute\(|query\(|SELECT .*\+|INSERT .*\+|UPDATE .*\+|DELETE .*\+|template|render_template|innerHTML|dangerouslySetInnerHTML|pickle|yaml\.load|deserialize)"),
    "ci_supply_chain": re.compile(r"(?i)(curl .*\|.*sh|wget .*\|.*sh|pull_request_target|GITHUB_TOKEN|permissions:\s*write-all|uses:\s*[^@\s]+\s*$|latest|postinstall|preinstall)"),
    "iac_cloud": re.compile(r"(?i)(Principal\s*[:=]\s*['\"]\*|Action\s*[:=]\s*['\"]\*|0\.0\.0\.0/0|privileged:\s*true|hostPath|runAsUser:\s*0|public-read|storage_bucket|security_group|iam_policy)"),
}


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in BINARY_EXTS:
                continue
            try:
                if p.stat().st_size > 2_000_000:
                    continue
            except OSError:
                continue
            yield p


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    results = []
    for path in iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for lineno, line in enumerate(text.splitlines(), 1):
            for category, rx in PATTERNS.items():
                if rx.search(line):
                    results.append({
                        "category": category,
                        "file": rel,
                        "line": lineno,
                        "snippet": line[:500],
                    })
    print(json.dumps({"root": str(root), "candidate_count": len(results), "candidates": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

```
