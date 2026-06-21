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
