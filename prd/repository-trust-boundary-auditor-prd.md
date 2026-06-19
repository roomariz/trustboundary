# PRD: Repository Trust Boundary Auditor

## Problem Statement

Developers increasingly build software using AI-generated code, open-source repositories, Model Context Protocol (MCP) servers, plugins, skills, automation frameworks and third-party dependencies.

Existing workflows often rely on manual review, README inspection, or trust assumptions before code is executed, merged, deployed or incorporated into production systems.

Traditional static application security testing tools focus on vulnerability detection, compliance and secure coding practices. They generally do not answer the developer's primary trust question:

"Can this code compromise my machine, my credentials, my repository, my users, my infrastructure or my production environment?"

Developers need a fast, local, read-only mechanism that identifies trust-boundary violations, malicious behaviours, AI-specific attack surfaces and production-readiness concerns before code reaches production.

## Solution

Provide a CLI-backed repository auditing plugin that performs local, read-only trust-boundary analysis against a target repository.

The system analyses the repository and generates structured findings, trust-boundary assessments and production-readiness recommendations.

The output helps developers determine:

* Whether a repository can be trusted.
* Whether code contains dangerous execution pathways.
* Whether prompt-injection vulnerabilities exist.
* Whether secrets may be exposed.
* Whether AI agents can be abused.
* Whether tenant boundaries are protected.
* Whether the repository is ready for production deployment.

The system generates:

* security-audit-findings.json
* SECURITY_AUDIT_REPORT.md

The scanner remains local, deterministic and read-only.

## User Stories

1. As a developer, I want to scan a repository before running it so that I can identify potentially malicious behaviour.
2. As a developer, I want to understand the trust boundaries of a repository so that I can make an informed trust decision.
3. As a developer, I want to identify dangerous shell execution patterns so that I can prevent command execution abuse.
4. As a developer, I want to identify use of eval and exec so that I can reduce code execution risk.
5. As a developer, I want to identify secret exposure risks so that credentials are not leaked.
6. As a developer, I want to identify exfiltration patterns so that sensitive data cannot be transmitted externally.
7. As a developer, I want to identify suspicious dependency usage so that supply-chain attacks can be reduced.
8. As a developer, I want to understand repository filesystem access so that I can assess operational risk.
9. As a developer, I want to understand repository network access so that I can assess data exposure risk.
10. As a developer, I want to identify prompt-injection vulnerabilities so that AI systems cannot be manipulated.
11. As a developer, I want to identify unsafe agent-tool integrations so that tool abuse cannot occur.
12. As a developer, I want to identify unrestricted filesystem tools so that agent boundaries remain controlled.
13. As a developer, I want to identify unrestricted shell tools so that arbitrary execution risks are visible.
14. As a developer, I want to identify MCP trust-boundary violations so that unsafe integrations can be reviewed.
15. As a developer, I want to identify retrieval-layer weaknesses so that cross-tenant access cannot occur.
16. As a developer, I want to identify missing authorisation controls so that privilege escalation risks are reduced.
17. As a developer, I want production-readiness guidance so that deployments can be blocked when necessary.
18. As a developer, I want prioritised remediation guidance so that critical issues are fixed first.
19. As a developer, I want machine-readable findings so that results can be integrated into automation.
20. As a developer, I want human-readable reports so that findings can be reviewed quickly.
21. As a developer, I want the scanner to remain read-only so that audited repositories are never modified.
22. As a developer, I want the scanner to operate locally so that source code does not leave my environment.

## Implementation Decisions

* The product remains a local CLI-first audit system.
* All scanning is performed locally without network access.
* Repository modification is prohibited.
* Findings are generated from scanner evidence only.
* Trust-boundary analysis becomes a first-class reporting domain.
* Production-readiness assessment becomes a first-class reporting domain.
* Findings are grouped into categories including:

  * Secrets
  * Dependency Risk
  * Execution Risk
  * Exfiltration Risk
  * Agent Security
  * MCP Security
  * Prompt Injection
  * Authentication
  * Authorisation
  * Multi-Tenant Isolation
  * Production Readiness
* A repository trust profile is generated summarising:

  * Filesystem access
  * Network access
  * Credential access
  * Code execution capabilities
  * External communication pathways
* Findings must include:

  * Category
  * Severity
  * Confidence
  * Location
  * Impact
  * Recommendation
* Release decisions are derived from aggregated findings:

  * Ready for Production
  * Review Required
  * Not Ready for Production

## Testing Decisions

* Tests validate observable behaviour only.
* Tests do not inspect implementation details.
* Tests verify scanner outputs rather than internal scanner logic.
* Tests verify:

  * JSON report generation
  * Markdown report generation
  * CLI execution
  * Plugin command availability
  * Validation script execution
  * Trust-boundary report generation
  * Prompt-injection detection rules
  * Dangerous execution detection rules
  * MCP and agent security findings
* Fixture repositories should simulate realistic attack patterns while remaining safe.

## Out of Scope

* Dynamic application testing.
* Penetration testing.
* Runtime exploitation.
* Network scanning.
* Vulnerability database enrichment.
* Automatic code modification.
* Automatic remediation.
* Automatic pull-request generation.
* Cloud-hosted scanning services.
* Security guarantees or certification.

## Further Notes

The product is positioned as a trust-boundary and production-readiness reviewer for developers rather than a generic static analysis tool.

Its primary purpose is helping developers evaluate whether repositories, AI-generated code, MCP servers, skills, plugins and applications are safe to trust, execute and deploy.
