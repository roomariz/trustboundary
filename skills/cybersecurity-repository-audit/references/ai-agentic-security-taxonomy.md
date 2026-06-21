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
