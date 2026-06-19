# Finding Category → OWASP Reference Mapping

Use these tags in `findings.json` (`owasp_refs`) and in ticket/issue filing so
findings are traceable to an established taxonomy.

| Audit category | OWASP Top 10 for Agentic Applications (ASI) 2026 | OWASP MCP Top 10 (where applicable) |
|---|---|---|
| supply_chain | ASI04 — Agentic Supply Chain Compromise | MCP supply chain (typosquatting / dependency confusion / compromised maintainer) |
| prompt_injection | ASI01 — Agent Goal Hijack | MCP — Tool Poisoning (descriptor-level injection) |
| dependency_confusion | ASI04 — Agentic Supply Chain Compromise | MCP supply chain |
| malicious_packages | ASI04 — Agentic Supply Chain Compromise; ASI05 — Unexpected Code Execution | MCP supply chain |
| leaked_secrets | ASI03 — Agent Identity & Privilege Abuse | n/a (classic secrets hygiene, amplified by agent's broader file/credential access) |
| unsafe_execution | ASI05 — Unexpected Code Execution | MCP — Command/Injection equivalent ("Clinejection"-style) |
| insecure_config | ASI03 — Agent Identity & Privilege Abuse | n/a |
| data_exfiltration | ASI06 — Memory & Context Poisoning (when via poisoned RAG/memory); general data-handling risk otherwise | MCP — uncontrolled tool output / undeclared egress |
| mcp_tool_abuse | ASI02 — Tool Misuse & Exploitation | MCP — Tool Poisoning, Tool Shadowing, Rug Pulls, Shadow MCP Servers |
| recent_attack_patterns | Cross-cutting — see specific ASI ID noted per matched rule | Cross-cutting |

Keep this file versioned and update it whenever OWASP revises the ASI or MCP
Top 10 lists — the mapping, not the underlying detection logic, is what should
need the most frequent updates as the threat landscape shifts.
