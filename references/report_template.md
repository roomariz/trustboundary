# Report template — SECURITY_AUDIT_REPORT.md

Render this structure after `score.py` produces `findings.json`. Group findings
by `category`, sort within each group by `severity` desc then `confidence` desc.

```markdown
# Repo Security Audit — {{ repo_name }} — {{ date }}

## Executive Summary
- Total findings: {{ total }} (Critical: {{ c }}, High: {{ h }}, Medium: {{ m }}, Low: {{ l }}, Info: {{ i }})
- Top 3 risks requiring immediate action:
  1. {{ top_finding_1 }}
  2. {{ top_finding_2 }}
  3. {{ top_finding_3 }}
- Overall posture: {{ Critical | Needs Attention | Acceptable | Strong }}
- Network-verification pass: {{ run | skipped (reason) }}

## Findings by Category

### Supply-Chain Risk
| Severity | Confidence | Location | Description |
|---|---|---|---|
{{ rows }}

### Prompt Injection
...

### Dependency Confusion
...

### Malicious Packages
...

### Leaked Secrets
...

### Unsafe Execution
...

### Insecure Config
...

### Data Exfiltration
...

### MCP / Tool Abuse
...

### Recent AI-Agent Attack Patterns
...

## Cross-Category Correlations
{{ for each item in correlations: "- " + note + " (" + file + ")" }}

## Remediation Plan
### Immediate (Critical / High, Confirmed or Likely)
- [ ] {{ finding.id }}: {{ remediation text }} — see proposed patch {{ link }}

### Near-term (Medium)
- [ ] ...

### Hygiene (Low / Info)
- [ ] ...

## Methodology & Limitations
- Modules run: scan_secrets, scan_dependencies, scan_skills_and_mcp, scan_exec_patterns, scan_exfil_patterns
- Network-verified registry checks: {{ status }}
- Known false-positive classes suppressed: {{ list, with reviewer note + expiry if from .audit-allowlist }}
- This is a heuristic static review, not a substitute for a full penetration test
  or dependency SCA tool; treat "Possible"/"Speculative" findings as leads, not facts.
```

Formatting rules:
- Never include unredacted secret values in the report, even ones already found —
  use the `evidence_redacted` field as-is.
- If zero findings in a category, write "No findings in this category" rather
  than omitting the heading — omission reads as "not checked."
- Always state explicitly which checks were *not* run and why (e.g., network
  pass skipped because not approved) — silent gaps undermine trust in the report.
