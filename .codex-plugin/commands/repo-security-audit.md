---
description: Run the offline repository security audit and review the generated outputs
---

Run `repo-security-audit .` from the current repository root.

This audit is read-only and uses local static checks only. It produces:
- `security-audit-findings.json`
- `SECURITY_AUDIT_REPORT.md`

Read both files before summarising.

Summarise only the scanner findings. Do not invent vulnerabilities, speculate beyond the output, make network calls, or auto-remediate anything.
