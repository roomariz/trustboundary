---
description: Audit the whole repo for security issues, not over-engineering
---

Audit the entire repository for security risks only, not a diff. One line per finding, ranked by severity first. Call out secrets, dependency confusion, malicious packages, unsafe execution, exfiltration, prompt injection, insecure config, and MCP/tool abuse. End with a short remediation list. If nothing is found: `No security findings. Ship.`
