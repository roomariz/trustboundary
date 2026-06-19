# Repo Security Audit Plugin

This bundle packages the `repo-security-audit` skill so it can be installed and used in Codex like other skill plugins.

## Contents

- `skills/repo-security-audit/SKILL.md`
- `.codex-plugin/plugin.json`
- `package.json`

## Install

Add this repository as a Codex plugin source, then install the plugin from Codex's plugin UI or CLI if available in your setup.

## Use

Invoke the skill by its name:

- `repo-security-audit`

Or use the slash command form if your Codex setup exposes skill commands that way:

- `/repo-security-audit`

## Notes

This skill is designed for read-only security audits of repositories, skills, and MCP configuration. It does not auto-remediate findings.
