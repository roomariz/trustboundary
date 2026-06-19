# Trustboundary

This bundle packages the `repo-security-audit` skill so it can be installed and used in Codex like other skill plugins.

## Contents

- `skills/repo-security-audit/SKILL.md`
- `scripts/`
- `references/`
- `.codex-plugin/plugin.json`
- `package.json`

## Install

Add this repository as a Codex plugin source, then install the plugin from Codex's plugin UI or CLI if available in your setup.

## Use

Invoke the skill by its name:

- `repo-security-audit`

Or use the slash command form if your Codex setup exposes skill commands that way:

- `/repo-security-audit`

Command-style aliases included in this bundle:

- `.codex-plugin/commands/repo-security-audit.toml`
- `.opencode/command/repo-security-audit.md`

## Notes

This skill is designed for read-only security audits of repositories, skills, and plugin/MCP configuration. It does not auto-remediate findings.
