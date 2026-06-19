# Trustboundary

This bundle packages the `trustboundary` skill so it can be installed and used in Codex like other skill plugins.

## Contents

- `skills/trustboundary/SKILL.md`
- `scripts/`
- `references/`
- `.codex-plugin/plugin.json`
- `package.json`

## Install

Add this repository as a Codex plugin source, then install the plugin from Codex's plugin UI or CLI if available in your setup.

## Use

Invoke the skill by its name:

- `trustboundary`

Or use the slash command form if your Codex setup exposes skill commands that way:

- `/trustboundary`

Command-style aliases included in this bundle:

- `.codex-plugin/commands/trustboundary.toml`
- `.opencode/command/trustboundary.md`

## Notes

This skill is designed for read-only security audits of repositories, skills, and plugin/MCP configuration. It does not auto-remediate findings.
