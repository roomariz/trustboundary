# Changelog

## 2.0.0 - v2 Baseline Release

- Added the Production Security Gate and report decision flow.
- Added the Windows npm wrapper for smoother local installs.
- Tightened scan scope exclusions for repos, dependencies, and generated paths.
- Added visual CLI status output for progress, warnings, and release decisions.
- Expanded the confidence and evidence engine for deduped, evidence-rich findings.
- Deduplicated repeated findings into aggregated records with occurrence tracking.
- Added the Top Risks section for the most important review items.
- Added the Trust-Boundary Assessment summary for cross-boundary risk paths.
- Fixed production gate wording so review findings and true blockers are reported distinctly.

## 1.0.0 - Initial release

- Added the `repo-security-audit` CLI entry point.
- Added offline scanners, scoring, and report generation.
- Added Codex and OpenCode command wiring.
- Added release-readiness validation and tests.
