#!/usr/bin/env python3
"""
validate_plugin.py - lightweight release-readiness checks for the plugin bundle.

This script stays read-only except for temporary audit outputs created during the
fixture run. It does not make network calls or modify the repository under test.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_COMMAND_FILES = [
    ROOT / "commands" / "repo-security-audit.md",
    ROOT / ".opencode" / "command" / "repo-security-audit.md",
    ROOT / ".codex-plugin" / "commands" / "repo-security-audit.md",
]
REQUIRED_PACKAGE_FILES = [
    "bin",
    "scripts",
    "commands",
    ".opencode",
    ".codex-plugin",
    "skills",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
]


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    package_path = ROOT / "package.json"
    if not package_path.exists():
        return fail("package.json is missing")

    try:
        package_data = json.loads(package_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return fail(f"package.json could not be parsed: {exc}")

    if package_data.get("bin", {}).get("repo-security-audit") != "bin/repo-security-audit.js":
        return fail("package.json is missing the repo-security-audit bin entry")
    if not package_data.get("name") or not package_data.get("version") or "bin" not in package_data or "files" not in package_data:
        return fail("package.json must include name, version, bin, and files")

    files = set(package_data.get("files") or [])
    missing_package_files = [entry for entry in REQUIRED_PACKAGE_FILES if entry not in files]
    if missing_package_files:
        return fail("package.json files is missing: " + ", ".join(missing_package_files))

    run_audit = ROOT / "scripts" / "run_audit.py"
    if not run_audit.exists():
        return fail("scripts/run_audit.py is missing")

    wrapper = ROOT / "bin" / "repo-security-audit.js"
    if not wrapper.exists():
        return fail("bin/repo-security-audit.js is missing")

    for command_file in REQUIRED_COMMAND_FILES:
        if not command_file.exists():
            return fail(f"Missing command file: {command_file.relative_to(ROOT).as_posix()}")

    skill_file = ROOT / "skills" / "repo-security-audit" / "SKILL.md"
    if not skill_file.exists():
        return fail("skills/repo-security-audit/SKILL.md is missing")

    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        return fail("CHANGELOG.md is missing")

    license_file = ROOT / "LICENSE"
    if not license_file.exists():
        return fail("LICENSE is missing")

    readme = ROOT / "README.md"
    if not readme.exists():
        return fail("README.md is missing")

    readme_text = readme.read_text(encoding="utf-8")
    if "repo-security-audit /path/to/repo" not in readme_text:
        return fail("README.md does not document CLI usage")
    if "Python 3 is required" not in readme_text:
        return fail("README.md does not document the Python 3 requirement")
    if "Node wrapper which locates Python automatically" not in readme_text:
        return fail("README.md does not document the Windows npm wrapper note")
    if "security-audit-findings.json" not in readme_text or "SECURITY_AUDIT_REPORT.md" not in readme_text:
        return fail("README.md does not document the generated outputs")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        fixture_repo = tmp / "fixture"
        fixture_repo.mkdir()
        (fixture_repo / "app.py").write_text('EXAMPLE_VALUE = "sample-data"\n', encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(run_audit), str(fixture_repo)],
            cwd=tmp,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            return fail(f"run_audit.py failed during validation: {result.stderr.strip() or result.stdout.strip()}")

        findings = tmp / "security-audit-findings.json"
        report = tmp / "SECURITY_AUDIT_REPORT.md"
        if not findings.exists() or not report.exists():
            return fail("Audit outputs were not created during validation")

    print("Plugin validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
