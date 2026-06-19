from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "coverage",
    ".next",
    "out",
    "target",
    "vendor",
    "site-packages",
    ".venv-windows",
}
DEFAULT_IGNORE_FILES = {".trustboundaryignore", ".gitignore"}
TEST_DIR_NAMES = {"test", "tests", "__tests__", "spec", "specs"}
DEPENDENCY_DIR_NAMES = {"node_modules", "site-packages", "vendor"}
DOCUMENTATION_DIR_NAMES = {"doc", "docs", "documentation"}
GENERATED_DIR_NAMES = {"gen", "generated", "generated-code", "generated_files", "autogen", "auto-generated"}
DOCUMENTATION_FILE_PREFIXES = ("readme", "changelog", "contributing", "license", "docs", "guide")
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".woff", ".woff2", ".ttf", ".otf", ".ico", ".exe", ".dll", ".so"}
MAX_FILE_SIZE = 1024 * 1024
TEXT_SUFFIXES = {".py", ".js", ".ts", ".sh", ".yml", ".yaml", ".json", ".toml", ".md", ".txt", ".ini", ".cfg", ".conf"}
ENV_FILE_NAMES = {".env", ".env.local", ".env.development", ".env.production", ".env.test", ".env.sample", ".env.example"}
LOCKFILE_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Gemfile.lock",
    "composer.lock",
    "Cargo.lock",
    "Pipfile.lock",
    "poetry.lock",
    "go.sum",
}


def is_env_file(path: Path) -> bool:
    return path.name in ENV_FILE_NAMES or path.name.startswith(".env.")


def is_test_path(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return any(name in parts for name in TEST_DIR_NAMES) or any(part.endswith((".test", ".spec")) for part in path.parts)


def is_dependency_path(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return any(part in DEPENDENCY_DIR_NAMES for part in parts)


def is_generated_path(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    if any(part in GENERATED_DIR_NAMES for part in parts):
        return True
    name = path.name.lower()
    return name.endswith(".generated") or ".generated." in name or name.endswith(".gen.py") or name.endswith(".gen.js") or name.endswith(".gen.ts")


def is_documentation_path(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    if any(part in DOCUMENTATION_DIR_NAMES for part in parts):
        return True
    name = path.name.lower()
    return name.startswith(DOCUMENTATION_FILE_PREFIXES) or name.endswith((".md", ".rst", ".txt", ".adoc"))


def path_scope_tags(path: Path, config: ScanConfig | None = None) -> tuple[str, ...]:
    tags: list[str] = []
    if is_test_path(path):
        tags.append("test")
    if is_dependency_path(path):
        tags.append("dependency")
    if is_generated_path(path):
        tags.append("generated")
    if is_documentation_path(path):
        tags.append("documentation")
    if config and config.scope_rules:
        rel = path.as_posix()
        for scope_name, patterns in config.scope_rules.items():
            if any(Path(rel).match(pattern) or path.name == pattern for pattern in patterns):
                tags.append(scope_name)
    if not tags:
        tags.append("production")
    return tuple(tags)


def is_lockfile(path: Path) -> bool:
    return path.name in LOCKFILE_NAMES


@dataclass(frozen=True)
class ScanConfig:
    enabled_scanners: tuple[str, ...] = ()
    severity_thresholds: dict[str, str] = field(default_factory=dict)
    exclusions: tuple[str, ...] = ()
    ignore_patterns: tuple[str, ...] = ()
    scope_rules: dict[str, tuple[str, ...]] = field(default_factory=dict)
    suppressions: tuple[dict[str, Any], ...] = ()
    risk_acceptance: tuple[dict[str, Any], ...] = ()
    report_options: dict[str, Any] = field(default_factory=dict)


def _coerce_scalar(value: str):
    raw = value.strip()
    if not raw:
        return ""
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if raw.isdigit():
        return int(raw)
    try:
        return json.loads(raw)
    except Exception:
        return raw.strip("'\"")


def _strip_yaml_comment(line: str) -> str:
    in_quote = None
    out = []
    for char in line:
        if char in {"'", '"'}:
            in_quote = None if in_quote == char else char
        if char == "#" and in_quote is None:
            break
        out.append(char)
    return "".join(out).rstrip()


def load_trustboundary_config(repo_path: Path) -> ScanConfig:
    config_path = repo_path / "trustboundary.yml"
    if not config_path.exists():
        return ScanConfig()
    text = config_path.read_text(encoding="utf-8", errors="ignore")
    data: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[Any] | None = None
    current_scope: str | None = None
    current_item: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = _strip_yaml_comment(raw_line.rstrip())
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if stripped.startswith("- ") and current_list is not None:
            value = stripped[2:]
            if current_key in {"suppressions", "risk_acceptance"}:
                current_item = {}
                current_list.append(current_item)
                if value and ":" in value:
                    key, item_value = value.split(":", 1)
                    current_item[key.strip()] = _coerce_scalar(item_value)
                continue
            current_list.append(_coerce_scalar(value))
            continue
        if indent == 0 and stripped.endswith(":"):
            current_key = stripped[:-1]
            current_scope = None
            current_item = None
            if current_key in {"exclusions", "ignore", "enabled_scanners", "suppressions", "risk_acceptance"}:
                current_list = []
                data[current_key] = current_list
            elif current_key in {"scope", "scopes", "classify"}:
                data.setdefault("scope_rules", {})
                current_list = None
            else:
                current_list = None
            continue
        if current_key in {"scope", "scopes", "classify"}:
            if indent == 2 and stripped.endswith(":"):
                current_scope = stripped[:-1]
                data.setdefault("scope_rules", {}).setdefault(current_scope, [])
                continue
            if current_scope and indent >= 4 and stripped.startswith("- "):
                data.setdefault("scope_rules", {}).setdefault(current_scope, []).append(_coerce_scalar(stripped[2:]))
                continue
        if current_key in {"suppressions", "risk_acceptance"} and current_item is not None and ":" in line and indent >= 2:
            key, value = line.split(":", 1)
            current_item[key.strip()] = _coerce_scalar(value)
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            current_key = key
            current_scope = None
            current_item = None
            if not value:
                current_list = []
                data[key] = current_list
            else:
                data[key] = _coerce_scalar(value)
                current_list = data[key] if isinstance(data[key], list) else None
    exclusions = tuple(str(item) for item in data.get("exclusions", []) if str(item))
    ignore_patterns = tuple(str(item) for item in data.get("ignore", []) if str(item))
    suppressions = tuple(item for item in data.get("suppressions", []) if isinstance(item, dict))
    risk_acceptance = tuple(item for item in data.get("risk_acceptance", []) if isinstance(item, dict))
    enabled_scanners = tuple(str(item) for item in data.get("enabled_scanners", []) if str(item))
    severity_thresholds = data.get("severity_thresholds", {})
    report_options = data.get("report_options", {})
    scope_rules_raw = data.get("scope_rules", {})
    scope_rules: dict[str, tuple[str, ...]] = {}
    if isinstance(scope_rules_raw, dict):
        for key, value in scope_rules_raw.items():
            if isinstance(value, list):
                scope_rules[str(key)] = tuple(str(item) for item in value if str(item))
    if not isinstance(severity_thresholds, dict):
        severity_thresholds = {}
    if not isinstance(report_options, dict):
        report_options = {}
    return ScanConfig(
        enabled_scanners=enabled_scanners,
        severity_thresholds=severity_thresholds,
        exclusions=exclusions,
        ignore_patterns=ignore_patterns,
        scope_rules=scope_rules,
        suppressions=suppressions,
        risk_acceptance=risk_acceptance,
        report_options=report_options,
    )


def load_ignore_patterns(repo_path: Path) -> tuple[str, ...]:
    patterns: list[str] = []
    for name in sorted(DEFAULT_IGNORE_FILES):
        path = repo_path / name
        if not path.exists():
            continue
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line.rstrip("/"))
    return tuple(patterns)


def is_excluded_by_patterns(path: Path, repo_root: Path, patterns: tuple[str, ...]) -> bool:
    rel = path.resolve().relative_to(repo_root.resolve()).as_posix()
    parts = set(Path(rel).parts)
    for pattern in patterns:
        if pattern in parts or rel.startswith(pattern.rstrip("/") + "/") or Path(rel).match(pattern):
            return True
    return False


def iter_repo_files(repo_path, include_tests: bool = False, include_dependencies: bool = False, progress_callback=None, ignore_patterns: tuple[str, ...] = (), extra_skip_dirs: set[str] | None = None):
    repo_root = Path(repo_path).resolve()
    if not ignore_patterns:
        config = load_trustboundary_config(repo_root)
        merged_patterns: list[str] = []
        seen_patterns: set[str] = set()
        for pattern in (*load_ignore_patterns(repo_root), *config.exclusions, *config.ignore_patterns):
            if pattern and pattern not in seen_patterns:
                merged_patterns.append(pattern)
                seen_patterns.add(pattern)
        ignore_patterns = tuple(merged_patterns)
    skip_dirs = set(DEFAULT_SKIP_DIRS)
    if extra_skip_dirs:
        skip_dirs |= set(extra_skip_dirs)
    checked = 0
    for root, dirs, files in os.walk(repo_root, followlinks=False):
        root_path = Path(root)
        dirs[:] = sorted([
            d
            for d in dirs
            if (
                d not in skip_dirs
                or (include_dependencies and d in {"node_modules", "vendor", "site-packages"})
            )
            and not (root_path / d).is_symlink()
        ])
        for name in sorted(files):
            path = root_path / name
            if path.is_symlink():
                continue
            if ignore_patterns and is_excluded_by_patterns(path, repo_root, ignore_patterns):
                continue
            if not include_tests and is_test_path(path):
                continue
            if not include_dependencies and is_dependency_path(path):
                continue
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            checked += 1
            if progress_callback is not None:
                progress_callback(checked, path)
            yield repo_root, path


def relativise(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def is_text_scan_target(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES
