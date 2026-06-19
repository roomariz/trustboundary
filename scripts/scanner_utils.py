from __future__ import annotations

import os
from pathlib import Path


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
TEST_DIR_NAMES = {"test", "tests", "__tests__", "spec", "specs"}
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
    return any(part in {"node_modules", "site-packages", "vendor"} for part in parts)


def is_lockfile(path: Path) -> bool:
    return path.name in LOCKFILE_NAMES


def iter_repo_files(repo_path, include_tests: bool = False, include_dependencies: bool = False, progress_callback=None):
    repo_root = Path(repo_path).resolve()
    checked = 0
    for root, dirs, files in os.walk(repo_root, followlinks=False):
        root_path = Path(root)
        dirs[:] = [
            d
            for d in dirs
            if (
                d not in DEFAULT_SKIP_DIRS
                or (include_dependencies and d in {"node_modules", "vendor", "site-packages"})
            )
            and not (root_path / d).is_symlink()
        ]
        for name in files:
            path = root_path / name
            if path.is_symlink():
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
