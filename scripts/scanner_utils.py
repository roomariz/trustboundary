from __future__ import annotations

import os
from pathlib import Path


SKIP_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", "coverage"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".woff", ".woff2", ".ttf", ".otf", ".ico", ".exe", ".dll", ".so"}
MAX_FILE_SIZE = 1024 * 1024
TEXT_SUFFIXES = {".py", ".js", ".ts", ".sh", ".yml", ".yaml", ".json", ".toml", ".md", ".txt", ".ini", ".cfg", ".conf"}


def iter_repo_files(repo_path):
    repo_root = Path(repo_path).resolve()
    for root, dirs, files in os.walk(repo_root, followlinks=False):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (root_path / d).is_symlink()]
        for name in files:
            path = root_path / name
            if path.is_symlink():
                continue
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield repo_root, path


def relativise(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def is_text_scan_target(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES
