#!/usr/bin/env python3
"""
scan_dependencies.py — offline supply-chain heuristics.
Parses manifests/lockfiles for: unpinned versions, install/postinstall scripts,
suspicious package name patterns (typosquat-distance vs a small seed list),
and internal-looking names that might collide with public registries
(dependency-confusion candidates). No network access — registry confirmation
is a separate, human-approved step (see SKILL.md step 3).
"""
import sys, os, json, re

MANIFESTS = ["package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml"]
POPULAR_NPM = ["react", "lodash", "express", "axios", "chalk", "request", "commander"]
POPULAR_PY = ["requests", "numpy", "flask", "django", "boto3", "pandas"]

def levenshtein(a, b):
    if a == b:
        return 0
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, dp[0] = dp[0], i
        for j, cb in enumerate(b, 1):
            cur = dp[j]
            dp[j] = min(dp[j] + 1, dp[j-1] + 1, prev + (ca != cb))
            prev = cur
    return dp[-1]

def typosquat_score(name, seed):
    best = min((levenshtein(name, s) for s in seed), default=99)
    return best  # 1-2 = highly suspicious near-miss; 0 = exact match (not squat)

def scan_package_json(path, findings):
    try:
        data = json.load(open(path))
    except Exception:
        return
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            if version.strip().startswith(("^", "~", "*", "latest")) or version.strip() == "":
                findings.append({
                    "category": "supply_chain", "rule": "unpinned_version",
                    "file": path, "line": None,
                    "evidence_redacted": f"{name}@{version}",
                    "base_confidence": 60,
                })
            d = typosquat_score(name, POPULAR_NPM)
            if 0 < d <= 2:
                findings.append({
                    "category": "supply_chain", "rule": "possible_typosquat",
                    "file": path, "line": None,
                    "evidence_redacted": name,
                    "base_confidence": 45,
                })
            if name.startswith(("@internal", "internal-", "company-")):
                findings.append({
                    "category": "dependency_confusion", "rule": "internal_name_public_registry_risk",
                    "file": path, "line": None,
                    "evidence_redacted": name,
                    "base_confidence": 50,
                })
    for hook in ("scripts",):
        for k, v in data.get(hook, {}).items():
            if k in ("postinstall", "preinstall", "install"):
                findings.append({
                    "category": "malicious_packages", "rule": "install_time_script",
                    "file": path, "line": None,
                    "evidence_redacted": f"{k}: {v}",
                    "base_confidence": 55,
                })

def scan_requirements_txt(path, findings):
    for lineno, line in enumerate(open(path, errors="ignore"), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line and not line.startswith("-"):
            findings.append({
                "category": "supply_chain", "rule": "unpinned_version",
                "file": path, "line": lineno,
                "evidence_redacted": line,
                "base_confidence": 60,
            })
        name = re.split(r"[=<>~!\[]", line)[0].strip()
        d = typosquat_score(name, POPULAR_PY)
        if 0 < d <= 2:
            findings.append({
                "category": "supply_chain", "rule": "possible_typosquat",
                "file": path, "line": lineno,
                "evidence_redacted": name,
                "base_confidence": 45,
            })

def walk(repo_path):
    findings = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "venv", ".venv")]
        for fn in files:
            full = os.path.join(root, fn)
            if fn == "package.json":
                scan_package_json(full, findings)
            elif fn in ("requirements.txt", "requirements-dev.txt"):
                scan_requirements_txt(full, findings)
    return findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
