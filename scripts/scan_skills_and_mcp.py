#!/usr/bin/env python3
"""
scan_skills_and_mcp.py — audits this repo's skill and plugin surfaces for
over-broad allowed-tools, dynamic-context (`!cmd`) directives that bypass
model-level review, prompt-injection phrasing embedded in descriptions, and
untrusted plugin / MCP references.
"""
import sys, os, re, json, fnmatch
from pathlib import Path
from scanner_utils import iter_repo_files, relativise, is_env_file

INJECTION_PHRASES = [
    r"ignore (all )?(previous|prior) instructions",
    r"you are now",
    r"do not (tell|inform|mention) the user",
    r"<important>",
    r"system prompt",
    r"exfiltrate",
    r"send (this|the) (data|secret|key|token) to",
]

BROAD_TOOLS = {"Bash", "WebFetch", "Write", "Execute"}


def warn_parse(path, findings, message, confidence=25):
    findings.append({
        "category": "mcp_tool_abuse",
        "rule": "unparsed_mcp_config",
        "file": path,
        "line": None,
        "evidence_redacted": f"{Path(path).name}: {message}",
        "base_confidence": confidence,
    })


def iter_config_items(value):
    if isinstance(value, dict):
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            yield key, item
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield index, item


def value_to_text(value):
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        return json.dumps(value)
    return None


def scan_config_value(path, findings, label, value):
    text = value_to_text(value)
    if text is None:
        warn_parse(path, findings, f"unsupported item type {type(value).__name__}")
        return
    if isinstance(value, dict) and not value.get("version"):
        findings.append({
            "category": "mcp_tool_abuse", "rule": "unpinned_mcp_server_version",
            "file": path, "line": None,
            "evidence_redacted": str(label),
            "base_confidence": 55,
        })
    for pat in INJECTION_PHRASES:
        if re.search(pat, text, re.IGNORECASE):
            findings.append({
                "category": "mcp_tool_abuse", "rule": "suspicious_mcp_tool_description",
                "file": path, "line": None,
                "evidence_redacted": f"{label}: matched '{pat}'",
                "base_confidence": 80,
            })
    if isinstance(value, dict):
        for child_label, child in iter_config_items(value):
            scan_config_value(path, findings, f"{label}.{child_label}", child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            scan_config_value(path, findings, f"{label}[{index}]", item)

def find_skill_files(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    out = []
    for _, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        if is_env_file(path) and not include_env_files:
            continue
        if path.name == "SKILL.md":
            out.append(str(path))
    return sorted(out)

def find_mcp_configs(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    out = []
    for _, path in iter_repo_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        if is_env_file(path) and not include_env_files:
            continue
        fn = path.name
        root = str(path.parent)
        if fn in ("plugin.json", "package.json") or fnmatch.fnmatch(fn, "mcp*.json") or fn == "mcp.json":
            out.append(str(path))
        if fn.endswith(".toml") and "command" in root.lower():
            out.append(str(path))
    return sorted(set(out))

def scan_skill_md(path, findings):
    text = open(path, errors="ignore").read()
    # over-broad allowed-tools
    m = re.search(r"allowed-tools:\s*(.+)", text)
    if m:
        tools_line = m.group(1)
        broad = [t for t in BROAD_TOOLS if t in tools_line and "(" not in tools_line.split(t)[-1][:3]]
        if "Bash" in tools_line and "Bash(" not in tools_line:
            findings.append({
                "category": "mcp_tool_abuse", "rule": "unscoped_bash_tool",
                "file": path, "line": None,
                "evidence_redacted": tools_line.strip(),
                "base_confidence": 65,
            })
    # dynamic context directives — run before model review (Datadog-documented bypass)
    for lineno, line in enumerate(text.splitlines(), start=1):
        if re.search(r"^\s*!\S", line):
            findings.append({
                "category": "unsafe_execution", "rule": "dynamic_context_pre_review_exec",
                "file": path, "line": lineno,
                "evidence_redacted": line.strip()[:80],
                "base_confidence": 75,
            })
    # injection phrasing inside description/body
    for pat in INJECTION_PHRASES:
        for m2 in re.finditer(pat, text, re.IGNORECASE):
            findings.append({
                "category": "prompt_injection", "rule": "injection_phrase_in_skill",
                "file": path, "line": None,
                "evidence_redacted": m2.group(0),
                "base_confidence": 70,
            })

def scan_mcp_config(path, findings):
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            data = json.load(handle)
    except Exception:
        warn_parse(path, findings, "malformed JSON or unsupported config shape")
        return
    base = os.path.basename(path)
    if base == "package.json":
        if not isinstance(data, dict):
            warn_parse(path, findings, "package.json did not parse as an object")
            return
        if not data.get("pi", {}).get("skills"):
            findings.append({
                "category": "mcp_tool_abuse", "rule": "unscoped_bash_tool",
                "file": path, "line": None,
                "evidence_redacted": "package.json missing explicit skills entry",
                "base_confidence": 50,
            })
        return
    if base == "plugin.json":
        if not isinstance(data, dict):
            warn_parse(path, findings, "plugin.json did not parse as an object")
            return
        interface = data.get("interface", {})
        if not isinstance(interface, dict):
            warn_parse(path, findings, "plugin.json interface was not an object")
            interface = {}
        for field in ("longDescription", "defaultPrompt"):
            value = interface.get(field)
            if isinstance(value, list):
                value = "\n".join(value)
            if isinstance(value, str):
                for pat in INJECTION_PHRASES:
                    if re.search(pat, value, re.IGNORECASE):
                        findings.append({
                            "category": "prompt_injection", "rule": "injection_phrase_in_skill",
                            "file": path, "line": None,
                            "evidence_redacted": f"interface.{field}",
                            "base_confidence": 70,
                        })
        return
    if isinstance(data, dict):
        servers = data.get("mcpServers", data.get("servers", {}))
    elif isinstance(data, list):
        servers = data
    else:
        warn_parse(path, findings, f"unsupported top-level type {type(data).__name__}")
        return

    if isinstance(servers, dict):
        items = iter_config_items(servers)
    elif isinstance(servers, list):
        items = ((f"[{index}]", item) for index, item in enumerate(servers))
    else:
        warn_parse(path, findings, f"unsupported servers type {type(servers).__name__}")
        return

    for name, cfg in items:
        scan_config_value(path, findings, str(name), cfg)

def walk(repo_path, include_tests: bool = False, include_dependencies: bool = False, include_env_files: bool = False, progress_callback=None, ignore_patterns=()):
    findings = []
    for skill_file in find_skill_files(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, include_env_files=include_env_files, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        scan_skill_md(skill_file, findings)
    for mcp_file in find_mcp_configs(repo_path, include_tests=include_tests, include_dependencies=include_dependencies, include_env_files=include_env_files, progress_callback=progress_callback, ignore_patterns=ignore_patterns):
        scan_mcp_config(mcp_file, findings)
    repo_root = Path(repo_path).resolve()
    for finding in findings:
        finding["file"] = relativise(repo_root, Path(finding["file"]))
    return findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
