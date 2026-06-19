#!/usr/bin/env python3
"""
scan_skills_and_mcp.py — audits this repo's skill and plugin surfaces for
over-broad allowed-tools, dynamic-context (`!cmd`) directives that bypass
model-level review, prompt-injection phrasing embedded in descriptions, and
untrusted plugin / MCP references.
"""
import sys, os, re, json, fnmatch

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

def find_skill_files(repo_path):
    out = []
    for root, dirs, files in os.walk(repo_path):
        if ".git" in root:
            continue
        for fn in files:
            if fn == "SKILL.md":
                out.append(os.path.join(root, fn))
    return out

def find_mcp_configs(repo_path):
    out = []
    for root, dirs, files in os.walk(repo_path):
        if ".git" in root:
            continue
        for fn in files:
            if fn in ("plugin.json", "package.json") or fnmatch.fnmatch(fn, "mcp*.json") or fn == "mcp.json":
                out.append(os.path.join(root, fn))
            if fn.endswith(".toml") and "command" in root.lower():
                out.append(os.path.join(root, fn))
    return out

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
        data = json.load(open(path))
    except Exception:
        return
    base = os.path.basename(path)
    if base == "package.json":
        if not data.get("pi", {}).get("skills"):
            findings.append({
                "category": "mcp_tool_abuse", "rule": "unscoped_bash_tool",
                "file": path, "line": None,
                "evidence_redacted": "package.json missing explicit skills entry",
                "base_confidence": 50,
            })
        return
    if base == "plugin.json":
        interface = data.get("interface", {})
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
    servers = data.get("mcpServers", data.get("servers", {}))
    for name, cfg in (servers or {}).items():
        if isinstance(cfg, dict) and not cfg.get("version"):
            findings.append({
                "category": "mcp_tool_abuse", "rule": "unpinned_mcp_server_version",
                "file": path, "line": None,
                "evidence_redacted": name,
                "base_confidence": 55,
            })
        desc = json.dumps(cfg)
        for pat in INJECTION_PHRASES:
            if re.search(pat, desc, re.IGNORECASE):
                findings.append({
                    "category": "mcp_tool_abuse", "rule": "suspicious_mcp_tool_description",
                    "file": path, "line": None,
                    "evidence_redacted": f"{name}: matched '{pat}'",
                    "base_confidence": 80,
                })

def walk(repo_path):
    findings = []
    for skill_file in find_skill_files(repo_path):
        scan_skill_md(skill_file, findings)
    for mcp_file in find_mcp_configs(repo_path):
        scan_mcp_config(mcp_file, findings)
    return findings

if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(walk(repo_path), indent=2))
