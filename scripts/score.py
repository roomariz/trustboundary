#!/usr/bin/env python3
"""
score.py — aggregates raw findings from the scan_*.py modules into
(severity, confidence) scored, deduplicated findings, and flags cross-category
correlations. Reads a JSON list of raw finding dicts from stdin or --in file,
writes scored findings.json to stdout or --out file.

Usage:
  cat all_raw_findings.json | python3 score.py > findings.json
  python3 score.py --in raw.json --out findings.json
"""
import sys, json, argparse, itertools

SEVERITY_BY_RULE = {
    # rule -> default severity (can be overridden by corroboration)
    "aws_secret_key_assignment": "Critical",
    "private_key_block": "Critical",
    "aws_access_key_id": "Critical",
    "gcp_api_key": "High",
    "github_token": "High",
    "slack_token": "High",
    "generic_secret_assignment": "High",
    "high_entropy_literal": "Medium",
    "install_time_script": "High",
    "possible_typosquat": "High",
    "internal_name_public_registry_risk": "High",
    "unpinned_version": "Low",
    "unscoped_bash_tool": "Medium",
    "dynamic_context_pre_review_exec": "High",
    "injection_phrase_in_skill": "High",
    "suspicious_mcp_tool_description": "Critical",
    "unpinned_mcp_server_version": "Medium",
    "eval_on_dynamic_input": "High",
    "exec_call": "Medium",
    "shell_true": "High",
    "os_system": "Medium",
    "child_process_exec": "Medium",
    "string_concat_into_shell": "High",
    "debug_enabled_prod": "Low",
    "tls_verify_disabled": "High",
    "wildcard_cors": "Medium",
    "default_credentials": "High",
    "world_writable_perm": "Medium",
    "hardcoded_webhook_url": "Medium",
    "data_in_url_query": "High",
    "suspicious_dns_exfil_shape": "Medium",
    "base64_post_body": "Medium",
    "undeclared_telemetry_beacon": "Low",
}

LOW_CONTEXT_TAGS = ["test", "fixture", "example", "sample", "mock"]

def confidence_bucket(score):
    if score >= 80:
        return "Confirmed"
    if score >= 50:
        return "Likely"
    if score >= 25:
        return "Possible"
    return "Speculative"

def adjust_confidence(finding):
    score = finding.get("base_confidence", 40)
    path = (finding.get("file") or "").lower()
    if any(tag in path for tag in LOW_CONTEXT_TAGS):
        score -= 30
    return max(0, min(100, score))

def correlate(findings):
    """Bump severity when independent risk signals co-occur in the same file."""
    by_file = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)
    correlations = []
    for file, items in by_file.items():
        cats = {f["category"] for f in items}
        if "unsafe_execution" in cats and "data_exfiltration" in cats:
            correlations.append({
                "type": "exec_plus_exfil_chain",
                "file": file,
                "note": "Unsafe execution and outbound data patterns in the same file — "
                        "treat as a compound exfiltration-via-execution risk, not two independent low findings.",
            })
        if "mcp_tool_abuse" in cats and "prompt_injection" in cats:
            correlations.append({
                "type": "tool_abuse_plus_injection",
                "file": file,
                "note": "Tool/MCP config combined with injection-shaped phrasing — possible tool poisoning.",
            })
    return correlations

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", default=None)
    ap.add_argument("--out", dest="outfile", default=None)
    args = ap.parse_args()

    raw = json.load(open(args.infile)) if args.infile else json.load(sys.stdin)

    scored = []
    counter = itertools.count(1)
    for f in raw:
        conf = adjust_confidence(f)
        severity = SEVERITY_BY_RULE.get(f["rule"], "Medium")
        scored.append({
            "id": f"{f['category'].upper()}-{next(counter):04d}",
            "category": f["category"],
            "rule": f["rule"],
            "severity": severity,
            "confidence": conf,
            "confidence_bucket": confidence_bucket(conf),
            "file": f.get("file"),
            "line": f.get("line"),
            "evidence_redacted": f.get("evidence_redacted"),
            "status": "open",
        })

    correlations = correlate(scored)

    output = {"findings": scored, "correlations": correlations}
    text = json.dumps(output, indent=2)
    if args.outfile:
        open(args.outfile, "w").write(text)
    else:
        print(text)

if __name__ == "__main__":
    main()
