"""Generates severity-classified JSON and Markdown reports from aggregated findings."""

import json
import os
from datetime import datetime

_SEVERITY_EMOJI = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "🟢 Low",
}

_CATEGORY_LABEL = {
    "jailbreak": "Jailbreak",
    "prompt_injection": "Prompt Injection",
    "system_prompt_leakage": "System Prompt Leakage",
    "data_leakage": "Data Leakage",
    "indirect_injection": "Indirect Injection",
    "toxicity": "Toxicity",
}


def generate_report(aggregated):
    """Write findings/<timestamp>.json and reports/report_<timestamp>.md.

    Returns {"json": "<path>", "md": "<path>"}.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    os.makedirs("findings", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    json_path = f"findings/scan_{timestamp}.json"
    md_path = f"reports/report_{timestamp}.md"

    with open(json_path, "w") as fh:
        json.dump(aggregated, fh, indent=2)

    meta = aggregated["meta"]
    findings = aggregated["findings"]

    lines = []
    lines.append("# LLM Security Scan Report")
    lines.append(f"**Scan Date:** {scan_dt}")
    lines.append(f"**Total Findings:** {meta['total']}")
    lines.append("")
    lines.append("## Severity Summary")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for key in ("critical", "high", "medium", "low"):
        lines.append(f"| {_SEVERITY_EMOJI[key]} | {meta[key]} |")
    lines.append("")
    lines.append("## Category Breakdown")
    lines.append("| Category | Count |")
    lines.append("|----------|-------|")
    for cat_key, cat_label in _CATEGORY_LABEL.items():
        lines.append(f"| {cat_label} | {meta['categories'].get(cat_key, 0)} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    for f in findings:
        sev = f.get("severity", "low").upper()
        cat_label = _CATEGORY_LABEL.get(f.get("category", ""), f.get("category", ""))
        source = f.get("source", "")
        fid = (f.get("id") or "")[:8]
        prompt = f.get("prompt") or ""
        response = f.get("response") or ""
        if len(response) > 300:
            response = response[:300] + "…"
        rationale = f.get("rationale") or ""

        lines.append(f"### [{sev}] {cat_label} — {source} ({fid})")
        lines.append("**Prompt:**")
        lines.append("")
        lines.append(prompt)
        lines.append("")
        lines.append("**Response:**")
        lines.append("")
        lines.append(response)
        lines.append("")
        lines.append(f"**Rationale:** {rationale}")
        lines.append("")
        lines.append("---")
        lines.append("")

    with open(md_path, "w") as fh:
        fh.write("\n".join(lines))

    return {"json": json_path, "md": md_path}


def write_json_report(findings, output_path):
    with open(output_path, "w") as fh:
        json.dump(findings, fh, indent=2)


def write_markdown_report(findings, output_path):
    result = generate_report(findings)
    os.rename(result["md"], output_path)
