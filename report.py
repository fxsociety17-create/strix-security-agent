"""
report.py
Generate a Markdown report from a storage-exported report.
"""
import json
from datetime import datetime


def generate_markdown(report):
    lines = []
    lines.append(f"# Assessment Report for {report['target']}")
    lines.append(f"Run ID: {report['run_id']}")
    lines.append(f"Generated: {datetime.utcnow().isoformat()} UTC")
    lines.append("\n## Executive Summary\n")
    confirmed = [f for f in report["findings"] if f["confirmed"]]
    unconfirmed = [f for f in report["findings"] if not f["confirmed"]]
    lines.append(f"- Confirmed findings: {len(confirmed)}")
    lines.append(f"- Unconfirmed hypotheses: {len(unconfirmed)}\n")
    if confirmed:
        lines.append("## Confirmed Vulnerabilities\n")
        for f in confirmed:
            lines.append(f"### {f['title']} — Severity: {f['severity']}\n")
            lines.append(f"{f['description']}\n")
            lines.append("Evidence (sanitized):")
            lines.append("```json")
            lines.append(json.dumps(f["evidence"], indent=2)[:4000])
            lines.append("```\n")
    if unconfirmed:
        lines.append("## Unconfirmed Hypotheses / Observations\n")
        for f in unconfirmed:
            lines.append(f"### {f['title']} — Severity (est.): {f['severity']}\n")
            lines.append(f"{f['description']}\n")
    lines.append("## Logs & Artifacts\n")
    for l in report.get("logs", [])[:50]:
        lines.append(f"- {l['kind']} @ {l['created_at']}")
    return "\n".join(lines)
