"""Markdown report exporter."""

from __future__ import annotations

from pathlib import Path

from vulnscope.domain.models import Scan
from vulnscope.utils.files import ensure_dir
from vulnscope.utils.text import redact_secrets


def export_markdown(scan: Scan, path: str | Path) -> Path:
    """Export scan as a readable Markdown report."""

    lines = [
        f"# VulnScope Report: {scan.target}",
        "",
        f"- Scan ID: `{scan.id}`",
        f"- Profile: `{scan.profile}`",
        f"- Status: `{scan.status}`",
        f"- Started: `{scan.started_at.isoformat()}`",
        f"- Finished: `{scan.finished_at.isoformat() if scan.finished_at else 'n/a'}`",
        "",
        "## Summary",
        "",
    ]
    for key, value in scan.summary.items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Findings", ""])
    if not scan.findings:
        lines.append("No findings were detected.")
    for finding in scan.findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- Severity: `{finding.severity.value}`",
                f"- Confidence: `{finding.confidence}%`",
                f"- Risk score: `{finding.risk_score}`",
                f"- URL: {finding.url}",
                f"- Parameter: `{finding.parameter or 'n/a'}`",
                f"- Rule: `{finding.rule_id or 'n/a'}`",
                "",
                f"Evidence: {redact_secrets(finding.evidence)}",
                "",
                f"Recommendation: {finding.recommendation}",
                "",
            ]
        )
    lines.extend(["## Components", ""])
    for component in scan.components:
        lines.append(f"- {component.name} {component.version or ''} ({component.source})")
    output = Path(path)
    ensure_dir(output.parent)
    output.write_text("\n".join(lines), encoding="utf-8")
    return output
