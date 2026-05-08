"""HTML report exporter."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from vulnscope.domain.models import Scan
from vulnscope.utils.files import ensure_dir


def export_html(scan: Scan, path: str | Path, theme: str = "dark") -> Path:
    """Export scan as self-contained HTML."""

    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    template = env.get_template("report.html.j2")
    output = Path(path)
    ensure_dir(output.parent)
    findings = sorted(scan.findings, key=lambda finding: finding.risk_score, reverse=True)
    output.write_text(
        template.render(scan=scan, findings=findings, summary=scan.summary, theme=theme),
        encoding="utf-8",
    )
    return output
