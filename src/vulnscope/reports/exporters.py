"""Report exporter facade."""

from __future__ import annotations

from pathlib import Path

from vulnscope.domain.models import Scan
from vulnscope.reports.html import export_html
from vulnscope.reports.json import export_json
from vulnscope.reports.markdown import export_markdown


def export_scan(
    scan: Scan,
    fmt: str,
    output_dir: str | Path,
    *,
    theme: str = "dark",
    pretty_json: bool = True,
) -> Path:
    """Export scan to the requested format."""

    directory = Path(output_dir)
    stem = f"vulnscope-{scan.id}"
    normalized = fmt.lower()
    if normalized == "html":
        return export_html(scan, directory / f"{stem}.html", theme=theme)
    if normalized == "json":
        return export_json(scan, directory / f"{stem}.json", pretty=pretty_json)
    if normalized in {"md", "markdown"}:
        return export_markdown(scan, directory / f"{stem}.md")
    raise ValueError(f"Unsupported export format: {fmt}")
