"""JSON report exporter."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscope.domain.models import Scan
from vulnscope.utils.files import ensure_dir
from vulnscope.utils.text import redact_secrets


def scan_to_dict(scan: Scan, include_response_bodies: bool = False) -> dict[str, object]:
    """Convert a scan into exportable structured data."""

    data = scan.model_dump(mode="json")
    for finding in data.get("findings", []):
        if isinstance(finding, dict):
            finding["request"] = redact_secrets(str(finding.get("request", "")))
            finding["response"] = redact_secrets(str(finding.get("response", "")))
            if not include_response_bodies:
                finding["response"] = finding["response"][:1000]
    return {"summary": scan.summary, **data}


def export_json(scan: Scan, path: str | Path, pretty: bool = True) -> Path:
    """Export scan as JSON."""

    output = Path(path)
    ensure_dir(output.parent)
    output.write_text(
        json.dumps(scan_to_dict(scan), indent=2 if pretty else None, ensure_ascii=False),
        encoding="utf-8",
    )
    return output

