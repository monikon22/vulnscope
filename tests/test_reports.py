import json

from vulnscope.domain.enums import Severity
from vulnscope.domain.models import Finding, Scan
from vulnscope.reports.exporters import export_scan
from vulnscope.utils.text import redact_secrets


def sample_scan() -> Scan:
    return Scan(
        target="https://example.local/",
        profile="safe",
        status="completed",
        findings=[
            Finding(
                title="Missing CSP",
                severity=Severity.MEDIUM,
                category="headers",
                confidence=90,
                risk_score=5.5,
                url="https://example.local/",
                evidence="Missing header",
                recommendation="Add CSP",
                request="Authorization: Bearer secret-token",
            )
        ],
    )


def test_json_report_generation(tmp_path) -> None:
    path = export_scan(sample_scan(), "json", tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 1
    assert "secret-token" not in json.dumps(data)


def test_html_and_markdown_reports(tmp_path) -> None:
    html = export_scan(sample_scan(), "html", tmp_path)
    md = export_scan(sample_scan(), "markdown", tmp_path)
    assert "VulnScope Security Report" in html.read_text(encoding="utf-8")
    assert "# VulnScope Report" in md.read_text(encoding="utf-8")


def test_html_report_escapes_saved_response_content(tmp_path) -> None:
    scan = sample_scan()
    scan.findings[0].response = "<style>body{display:none}</style><script>alert(1)</script>"
    scan.findings[0].evidence = "<img src=x onerror=alert(1)>"

    html = export_scan(scan, "html", tmp_path).read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in html
    assert "<style>body{display:none}</style>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;style&gt;body{display:none}&lt;/style&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_html_report_sorts_findings_by_risk_desc(tmp_path) -> None:
    scan = sample_scan()
    scan.findings.append(
        Finding(
            title="Critical issue",
            severity=Severity.CRITICAL,
            category="xss",
            confidence=95,
            risk_score=9.2,
            url="https://example.local/high",
        )
    )

    html = export_scan(scan, "html", tmp_path).read_text(encoding="utf-8")

    assert html.index("Critical issue") < html.index("Missing CSP")


def test_secret_redaction() -> None:
    assert "abc" not in redact_secrets("Authorization: Bearer abc")
