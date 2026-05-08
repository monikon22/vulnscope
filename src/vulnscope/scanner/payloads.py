"""Safe scanner payload catalog."""

XSS_SAFE_PAYLOADS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
SQLI_SAFE_PAYLOADS = ["'", "\"", "1' OR '1'='1"]
PATH_TRAVERSAL_SAFE_PAYLOADS = ["../etc/passwd", "..\\windows\\win.ini"]
REDIRECT_SAFE_PAYLOADS = ["https://example.invalid/"]


def profile_payloads(profile: str) -> list[str]:
    """Return safe payloads suitable for a scan profile."""

    if profile in {"headers", "dependency"}:
        return []
    if profile == "quick":
        return XSS_SAFE_PAYLOADS[:1] + SQLI_SAFE_PAYLOADS[:1]
    if profile == "deep":
        return (
            XSS_SAFE_PAYLOADS
            + SQLI_SAFE_PAYLOADS
            + PATH_TRAVERSAL_SAFE_PAYLOADS
            + REDIRECT_SAFE_PAYLOADS
        )
    if profile == "owasp_top_10":
        return XSS_SAFE_PAYLOADS + SQLI_SAFE_PAYLOADS[:2] + REDIRECT_SAFE_PAYLOADS
    return XSS_SAFE_PAYLOADS[:1] + SQLI_SAFE_PAYLOADS[:2] + REDIRECT_SAFE_PAYLOADS
