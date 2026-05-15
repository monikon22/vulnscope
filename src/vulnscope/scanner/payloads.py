"""Safe scanner payload catalog."""

XSS_SAFE_PAYLOADS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
SQLI_SAFE_PAYLOADS = ["'", "\"", "1' OR '1'='1"]
PATH_TRAVERSAL_SAFE_PAYLOADS = ["../etc/passwd", "..\\windows\\win.ini"]
REDIRECT_SAFE_PAYLOADS = ["https://example.invalid/"]


def profile_payloads(_profile: str | None = None) -> list[str]:
    """Return the default safe payload set for custom scan profiles."""

    return (
        XSS_SAFE_PAYLOADS
        + SQLI_SAFE_PAYLOADS
        + PATH_TRAVERSAL_SAFE_PAYLOADS
        + REDIRECT_SAFE_PAYLOADS
    )
