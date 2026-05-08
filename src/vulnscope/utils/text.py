"""Text utilities including secret redaction."""

from __future__ import annotations

import re

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(cookie:\s*)[^\r\n]+"),
    re.compile(r"(?i)(token=)[^&\s]+"),
    re.compile(r"(?i)(password=)[^&\s]+"),
]


def redact_secrets(text: str) -> str:
    """Redact common authentication secrets from text."""

    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted


def compact(text: str, limit: int = 500) -> str:
    """Compact whitespace and cap the string length."""

    cleaned = " ".join(text.split())
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[: limit - 3]}..."

