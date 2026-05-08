"""Shared domain enumerations."""

from enum import StrEnum


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanProfile(StrEnum):
    """Supported scanner profiles."""

    QUICK = "quick"
    SAFE = "safe"
    OWASP_TOP_10 = "owasp_top_10"
    HEADERS = "headers"
    DEPENDENCY = "dependency"
    DEEP = "deep"
    AUTHENTICATED = "authenticated"


class ScopeMode(StrEnum):
    """Target scope restriction mode."""

    SAME_HOST = "same_host"
    SAME_DOMAIN = "same_domain"
    CUSTOM = "custom"


class Confidence(StrEnum):
    """Human-readable confidence labels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
