"""Scope checks used to keep scans within allowed targets."""

from __future__ import annotations

import fnmatch
from urllib.parse import urlparse

from vulnscope.domain.enums import ScopeMode
from vulnscope.domain.models import Target


def _registrable_domain(host: str) -> str:
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


class ScopePolicy:
    """Evaluate whether URLs are allowed for a target."""

    def __init__(self, target: Target) -> None:
        self.target = target
        self.base = urlparse(target.url)
        if not self.base.netloc:
            raise ValueError("target URL must include host")

    def allowed(self, url: str) -> bool:
        """Return true when URL is inside configured scan scope."""

        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return False

        if any(fnmatch.fnmatch(url, pattern) for pattern in self.target.exclude_patterns):
            return False

        if self.target.scope_mode == ScopeMode.CUSTOM and self.target.include_patterns:
            return any(fnmatch.fnmatch(url, pattern) for pattern in self.target.include_patterns)

        if self.target.scope_mode == ScopeMode.SAME_DOMAIN:
            return _registrable_domain(parsed.hostname or "") == _registrable_domain(
                self.base.hostname or ""
            )

        return parsed.hostname == self.base.hostname
