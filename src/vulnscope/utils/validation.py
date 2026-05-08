"""Validation helpers."""

from __future__ import annotations

from pathlib import Path

from vulnscope.utils.urls import normalize_url


def validate_target_url(url: str) -> str:
    """Validate and normalize a target URL."""

    return normalize_url(url)


def readable_file(path: str | Path) -> Path:
    """Return path when it exists and is readable."""

    candidate = Path(path)
    if not candidate.exists() or not candidate.is_file():
        raise ValueError(f"File does not exist: {candidate}")
    return candidate

