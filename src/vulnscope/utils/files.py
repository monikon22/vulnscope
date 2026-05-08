"""Filesystem helpers."""

from __future__ import annotations

from pathlib import Path


def ensure_dir(path: str | Path) -> Path:
    """Create a directory if needed and return it as a Path."""

    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def project_root() -> Path:
    """Return the current project root for editable/source-tree usage."""

    return Path.cwd()

