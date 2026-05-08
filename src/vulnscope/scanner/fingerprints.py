"""Technology fingerprint database loaded from YAML files."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Fingerprint(BaseModel):
    """One component fingerprint."""

    name: str
    pattern: str
    header: str | None = None
    source: str = "fingerprint"
    confidence: int = Field(default=75, ge=0, le=100)

    def regex(self) -> re.Pattern[str]:
        """Compile the fingerprint pattern."""

        return re.compile(self.pattern, re.IGNORECASE)


class FingerprintDatabase:
    """Load and apply server/framework/library fingerprints."""

    def __init__(self, fingerprints: list[Fingerprint]) -> None:
        self.fingerprints = fingerprints

    @classmethod
    def from_paths(cls, paths: list[str | Path]) -> FingerprintDatabase:
        """Load fingerprints from YAML files under configured rule paths."""

        fingerprints: list[Fingerprint] = []
        candidates: list[Path] = []
        for raw_path in paths:
            path = Path(raw_path)
            roots = [path]
            if path.name == "web":
                roots.append(path.parent / "fingerprints")
            if path.name == "rules":
                roots.append(path / "fingerprints")
            for root in roots:
                if root.is_file() and root.suffix in {".yaml", ".yml"}:
                    candidates.append(root)
                elif root.exists():
                    candidates.extend(sorted(root.rglob("*.yaml")))

        for candidate in sorted(set(candidates)):
            loaded = yaml.safe_load(candidate.read_text(encoding="utf-8")) or []
            if isinstance(loaded, dict):
                loaded = [loaded]
            if not isinstance(loaded, list):
                continue
            for item in loaded:
                if isinstance(item, dict) and item.get("name") and item.get("pattern"):
                    fingerprints.append(
                        Fingerprint.model_validate(
                            item | {"source": candidate.stem.replace("_", " ")}
                        )
                    )
        return cls(fingerprints)
