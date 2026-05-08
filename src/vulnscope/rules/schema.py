"""YAML rule schema."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from vulnscope.domain.enums import Severity

MatchType = Literal[
    "contains_any",
    "contains_all",
    "regex",
    "reflected_without_encoding",
    "missing_header",
    "insecure_cookie",
    "status_code_changed",
    "response_length_delta",
    "server_error",
    "technology_detected",
]


class RuleMatch(BaseModel):
    """Rule match configuration."""

    type: MatchType
    values: list[str] = Field(default_factory=list)
    header: str | None = None
    pattern: str | None = None
    status_codes: list[int] = Field(default_factory=list)
    threshold: int | None = None


class Rule(BaseModel):
    """Validated vulnerability rule."""

    id: str
    title: str
    description: str
    category: str
    severity: Severity
    confidence_base: int = Field(ge=0, le=100)
    cwe: str | None = None
    tags: list[str] = Field(default_factory=list)
    payloads: list[str] = Field(default_factory=list)
    match: RuleMatch
    recommendation: str
    references: list[str] = Field(default_factory=list)
    safe: bool = True
    enabled: bool = True
    registry: str = "web"
    source: str = "local"
