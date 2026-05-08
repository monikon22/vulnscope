"""Pydantic domain models used across scanner, TUI, storage, and reports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from vulnscope.domain.enums import ScopeMode, Severity


def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""

    return datetime.now(UTC)


class Target(BaseModel):
    """A normalized scan target."""

    url: str
    scope_mode: ScopeMode = ScopeMode.SAME_HOST
    include_patterns: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    """Effective scanner configuration for one scan."""

    target: Target
    profile: str = "safe"
    rate_limit: float = 5.0
    timeout: float = 10.0
    max_depth: int = 2
    max_pages: int = 50
    user_agent: str = "VulnScope/0.1"
    dependency_audit: bool = True
    auth_headers: dict[str, str] = Field(default_factory=dict)
    enabled_registries: list[str] = Field(default_factory=list)
    enabled_categories: list[str] = Field(default_factory=list)
    enabled_rule_ids: list[str] = Field(default_factory=list)
    enabled_rule_refs: list[str] = Field(default_factory=list)
    remote_feeds: list[str] = Field(default_factory=list)

    @field_validator("rate_limit")
    @classmethod
    def positive_rate_limit(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("rate_limit must be positive")
        return value


class RequestRecord(BaseModel):
    """HTTP request/response metadata captured during a scan."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    method: str
    url: str
    status_code: int | None = None
    duration_ms: float | None = None
    size_bytes: int = 0
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    request_preview: str = ""
    response_preview: str = ""
    related_finding_id: str | None = None


class Component(BaseModel):
    """Detected server, framework, or library component."""

    name: str
    version: str | None = None
    source: str
    confidence: int = Field(default=70, ge=0, le=100)
    externally_exposed: bool = True


class Finding(BaseModel):
    """A structured security finding."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str = ""
    severity: Severity
    category: str
    confidence: int = Field(ge=0, le=100)
    risk_score: float = Field(default=0, ge=0, le=10)
    risk_explanation: str = ""
    url: str
    method: str = "GET"
    parameter: str | None = None
    payload: str | None = None
    evidence: str = ""
    source: str = "local"
    rule_id: str | None = None
    cwe: str | None = None
    references: list[str] = Field(default_factory=list)
    recommendation: str = ""
    request: str = ""
    response: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class Scan(BaseModel):
    """Completed or running scan aggregate."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    profile: str = "safe"
    authenticated: bool = False
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    status: str = "created"
    findings: list[Finding] = Field(default_factory=list)
    traffic: list[RequestRecord] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def summary(self) -> dict[str, int]:
        """Return severity counts for this scan."""

        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        counts["total"] = len(self.findings)
        return counts


class Report(BaseModel):
    """Report export metadata."""

    scan_id: str
    format: str
    path: str
    created_at: datetime = Field(default_factory=utc_now)
