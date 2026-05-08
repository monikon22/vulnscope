"""Deterministic risk scoring."""

from __future__ import annotations

from dataclasses import dataclass

from vulnscope.domain.enums import Severity
from vulnscope.domain.models import Finding

BASE_SEVERITY_SCORE: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 1.0,
}


@dataclass(frozen=True)
class ScoreResult:
    """Computed risk score with a human-readable explanation."""

    score: float
    explanation: str


def score_finding(
    severity: Severity,
    confidence: int,
    *,
    authenticated: bool = False,
    public_endpoint: bool = True,
) -> ScoreResult:
    """Compute a deterministic 0-10 risk score."""

    base = BASE_SEVERITY_SCORE[severity]
    score = base * max(0, min(confidence, 100)) / 100
    parts = [f"{severity.value} base {base:g} with {confidence}% confidence"]

    if public_endpoint:
        score += 1.0
        parts.append("public endpoint +1")
    elif authenticated:
        score += 0.5
        parts.append("authenticated endpoint +0.5")

    final = round(max(0.0, min(score, 10.0)), 2)
    return ScoreResult(final, "; ".join(parts))


def apply_score(finding: Finding) -> Finding:
    """Return a copy of a finding with risk score fields populated."""

    result = score_finding(finding.severity, finding.confidence)
    return finding.model_copy(
        update={"risk_score": result.score, "risk_explanation": result.explanation}
    )
