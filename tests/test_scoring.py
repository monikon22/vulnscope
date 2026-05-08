from vulnscope.domain.enums import Severity
from vulnscope.domain.models import Finding
from vulnscope.domain.scoring import apply_score, score_finding


def test_risk_scoring_clamps_to_ten() -> None:
    result = score_finding(Severity.CRITICAL, 100)
    assert result.score == 10


def test_apply_score_adds_explanation() -> None:
    finding = Finding(title="Test", severity=Severity.MEDIUM, category="test", confidence=80, url="https://a.test/")
    scored = apply_score(finding)
    assert scored.risk_score > 0
    assert "medium base" in scored.risk_explanation
