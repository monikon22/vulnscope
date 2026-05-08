"""Rule engine converting observations into findings."""

from __future__ import annotations

from vulnscope.domain.models import Finding
from vulnscope.domain.scoring import apply_score
from vulnscope.rules.matchers import match_rule
from vulnscope.rules.schema import Rule
from vulnscope.scanner.http_client import HttpObservation


class RuleEngine:
    """Apply enabled rules to HTTP observations."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = [rule for rule in rules if rule.enabled and rule.safe]

    def analyze(self, observation: HttpObservation, payload: str | None = None) -> list[Finding]:
        """Analyze one observation and return structured findings."""

        findings: list[Finding] = []
        for rule in self.rules:
            evidence = match_rule(rule, observation, payload=payload)
            if not evidence:
                continue
            finding = Finding(
                title=rule.title,
                description=rule.description,
                severity=rule.severity,
                category=rule.category,
                confidence=rule.confidence_base,
                url=observation.url,
                method=observation.method,
                parameter=observation.parameter,
                payload=payload,
                evidence=evidence,
                source=rule.source,
                rule_id=rule.id,
                cwe=rule.cwe,
                references=rule.references,
                recommendation=rule.recommendation,
                request=observation.request_preview,
                response=observation.response_preview,
            )
            findings.append(apply_score(finding))
        return findings
