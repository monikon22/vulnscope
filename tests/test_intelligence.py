from vulnscope.rules.engine import RuleEngine
from vulnscope.scanner.analyzer import detect_components
from vulnscope.scanner.fingerprints import FingerprintDatabase
from vulnscope.scanner.http_client import HttpObservation


def test_fingerprint_database_contributes_component_detection() -> None:
    observation = HttpObservation(
        method="GET",
        url="https://example.local/",
        status_code=200,
        response_headers={"Server": "nginx/1.20.1"},
        response_text="<html></html>",
        duration_ms=1,
        size_bytes=13,
    )
    fingerprints = FingerprintDatabase.from_paths(["rules/web"])
    components = detect_components(observation, fingerprints)
    assert any(
        component.name == "nginx" and component.version == "1.20.1"
        for component in components
    )

def test_rule_engine_with_empty_rules_returns_no_findings() -> None:
    findings = RuleEngine([]).analyze(observation=HttpObservation(
        method="GET",
        url="https://example.local/",
        status_code=200,
        response_headers={},
        response_text="<html></html>",
        duration_ms=1,
        size_bytes=13,
    ))
    assert findings == []
