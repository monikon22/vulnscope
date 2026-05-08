from pathlib import Path

import pytest

from vulnscope.rules.engine import RuleEngine
from vulnscope.rules.feed import build_local_index
from vulnscope.rules.loader import RuleLoader, RuleLoadError
from vulnscope.scanner.http_client import HttpObservation


def observation(body: str, headers: dict[str, str] | None = None) -> HttpObservation:
    return HttpObservation(
        method="GET",
        url="https://example.local/?q=x",
        status_code=200,
        response_headers=headers or {},
        response_text=body,
        duration_ms=10,
        size_bytes=len(body),
    )


def test_rule_loader_loads_builtin_rules() -> None:
    rules = RuleLoader(["rules/web"]).load()
    assert {rule.id for rule in rules} >= {"XSS_REFLECTED_001", "SQLI_ERROR_001"}


def test_rule_loader_rejects_invalid_rule(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("title: Missing ID\n", encoding="utf-8")
    with pytest.raises(RuleLoadError):
        RuleLoader([path]).load()


def test_matcher_reflected_xss() -> None:
    rules = [rule for rule in RuleLoader(["rules/web/xss.yaml"]).load()]
    findings = RuleEngine(rules).analyze(
        observation("<script>alert(1)</script>"),
        "<script>alert(1)</script>",
    )
    assert findings
    assert findings[0].category == "xss"


def test_missing_header_rule() -> None:
    rules = RuleLoader(["rules/web/security_headers.yaml"]).load()
    findings = RuleEngine(rules).analyze(observation("ok", {"server": "nginx"}))
    assert any(finding.rule_id == "HEADER_CSP_001" for finding in findings)


def test_local_feed_index_contains_hashes() -> None:
    index = build_local_index(Path("rules"))
    assert isinstance(index.get("feed_hash"), str)
    registries = index.get("registries", [])
    assert isinstance(registries, list) and registries
    first_registry = registries[0]
    assert isinstance(first_registry, dict)
    rules = first_registry.get("rules", [])
    assert isinstance(rules, list) and rules
    assert isinstance(rules[0].get("hash"), str)


def test_remote_feed_cache_reuses_unchanged_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    feed = "https://feed.example.local"
    index_state = {
        "feed_hash": "feed-v1",
        "registries": [
            {
                "name": "web",
                "rules": [
                    {
                        "id": "RULE_ONE",
                        "kind": "rule",
                        "category": "xss",
                        "path": "/rules/web/rule-one.yaml",
                        "hash": "hash-one-v1",
                    },
                    {
                        "id": "RULE_TWO",
                        "kind": "rule",
                        "category": "xss",
                        "path": "/rules/web/rule-two.yaml",
                        "hash": "hash-two-v1",
                    },
                ],
            }
        ],
    }
    yaml_docs = {
        "/rules/web/rule-one.yaml": (
            "id: RULE_ONE\n"
            "title: One\n"
            "description: One\n"
            "category: xss\n"
            "severity: high\n"
            "confidence_base: 80\n"
            "match:\n  type: contains_any\n  values: ['x']\n"
            "recommendation: Fix one\n"
        ),
        "/rules/web/rule-two.yaml": (
            "id: RULE_TWO\n"
            "title: Two\n"
            "description: Two\n"
            "category: xss\n"
            "severity: medium\n"
            "confidence_base: 70\n"
            "match:\n  type: contains_any\n  values: ['y']\n"
            "recommendation: Fix two\n"
        ),
    }
    rule_fetches: list[str] = []

    def fake_fetch_index(_: str) -> dict[str, object]:
        return index_state

    def fake_fetch_rule_yaml(_: str, path: str) -> str:
        rule_fetches.append(path)
        return yaml_docs[path]

    monkeypatch.setattr("vulnscope.rules.loader.fetch_remote_index", fake_fetch_index)
    monkeypatch.setattr("vulnscope.rules.loader.fetch_remote_rule_yaml", fake_fetch_rule_yaml)

    loader = RuleLoader(["rules/web"], remote_cache_dir=tmp_path / "cache")
    first = loader.load_remote_feeds([feed])
    assert {rule.id for rule in first} == {"RULE_ONE", "RULE_TWO"}
    assert rule_fetches == ["/rules/web/rule-one.yaml", "/rules/web/rule-two.yaml"]

    second = loader.load_remote_feeds([feed])
    assert {rule.id for rule in second} == {"RULE_ONE", "RULE_TWO"}
    assert rule_fetches == ["/rules/web/rule-one.yaml", "/rules/web/rule-two.yaml"]

    index_state["feed_hash"] = "feed-v2"
    index_state["registries"][0]["rules"][0]["hash"] = "hash-one-v2"
    third = loader.load_remote_feeds([feed])
    assert {rule.id for rule in third} == {"RULE_ONE", "RULE_TWO"}
    assert rule_fetches == [
        "/rules/web/rule-one.yaml",
        "/rules/web/rule-two.yaml",
        "/rules/web/rule-one.yaml",
    ]
