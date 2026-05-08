"""Load and validate YAML rules."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import httpx
import yaml
from pydantic import ValidationError

from vulnscope.rules.feed import (
    fetch_remote_index,
    fetch_remote_rule_yaml,
    load_cached_feed_index,
    load_cached_feed_rule_yaml,
    save_cached_feed_index,
    save_cached_feed_rule_yaml,
)
from vulnscope.rules.schema import Rule


class RuleLoadError(ValueError):
    """Raised when a rule file cannot be loaded."""


class RuleLoader:
    """Load local and custom rules from YAML files."""

    def __init__(
        self,
        paths: Iterable[str | Path],
        *,
        remote_cache_dir: str | Path | None = None,
    ) -> None:
        self.paths = [Path(path) for path in paths]
        self.remote_cache_dir = Path(remote_cache_dir).expanduser() if remote_cache_dir else None

    def load(self) -> list[Rule]:
        """Load all YAML rules from configured paths."""

        rules: list[Rule] = []
        for path in self.paths:
            if not path.exists():
                continue
            files = (
                [path]
                if path.is_file()
                else [
                    candidate
                    for candidate in sorted(path.rglob("*.yaml"))
                    if "fingerprints" not in candidate.parts
                ]
            )
            for file in files:
                rules.extend(self._load_file(file))
        seen: set[str] = set()
        unique: list[Rule] = []
        for rule in rules:
            if rule.id in seen:
                raise RuleLoadError(f"Duplicate rule id: {rule.id}")
            seen.add(rule.id)
            unique.append(rule)
        return unique

    def load_remote(self, urls: Iterable[str]) -> list[Rule]:
        """Load rule YAML documents from remote URLs."""

        rules: list[Rule] = []
        for url in urls:
            if not url.strip():
                continue
            try:
                response = httpx.get(url, timeout=15)
                response.raise_for_status()
                data = yaml.safe_load(response.text)
            except Exception as exc:  # noqa: BLE001
                raise RuleLoadError(f"Unable to load remote rules from {url}: {exc}") from exc

            docs = data if isinstance(data, list) else [data]
            for item in docs:
                if not isinstance(item, dict):
                    raise RuleLoadError(f"Remote rule document in {url} must be a mapping")
                payload = item | {"source": f"remote:{url}"}
                try:
                    rules.append(
                        Rule.model_validate(payload | {"registry": "remote", "source": url})
                    )
                except ValidationError as exc:
                    raise RuleLoadError(f"Invalid remote rule in {url}: {exc}") from exc
        return rules

    def load_remote_feeds(
        self,
        feeds: Iterable[str],
        *,
        registries: set[str] | None = None,
        categories: set[str] | None = None,
    ) -> list[Rule]:
        """Load rules from remote feed index endpoints."""

        loaded: list[Rule] = []
        wanted_registries = {value.lower() for value in (registries or set())}
        wanted_categories = {value.lower() for value in (categories or set())}
        for feed in feeds:
            if not feed.strip():
                continue
            cached_index = load_cached_feed_index(feed, self.remote_cache_dir)
            try:
                index = fetch_remote_index(feed)
                save_cached_feed_index(feed, index, self.remote_cache_dir)
            except Exception as exc:  # noqa: BLE001
                raise RuleLoadError(f"Unable to load remote feed index from {feed}: {exc}") from exc
            same_feed_hash = _same_feed_hash(cached_index, index)
            cached_rule_hashes = _rule_hashes_by_path(cached_index)
            current_rule_hashes = _rule_hashes_by_path(index)
            for registry_data in index.get("registries", []):
                registry = str(registry_data.get("name", "")).strip()
                if wanted_registries and registry.lower() not in wanted_registries:
                    continue
                for rule_data in registry_data.get("rules", []):
                    if str(rule_data.get("kind", "rule")).lower() != "rule":
                        continue
                    category = str(rule_data.get("category", "")).strip()
                    if wanted_categories and category.lower() not in wanted_categories:
                        continue
                    path = str(rule_data.get("path", "")).strip()
                    if not path:
                        continue
                    try:
                        yaml_payload = self._load_cached_or_remote_rule_yaml(
                            feed=feed,
                            path=path,
                            same_feed_hash=same_feed_hash,
                            previous_rule_hash=cached_rule_hashes.get(path, ""),
                            current_rule_hash=current_rule_hashes.get(path, ""),
                        )
                        payload = yaml.safe_load(yaml_payload)
                    except Exception as exc:  # noqa: BLE001
                        raise RuleLoadError(
                            f"Unable to load remote rule {path} from {feed}: {exc}"
                        ) from exc
                    docs = payload if isinstance(payload, list) else [payload]
                    for item in docs:
                        if not isinstance(item, dict):
                            raise RuleLoadError(f"Remote rule document in {feed} must be a mapping")
                        try:
                            loaded.append(
                                Rule.model_validate(item | {"registry": registry, "source": feed})
                            )
                        except ValidationError as exc:
                            raise RuleLoadError(f"Invalid remote rule in {feed}: {exc}") from exc
        return loaded

    def _load_cached_or_remote_rule_yaml(
        self,
        *,
        feed: str,
        path: str,
        same_feed_hash: bool,
        previous_rule_hash: str,
        current_rule_hash: str,
    ) -> str:
        cached_yaml = load_cached_feed_rule_yaml(feed, path, self.remote_cache_dir)
        if same_feed_hash and cached_yaml is not None:
            return cached_yaml
        if (
            current_rule_hash
            and previous_rule_hash
            and previous_rule_hash == current_rule_hash
            and cached_yaml is not None
        ):
            return cached_yaml
        remote_yaml = fetch_remote_rule_yaml(feed, path)
        save_cached_feed_rule_yaml(feed, path, remote_yaml, self.remote_cache_dir)
        return remote_yaml

    def _load_file(self, file: Path) -> list[Rule]:
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8"))
        except OSError as exc:
            raise RuleLoadError(f"Unable to read {file}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise RuleLoadError(f"Invalid YAML in {file}: {exc}") from exc

        docs = data if isinstance(data, list) else [data]
        loaded: list[Rule] = []
        for item in docs:
            if not isinstance(item, dict):
                raise RuleLoadError(f"Rule document in {file} must be a mapping")
            try:
                normalized = str(file).replace("/", "\\")
                if "\\rules\\" in normalized:
                    registry = normalized.split("\\rules\\", 1)[1].split("\\", 1)[0]
                else:
                    registry = file.parent.name or "custom"
                loaded.append(Rule.model_validate(item | {"registry": registry, "source": "local"}))
            except ValidationError as exc:
                raise RuleLoadError(f"Invalid rule in {file}: {exc}") from exc
        return loaded


def _same_feed_hash(
    previous_index: dict[str, object] | None,
    current_index: dict[str, object],
) -> bool:
    if not previous_index:
        return False
    previous_hash = str(previous_index.get("feed_hash", "")).strip()
    current_hash = str(current_index.get("feed_hash", "")).strip()
    return bool(previous_hash and current_hash and previous_hash == current_hash)


def _rule_hashes_by_path(index: dict[str, object] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if not index:
        return result
    registries = index.get("registries", [])
    if not isinstance(registries, list):
        return result
    for registry in registries:
        if not isinstance(registry, dict):
            continue
        rules = registry.get("rules", [])
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            path = str(rule.get("path", "")).strip()
            if not path:
                continue
            result[path] = str(rule.get("hash", "")).strip()
    return result
