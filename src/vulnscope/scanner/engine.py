"""Safe scan orchestration engine."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import cast
from urllib.parse import urlencode

from vulnscope.domain.models import (
    Finding,
    Scan,
    ScanConfig,
    Target,
)
from vulnscope.rules.engine import RuleEngine
from vulnscope.scanner.analyzer import dedupe_components, detect_components
from vulnscope.scanner.crawler import Crawler, parse_forms
from vulnscope.scanner.fingerprints import FingerprintDatabase
from vulnscope.scanner.http_client import HttpObservation, SafeHttpClient
from vulnscope.scanner.payloads import profile_payloads
from vulnscope.scanner.scope import ScopePolicy
from vulnscope.utils.urls import normalize_url, query_parameters, replace_query_param


class ScanEvent(dict[str, object]):
    """Dictionary event emitted during scans."""


class ScannerEngine:
    """Coordinate crawling, payload checks, rule analysis, and scan aggregation."""

    def __init__(
        self,
        rule_engine: RuleEngine,
        *,
        fingerprints: FingerprintDatabase | None = None,
    ) -> None:
        self.rule_engine = rule_engine
        self.fingerprints = fingerprints
        self._pause = asyncio.Event()
        self._pause.set()
        self._stop = False

    def pause(self) -> None:
        """Pause the running scan."""

        self._pause.clear()

    def resume(self) -> None:
        """Resume a paused scan."""

        self._pause.set()

    def stop(self) -> None:
        """Request scan stop."""

        self._stop = True
        self._pause.set()

    async def run(self, config: ScanConfig) -> Scan:
        """Run a scan and return the completed aggregate."""

        events = [event async for event in self.run_events(config)]
        completed = [
            cast(Scan, event["scan"]) for event in events if event.get("type") == "completed"
        ]
        return (
            completed[-1]
            if completed
            else Scan(target=config.target.url, profile=config.profile, status="stopped")
        )

    async def run_events(self, config: ScanConfig) -> AsyncIterator[ScanEvent]:
        """Run scan and yield progress events for TUI consumers."""

        target_url = normalize_url(config.target.url)
        target = config.target.model_copy(update={"url": target_url})
        scope = ScopePolicy(target)
        client = SafeHttpClient(config.timeout, config.user_agent, config.auth_headers)
        crawler = Crawler(
            client,
            scope,
            config.max_depth,
            config.max_pages,
            seed_urls=self._seed_urls(target_url, config.profile),
        )
        scan = Scan(
            target=target_url,
            profile=config.profile,
            authenticated=bool(config.auth_headers),
            status="running",
            metadata={"config": config.model_dump(mode="json")},
        )
        payloads = profile_payloads(config.profile)
        checked_observation_urls: set[str] = set()
        finding_keys: set[tuple[str, str, str, str, str, str]] = set()
        yield ScanEvent(type="started", scan=scan)

        async for observation in crawler.iter_crawl(target_url):
            await self._pause.wait()
            if self._stop:
                scan.status = "stopped"
                break
            scan.traffic.append(observation.to_record())
            page_components = detect_components(observation, self.fingerprints)
            scan.components = dedupe_components([*scan.components, *page_components])
            findings = self.rule_engine.analyze(observation)
            findings = self._unique_findings(findings, finding_keys)
            scan.findings.extend(findings)
            yield ScanEvent(
                type="page",
                url=observation.url,
                findings=findings,
                scan=scan,
                discovered_components=page_components,
            )

            if observation.url not in checked_observation_urls:
                checked_observation_urls.add(observation.url)
                async for tested in self._payload_observations(
                    client,
                    observation,
                    target,
                    payloads,
                ):
                    if self._stop:
                        scan.status = "stopped"
                        break
                    scan.traffic.append(tested.to_record())
                    findings = self.rule_engine.analyze(tested, payload=tested.payload)
                    findings = self._unique_findings(findings, finding_keys)
                    scan.findings.extend(findings)
                    yield ScanEvent(type="check", url=tested.url, findings=findings, scan=scan)
                    if self._stop:
                        scan.status = "stopped"
                        break
                    await asyncio.sleep(1 / config.rate_limit)
                if self._stop:
                    break

        scan.components = dedupe_components(scan.components)
        if scan.status != "stopped":
            scan.status = "completed"
        scan.finished_at = datetime.now(UTC)
        yield ScanEvent(type="completed", scan=scan)

    def _seed_urls(self, target_url: str, profile: str) -> list[str]:
        """Add common web-app endpoints so scanner is useful on SPA/API targets."""

        common = [
            "/robots.txt",
            "/sitemap.xml",
            "/api",
            "/api-docs",
            "/swagger",
            "/graphql",
            "/rest/products/search?q=apple",
            "/rest/user/login",
            "/rest/basket",
        ]
        if profile == "quick":
            common = common[:3]
        if profile == "headers":
            common = common[:2]
        seeds: list[str] = []
        for path in common:
            url = f"{target_url.rstrip('/')}{path}"
            try:
                seeds.append(normalize_url(url))
            except ValueError:
                continue
        return list(dict.fromkeys(seeds))

    async def _payload_observations(
        self,
        client: SafeHttpClient,
        baseline: HttpObservation,
        target: Target,
        payloads: list[str],
    ) -> AsyncIterator[HttpObservation]:
        scope = ScopePolicy(target)
        params = query_parameters(baseline.url)
        if not params:
            params = {name: "" for name in self._common_probe_params(baseline.url)}
        for name in params:
            if self._stop:
                return
            for payload in payloads:
                if self._stop:
                    return
                url = replace_query_param(baseline.url, name, payload)
                if not scope.allowed(url):
                    continue
                obs = await client.get(url)
                obs.parameter = name
                obs.payload = payload
                obs.baseline_status_code = baseline.status_code
                obs.baseline_size = baseline.size_bytes
                yield obs

        for form in parse_forms(baseline.url, baseline.response_text):
            if self._stop:
                return
            if form.method != "GET" or not scope.allowed(form.action):
                continue
            for payload in payloads[:2]:
                if self._stop:
                    return
                query = urlencode({field.name: payload for field in form.inputs})
                separator = "&" if "?" in form.action else "?"
                obs = await client.get(f"{form.action}{separator}{query}" if query else form.action)
                obs.parameter = ",".join(field.name for field in form.inputs) or None
                obs.payload = payload
                obs.baseline_status_code = baseline.status_code
                obs.baseline_size = baseline.size_bytes
                yield obs

    def _common_probe_params(self, url: str) -> list[str]:
        """Return baseline probe parameter names based on endpoint semantics."""

        lower = url.lower()
        names = ["q", "search", "query"]
        if any(marker in lower for marker in ("/product", "/item", "/user", "/order")):
            names.extend(["id", "category"])
        if any(marker in lower for marker in ("/redirect", "/login", "/oauth", "/callback")):
            names.extend(["redirect", "next", "returnUrl"])
        if any(marker in lower for marker in ("/file", "/download", "/image", "/profile")):
            names.extend(["file", "path"])
        return list(dict.fromkeys(names))

    def _unique_findings(
        self,
        findings: list[Finding],
        seen: set[tuple[str, str, str, str, str, str]],
    ) -> list[Finding]:
        unique: list[Finding] = []
        for finding in findings:
            is_header = finding.category == "headers"
            key = (
                finding.source,
                finding.rule_id or finding.title,
                "" if is_header else finding.url.split("?", 1)[0],
                finding.parameter or "",
                finding.payload or "",
                "" if is_header else finding.evidence[:80],
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique
