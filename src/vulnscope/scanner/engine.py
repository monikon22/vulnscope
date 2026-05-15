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
from vulnscope.scanner.crawler import Crawler, Form, FormInput, parse_forms
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
            before_fetch=self._wait_if_running,
        )
        scan = Scan(
            target=target_url,
            profile=config.profile,
            authenticated=bool(config.auth_headers),
            status="running",
            metadata={"config": config.model_dump(mode="json")},
        )
        payloads = self._scan_payloads(config.profile)
        checked_observation_urls: set[str] = set()
        finding_keys: set[tuple[str, str, str, str, str, str]] = set()
        yield ScanEvent(type="started", scan=scan)

        try:
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
                        await self._throttle(config.rate_limit)
                    if self._stop:
                        break
        finally:
            await client.close()

        scan.components = dedupe_components(scan.components)
        if scan.status != "stopped":
            scan.status = "completed"
        scan.finished_at = datetime.now(UTC)
        yield ScanEvent(type="completed", scan=scan)

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
                if not await self._wait_if_running():
                    return
                obs = await client.get(url)
                obs.parameter = name
                obs.payload = payload
                obs.baseline_status_code = baseline.status_code
                obs.baseline_size = baseline.size_bytes
                yield obs

        for form in parse_forms(baseline.url, baseline.response_text):
            if self._stop:
                return
            if form.method not in {"GET", "POST"} or not scope.allowed(form.action):
                continue
            if self._skip_form(form):
                continue
            probe_fields = [field for field in form.inputs if self._probeable_form_field(field)]
            for field in probe_fields:
                for payload in self._payloads_for_parameter(field.name, payloads):
                    if self._stop:
                        return
                    data = self._form_payload(form, field.name, payload)
                    if not await self._wait_if_running():
                        return
                    if form.method == "POST":
                        obs = await client.post(form.action, data=data)
                    else:
                        query = urlencode(data)
                        separator = "&" if "?" in form.action else "?"
                        obs = await client.get(
                            f"{form.action}{separator}{query}" if query else form.action
                        )
                    obs.parameter = field.name
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
        if any(marker in lower for marker in ("/sqli", "/user", "/account", "/api")):
            names.extend(["id", "user", "username"])
        if any(marker in lower for marker in ("/ssrf", "/fetch", "/proxy", "/webhook")):
            names.extend(["url", "uri", "target"])
        return list(dict.fromkeys(names))

    def _scan_payloads(self, profile: str) -> list[str]:
        payloads = list(profile_payloads(profile))
        for rule in self.rule_engine.rules:
            payloads.extend(rule.payloads)
        return list(dict.fromkeys(payload for payload in payloads if payload))

    def _payloads_for_parameter(self, name: str, payloads: list[str]) -> list[str]:
        lower = name.lower()
        if lower in {"id", "uid", "user_id", "userid", "account", "item"}:
            preferred = ["'", '"', "1' OR '1'='1", "1 OR 1=1", "1 AND 1=2"]
        elif any(token in lower for token in ("url", "uri", "redirect", "next", "return")):
            preferred = ["https://example.invalid/", "http://127.0.0.1/"]
        elif any(token in lower for token in ("file", "path", "page", "include")):
            preferred = ["../etc/passwd", "..\\windows\\win.ini", "https://example.invalid/"]
        elif any(token in lower for token in ("name", "message", "comment", "search", "q")):
            preferred = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'"]
        else:
            preferred = payloads
        return list(dict.fromkeys([*preferred, *payloads]))

    def _skip_form(self, form: Form) -> bool:
        names = {field.name.lower() for field in form.inputs}
        destructive = {
            "password_new",
            "password_conf",
            "upload",
            "delete",
            "reset",
            "create",
            "setup",
        }
        if names & destructive:
            return True
        return any(field.input_type == "file" for field in form.inputs)

    def _probeable_form_field(self, field: FormInput) -> bool:
        if field.input_type in {"hidden", "submit", "button", "reset", "image", "file"}:
            return False
        return field.name.lower() not in {"user_token", "csrf", "token", "submit", "login"}

    def _form_payload(self, form: Form, probe_name: str, payload: str) -> dict[str, str]:
        data: dict[str, str] = {}
        for field in form.inputs:
            if field.input_type in {"button", "reset", "image", "file"}:
                continue
            value = payload if field.name == probe_name else self._default_form_value(field)
            if field.input_type in {"checkbox", "radio"} and value == "":
                continue
            data[field.name] = value
        return data

    def _default_form_value(self, field: FormInput) -> str:
        if field.value:
            return field.value
        name = field.name.lower()
        if name in {"submit", "login", "change", "btnsign"}:
            return field.name[0].upper() + field.name[1:]
        if field.input_type == "password":
            return "password"
        if "user" in name:
            return "admin"
        if name in {"id", "uid", "user_id", "userid"}:
            return "1"
        if name in {"ip", "host"}:
            return "127.0.0.1"
        if any(token in name for token in ("url", "uri", "redirect", "next")):
            return "https://example.invalid/"
        if name in {"q", "search", "query"}:
            return "test"
        return "test"

    def _unique_findings(
        self,
        findings: list[Finding],
        seen: set[tuple[str, str, str, str, str, str]],
    ) -> list[Finding]:
        unique: list[Finding] = []
        for finding in findings:
            is_global_policy = finding.category == "headers" or finding.evidence.startswith(
                ("Missing security header:", "Cookie missing security attributes:")
            )
            key = (
                finding.source,
                finding.rule_id or finding.title,
                "" if is_global_policy else finding.url.split("?", 1)[0],
                "" if is_global_policy else finding.parameter or "",
                "" if is_global_policy else finding.payload or "",
                finding.evidence[:80],
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    async def _wait_if_running(self) -> bool:
        await self._pause.wait()
        return not self._stop

    async def _throttle(self, rate_limit: float) -> None:
        remaining = 1 / rate_limit
        loop = asyncio.get_running_loop()
        while remaining > 0 and not self._stop:
            await self._pause.wait()
            if self._stop:
                return
            chunk = min(0.1, remaining)
            started = loop.time()
            await asyncio.sleep(chunk)
            if self._pause.is_set():
                remaining -= loop.time() - started
