"""Response analysis helpers for components and security posture."""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from vulnscope.domain.models import Component
from vulnscope.scanner.fingerprints import FingerprintDatabase
from vulnscope.scanner.http_client import HttpObservation

JS_LIBRARY_PATTERNS: dict[str, re.Pattern[str]] = {
    "jquery": re.compile(r"jquery[-.]([0-9][0-9.]+)", re.I),
    "bootstrap": re.compile(r"bootstrap(?:\.bundle)?[-.]([0-9][0-9.]+)", re.I),
    "react": re.compile(r"react(?:\.production\.min)?\.js|react@([0-9][0-9.]+)", re.I),
}


def detect_components(
    observation: HttpObservation,
    fingerprints: FingerprintDatabase | None = None,
) -> list[Component]:
    """Detect components from headers, HTML meta tags, and asset URLs."""

    components: list[Component] = []
    server = observation.response_headers.get("server")
    if server:
        parts = server.split("/", 1)
        components.append(
            Component(
                name=parts[0].strip(),
                version=parts[1].strip() if len(parts) == 2 else None,
                source="Server",
            )
        )
    powered_by = observation.response_headers.get("x-powered-by")
    if powered_by:
        parts = powered_by.split("/", 1)
        components.append(
            Component(
                name=parts[0].strip(),
                version=parts[1].strip() if len(parts) == 2 else None,
                source="X-Powered-By",
                confidence=80,
            )
        )

    soup = BeautifulSoup(observation.response_text, "html.parser")
    title = (soup.title.string or "").strip().lower() if soup.title and soup.title.string else ""
    if "juice shop" in title:
        components.append(Component(name="juice-shop", source="HTML title", confidence=85))
    generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if generator and generator.get("content"):
        components.append(
            Component(name=str(generator["content"]), source="HTML generator", confidence=75)
        )

    html_blob = observation.response_text[:100_000]
    for name, pattern in JS_LIBRARY_PATTERNS.items():
        match = pattern.search(html_blob)
        if match:
            version = match.group(1) if match.groups() else None
            components.append(
                Component(name=name, version=version, source="HTML asset", confidence=70)
            )
    if fingerprints:
        components.extend(_detect_fingerprinted_components(observation, fingerprints))
    return components


def dedupe_components(components: list[Component]) -> list[Component]:
    """Deduplicate components by name/version/source."""

    seen: set[tuple[str, str | None, str]] = set()
    result: list[Component] = []
    for component in components:
        key = (component.name.lower(), component.version, component.source)
        if key not in seen:
            seen.add(key)
            result.append(component)
    return result


def _detect_fingerprinted_components(
    observation: HttpObservation,
    fingerprints: FingerprintDatabase,
) -> list[Component]:
    components: list[Component] = []
    lower_headers = {key.lower(): value for key, value in observation.response_headers.items()}
    headers_blob = "\n".join(
        f"{key}: {value}" for key, value in observation.response_headers.items()
    )
    body = observation.response_text[:100_000]
    for fingerprint in fingerprints.fingerprints:
        haystack = (
            lower_headers.get(fingerprint.header.lower(), "")
            if fingerprint.header
            else f"{headers_blob}\n{body}"
        )
        match = fingerprint.regex().search(haystack)
        if not match:
            continue
        version = match.group(1) if match.groups() else None
        components.append(
            Component(
                name=fingerprint.name,
                version=version,
                source=fingerprint.source,
                confidence=fingerprint.confidence,
            )
        )
    return components
