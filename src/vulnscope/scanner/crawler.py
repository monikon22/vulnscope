"""Safe HTML crawler and form/link parser."""

from __future__ import annotations

import re
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from bs4 import BeautifulSoup
from bs4.element import AttributeValueList

from vulnscope.scanner.http_client import HttpObservation, SafeHttpClient
from vulnscope.scanner.scope import ScopePolicy
from vulnscope.utils.urls import absolute_url, normalize_url


def _attr(value: object, default: str = "") -> str:
    """Convert BeautifulSoup attribute values to strings for type-checkers."""

    if value is None:
        return default
    if isinstance(value, AttributeValueList):
        return " ".join(str(item) for item in value)
    return str(value)


@dataclass(slots=True)
class FormInput:
    """HTML form input metadata."""

    name: str
    input_type: str = "text"


@dataclass(slots=True)
class Form:
    """HTML form metadata."""

    action: str
    method: str = "GET"
    inputs: list[FormInput] = field(default_factory=list)


def parse_links(base_url: str, html_text: str) -> list[str]:
    """Extract absolute HTTP links from HTML."""

    soup = BeautifulSoup(html_text, "html.parser")
    links: list[str] = []
    for tag in soup.find_all(["a", "link", "script", "iframe", "frame"]):
        href = _attr(tag.get("href") or tag.get("src"))
        resolved = absolute_url(base_url, href) if href else None
        if resolved:
            links.append(resolved)
    for form in soup.find_all("form"):
        action = _attr(form.get("action"), base_url)
        resolved = absolute_url(base_url, action)
        if resolved:
            links.append(resolved)
    for meta in soup.find_all("meta"):
        if _attr(meta.get("http-equiv")).lower() != "refresh":
            continue
        content = _attr(meta.get("content"))
        if "url=" in content.lower():
            href = content.split("=", 1)[1].strip(" '\"")
            resolved = absolute_url(base_url, href)
            if resolved:
                links.append(resolved)
    links.extend(parse_javascript_endpoints(base_url, html_text))
    return sorted(set(links))


def parse_javascript_endpoints(base_url: str, text: str) -> list[str]:
    """Extract simple same-origin endpoint strings from inline JavaScript."""

    endpoints: list[str] = []
    for match in re.finditer(r"""["'](/[A-Za-z0-9_./?&=%-]{2,})["']""", text):
        value = match.group(1)
        if value.startswith("//"):
            continue
        resolved = absolute_url(base_url, value)
        if resolved:
            endpoints.append(normalize_url(resolved))
    return endpoints


def parse_forms(base_url: str, html_text: str) -> list[Form]:
    """Extract HTML forms with action, method, and named inputs."""

    soup = BeautifulSoup(html_text, "html.parser")
    forms: list[Form] = []
    for form in soup.find_all("form"):
        action = absolute_url(base_url, _attr(form.get("action"), base_url)) or base_url
        method = _attr(form.get("method"), "GET").upper()
        inputs = [
            FormInput(name=_attr(tag.get("name")), input_type=_attr(tag.get("type"), "text"))
            for tag in form.find_all(["input", "textarea", "select"])
            if tag.get("name")
        ]
        forms.append(Form(action=action, method=method, inputs=inputs))
    return forms


class Crawler:
    """Breadth-first crawler respecting scope and page limits."""

    def __init__(
        self,
        client: SafeHttpClient,
        scope: ScopePolicy,
        max_depth: int,
        max_pages: int,
        seed_urls: list[str] | None = None,
    ) -> None:
        self.client = client
        self.scope = scope
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.seed_urls = seed_urls or []

    async def crawl(self, start_url: str) -> list[HttpObservation]:
        """Crawl pages and return fetched observations."""

        return [observation async for observation in self.iter_crawl(start_url)]

    async def iter_crawl(self, start_url: str) -> AsyncIterator[HttpObservation]:
        """Yield fetched observations as soon as each page is crawled."""

        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        for seed in self.seed_urls:
            queue.append((seed, 1))
        seen: set[str] = set()

        while queue and len(seen) < self.max_pages:
            url, depth = queue.popleft()
            if url in seen or depth > self.max_depth or not self.scope.allowed(url):
                continue
            seen.add(url)
            observation = await self.client.get(url)
            yield observation
            if observation.status_code >= 400:
                continue
            for link in parse_links(url, observation.response_text):
                if link not in seen and self.scope.allowed(link):
                    queue.append((link, depth + 1))
