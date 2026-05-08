from pathlib import Path

from vulnscope.domain.models import Target
from vulnscope.scanner.crawler import Crawler, parse_forms, parse_links
from vulnscope.scanner.http_client import HttpObservation
from vulnscope.scanner.scope import ScopePolicy


def test_crawler_parses_links_and_forms() -> None:
    html = Path("tests/fixtures/sample.html").read_text(encoding="utf-8")
    links = parse_links("https://example.local/", html)
    forms = parse_forms("https://example.local/", html)
    assert "https://example.local/login?next=%2Fadmin" in links
    assert "https://example.local/search" in links
    assert "https://example.local/api/items?limit=10" in links
    assert "https://example.local/embedded/status" in links
    assert forms[0].action == "https://example.local/search"
    assert {field.name for field in forms[0].inputs} == {"q", "page"}


class FakeClient:
    pages = {
        "https://example.local/": '<a href="/one">one</a>',
        "https://example.local/one": '<a href="/two">two</a>',
        "https://example.local/two": "done",
    }

    async def get(self, url: str) -> HttpObservation:
        body = self.pages[url]
        return HttpObservation(
            method="GET",
            url=url,
            status_code=200,
            response_headers={},
            response_text=body,
            duration_ms=1,
            size_bytes=len(body),
        )


async def test_crawler_streams_multiple_depths() -> None:
    crawler = Crawler(
        FakeClient(),
        ScopePolicy(Target(url="https://example.local/")),
        max_depth=2,
        max_pages=10,
    )
    urls = [observation.url async for observation in crawler.iter_crawl("https://example.local/")]
    assert urls == [
        "https://example.local/",
        "https://example.local/one",
        "https://example.local/two",
    ]
