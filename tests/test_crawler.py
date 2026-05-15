from pathlib import Path

from vulnscope.domain.models import Target
from vulnscope.scanner.crawler import Crawler, parse_forms, parse_javascript_endpoints, parse_links
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


def test_crawler_preserves_form_control_defaults() -> None:
    forms = parse_forms(
        "https://example.local/login.php",
        """
        <form action="login.php" method="post">
          <input type="hidden" name="user_token" value="abc123">
          <input type="text" name="username">
          <select name="id">
            <option value="1">One</option>
            <option value="2" selected>Two</option>
          </select>
          <input type="submit" name="Login" value="Login">
        </form>
        """,
    )

    assert forms[0].method == "POST"
    assert [(field.name, field.input_type, field.value) for field in forms[0].inputs] == [
        ("user_token", "hidden", "abc123"),
        ("username", "text", ""),
        ("id", "select", "2"),
        ("Login", "submit", "Login"),
    ]


def test_crawler_parses_spa_routes_from_javascript() -> None:
    routes = parse_javascript_endpoints(
        "http://localhost:3000/",
        'path:"score-board",path:"address/select",path:"order-completion/:id",'
        'this.router.navigate(["/login"]),path:"**",routerLink:"routerLink","/10"',
    )

    assert "http://localhost:3000/score-board" in routes
    assert "http://localhost:3000/address/select" in routes
    assert "http://localhost:3000/login" in routes
    assert "http://localhost:3000/order-completion/%3Aid" not in routes
    assert "http://localhost:3000/routerLink" not in routes
    assert "http://localhost:3000/10" not in routes


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


async def test_crawler_discovers_routes_from_script_assets() -> None:
    class SpaClient:
        pages = {
            "http://localhost:3000/": '<script src="/main.js"></script>',
            "http://localhost:3000/main.js": 'path:"score-board",navigate(["/login"])',
            "http://localhost:3000/login": "login",
            "http://localhost:3000/score-board": "score",
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

    crawler = Crawler(
        SpaClient(),
        ScopePolicy(Target(url="http://localhost:3000/")),
        max_depth=2,
        max_pages=10,
    )

    urls = [observation.url async for observation in crawler.iter_crawl("http://localhost:3000/")]

    assert "http://localhost:3000/main.js" in urls
    assert "http://localhost:3000/login" in urls
    assert "http://localhost:3000/score-board" in urls


async def test_crawler_checks_pause_callback_before_fetching_next_page() -> None:
    calls = 0

    async def before_fetch() -> bool:
        nonlocal calls
        calls += 1
        return calls == 1

    crawler = Crawler(
        FakeClient(),
        ScopePolicy(Target(url="https://example.local/")),
        max_depth=2,
        max_pages=10,
        before_fetch=before_fetch,
    )
    urls = [observation.url async for observation in crawler.iter_crawl("https://example.local/")]

    assert urls == ["https://example.local/"]
