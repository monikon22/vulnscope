from vulnscope.domain.models import Target
from vulnscope.rules.engine import RuleEngine
from vulnscope.scanner.engine import ScannerEngine
from vulnscope.scanner.http_client import HttpObservation


def observation(url: str, body: str) -> HttpObservation:
    return HttpObservation(
        method="GET",
        url=url,
        status_code=200,
        response_headers={},
        response_text=body,
        duration_ms=1,
        size_bytes=len(body),
    )


class FormClient:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict[str, str]]] = []

    async def get(self, url: str) -> HttpObservation:
        return observation(url, "ok")

    async def post(self, url: str, data: dict[str, str]) -> HttpObservation:
        self.posts.append((url, data))
        return HttpObservation(
            method="POST",
            url=url,
            status_code=500 if data.get("id") == "'" else 200,
            response_headers={},
            response_text="SQL syntax error" if data.get("id") == "'" else "ok",
            duration_ms=1,
            size_bytes=16,
        )


async def test_engine_probes_post_forms_with_defaults() -> None:
    html = """
    <form action="/vulnerabilities/sqli/" method="post">
      <input type="hidden" name="user_token" value="token-1">
      <select name="id"><option value="1">1</option></select>
      <input type="submit" name="Submit" value="Submit">
    </form>
    """
    engine = ScannerEngine(RuleEngine([]))
    client = FormClient()

    observations = [
        item
        async for item in engine._payload_observations(
            client,
            observation("https://dvwa.local/vulnerabilities/sqli/", html),
            Target(url="https://dvwa.local/"),
            ["'"],
        )
    ]

    post_observations = [item for item in observations if item.method == "POST"]

    assert post_observations[0].parameter == "id"
    assert client.posts[0] == (
        "https://dvwa.local/vulnerabilities/sqli/",
        {"user_token": "token-1", "id": "'", "Submit": "Submit"},
    )
