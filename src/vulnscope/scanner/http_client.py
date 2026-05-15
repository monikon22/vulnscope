"""Async HTTP client with safe defaults and redaction."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from vulnscope.domain.models import RequestRecord
from vulnscope.utils.text import compact, redact_secrets


@dataclass(slots=True)
class HttpObservation:
    """HTTP response plus metadata used by analyzers and rule matchers."""

    method: str
    url: str
    status_code: int
    response_headers: dict[str, str]
    response_text: str
    duration_ms: float
    size_bytes: int
    request_preview: str = ""
    response_preview: str = ""
    parameter: str | None = None
    payload: str | None = None
    baseline_status_code: int | None = None
    baseline_size: int | None = None

    def to_record(self) -> RequestRecord:
        """Convert to a storable traffic record."""

        return RequestRecord(
            method=self.method,
            url=self.url,
            status_code=self.status_code,
            duration_ms=self.duration_ms,
            size_bytes=self.size_bytes,
            response_headers=self.response_headers,
            request_preview=self.request_preview,
            response_preview=self.response_preview,
        )


@dataclass(slots=True)
class SafeHttpClient:
    """Small httpx wrapper that enforces timeout, UA, and safe previews."""

    timeout: float = 10.0
    user_agent: str = "VulnScope/0.1"
    headers: dict[str, str] = field(default_factory=dict)
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)

    async def close(self) -> None:
        """Close the underlying HTTP session."""

        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get(self, url: str) -> HttpObservation:
        """Perform a GET request and return a normalized observation."""

        return await self.request("GET", url)

    async def post(self, url: str, data: dict[str, str]) -> HttpObservation:
        """Perform a form POST request and return a normalized observation."""

        return await self.request("POST", url, data=data)

    async def request(
        self,
        method: str,
        url: str,
        *,
        data: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> HttpObservation:
        """Perform an HTTP request and return a normalized observation."""

        request_headers = {"User-Agent": self.user_agent, **self.headers}
        started = time.perf_counter()
        try:
            response = await self._session(request_headers).request(
                method,
                url,
                data=data,
                json=json,
            )
        except httpx.HTTPError as exc:
            elapsed = (time.perf_counter() - started) * 1000
            return HttpObservation(
                method=method.upper(),
                url=url,
                status_code=0,
                response_headers={},
                response_text="",
                duration_ms=elapsed,
                size_bytes=0,
                request_preview=redact_secrets(
                    f"{method.upper()} {url}\n{request_headers}\n\n{data or json or ''}"
                ),
                response_preview=f"Network error: {exc}",
            )

        elapsed = (time.perf_counter() - started) * 1000
        text = response.text
        return HttpObservation(
            method=method.upper(),
            url=str(response.url),
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_text=text,
            duration_ms=elapsed,
            size_bytes=len(response.content),
            request_preview=redact_secrets(
                f"{method.upper()} {url}\n{request_headers}\n\n{data or json or ''}"
            ),
            response_preview=redact_secrets(
                f"HTTP {response.status_code}\n{dict(response.headers)}\n\n{compact(text, 1500)}"
            ),
        )

    def _session(self, request_headers: dict[str, str]) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=True,
                headers=request_headers,
            )
        return self._client
