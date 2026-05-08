"""URL normalization and parsing helpers."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


def normalize_url(url: str) -> str:
    """Normalize a user supplied HTTP(S) URL."""

    raw = url.strip()
    if not raw:
        raise ValueError("URL is empty")
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https targets are supported")
    if not parsed.netloc:
        raise ValueError("URL must include a host")
    path = parsed.path or "/"
    netloc = parsed.netloc.lower()
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), netloc, path, "", query, ""))


def absolute_url(base_url: str, href: str) -> str | None:
    """Resolve an href against a base URL and keep only HTTP(S) URLs."""

    if not href or href.startswith(("mailto:", "tel:", "javascript:")):
        return None
    resolved = urljoin(base_url, href)
    parsed = urlparse(resolved)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return normalize_url(resolved)


def query_parameters(url: str) -> dict[str, str]:
    """Return decoded query parameters for a URL."""

    return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))


def replace_query_param(url: str, name: str, value: str) -> str:
    """Return URL with one query parameter replaced."""

    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[name] = value
    return urlunparse(parsed._replace(query=urlencode(params)))

