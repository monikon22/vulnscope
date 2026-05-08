"""Remote rule feed index and local feed server helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urljoin

import httpx
import yaml


@dataclass(slots=True)
class RuleEntry:
    registry: str
    rule_id: str
    name: str
    description: str
    category: str
    relative_path: str


def default_remote_feed_cache_root() -> Path:
    return Path.home() / ".vulnscope" / "cache" / "remote-feeds"


def resolve_remote_feed_cache_root(cache_root: str | Path | None = None) -> Path:
    return (
        Path(cache_root) if cache_root is not None else default_remote_feed_cache_root()
    ).expanduser()


def cache_dir_for_feed(feed_url: str, cache_root: str | Path | None = None) -> Path:
    return resolve_remote_feed_cache_root(cache_root) / quote(feed_url, safe="")


def load_cached_feed_index(
    feed_url: str, cache_root: str | Path | None = None
) -> dict[str, object] | None:
    index_path = cache_dir_for_feed(feed_url, cache_root) / "index.json"
    if not index_path.exists():
        return None
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def save_cached_feed_index(
    feed_url: str,
    index_payload: dict[str, object],
    cache_root: str | Path | None = None,
) -> None:
    cache_dir = cache_dir_for_feed(feed_url, cache_root)
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "index.json").write_text(
        json.dumps(index_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def load_cached_feed_rule_yaml(
    feed_url: str,
    path: str,
    cache_root: str | Path | None = None,
) -> str | None:
    rule_path = cache_dir_for_feed(feed_url, cache_root) / "rules" / _cache_rule_relative_path(path)
    if not rule_path.exists():
        return None
    try:
        return rule_path.read_text(encoding="utf-8")
    except Exception:
        return None


def save_cached_feed_rule_yaml(
    feed_url: str,
    path: str,
    content: str,
    cache_root: str | Path | None = None,
) -> None:
    rule_path = cache_dir_for_feed(feed_url, cache_root) / "rules" / _cache_rule_relative_path(path)
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(content, encoding="utf-8")


def build_local_index(root: Path) -> dict[str, object]:
    registries: dict[str, dict[str, object]] = {}
    seen: set[tuple[str, str]] = set()
    required_rule_keys = {
        "id",
        "title",
        "description",
        "severity",
        "confidence_base",
        "match",
        "recommendation",
    }
    for file in sorted(root.rglob("*.yaml")):
        rel = file.relative_to(root)
        parts = rel.parts
        if not parts:
            continue
        registry = parts[0]
        file_text = file.read_text(encoding="utf-8")
        file_hash = _sha256_text(file_text)
        docs = yaml.safe_load(file_text)
        docs = docs if isinstance(docs, list) else [docs]
        if not docs:
            docs = [{}]
        for item in docs:
            if not isinstance(item, dict):
                continue
            is_rule = required_rule_keys.issubset(item.keys())
            rule_id = str(item.get("id") or file.stem)
            unique_key = (registry.lower(), rule_id.lower())
            if unique_key in seen:
                continue
            seen.add(unique_key)
            title = str(item.get("title") or rule_id)
            description = str(item.get("description") or "")
            category = str(item.get("category") or "uncategorized")
            registry_bucket = registries.setdefault(
                registry,
                {"name": registry, "rules": []},
            )
            registry_bucket["rules"].append(
                {
                    "id": rule_id,
                    "name": title,
                    "description": description,
                    "category": category,
                    "kind": "rule" if is_rule else "uncategorized",
                    "relative_path": str(rel).replace("\\", "/"),
                    "path": f"/rules/{registry}/{file.name}",
                    "hash": file_hash,
                }
            )
    sorted_registries = sorted(registries.values(), key=lambda item: str(item["name"]).lower())
    feed_hash = _hash_feed_payload(sorted_registries)
    return {"feed_hash": feed_hash, "registries": sorted_registries}


def wants_json(accept_header: str | None) -> bool:
    value = (accept_header or "").lower()
    return "application/json" in value or "json" in value


def render_index_html(index_payload: dict[str, object]) -> str:
    cards: list[str] = []
    for registry in index_payload.get("registries", []):
        name = str(registry.get("name", "registry"))
        rules = registry.get("rules", [])
        items = "".join(
            (
                f"<li><a href='{rule['path']}'>{rule['name']}</a>"
                f" <small>({rule['category']})</small><br>{rule['description']}</li>"
            )
            for rule in rules
        )
        cards.append(f"<section><h2>{name}</h2><ul>{items}</ul></section>")
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>VulnScope Rule Feed</title>"
        "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;background:#0b1220;color:#e5e7eb;}"
        "a{color:#7dd3fc;}section{background:#111827;padding:1rem;border-radius:12px;margin-bottom:1rem;}"
        "input{padding:.6rem;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e5e7eb;width:100%;max-width:720px;}"
        "li{margin:.65rem 0;}</style>"
        "<script>function filterRules(){const q=document.getElementById('q').value.toLowerCase();"
        "document.querySelectorAll('li').forEach(li=>li.style.display=li.innerText.toLowerCase().includes(q)?'':'none');}</script>"
        "</head><body><h1>VulnScope Rule Feed</h1><p>Available registries and YAML rules.</p>"
        "<input id='q' oninput='filterRules()' placeholder='Search by name, category, description'>"
        f"{''.join(cards)}</body></html>"
    )


def render_rule_html(title: str, description: str, content: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Rule</title>"
        "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;background:#0b1220;color:#e5e7eb;}"
        "pre{background:#111827;border:1px solid #334155;padding:1rem;border-radius:12px;overflow:auto;}"
        "button{padding:.5rem .8rem;border-radius:8px;border:0;background:#0284c7;color:#fff;cursor:pointer;}</style>"
        "<script>function copyCode(){navigator.clipboard.writeText(document.getElementById('rule').innerText);}</script>"
        f"</head><body><h1>{title}</h1><p>{description}</p><button onclick='copyCode()'>Copy YAML</button>"
        f"<pre id='rule'>{content}</pre></body></html>"
    )


def fetch_remote_index(feed_url: str) -> dict[str, object]:
    response = httpx.get(
        feed_url.rstrip("/") + "/", headers={"Accept": "application/json"}, timeout=15
    )
    response.raise_for_status()
    return response.json()


def fetch_remote_rule_yaml(feed_url: str, path: str) -> str:
    url = urljoin(feed_url.rstrip("/") + "/", path.lstrip("/"))
    response = httpx.get(url, headers={"Accept": "application/x-yaml"}, timeout=15)
    response.raise_for_status()
    return response.text


def feed_index_as_json(index_payload: dict[str, object]) -> str:
    return json.dumps(index_payload, ensure_ascii=False, indent=2)


def _cache_rule_relative_path(path: str) -> Path:
    normalized = path.strip().replace("\\", "/").lstrip("/")
    if normalized.startswith("rules/"):
        normalized = normalized.split("rules/", 1)[1]
    return Path(normalized)


def _sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _hash_feed_payload(registries: list[dict[str, object]]) -> str:
    digest_items: list[str] = []
    for registry in registries:
        name = str(registry.get("name", "")).strip()
        rules = registry.get("rules", [])
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            digest_items.append(
                "|".join(
                    [
                        name,
                        str(rule.get("id", "")).strip(),
                        str(rule.get("path", "")).strip(),
                        str(rule.get("hash", "")).strip(),
                    ]
                )
            )
    digest_items.sort()
    return _sha256_text("\n".join(digest_items))
