"""HTTP server for exposing local YAML rules as a remote feed."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

import yaml

from vulnscope.rules.feed import (
    build_local_index,
    feed_index_as_json,
    render_index_html,
    render_rule_html,
    wants_json,
)


def serve_rules(root: Path, host: str, port: int) -> None:
    index = build_local_index(root)
    routes: dict[str, Path] = {}
    for registry in index.get("registries", []):
        for rule in registry.get("rules", []):
            routes[str(rule["path"])] = root / str(rule["relative_path"])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = unquote(self.path.split("?", 1)[0])
            accept = self.headers.get("Accept")
            if path == "/" or path == "":
                if wants_json(accept):
                    self._write(200, "application/json; charset=utf-8", feed_index_as_json(index))
                    return
                self._write(200, "text/html; charset=utf-8", render_index_html(index))
                return
            file = routes.get(path)
            if not file or not file.exists():
                self._write(404, "application/json; charset=utf-8", json.dumps({"error": "Not found"}))
                return
            content = file.read_text(encoding="utf-8")
            docs = yaml.safe_load(content)
            docs = docs if isinstance(docs, list) else [docs]
            first = docs[0] if docs and isinstance(docs[0], dict) else {}
            title = str(first.get("title") or first.get("id") or file.stem)
            description = str(first.get("description") or "")
            if wants_json(accept) or "yaml" in (accept or "").lower():
                self._write(200, "application/x-yaml; charset=utf-8", content)
                return
            self._write(200, "text/html; charset=utf-8", render_rule_html(title, description, content))

        def log_message(self, format: str, *args: object) -> None:
            return

        def _write(self, status: int, content_type: str, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()
