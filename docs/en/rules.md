# Rules

## Rule Registries

Rules are grouped by registry (for example `web`, `fingerprints`, or remote registries). Finding source is always the registry name.

## Rule Schema

YAML rule document fields:
- `id` (string, unique)
- `title` (string)
- `description` (string)
- `category` (string)
- `severity` (`critical|high|medium|low|info`)
- `confidence_base` (0-100)
- `match` object (`type` plus matcher-specific fields)
- `recommendation` (string)

Optional fields: `cwe`, `tags`, `payloads`, `references`, `safe`, `enabled`.

Supported matchers: `contains_any`, `contains_all`, `regex`, `reflected_without_encoding`, `missing_header`, `insecure_cookie`, `status_code_changed`, `response_length_delta`, `server_error`, `technology_detected`.

## Creating Custom Rule (Step by Step)

1. Choose registry folder.
- Local: put file in `rules/<registry>/`.
- Example: `rules/web/my_custom_rule.yaml`.

2. Create YAML rule.

```yaml
id: XSS_REFLECTED_CUSTOM_001
title: Reflected XSS marker in response
description: Payload is reflected without output encoding.
category: xss
severity: high
confidence_base: 85
match:
  type: reflected_without_encoding
recommendation: Encode output and use strict template escaping.
safe: true
enabled: true
```

3. Validate.
- Run `vulnscope doctor`.
- Loader validates schema and duplicate IDs.

4. Run scan and verify source.
- Start scan in TUI.
- Findings from this file will show source equal to the registry (`web` in this example).

## Remote Rule Feed

Use `vulnscope serve` in a workspace that has `rules/` directory.

```bash
vulnscope serve --ip 127.0.0.1 --port 8080
vulnscope serve --path ./rules
```

Feed endpoints:
- `/` JSON index when `Accept: application/json`.
- `/` styled HTML index with search otherwise.
- `/rules/<registry>/<file>.yaml` raw YAML for machine clients, styled HTML for browser clients.

Feed hash metadata:
- Index includes `feed_hash` for the full feed content.
- Every rule entry includes `hash` for rule payload content.
- Client cache compares `feed_hash` first; if changed, it compares per-rule `hash` and downloads only changed rules.

## Remote Feed Selection

In New Scan screen:
- local and remote feeds are shown in a shared hierarchical tree,
- remote feeds are loaded on demand,
- every tree item can be toggled for per-scan rule selection.

Cache layout:
- `~/.vulnscope/cache/remote-feeds/{encoded_url}/index.json`
- `~/.vulnscope/cache/remote-feeds/{encoded_url}/rules/...`
