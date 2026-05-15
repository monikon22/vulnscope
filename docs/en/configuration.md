# Configuration

Configuration precedence:
1. `VULNSCOPE_CONFIG`
2. `./vulnscope.yaml`
3. `~/.config/vulnscope/vulnscope.yaml`

## Environment Variables

- `VULNSCOPE_CONFIG`: absolute or relative path to a YAML config file.
- `VULNSCOPE_DATABASE_PATH`: override for `app.database_path`.
- `VULNSCOPE_REPORT_DIR`: override for `app.report_dir` and `export.report_dir`.
- `VULNSCOPE_RATE_LIMIT`: override for `scanner.rate_limit`.

## Full YAML Schema

### `app`
- `database_path` (string, default `./data/vulnscope.db`): path to the SQLite database.
- `report_dir` (string, default `./reports`): report directory (base value).

### `scanner`
- `default_profile` (string, default `default`): default scan profile name.
- `rate_limit` (float, default `5.0`): requests per second.
- `timeout` (float, default `10.0`): HTTP request timeout.
- `max_depth` (int, default `2`): BFS crawl depth.
- `max_pages` (int, default `50`): max pages per scan.
- `user_agent` (string, default `VulnScope/0.1`): user agent used by the HTTP client.
- `auth_headers` (map[string,string], default `{}`): HTTP headers for authenticated scans,
  for example `Cookie: PHPSESSID=...; security=low`.

### `rules`
- `paths` (list[string], default `['./rules']`): local paths to YAML rule files/directories.
- `enabled_categories` (list[string], default `[]`): default category filter.
- `enabled_registries` (list[string], default `[]`): default registry filter.
- `remote_feeds` (list[string], default `[]`): list of remote rule-feed URLs.
- `remote_cache_dir` (string|null, default `null`): root directory for remote feed cache.
  If `null`, `~/.vulnscope/cache/remote-feeds` is used.

### `export`
- `default_format` (string, default `html`): default export format (`html|json|markdown`).
- `report_dir` (string, default `./reports`): export output directory.
- `include_http_evidence` (bool, default `true`): compatibility flag retained in config for UI/export usage.
- `include_response_bodies` (bool, default `false`): flag used by JSON export body truncation scenarios.
- `json_pretty` (bool, default `true`): pretty-print JSON (`indent=2`).
- `html_theme` (string, default `dark`): HTML report theme (`dark|light|academic`).

### `profiles`

User-defined scan profiles map:

`profiles.<name>`:
- `rate_limit` (float, default `5.0`)
- `max_depth` (int, default `2`)
- `max_pages` (int, default `50`)
- `enabled_registries` (list[string], default `[]`)
- `enabled_categories` (list[string], default `[]`)
- `enabled_rule_ids` (list[string], default `[]`)
- `enabled_rule_refs` (list[string], default `[]`, format `source::rule_id`)
- `remote_feeds` (list[string], default `[]`)

## Runtime ScanConfig (effective, per scan)

In addition to YAML settings, an effective `ScanConfig` is created per scan run:

- `target.url`
- `target.scope_mode` (`same_host|same_domain|custom`)
- `target.include_patterns` / `target.exclude_patterns`
- `profile`
- `rate_limit`, `timeout`, `max_depth`, `max_pages`, `user_agent`
- `dependency_audit`
- `auth_headers`
- `enabled_registries`, `enabled_categories`, `enabled_rule_ids`, `enabled_rule_refs`
- `remote_feeds`

These fields are serialized to `scan.metadata.config` and shown in Scan Detail.

## Complete Example

```yaml
app:
	database_path: ./data/vulnscope.db
	report_dir: ./reports

scanner:
	default_profile: default
	rate_limit: 5
	timeout: 10
	max_depth: 2
	max_pages: 50
	user_agent: "VulnScope/0.1"
	auth_headers: {}

rules:
	paths:
		- ./rules
	enabled_categories: []
	enabled_registries: []
	remote_feeds:
		- http://127.0.0.1:8080
	remote_cache_dir: null

profiles:
	default:
		rate_limit: 5
		max_depth: 2
		max_pages: 50
		enabled_registries: []
		enabled_categories: []
		enabled_rule_ids: []
		enabled_rule_refs: []
		remote_feeds: []

export:
	default_format: html
	report_dir: ./reports
	include_http_evidence: true
	include_response_bodies: false
	json_pretty: true
	html_theme: dark
```

See `examples/vulnscope.yaml` for a complete configuration with scanner, rules, profiles, and export settings.
