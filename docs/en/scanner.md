# Scanner

The scanner normalizes targets, enforces same-host or same-domain scope, crawls pages breadth-first, collects links and forms, identifies request parameters, sends bounded safe payload probes, and emits events for the TUI.

Profiles tune request volume and check types. Safe Scan is the default. The scanner does not brute force, delete data, execute commands, or attempt post-detection exploitation.

## Scanner Runtime Flow

```mermaid
flowchart TD
		A[ScanConfig] --> B[Normalize URL]
		B --> C[ScopePolicy]
		C --> D[Crawler BFS]
		D --> E[HttpObservation]
		E --> F[Component Analyzer]
		E --> G[RuleEngine]
		D --> H[Payload Probes]
		H --> I[Tested Observation]
		I --> G
		F --> J[Components]
		G --> K[Findings]
		E --> L[Traffic]
		J --> M[Scan Aggregate]
		K --> M
		L --> M
		M --> N[Scan events + persistence]
```

## Safety And Scope

- Only `http/https` targets are supported.
- Scope policy:
	- `same_host` (default): only the same host.
	- `same_domain`: the same registrable domain.
	- `custom`: include/exclude glob patterns.
- The crawler ignores out-of-scope URLs.
- Checks skip obviously destructive forms such as password-change, upload, setup, reset,
  create, and delete flows.

## Crawl Behavior


- Strategy: breadth-first search (BFS).
- Limits: `max_depth`, `max_pages`.
- URL sources:
	- starting target,
	- HTML links/assets/forms,
	- simple endpoint strings from inline JavaScript.
- Error responses (>=400) do not expand the link graph further.

## Payload Probing

- Payload checks are executed for query parameters and non-destructive GET/POST forms.
- Form probes preserve hidden/default/select/submit values so CSRF-protected training apps
  and PHP forms reach the intended handler.
- If no query parameters exist, a context-aware probe parameter set is used (for example
  `id`, `q`, `search`, `redirect`, `url`, `file`).
- Baseline fields are saved per check (`baseline_status_code`, `baseline_size`).
- Rate limiting applies: pause of $1 / rate\_limit$ seconds between checks.

## Profiles

Profiles are saved scan presets from configuration. Profile names are custom labels, not a
fixed enum, and the scanner does not branch on profile names at runtime.

Payload checks use the default safe payload set for every profile. Scope, rate limit,
page limits, rule selections, and remote feeds come from the selected saved profile.

## Scan Events (for TUI)

`ScannerEngine.run_events` emits events:

- `started`: scan started.
- `page`: crawler page processed.
- `check`: payload probe processed.
- `completed`: final status.

Each event contains the current `scan` snapshot.

## Pause/Resume/Stop

- `pause()`: temporarily pauses progress without losing state.
- `resume()`: resumes the scan loop.
- `stop()`: gracefully stops a scan with status `stopped`.

## Component Detection

Component sources:
- HTTP headers (`Server`, `X-Powered-By`).
- HTML (`meta generator`, title heuristics).
- JS assets (library patterns).
- YAML fingerprints (`rules/fingerprints/*`).

Results are deduplicated by `(name, version, source)`.

## Finding Deduplication

During scan execution, duplicate findings are filtered by key:
- source,
- rule_id/title,
- URL (without query for most categories),
- parameter,
- payload,
- evidence fragment.

This reduces noise and duplicates in reports and TUI.
