# VulnScope

VulnScope is a TUI-first vulnerability scanner for automated discovery of common web application vulnerabilities.

## Features

- TUI-first workflow with dashboard, new scan flow, live scan progress, scan history, and settings.
- Safe DAST scanning with scope restrictions, rate limiting, timeouts, and non-destructive payloads.
- User-defined scan profiles with saved request limits and per-rule selections.
- YAML rule engine with rule registries (`web`, `fingerprints`) and custom rule imports.
- Remote rule feeds with local feed server (`vulnscope serve`) and hash-aware local cache.
- Local-first SQLite scan history.
- Deterministic risk scoring with confidence and exposure modifiers.
- HTML, JSON, and Markdown reports.
- Component detection from headers, meta tags, and JavaScript asset patterns.

## Comparison

| Feature | VulnScope | Traditional DAST (e.g., ZAP, Burp) | Template-based Scanners (e.g., Nuclei) |
| :--- | :--- | :--- | :--- |
| **Primary Interface** | **TUI-first** (Interactive Terminal) | Heavy GUI / Web UI | CLI-only |
| **Safety Model** | **Safe-by-Design** (GET-only, no destructive actions) | Full-spectrum (can be destructive if misconfigured) | Depends on templates (can be aggressive) |
| **Rule Definition** | **Declarative YAML** (Registry-based) | Scripted / Manual / Plugin-based | YAML Templates |
| **Rule Distribution** | **Remote Feeds** (Hash-based sync) | Manual updates / Plugin store | Community-driven YAML repos |
| **Crawl Strategy** | BFS with strict scope enforcement | Complex spidering / Manual proxying | Usually target-list based (no deep crawl) |
| **Fingerprinting** | Integrated YAML-based component detection | Heuristic / Manual | Template-based detection |
| **CI/CD Integration** | Headless CLI $\rightarrow$ JSON/HTML/MD | API-driven / Heavy containers | Lightweight CLI $\rightarrow$ JSON/Text |
| **State Management** | Local SQLite Repository (Reproducible) | Session-based / Project files | Usually stateless (output to file) |

## Quick Start

```bash
pipx install vulnscope
vulnscope
```

From source:

```bash
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
vulnscope
```

## Basic Usage

```bash
vulnscope
vulnscope scan https://example.local
vulnscope doctor
vulnscope update
vulnscope serve --ip 127.0.0.1 --port 8080
vulnscope serve --path ./rules
vulnscope import ./report.json
```

## Rules

Local rules live under `rules/` and are grouped by registry (for example `rules/web` and `rules/fingerprints`).

Remote feeds expose an index and raw YAML rule pages. The client caches remote indexes and rules in `~/.vulnscope/cache/remote-feeds/` (or custom cache path via CLI override).

See [rules documentation](docs/rules.md).

## Documentation

- [Architecture](docs/architecture.md)
- [CLI](docs/cli.md)
- [TUI](docs/tui.md)
- [Scanner](docs/scanner.md)
- [Rules](docs/rules.md)
- [Reports](docs/reports.md)
- [Configuration](docs/configuration.md)
- [Deployment](docs/deployment.md)
- [Security Model](docs/security-model.md)
- [Development](docs/development.md)

## License

MIT. See [LICENSE](LICENSE).
