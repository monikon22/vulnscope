# CLI

`vulnscope` opens the TUI dashboard.

Commands:
- `vulnscope scan <url>`: open TUI with target prefilled.
- `vulnscope import <file>`: import JSON scan history.
- `vulnscope doctor`: check runtime, SQLite, rules, and report directory.
- `vulnscope update [--cache-dir <path>]`: validate configured remote feeds and report discovered local/remote rule counts.
- `vulnscope serve [--ip] [--port] [--path <dir>]`: start local web server that publishes rule registries and raw YAML rules.
- `vulnscope profiles ...`: list/create/delete/default profile commands.

`vulnscope serve` behavior:
- `GET /` with `Accept: application/json` returns JSON index of registries and rules.
- `GET /` without JSON accept returns styled HTML index with search.
- Rule links open raw YAML when the client requests YAML/JSON, otherwise a styled HTML page with copy button.
- Feed JSON includes rule hashes and a full feed hash for client-side cache checks.

Remote feed cache:
- Default cache root: `~/.vulnscope/cache/remote-feeds`.
- `vulnscope update --cache-dir ./cache` overrides cache root for the command run.
