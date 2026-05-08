# VulnScope Documentation

VulnScope is a TUI-first vulnerability scanner focused on safe web checks and registry-based YAML rules.

## Start Here

1. `docs/architecture.md` - full architecture and data flow.
2. `docs/scanner.md` - how the safe scan pipeline works.
3. `docs/rules.md` - rule schema and matcher mechanics.
4. `docs/security-model.md` - safety boundaries and constraints.

## Documentation Map

- `docs/architecture.md`: components, boundaries, and sequence diagrams.
- `docs/scanner.md`: scope, crawl, payload checks, scan events.
- `docs/rules.md`: YAML schema, registries, remote feeds, matching.
- `docs/reports.md`: HTML/JSON/Markdown export and data structure.
- `docs/tui.md`: screens, navigation, profile workflows, shortcuts.
- `docs/configuration.md`: full YAML + env overrides.
- `docs/cli.md`: CLI commands and options.
- `docs/development.md`: development and testing workflow.
- `docs/deployment.md`: local and container deployment.
- `docs/security-model.md`: safe-by-design restrictions.

## Typical Flows

### First Run

1. Configure `vulnscope.yaml` (or use defaults).
2. Run `vulnscope doctor`.
3. Open TUI (`vulnscope`) and run New Scan.
4. Review findings and export a report.

### Rule Authoring

1. Add a YAML rule under `rules/<registry>/`.
2. Validate loading via `vulnscope update`.
3. If needed, run a local feed with `vulnscope serve`.
4. Run a scan and verify the reports.

### Team Usage

1. Standardize profile sets in `profiles`.
2. Connect a centralized remote feed.
3. Use JSON export for automation and HTML/MD for reporting.
