"""Minimal Typer CLI for VulnScope."""

from __future__ import annotations

import json
import platform
import sqlite3
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from vulnscope.config import ScanProfileSettings, load_settings, save_settings
from vulnscope.domain.models import Scan
from vulnscope.rules.loader import RuleLoader
from vulnscope.rules.server import serve_rules
from vulnscope.storage.database import init_database
from vulnscope.storage.repositories import ScanRepository
from vulnscope.tui.main import run_tui

console = Console()
app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="VulnScope opens the interactive TUI by default.",
    invoke_without_command=True,
)
profiles_app = typer.Typer(help="Manage saved scan profiles.")
app.add_typer(profiles_app, name="profiles")


@app.callback()
def default(ctx: typer.Context) -> None:
    """Open the TUI dashboard when no subcommand is provided."""

    if ctx.invoked_subcommand is None:
        run_tui()


@app.command()
def scan(target: str, profile: Annotated[str | None, typer.Option("--profile")] = None) -> None:
    """Open the TUI and prefill a scan target."""

    run_tui(initial_target=target, initial_profile=profile)


@app.command("import")
def import_report(file: Path) -> None:
    """Import a previous JSON scan report into local history."""

    settings = load_settings()
    data = json.loads(file.read_text(encoding="utf-8"))
    scan = Scan.model_validate(data)
    sessions = init_database(settings.app.database_path)
    from sqlalchemy.orm import Session

    with Session(sessions) as session:
        ScanRepository(session).save(scan)
    console.print(f"[green]Imported scan[/] {scan.id} for {scan.target}")


@app.command()
def doctor() -> None:
    """Check runtime, rules, database, and report output path."""

    settings = load_settings()
    table = Table(title="VulnScope Doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Details")

    python_ok = sys.version_info >= (3, 12)
    table.add_row("Python", "OK" if python_ok else "FAIL", platform.python_version())
    table.add_row(
        "Terminal",
        "OK" if console.is_terminal else "WARN",
        f"color={console.color_system}",
    )

    try:
        sqlite3.connect(":memory:").close()
        init_database(settings.app.database_path)
        table.add_row("SQLite database", "OK", settings.app.database_path)
    except sqlite3.Error as exc:
        table.add_row("SQLite database", "FAIL", str(exc))

    try:
        rules = RuleLoader(
            settings.rules.paths,
            remote_cache_dir=settings.rules.remote_cache_dir,
        ).load()
        table.add_row("Rules", "OK", f"{len(rules)} loaded")
    except Exception as exc:
        table.add_row("Rules", "FAIL", str(exc))

    report_dir = Path(settings.export.report_dir)
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        probe = report_dir / ".vulnscope-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        table.add_row("Report directory", "OK", str(report_dir))
    except OSError as exc:
        table.add_row("Report directory", "FAIL", str(exc))

    console.print(table)


@app.command()
def update(cache_dir: Annotated[Path | None, typer.Option("--cache-dir")] = None) -> None:
    """Validate configured remote rule feeds and count discovered rules."""

    settings = load_settings()
    effective_cache_dir = cache_dir or settings.rules.remote_cache_dir
    loader = RuleLoader(settings.rules.paths, remote_cache_dir=effective_cache_dir)
    local_count = len(loader.load())
    remote_count = len(
        loader.load_remote_feeds(
            settings.rules.remote_feeds,
            registries=set(settings.rules.enabled_registries),
            categories=set(settings.rules.enabled_categories),
        )
    )
    console.print(f"Local rules: {local_count}")
    console.print(f"Remote rules: {remote_count}")
    if effective_cache_dir:
        console.print(f"Remote feed cache: {Path(effective_cache_dir).expanduser()}")


@app.command()
def serve(
    ip: str = "127.0.0.1",
    port: int = 8080,
    path: Annotated[Path | None, typer.Option("--path")] = None,
) -> None:
    """Serve local rules as remote registry feed."""

    root = path or (Path.cwd() / "rules")
    if not root.exists():
        raise typer.BadParameter(f"rules directory not found: {root}")
    if not root.is_dir():
        raise typer.BadParameter(f"rules path must be a directory: {root}")
    console.print(f"Serving rules from {root} at http://{ip}:{port}")
    serve_rules(root, ip, port)


@profiles_app.command("list")
def list_profiles() -> None:
    """List saved scan profiles."""

    settings = load_settings()
    table = Table(title="Scan profiles")
    table.add_column("Name")
    table.add_column("Rate")
    table.add_column("Depth")
    table.add_column("Pages")
    table.add_column("Rules")
    table.add_column("Remote feeds")
    for name, profile in sorted(settings.profiles.items()):
        table.add_row(
            name,
            str(profile.rate_limit),
            str(profile.max_depth),
            str(profile.max_pages),
            str(len(profile.enabled_rule_refs)),
            str(len(profile.remote_feeds)),
        )
    console.print(table)


@profiles_app.command("create")
def create_profile(
    name: str,
    rate_limit: Annotated[float, typer.Option("--rate-limit")] = 5.0,
    max_depth: Annotated[int, typer.Option("--max-depth")] = 2,
    max_pages: Annotated[int, typer.Option("--max-pages")] = 50,
    registry: Annotated[list[str] | None, typer.Option("--registry")] = None,
    category: Annotated[list[str] | None, typer.Option("--category")] = None,
    rule_id: Annotated[list[str] | None, typer.Option("--rule-id")] = None,
    rule_ref: Annotated[list[str] | None, typer.Option("--rule-ref")] = None,
    remote_feed: Annotated[list[str] | None, typer.Option("--remote-feed")] = None,
    default: Annotated[bool, typer.Option("--default")] = False,
) -> None:
    """Create or replace a saved scan profile."""

    settings = load_settings()
    settings.profiles[name] = ScanProfileSettings(
        rate_limit=rate_limit,
        max_depth=max_depth,
        max_pages=max_pages,
        enabled_registries=list(registry or []),
        enabled_categories=list(category or []),
        enabled_rule_ids=list(rule_id or []),
        enabled_rule_refs=list(rule_ref or []),
        remote_feeds=list(remote_feed or []),
    )
    if default:
        settings.scanner.default_profile = name
    path = save_settings(settings)
    console.print(f"[green]Saved profile[/] {name} to {path}")


@profiles_app.command("delete")
def delete_profile(name: str) -> None:
    """Delete a saved scan profile."""

    settings = load_settings()
    if name not in settings.profiles:
        raise typer.BadParameter(f"Unknown profile: {name}")
    if len(settings.profiles) == 1:
        raise typer.BadParameter("At least one profile must remain")
    del settings.profiles[name]
    if settings.scanner.default_profile == name:
        settings.scanner.default_profile = sorted(settings.profiles)[0]
    path = save_settings(settings)
    console.print(f"[green]Deleted profile[/] {name} from {path}")


@profiles_app.command("default")
def set_default_profile(name: str) -> None:
    """Set the default scan profile."""

    settings = load_settings()
    if name not in settings.profiles:
        raise typer.BadParameter(f"Unknown profile: {name}")
    settings.scanner.default_profile = name
    path = save_settings(settings)
    console.print(f"[green]Default profile[/] {name} saved to {path}")


def main() -> None:
    """Console script entry point."""

    app()
