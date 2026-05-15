"""Textual screens for VulnScope."""
# mypy: ignore-errors

from __future__ import annotations

import asyncio
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, unquote

from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    Select,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)

from vulnscope.config import ScanProfileSettings
from vulnscope.domain.models import Finding, ScanConfig, Target
from vulnscope.reports.exporters import export_scan
from vulnscope.rules.engine import RuleEngine
from vulnscope.rules.feed import build_local_index, fetch_remote_index
from vulnscope.rules.loader import RuleLoader
from vulnscope.scanner.engine import ScannerEngine
from vulnscope.scanner.fingerprints import FingerprintDatabase
from vulnscope.scanner.profiles import profile_from_config
from vulnscope.tui.bindings import SHORTCUTS
from vulnscope.tui.widgets import MetricCard
from vulnscope.utils.urls import normalize_url

LOGO = r"""
__     __     _       ____
\ \   / /   _| |_ __ / ___|  ___ ___  _ __   ___
 \ \ / / | | | | '_ \\___ \ / __/ _ \| '_ \ / _ \
  \ V /| |_| | | | | |___) | (_| (_) | |_) |  __/
   \_/  \__,_|_|_| |_|____/ \___\___/| .__/ \___|
                                     |_|
"""


@dataclass(frozen=True)
class RuleTreeItem:
    id: str
    label: str
    description: str = ""
    category: str = "uncategorized"
    source: str = "local"
    kind: str = "rule"


FINAL_SCAN_STATUSES = {"completed", "stopped"}


class HelpModal(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "[bold cyan]VulnScope 0.1.0[/]\n\n"
                "TUI-first scanner for safe discovery of common web vulnerabilities.\n\n"
                "Use only on systems you own or have explicit permission to test.\n\n"
                + "\n".join(f"[bold]{key}[/]  {value}" for key, value in SHORTCUTS.items()),
                id="help-box",
            ),
            Button("Close", id="close-help"),
            id="modal",
        )

    @on(Button.Pressed, "#close-help")
    def close_help(self) -> None:
        self.dismiss(None)


class FindingDetailModal(ModalScreen[None]):
    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        source_link = ""
        if self.finding.references:
            source_link = self.finding.references[0]
        elif self.finding.source.startswith("http"):
            source_link = self.finding.source
        body = (
            f"[bold]{self.finding.title}[/]\n\n"
            f"Severity: {self.finding.severity.value}\n"
            f"Category: {self.finding.category}\n"
            f"Source: {self.finding.source}\n"
            f"URL: {self.finding.url}\n"
            f"Confidence: {self.finding.confidence}%\n"
            f"Risk: {self.finding.risk_score}\n"
            f"Rule: {self.finding.rule_id or 'n/a'}\n"
            f"CWE: {self.finding.cwe or 'n/a'}\n\n"
            f"Description:\n{self.finding.description or 'n/a'}\n\n"
            f"Evidence:\n{self.finding.evidence or 'n/a'}\n\n"
            f"Recommendation:\n{self.finding.recommendation or 'n/a'}\n\n"
            f"Source link: {source_link or 'n/a'}"
        )
        yield Container(
            VerticalScroll(Static(body, id="finding-detail-box")),
            Button("Close", id="close-detail"),
            id="modal",
        )

    @on(Button.Pressed, "#close-detail")
    def close_modal(self) -> None:
        self.dismiss(None)


class RuleDetailModal(ModalScreen[None]):
    def __init__(self, rule: RuleTreeItem) -> None:
        super().__init__()
        self.rule = rule

    def compose(self) -> ComposeResult:
        body = (
            f"[bold]{self.rule.id}[/]\n\n"
            f"Category: {self.rule.category}\n"
            f"Source: {self.rule.source}\n"
            f"Kind: {self.rule.kind}\n\n"
            f"Description:\n{self.rule.description or 'n/a'}"
        )
        yield Container(
            VerticalScroll(Static(body, id="finding-detail-box")),
            Button("Close", id="close-rule-detail"),
            id="modal",
        )

    @on(Button.Pressed, "#close-rule-detail")
    def close_modal(self) -> None:
        self.dismiss(None)


class DashboardScreen(Screen[None]):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(f"[bold cyan]{LOGO}[/]", id="logo")
        yield Label("Recent Scans", classes="section-title")
        table = DataTable(id="recent-scans")
        table.cursor_type = "row"
        table.add_columns("ID", "Target", "Profile", "Status", "Findings")
        yield table
        yield Horizontal(
            Button("New Scan", id="new-scan", variant="primary"),
            Button("Settings", id="open-settings"),
            classes="actions",
        )
        yield Footer()

    async def on_mount(self) -> None:
        self.refresh_dashboard()
        self.set_interval(1.0, self.refresh_dashboard)

    def refresh_dashboard(self) -> None:
        scans = self.app.controller.recent_scans()
        table = self.query_one("#recent-scans", DataTable)
        table.clear()
        for scan in scans[:10]:
            table.add_row(
                scan.id[:8],
                scan.target,
                scan.profile,
                scan.status,
                str(len(scan.findings)),
                key=scan.id,
            )

    @on(DataTable.RowSelected, "#recent-scans")
    def open_scan_details(self, event: DataTable.RowSelected) -> None:
        row_key = getattr(event.row_key, "value", event.row_key)
        scan = self.app.controller.get_scan(str(row_key))
        if scan:
            self.app.push_screen(ScanDetailScreen(scan.id))

    @on(Button.Pressed, "#new-scan")
    def button_new_scan(self) -> None:
        self.app.push_screen(NewScanScreen())

    @on(Button.Pressed, "#open-settings")
    def button_settings(self) -> None:
        self.app.push_screen(SettingsScreen())


class ScanDetailScreen(Screen[None]):
    def __init__(self, scan_id: str) -> None:
        super().__init__()
        self.scan_id = scan_id
        self._findings: list[Finding] = []
        self._sort_column = "risk"
        self._sort_desc = True

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Scan", classes="screen-title", id="scan-detail-title")
        with TabbedContent(initial="scan-findings-tab"):
            with TabPane("Findings", id="scan-findings-tab"):
                table = DataTable(id="scan-detail-findings")
                table.cursor_type = "cell"
                table.add_columns("Severity", "Title", "Source", "Category", "URL", "Risk")
                yield table
            with TabPane("Scan Settings", id="scan-settings-tab"):
                yield VerticalScroll(Static("", id="scan-config-summary"))
        yield Horizontal(
            Button("Export HTML", id="detail-export-html", variant="primary"),
            Button("Export JSON", id="detail-export-json"),
            Button("Export Markdown", id="detail-export-md"),
            Button("Back", id="detail-back"),
            id="scan-detail-actions",
        )
        yield Footer()

    async def on_mount(self) -> None:
        self.refresh_scan()

    def refresh_scan(self) -> None:
        scan = self.app.controller.get_scan(self.scan_id)
        if not scan:
            self.notify("Scan was not found", severity="error")
            self.app.pop_screen()
            return
        self.query_one("#scan-detail-title", Label).update(
            f"Scan {scan.id[:8]} - {scan.target} ({scan.profile})"
        )
        self.query_one("#scan-config-summary", Static).update(_scan_config_summary(scan.metadata))
        export_visible = scan.status in FINAL_SCAN_STATUSES
        self.query_one("#detail-export-html", Button).display = export_visible
        self.query_one("#detail-export-json", Button).display = export_visible
        self.query_one("#detail-export-md", Button).display = export_visible
        self._findings = list(scan.findings)
        table = self.query_one("#scan-detail-findings", DataTable)
        self._render_rows(table)

    def _export_scan(self, fmt: str) -> None:
        scan = self.app.controller.get_scan(self.scan_id)
        if not scan:
            self.notify("Scan was not found", severity="error")
            return
        path = export_scan(
            scan,
            fmt,
            self.app.settings.export.report_dir,
            theme=self.app.settings.export.html_theme,
            pretty_json=self.app.settings.export.json_pretty,
        )
        self.notify(f"Exported {path}")

    @on(DataTable.RowSelected, "#scan-detail-findings")
    def open_scan_finding_details(self, event: DataTable.RowSelected) -> None:
        row_key = getattr(event.row_key, "value", event.row_key)
        finding = next((item for item in self._findings if item.id == str(row_key)), None)
        if finding:
            self.app.push_screen(FindingDetailModal(finding))

    @on(DataTable.CellSelected, "#scan-detail-findings")
    def open_scan_finding_details_cell(self, event: DataTable.CellSelected) -> None:
        row_index = int(getattr(getattr(event, "coordinate", None), "row", -1))
        finding = self._findings[row_index] if 0 <= row_index < len(self._findings) else None
        if finding:
            self.app.push_screen(FindingDetailModal(finding))

    def _render_rows(self, table: DataTable) -> None:
        self._findings = _sort_findings(self._findings, self._sort_column, self._sort_desc)
        table.clear()
        for finding in self._findings:
            table.add_row(*_finding_row_cells(finding), key=finding.id)

    @on(DataTable.HeaderSelected, "#scan-detail-findings")
    def sort_from_header(self, event: DataTable.HeaderSelected) -> None:
        columns = ["severity", "title", "source", "category", "url", "risk"]
        index = int(getattr(event, "column_index", 5))
        next_col = columns[index] if 0 <= index < len(columns) else "risk"
        if next_col == self._sort_column:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_column = next_col
            self._sort_desc = next_col in {"severity", "risk"}
        self._render_rows(self.query_one("#scan-detail-findings", DataTable))

    @on(Button.Pressed, "#detail-export-html")
    def export_html(self) -> None:
        self._export_scan("html")

    @on(Button.Pressed, "#detail-export-json")
    def export_json(self) -> None:
        self._export_scan("json")

    @on(Button.Pressed, "#detail-export-md")
    def export_md(self) -> None:
        self._export_scan("markdown")

    @on(Button.Pressed, "#detail-back")
    def back(self) -> None:
        self.app.pop_screen()


class NewScanScreen(Screen[None]):
    def __init__(self, target: str | None = None, profile: str | None = None) -> None:
        super().__init__()
        self.initial_target = target or ""
        self.initial_profile = profile
        self._tree_nodes: dict[str, object] = {}
        self._tree_labels: dict[str, str] = {}
        self._checked: dict[str, bool] = {}
        self._rule_refs: dict[str, str] = {}
        self._rule_items: dict[str, RuleTreeItem] = {}
        self._remote_loaded: set[str] = set()
        self._remote_loading: set[str] = set()
        self._last_rule_modal: tuple[str, float] | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("New Scan", classes="screen-title")
        with TabbedContent(initial="new-scan-target-tab"):
            with TabPane("Target", id="new-scan-target-tab"):
                yield VerticalScroll(
                    Vertical(
                        Label("Target URL"),
                        Input(
                            value=self.initial_target,
                            placeholder="https://example.local",
                            id="target",
                        ),
                        Label("Scan profile"),
                        Select(
                            self._profile_options(),
                            value=self._default_profile(),
                            allow_blank=False,
                            id="profile",
                        ),
                        Input(
                            value=self._default_profile(),
                            placeholder="Profile name",
                            id="profile-name",
                        ),
                        id="new-scan-target-form",
                    )
                )
            with TabPane("Settings", id="new-scan-settings-tab"):
                yield VerticalScroll(
                    Vertical(
                        Label("Rate limit"),
                        Input(
                            value=str(self.app.settings.scanner.rate_limit),
                            placeholder="Rate limit",
                            id="rate",
                        ),
                        Label("Max depth"),
                        Input(
                            value=str(self.app.settings.scanner.max_depth),
                            placeholder="Max depth",
                            id="depth",
                        ),
                        Label("Max pages"),
                        Input(
                            value=str(self.app.settings.scanner.max_pages),
                            placeholder="Max pages",
                            id="pages",
                        ),
                        id="new-scan-settings-form",
                    )
                )
            with TabPane("Selected Rules", id="new-scan-rules-tab"):
                yield Tree("Feeds", id="scan-feed-tree")
        yield Horizontal(
            Button("Start Scan", id="start", variant="primary"),
            Button("Save Profile", id="save-profile"),
            Button("Delete Profile", id="delete-profile", variant="error"),
            Button("Back", id="back"),
            id="new-scan-actions",
        )
        yield Footer()

    async def on_mount(self) -> None:
        tree = self.query_one("#scan-feed-tree", Tree)
        tree.show_root = False
        tree.root.expand()
        local_root = tree.root.add(_check_label("Local feeds", True))
        remote_root = tree.root.add(_check_label("Remote feeds", False))
        self._bind_node("group::local", "Local feeds", local_root)
        self._bind_node("group::remote", "Remote feeds", remote_root, checked=False)
        local_root.expand()
        remote_root.expand()
        hierarchy = _collect_rule_hierarchy(
            self.app.settings.rules.paths,
            [],
        )
        for source, registries in hierarchy.items():
            source_path = _source_path("local", source)
            source_node = local_root.add(_check_label(source, True))
            self._bind_node(source_path, source, source_node)
            for registry, categories in registries.items():
                reg_path = f"{source_path}/registry::{registry}"
                reg_node = source_node.add(_check_label(registry, True))
                self._bind_node(reg_path, registry, reg_node)
                for category, rules in categories.items():
                    cat_path = f"{reg_path}/category::{category}"
                    cat_node = reg_node.add(_check_label(category, True))
                    self._bind_node(cat_path, category, cat_node)
                    for rule_id in rules:
                        rule_path = f"{cat_path}/rule::{rule_id.id}"
                        rule_node = cat_node.add_leaf(_check_label(rule_id.label, True))
                        self._bind_node(rule_path, rule_id.label, rule_node)
                        self._rule_refs[rule_path] = f"{source}::{rule_id.id}"
                        self._rule_items[rule_path] = rule_id
                reg_node.expand()
            source_node.expand()
        for feed in self._available_remote_feeds():
            source_path = _source_path("remote", feed)
            if source_path in self._tree_nodes:
                continue
            source_node = remote_root.add(_check_label(feed, False))
            self._bind_node(source_path, feed, source_node, checked=False)
        await self._apply_profile_to_form(str(self.query_one("#profile", Select).value))

    def _profile_options(self) -> list[tuple[str, str]]:
        if not self.app.settings.profiles:
            self.app.settings.profiles["default"] = profile_from_config(
                self._config_from_form_defaults()
            )
        return [(name, name) for name in sorted(self.app.settings.profiles)]

    def _default_profile(self) -> str:
        if self.initial_profile and self.initial_profile in self.app.settings.profiles:
            return self.initial_profile
        configured = self.app.settings.scanner.default_profile
        if configured in self.app.settings.profiles:
            return configured
        return sorted(self.app.settings.profiles)[0]

    def _config_from_form_defaults(self) -> ScanConfig:
        return ScanConfig(
            target=Target(url="https://example.local"),
            profile="default",
            rate_limit=self.app.settings.scanner.rate_limit,
            max_depth=self.app.settings.scanner.max_depth,
            max_pages=self.app.settings.scanner.max_pages,
            timeout=self.app.settings.scanner.timeout,
            user_agent=self.app.settings.scanner.user_agent,
            auth_headers=dict(self.app.settings.scanner.auth_headers),
        )

    def _bind_node(self, path: str, label: str, node: object, *, checked: bool = True) -> None:
        self._tree_nodes[path] = node
        self._tree_labels[path] = label
        self._checked[path] = checked

    @on(Tree.NodeSelected, "#scan-feed-tree")
    async def toggle_tree_node(self, event: Tree.NodeSelected) -> None:
        node = event.node
        path = next((k for k, v in self._tree_nodes.items() if v == node), None)
        if not path:
            return
        new_state = not self._checked.get(path, True)
        source_info = _parse_source_path(path)
        if source_info and source_info[0] == "remote" and path == source_info[2] and new_state:
            source = source_info[1]
            if source not in self._remote_loaded:
                loaded = await self._load_remote_source(source, path)
                if not loaded:
                    self._checked[path] = False
                    self._refresh_tree_labels()
                    return
        self._set_checked_recursive(path, new_state)
        self._refresh_tree_labels()

    @on(Tree.NodeExpanded, "#scan-feed-tree")
    async def load_expanded_remote(self, event: Tree.NodeExpanded) -> None:
        node = event.node
        path = next((k for k, v in self._tree_nodes.items() if v == node), None)
        source_info = _parse_source_path(path or "")
        if not source_info or source_info[0] != "remote" or path != source_info[2]:
            return
        source = source_info[1]
        if source not in self._remote_loaded:
            await self._load_remote_source(source, path)

    async def _load_remote_source(self, source: str, path: str) -> bool:
        if source in self._remote_loaded:
            return True
        if source in self._remote_loading:
            return False
        self._remote_loading.add(source)
        node = self._tree_nodes[path]
        node.set_label(Text(f"[ ] {source} (loading...)"))
        try:
            index = await asyncio.to_thread(fetch_remote_index, source)
            registries: dict[str, dict[str, list[RuleTreeItem]]] = {}
            _merge_index_hierarchy(registries, index, source=source)
            self._append_rule_source(path, registries, checked=True)
            self._remote_loaded.add(source)
            return True
        except Exception as exc:
            self.notify(f"Unable to load remote feed {source}: {exc}", severity="error")
            return False
        finally:
            self._remote_loading.discard(source)

    def _append_rule_source(
        self,
        source_path: str,
        registries: dict[str, dict[str, list[RuleTreeItem]]],
        *,
        checked: bool,
    ) -> None:
        source_node = self._tree_nodes[source_path]
        source_info = _parse_source_path(source_path)
        source = source_info[1] if source_info else source_path
        for registry, categories in registries.items():
            reg_path = f"{source_path}/registry::{registry}"
            if reg_path in self._tree_nodes:
                continue
            reg_node = source_node.add(_check_label(registry, checked))
            self._bind_node(reg_path, registry, reg_node, checked=checked)
            for category, rules in categories.items():
                cat_path = f"{reg_path}/category::{category}"
                cat_node = reg_node.add(_check_label(category, checked))
                self._bind_node(cat_path, category, cat_node, checked=checked)
                for rule_id in rules:
                    rule_path = f"{cat_path}/rule::{rule_id.id}"
                    rule_node = cat_node.add_leaf(_check_label(rule_id.label, checked))
                    self._bind_node(rule_path, rule_id.label, rule_node, checked=checked)
                    self._rule_refs[rule_path] = f"{source}::{rule_id.id}"
                    self._rule_items[rule_path] = rule_id
            reg_node.expand()
        source_node.expand()

    @on(events.MouseDown, "#scan-feed-tree")
    def open_rule_details_from_context(self, event: events.MouseDown) -> None:
        self._open_rule_details_from_mouse_event(event)

    @on(events.MouseUp, "#scan-feed-tree")
    def open_rule_details_from_mouse_up(self, event: events.MouseUp) -> None:
        self._open_rule_details_from_mouse_event(event)

    @on(events.Click, "#scan-feed-tree")
    def open_rule_details_from_click(self, event: events.Click) -> None:
        self._open_rule_details_from_mouse_event(event)

    def on_mouse_down(self, event: events.MouseDown) -> None:
        self._open_rule_details_from_screen_mouse_event(event)

    def on_mouse_up(self, event: events.MouseUp) -> None:
        self._open_rule_details_from_screen_mouse_event(event)

    def on_click(self, event: events.Click) -> None:
        self._open_rule_details_from_screen_mouse_event(event)

    def _open_rule_details_from_screen_mouse_event(
        self, event: events.MouseDown | events.MouseUp | events.Click
    ) -> None:
        if event.button not in {2, 3}:
            return
        try:
            tree = self.query_one("#scan-feed-tree", Tree)
        except NoMatches:
            return
        if event.widget is None:
            return
        if event.widget is not tree and not event.widget.has_ancestor(tree):
            return
        self._open_rule_details_from_mouse_event(event)

    def _open_rule_details_from_mouse_event(
        self, event: events.MouseDown | events.MouseUp | events.Click
    ) -> None:
        if event.button not in {2, 3}:
            return
        tree = self.query_one("#scan-feed-tree", Tree)
        line = self._tree_line_from_mouse_event(tree, event)
        try:
            node = tree.get_node_at_line(line)
        except Exception:
            node = None
        path = next((key for key, value in self._tree_nodes.items() if value == node), None)
        if path not in self._rule_items:
            cursor_path = next(
                (key for key, value in self._tree_nodes.items() if value == tree.cursor_node),
                None,
            )
            path = cursor_path if cursor_path in self._rule_items else path
        if path and path in self._rule_items:
            now = time.monotonic()
            if (
                self._last_rule_modal
                and self._last_rule_modal[0] == path
                and now - self._last_rule_modal[1] < 0.25
            ):
                event.stop()
                return
            self._last_rule_modal = (path, now)
            event.stop()
            event.prevent_default()
            self.app.push_screen(RuleDetailModal(self._rule_items[path]))

    def _tree_line_from_mouse_event(
        self, tree: Tree, event: events.MouseDown | events.MouseUp | events.Click
    ) -> int:
        offset = event.get_content_offset(tree)
        if offset is not None:
            return int(offset.y + tree.scroll_y)
        if tree.hover_line is not None:
            return tree.hover_line
        return tree.cursor_line

    @on(Select.Changed, "#profile")
    async def profile_changed(self, event: Select.Changed) -> None:
        if event.value in {Select.BLANK}:
            fallback = self._default_profile()
            self.query_one("#profile", Select).value = fallback
            return
        profile_name = str(event.value)
        self.query_one("#profile-name", Input).value = profile_name
        await self._apply_profile_to_form(profile_name)

    async def _apply_profile_to_form(self, profile_name: str) -> None:
        profile = self.app.settings.profiles.get(profile_name)
        if profile is None:
            return
        self.query_one("#rate", Input).value = str(profile.rate_limit)
        self.query_one("#depth", Input).value = str(profile.max_depth)
        self.query_one("#pages", Input).value = str(profile.max_pages)
        self._set_checked_recursive("group::local", False)
        for feed in self._available_remote_feeds():
            self._set_checked_recursive(_source_path("remote", feed), False)
        for feed in profile.remote_feeds:
            path = _source_path("remote", feed)
            if path not in self._tree_nodes:
                continue
            if feed not in self._remote_loaded:
                loaded = await self._load_remote_source(feed, path)
                if not loaded:
                    continue
            self._checked[path] = True
            self._checked["group::remote"] = True
        wanted_refs = set(profile.enabled_rule_refs)
        if wanted_refs:
            for rule_path, rule_ref in self._rule_refs.items():
                if rule_ref in wanted_refs:
                    self._checked[rule_path] = True
                    parent = rule_path.rsplit("/rule::", 1)[0]
                    self._checked[parent] = True
                    registry_parent = parent.rsplit("/category::", 1)[0]
                    self._checked[registry_parent] = True
                    source_parent = registry_parent.rsplit("/registry::", 1)[0]
                    self._checked[source_parent] = True
                    group_parent = (
                        "group::remote" if "/source::remote::" in source_parent else "group::local"
                    )
                    self._checked[group_parent] = True
        else:
            self._set_checked_recursive("group::local", True)
        self._refresh_tree_labels()

    def _available_remote_feeds(self) -> list[str]:
        feeds = list(self.app.settings.rules.remote_feeds)
        for profile in self.app.settings.profiles.values():
            feeds.extend(profile.remote_feeds)
        return sorted(dict.fromkeys(feed for feed in feeds if feed))

    def _set_checked_recursive(self, path: str, state: bool) -> None:
        for key in list(self._checked.keys()):
            if key == path or key.startswith(path + "/"):
                self._checked[key] = state

    def _refresh_tree_labels(self) -> None:
        for path, node in self._tree_nodes.items():
            node.set_label(_check_label(self._tree_labels[path], self._checked.get(path, False)))

    def _selection_from_tree(
        self,
    ) -> tuple[list[str], list[str], list[str], list[str], list[str], list[str]]:
        sources: set[str] = set()
        feeds: set[str] = set()
        registries: set[str] = set()
        categories: set[str] = set()
        rules: set[str] = set()
        rule_refs: set[str] = set()
        for path, enabled in self._checked.items():
            if not enabled:
                continue
            if "/rule::" in path:
                rules.add(path.split("/rule::", 1)[1])
                if path in self._rule_refs:
                    rule_refs.add(self._rule_refs[path])
            if "/category::" in path:
                category = path.split("/category::", 1)[1]
                if category != "all":
                    categories.add(category.split("/", 1)[0])
            if "/registry::" in path:
                registries.add(path.split("/registry::", 1)[1].split("/", 1)[0])
            source_info = _parse_source_path(path)
            if source_info and path == source_info[2]:
                source_group, source, _source_root = source_info
                sources.add(source)
                if source_group == "remote":
                    feeds.add(source)
            if path == "group::local":
                sources.add("local")
        return (
            sorted(sources),
            sorted(feeds),
            sorted(registries),
            sorted(categories),
            sorted(rules),
            sorted(rule_refs),
        )

    @on(Button.Pressed, "#start")
    def start(self) -> None:
        target = self.query_one("#target", Input).value
        profile = self._selected_profile_name()
        try:
            config = self._build_scan_config(target, profile)
        except ValueError as exc:
            self.notify(str(exc), severity="error")
            return
        self.app.push_screen(LiveScanScreen(config))

    def _build_scan_config(self, target: str, profile: str) -> ScanConfig:
        (
            _selected_sources,
            selected_feeds,
            selected_registries,
            selected_categories,
            selected_rules,
            selected_rule_refs,
        ) = self._selection_from_tree()
        if not selected_rule_refs:
            selected_rule_refs = ["__none__"]
        return ScanConfig(
            target=Target(url=normalize_url(target)),
            profile=profile,
            rate_limit=float(self.query_one("#rate", Input).value or "5"),
            max_depth=int(self.query_one("#depth", Input).value or "2"),
            max_pages=int(self.query_one("#pages", Input).value or "50"),
            timeout=self.app.settings.scanner.timeout,
            user_agent=self.app.settings.scanner.user_agent,
            auth_headers=dict(self.app.settings.scanner.auth_headers),
            enabled_registries=selected_registries,
            enabled_categories=selected_categories,
            enabled_rule_ids=selected_rules,
            enabled_rule_refs=selected_rule_refs,
            remote_feeds=selected_feeds,
        )

    @on(Button.Pressed, "#save-profile")
    def save_profile(self) -> None:
        profile_name = self.query_one("#profile-name", Input).value.strip()
        if not profile_name:
            self.notify("Profile name is required", severity="error")
            return
        try:
            config = self._build_scan_config(
                self.query_one("#target", Input).value or "https://example.local", profile_name
            )
        except ValueError as exc:
            self.notify(str(exc), severity="error")
            return
        self.app.settings.profiles[profile_name] = profile_from_config(config)
        self.app.settings.scanner.default_profile = profile_name
        path = self.app.controller.save_settings(self.app.settings)
        select = self.query_one("#profile", Select)
        select.set_options(self._profile_options())
        select.value = profile_name
        self.notify(f"Profile saved to {path}")

    @on(Button.Pressed, "#delete-profile")
    def delete_profile(self) -> None:
        profile_name = self._selected_profile_name()
        if profile_name == "default":
            self.app.settings.profiles["default"] = ScanProfileSettings()
            self.app.settings.scanner.default_profile = "default"
            message = "Default profile reset"
        elif profile_name in self.app.settings.profiles:
            del self.app.settings.profiles[profile_name]
            if self.app.settings.scanner.default_profile == profile_name:
                self.app.settings.scanner.default_profile = "default"
            message = f"Profile deleted: {profile_name}"
        else:
            self.notify(f"Profile not found: {profile_name}", severity="error")
            return
        if "default" not in self.app.settings.profiles:
            self.app.settings.profiles["default"] = ScanProfileSettings()
        path = self.app.controller.save_settings(self.app.settings)
        select = self.query_one("#profile", Select)
        select.set_options(self._profile_options())
        select.value = self._default_profile()
        self.query_one("#profile-name", Input).value = self._default_profile()
        self.notify(f"{message}; saved to {path}")

    def _selected_profile_name(self) -> str:
        value = self.query_one("#profile", Select).value
        if value in {Select.BLANK}:
            return self._default_profile()
        return str(value)

    @on(Button.Pressed, "#back")
    def back(self) -> None:
        self.app.pop_screen()


class LiveScanScreen(Screen[None]):
    def __init__(self, config: ScanConfig) -> None:
        super().__init__()
        self.config = config
        self.engine: ScannerEngine | None = None
        self._task: asyncio.Task[None] | None = None
        self.last_saved_traffic_count = -1
        self._rows: list[Finding] = []
        self._visible_rows: list[Finding] = []
        self._pages_seen = 0
        self._checks_seen = 0
        self._sort_column = "risk"
        self._sort_desc = True
        self._latest_scan = None
        self._stop_requested = False
        self._finished = False

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(f"Scanning {self.config.target.url} ({self.config.profile})", id="scan-title")
        yield Label("Current URL: -", id="current-url")
        yield ProgressBar(total=100, id="progress")
        table = DataTable(id="latest-findings")
        table.cursor_type = "cell"
        table.add_columns("Severity", "Title", "Source", "Category", "URL", "Risk")
        yield table
        yield Horizontal(
            Button("Pause", id="pause"),
            Button("Resume", id="resume"),
            Button("Stop", id="stop", variant="error"),
            id="scan-controls",
        )
        yield Horizontal(
            Button("Export HTML", id="live-export-html", variant="primary"),
            Button("Export JSON", id="live-export-json"),
            Button("Export Markdown", id="live-export-md"),
            Button("Back", id="live-back"),
            id="live-export-controls",
        )
        yield Footer()

    async def on_mount(self) -> None:
        self.query_one("#live-export-controls").display = False
        loader = RuleLoader(
            self.app.settings.rules.paths,
            remote_cache_dir=self.app.settings.rules.remote_cache_dir,
        )
        rules = loader.load()
        if self.config.remote_feeds:
            rules.extend(
                loader.load_remote_feeds(
                    self.config.remote_feeds,
                    registries=set(self.config.enabled_registries),
                    categories=set(self.config.enabled_categories),
                )
            )
        enabled_categories = {item.lower() for item in self.config.enabled_categories}
        if enabled_categories:
            rules = [rule for rule in rules if rule.category.lower() in enabled_categories]
        enabled_registries = {item.lower() for item in self.config.enabled_registries}
        if enabled_registries:
            rules = [rule for rule in rules if rule.registry.lower() in enabled_registries]
        enabled_rule_ids = {item.lower() for item in self.config.enabled_rule_ids}
        if enabled_rule_ids:
            rules = [rule for rule in rules if rule.id.lower() in enabled_rule_ids]
        enabled_rule_refs = {item.lower() for item in self.config.enabled_rule_refs}
        if enabled_rule_refs:
            rules = [
                rule for rule in rules if f"{rule.source}::{rule.id}".lower() in enabled_rule_refs
            ]
        fingerprints = FingerprintDatabase.from_paths(self.app.settings.rules.paths)
        self.engine = ScannerEngine(RuleEngine(rules), fingerprints=fingerprints)
        self._task = asyncio.create_task(self._run())

    async def on_unmount(self) -> None:
        if self.engine:
            self.engine.stop()
        if self._task and not self._task.done():
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    async def _run(self) -> None:
        assert self.engine is not None
        try:
            progress = self.query_one("#progress", ProgressBar)
            table = self.query_one("#latest-findings", DataTable)
        except NoMatches:
            return
        try:
            async for event in self.engine.run_events(self.config):
                scan = event["scan"]
                self._latest_scan = scan
                event_type = str(event.get("type", ""))
                if event_type == "page":
                    self._pages_seen += 1
                if event_type == "check":
                    self._checks_seen += 1
                crawl_pct = min(70, int((self._pages_seen / max(1, self.config.max_pages)) * 70))
                check_pct = min(25, self._checks_seen)
                progress.progress = min(99, crawl_pct + check_pct)
                self._update_label("#current-url", f"Current URL: {event.get('url', '-')}")
                for finding in event.get("findings", []):
                    self._rows.append(finding)
                self._render_rows(table)
                if len(scan.traffic) != self.last_saved_traffic_count or event.get("type") in {
                    "started",
                    "completed",
                }:
                    self.app.controller.save_scan(scan)
                    self.last_saved_traffic_count = len(scan.traffic)
                if event.get("type") == "completed":
                    if getattr(scan, "status", "") == "stopped":
                        self._finish_stopped()
                        self.notify("Scan stopped")
                        return
                    self._finished = True
                    progress.progress = 100
                    self._show_export_controls()
                    self.notify(f"Scan completed with {len(scan.findings)} findings")
        except asyncio.CancelledError:
            self._finish_stopped()
            return

    def _finish_stopped(self) -> None:
        if self._finished:
            return
        self._finished = True
        if self._latest_scan is not None:
            self._latest_scan.status = "stopped"
            self._latest_scan.finished_at = datetime.now(UTC)
            self.app.controller.save_scan(self._latest_scan)
        self._update_label("#current-url", "Stopped")
        self._update_metric("#metric-status", "[dim]Status[/]\n[bold red]stopped[/]")
        self._show_export_controls(show_exports=self._latest_scan is not None)

    def _show_export_controls(self, *, show_exports: bool = True) -> None:
        try:
            self.query_one("#scan-controls").display = False
            self.query_one("#live-export-controls").display = True
            self.query_one("#live-export-html", Button).display = show_exports
            self.query_one("#live-export-json", Button).display = show_exports
            self.query_one("#live-export-md", Button).display = show_exports
        except NoMatches:
            return

    def _update_metric(self, selector: str, content: str) -> None:
        try:
            self.query_one(selector, MetricCard).update(content)
        except NoMatches:
            return

    def _update_label(self, selector: str, content: str) -> None:
        try:
            self.query_one(selector, Label).update(content)
        except NoMatches:
            return

    def _render_rows(self, table: DataTable) -> None:
        rows = _sort_findings(self._rows, self._sort_column, self._sort_desc)
        self._visible_rows = rows
        table.clear()
        for finding in rows:
            table.add_row(*_finding_row_cells(finding), key=finding.id)

    @on(DataTable.HeaderSelected, "#latest-findings")
    def sort_from_header(self, event: DataTable.HeaderSelected) -> None:
        columns = ["severity", "title", "source", "category", "url", "risk"]
        index = int(getattr(event, "column_index", 5))
        next_col = columns[index] if 0 <= index < len(columns) else "risk"
        if next_col == self._sort_column:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_column = next_col
            self._sort_desc = next_col in {"severity", "risk"}
        self._render_rows(self.query_one("#latest-findings", DataTable))

    @on(DataTable.RowSelected, "#latest-findings")
    def open_live_finding_details(self, event: DataTable.RowSelected) -> None:
        row_key = getattr(event.row_key, "value", event.row_key)
        finding = next((item for item in self._rows if item.id == str(row_key)), None)
        if not finding:
            row_index = int(getattr(event, "cursor_row", -1))
            if 0 <= row_index < len(self._visible_rows):
                finding = self._visible_rows[row_index]
        if finding:
            self.app.push_screen(FindingDetailModal(finding))

    @on(DataTable.CellSelected, "#latest-findings")
    def open_live_finding_details_cell(self, event: DataTable.CellSelected) -> None:
        row_index = int(getattr(getattr(event, "coordinate", None), "row", -1))
        finding = (
            self._visible_rows[row_index] if 0 <= row_index < len(self._visible_rows) else None
        )
        if finding:
            self.app.push_screen(FindingDetailModal(finding))

    @on(Button.Pressed, "#pause")
    def pause(self) -> None:
        if self.engine and not self._stop_requested:
            self.engine.pause()
            self._update_label("#current-url", "Paused")

    @on(Button.Pressed, "#resume")
    def resume(self) -> None:
        if self.engine and not self._stop_requested:
            self.engine.resume()

    @on(Button.Pressed, "#stop")
    async def stop(self) -> None:
        self._stop_requested = True
        if self.engine:
            self.engine.stop()
        self._finish_stopped()
        if self._task and not self._task.done():
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
        self.notify("Scan stopped")

    def _export_latest_scan(self, fmt: str) -> None:
        if self._latest_scan is None:
            self.notify("No finished scan to export", severity="warning")
            return
        path = export_scan(
            self._latest_scan,
            fmt,
            self.app.settings.export.report_dir,
            theme=self.app.settings.export.html_theme,
            pretty_json=self.app.settings.export.json_pretty,
        )
        self.notify(f"Exported {path}")

    @on(Button.Pressed, "#live-export-html")
    def export_live_html(self) -> None:
        self._export_latest_scan("html")

    @on(Button.Pressed, "#live-export-json")
    def export_live_json(self) -> None:
        self._export_latest_scan("json")

    @on(Button.Pressed, "#live-export-md")
    def export_live_md(self) -> None:
        self._export_latest_scan("markdown")

    @on(Button.Pressed, "#live-back")
    def back_from_live(self) -> None:
        self.app.pop_screen()


class SettingsScreen(Screen[None]):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Settings", classes="screen-title")
        with TabbedContent(initial="general"):
            with TabPane("General", id="general"):
                yield VerticalScroll(
                    Vertical(
                        Label("Database path"),
                        Input(value=self.app.settings.app.database_path, id="database-path"),
                        Label("Report directory"),
                        Input(value=self.app.settings.export.report_dir, id="report-dir"),
                        Label("Default export format"),
                        Select(
                            [("HTML", "html"), ("JSON", "json"), ("Markdown", "markdown")],
                            value=self.app.settings.export.default_format,
                            allow_blank=False,
                            id="default-format",
                        ),
                        Label("HTML theme"),
                        Select(
                            [("Dark", "dark"), ("Light", "light"), ("Academic", "academic")],
                            value=self.app.settings.export.html_theme,
                            allow_blank=False,
                            id="html-theme",
                        ),
                        id="settings-general-form",
                    )
                )
            with TabPane("Scanner", id="scanner"):
                yield VerticalScroll(
                    Vertical(
                        Label("Default rate limit"),
                        Input(value=str(self.app.settings.scanner.rate_limit), id="rate-limit"),
                        Label("Default max depth"),
                        Input(value=str(self.app.settings.scanner.max_depth), id="max-depth"),
                        Label("Default max pages"),
                        Input(value=str(self.app.settings.scanner.max_pages), id="max-pages"),
                        id="settings-scanner-form",
                    )
                )
            with TabPane("Rules", id="rules"):
                yield VerticalScroll(
                    Vertical(
                        Label("Rule paths (comma separated)"),
                        Input(value=", ".join(self.app.settings.rules.paths), id="rule-paths"),
                        Label("Remote feed cache directory (optional)"),
                        Input(
                            value=self.app.settings.rules.remote_cache_dir or "",
                            id="remote-cache-dir",
                        ),
                        Label("Remote feeds (one URL per line)"),
                        Input(
                            value="\n".join(self.app.settings.rules.remote_feeds),
                            id="remote-feeds",
                        ),
                        id="settings-rules-form",
                    )
                )
        yield Horizontal(
            Button("Save", id="save-settings", variant="primary"),
            Button("Back", id="back"),
            id="settings-actions",
        )
        yield Footer()

    @on(Button.Pressed, "#save-settings")
    def save(self) -> None:
        try:
            self.app.settings.app.database_path = self.query_one("#database-path", Input).value
            report_dir = self.query_one("#report-dir", Input).value
            self.app.settings.app.report_dir = report_dir
            self.app.settings.export.report_dir = report_dir
            self.app.settings.export.default_format = str(
                self.query_one("#default-format", Select).value
            )
            self.app.settings.export.html_theme = str(self.query_one("#html-theme", Select).value)
            self.app.settings.scanner.rate_limit = float(self.query_one("#rate-limit", Input).value)
            self.app.settings.scanner.max_depth = int(self.query_one("#max-depth", Input).value)
            self.app.settings.scanner.max_pages = int(self.query_one("#max-pages", Input).value)
            self.app.settings.rules.paths = [
                item.strip()
                for item in self.query_one("#rule-paths", Input).value.split(",")
                if item.strip()
            ]
            self.app.settings.rules.remote_feeds = [
                line.strip()
                for line in self.query_one("#remote-feeds", Input).value.splitlines()
                if line.strip()
            ]
            cache_dir_raw = self.query_one("#remote-cache-dir", Input).value.strip()
            self.app.settings.rules.remote_cache_dir = cache_dir_raw or None
        except ValueError as exc:
            self.notify(f"Invalid settings: {exc}", severity="error")
            return
        path = self.app.controller.save_settings(self.app.settings)
        self.notify(f"Settings saved to {path}")

    @on(Button.Pressed, "#back")
    def back(self) -> None:
        self.app.pop_screen()


class PlaceholderScreen(Screen[None]):
    def __init__(self, title: str, body: str) -> None:
        super().__init__()
        self.title = title
        self.body = body

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(f"[bold cyan]{self.title}[/]\n\n{self.body}")
        yield Footer()


def _check_label(label: str, checked: bool) -> Text:
    marker = Text("x", style="bold green") if checked else Text(" ")
    text = Text("[")
    text.append(marker)
    text.append(f"] {label}")
    return text


def _source_path(group: str, source: str) -> str:
    return f"group::{group}/source::{group}::{quote(source, safe='')}"


def _parse_source_path(path: str) -> tuple[str, str, str] | None:
    if "/source::" not in path:
        return None
    group_path, tail = path.split("/source::", 1)
    if not group_path.startswith("group::"):
        return None
    group = group_path.split("group::", 1)[1]
    prefix = f"{group}::"
    if not tail.startswith(prefix):
        return None
    source_key = tail[len(prefix) :].split("/", 1)[0]
    return group, unquote(source_key), f"{group_path}/source::{group}::{source_key}"


def _severity_style(finding: Finding) -> str:
    severity = finding.severity.value.lower()
    if severity in {"critical", "high"}:
        return "bold red"
    if severity == "medium":
        return "bold yellow"
    if severity == "low":
        return "cyan"
    return "dim"


def _finding_row_cells(finding: Finding) -> tuple[Text, Text, str, str, str, Text]:
    style = _severity_style(finding)
    return (
        Text(finding.severity.value, style=style),
        Text(finding.title, style=style),
        finding.source,
        finding.category,
        finding.url,
        Text(str(finding.risk_score), style=style),
    )


def _sort_findings(findings: list[Finding], column: str, descending: bool) -> list[Finding]:
    rows = list(findings)
    if column == "severity":
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows.sort(key=lambda finding: order.get(finding.severity.value.lower(), 9))
        if not descending:
            rows.reverse()
        return rows
    if column == "title":
        rows.sort(key=lambda finding: finding.title.lower(), reverse=descending)
    elif column == "source":
        rows.sort(key=lambda finding: finding.source.lower(), reverse=descending)
    elif column == "category":
        rows.sort(key=lambda finding: finding.category.lower(), reverse=descending)
    elif column == "url":
        rows.sort(key=lambda finding: finding.url.lower(), reverse=descending)
    else:
        rows.sort(key=lambda finding: float(finding.risk_score), reverse=descending)
    return rows


def _scan_config_summary(metadata: dict[str, object]) -> str:
    raw_config = metadata.get("config") if isinstance(metadata, dict) else None
    if not isinstance(raw_config, dict):
        return "[dim]Scan settings were not stored for this scan.[/]"
    target = raw_config.get("target") if isinstance(raw_config.get("target"), dict) else {}
    lines = [
        "[bold]Scan settings[/]",
        f"Target: {target.get('url', raw_config.get('target', 'n/a'))}",
        f"Profile: {raw_config.get('profile', 'n/a')}",
        f"Rate limit: {raw_config.get('rate_limit', 'n/a')}",
        f"Max depth: {raw_config.get('max_depth', 'n/a')}",
        f"Max pages: {raw_config.get('max_pages', 'n/a')}",
        f"Timeout: {raw_config.get('timeout', 'n/a')}",
        f"User agent: {raw_config.get('user_agent', 'n/a')}",
        f"Remote feeds: {_join_config_values(raw_config.get('remote_feeds'))}",
        f"Registries: {_join_config_values(raw_config.get('enabled_registries'))}",
        f"Categories: {_join_config_values(raw_config.get('enabled_categories'))}",
        f"Rule ids: {_join_config_values(raw_config.get('enabled_rule_ids'))}",
        f"Rule refs: {_join_config_values(raw_config.get('enabled_rule_refs'))}",
    ]
    return "\n".join(lines)


def _join_config_values(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "none"
    return str(value or "none")


def _collect_rule_hierarchy(
    rule_paths: list[str],
    feeds: list[str],
) -> dict[str, dict[str, dict[str, list[RuleTreeItem]]]]:
    result: dict[str, dict[str, dict[str, list[RuleTreeItem]]]] = {"local": {}}
    for raw_path in rule_paths:
        path = Path(raw_path).expanduser().resolve()
        root = path if path.is_dir() else path.parent
        if root.parent.name == "rules":
            root = root.parent
        try:
            index = build_local_index(root)
        except Exception:
            continue
        _merge_index_hierarchy(result["local"], index, source="local")
    for feed in feeds:
        registries = result.setdefault(feed, {})
        try:
            index = fetch_remote_index(feed)
        except Exception:
            continue
        _merge_index_hierarchy(registries, index, source=feed)
    return {source: registries for source, registries in result.items() if registries}


def _merge_index_hierarchy(
    target: dict[str, dict[str, list[RuleTreeItem]]],
    index: dict[str, object],
    *,
    source: str,
) -> None:
    for registry in index.get("registries", []):
        if not isinstance(registry, dict):
            continue
        registry_name = str(registry.get("name", "")).strip()
        if not registry_name:
            continue
        categories = target.setdefault(registry_name, {})
        for rule in registry.get("rules", []):
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("id", "")).strip()
            if not rule_id:
                continue
            category = str(rule.get("category") or "uncategorized").strip() or "uncategorized"
            label = rule_id
            description = str(rule.get("description") or "").strip()
            kind = str(rule.get("kind", "rule")).lower()
            bucket = categories.setdefault(category, [])
            if not any(item.id == rule_id for item in bucket):
                bucket.append(
                    RuleTreeItem(
                        id=rule_id,
                        label=label,
                        description=description,
                        category=category,
                        source=source,
                        kind=kind,
                    )
                )
        for rules in categories.values():
            rules.sort(key=lambda item: item.label.lower())
