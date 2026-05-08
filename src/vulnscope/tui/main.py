"""Textual application entry point."""

from __future__ import annotations

from textual.app import App

from vulnscope.config import Settings, load_settings
from vulnscope.tui.controllers import AppController
from vulnscope.tui.screens import (
    DashboardScreen,
    HelpModal,
    NewScanScreen,
    PlaceholderScreen,
    SettingsScreen,
)


class VulnScopeApp(App[None]):
    """Main VulnScope Textual application."""

    CSS_PATH = "styles.tcss"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "dashboard", "Dashboard"),
        ("n", "new_scan", "New Scan"),
        ("s", "settings", "Settings"),
        ("?", "help", "Help"),
    ]

    def __init__(
        self,
        settings: Settings | None = None,
        initial_target: str | None = None,
        initial_profile: str | None = None,
    ) -> None:
        super().__init__()
        self.settings = settings or load_settings()
        self.controller = AppController(self.settings)
        self.initial_target = initial_target
        self.initial_profile = initial_profile

    def on_mount(self) -> None:
        if self.initial_target:
            self.push_screen(NewScanScreen(self.initial_target, self.initial_profile))
        else:
            self.push_screen(DashboardScreen())

    def action_dashboard(self) -> None:
        self.switch_screen(DashboardScreen())

    def action_new_scan(self) -> None:
        self.push_screen(NewScanScreen())

    def action_settings(self) -> None:
        self.push_screen(SettingsScreen())

    def action_help(self) -> None:
        self.push_screen(HelpModal())

    def action_rules(self) -> None:
        self.push_screen(
            PlaceholderScreen(
                "Rules",
                "Rule registries and custom YAML rules can be validated, enabled, and disabled.",
            )
        )


def run_tui(initial_target: str | None = None, initial_profile: str | None = None) -> None:
    """Run the Textual TUI."""

    VulnScopeApp(initial_target=initial_target, initial_profile=initial_profile).run()
