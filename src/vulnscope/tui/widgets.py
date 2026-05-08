"""Reusable Textual widgets."""

from __future__ import annotations

from typing import Any

from textual.widgets import Static


class MetricCard(Static):
    """Small dashboard metric card."""

    DEFAULT_CSS = """
    MetricCard {
        border: round $primary;
        padding: 1 2;
        height: 5;
        background: $surface;
    }
    """

    def __init__(self, label: str, value: str | int, **kwargs: Any) -> None:
        super().__init__(f"[dim]{label}[/]\n[bold cyan]{value}[/]", **kwargs)
