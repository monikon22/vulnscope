"""TUI controller facade."""

from __future__ import annotations

from pathlib import Path

from vulnscope.config import Settings, save_settings
from vulnscope.domain.models import Scan
from vulnscope.storage.database import session_factory
from vulnscope.storage.repositories import ScanRepository


class AppController:
    """Bridge between Textual screens and application services."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.sessions = session_factory(settings.app.database_path)

    def recent_scans(self) -> list[Scan]:
        """Return recent scans for dashboard/report screens."""

        with self.sessions() as session:
            return ScanRepository(session).list_scans()

    def get_scan(self, scan_id: str) -> Scan | None:
        """Return one scan by ID."""

        with self.sessions() as session:
            return ScanRepository(session).get(scan_id)

    def save_scan(self, scan: Scan) -> None:
        """Persist a scan."""

        with self.sessions() as session:
            ScanRepository(session).save(scan)

    def save_settings(self, settings: Settings) -> Path:
        """Persist settings and refresh controller state."""

        self.settings = settings
        self.sessions = session_factory(settings.app.database_path)
        return save_settings(settings)

    def report_dir(self) -> Path:
        """Return configured report directory."""

        return Path(self.settings.export.report_dir)
