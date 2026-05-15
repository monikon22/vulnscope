"""Application configuration loading."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class AppSettings(BaseModel):
    """General application settings."""

    database_path: str = "./data/vulnscope.db"
    report_dir: str = "./reports"


class ScannerSettings(BaseModel):
    """Scanner defaults."""

    default_profile: str = "default"
    rate_limit: float = 5.0
    timeout: float = 10.0
    max_depth: int = 2
    max_pages: int = 50
    user_agent: str = "VulnScope/0.1"
    auth_headers: dict[str, str] = Field(default_factory=dict)


class RuleSettings(BaseModel):
    """Rule configuration."""

    paths: list[str] = Field(default_factory=lambda: ["./rules"])
    enabled_categories: list[str] = Field(default_factory=list)
    enabled_registries: list[str] = Field(default_factory=list)
    remote_feeds: list[str] = Field(default_factory=list)
    remote_cache_dir: str | None = None


class ExportSettings(BaseModel):
    """Report export defaults."""

    default_format: str = "html"
    report_dir: str = "./reports"
    include_http_evidence: bool = True
    include_response_bodies: bool = False
    json_pretty: bool = True
    html_theme: str = "dark"


class ScanProfileSettings(BaseModel):
    """Saved scan form profile."""

    rate_limit: float = 5.0
    max_depth: int = 2
    max_pages: int = 50
    enabled_registries: list[str] = Field(default_factory=list)
    enabled_categories: list[str] = Field(default_factory=list)
    enabled_rule_ids: list[str] = Field(default_factory=list)
    enabled_rule_refs: list[str] = Field(default_factory=list)
    remote_feeds: list[str] = Field(default_factory=list)


class Settings(BaseModel):
    """Top-level application settings."""

    app: AppSettings = Field(default_factory=AppSettings)
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    rules: RuleSettings = Field(default_factory=RuleSettings)
    export: ExportSettings = Field(default_factory=ExportSettings)
    profiles: dict[str, ScanProfileSettings] = Field(
        default_factory=lambda: {"default": ScanProfileSettings()}
    )


def candidate_config_paths() -> list[Path]:
    """Return config paths in precedence order."""

    paths = [Path.cwd() / "vulnscope.yaml"]
    home = Path.home()
    paths.append(home / ".config" / "vulnscope" / "vulnscope.yaml")
    if env_path := os.getenv("VULNSCOPE_CONFIG"):
        paths.insert(0, Path(env_path))
    return paths


def load_settings(path: str | Path | None = None) -> Settings:
    """Load settings from YAML and environment overrides."""

    selected = (
        Path(path) if path else next((p for p in candidate_config_paths() if p.exists()), None)
    )
    data: dict[str, object] = {}
    if selected and selected.exists():
        loaded = yaml.safe_load(selected.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError("Configuration root must be a mapping")
        data = loaded
    settings = Settings.model_validate(data)
    if database_path := os.getenv("VULNSCOPE_DATABASE_PATH"):
        settings.app.database_path = database_path
    if report_dir := os.getenv("VULNSCOPE_REPORT_DIR"):
        settings.app.report_dir = report_dir
        settings.export.report_dir = report_dir
    if rate_limit := os.getenv("VULNSCOPE_RATE_LIMIT"):
        settings.scanner.rate_limit = float(rate_limit)
    return settings


def save_settings(settings: Settings, path: str | Path = "vulnscope.yaml") -> Path:
    """Persist editable settings to a YAML file."""

    output = Path(path)
    output.write_text(
        yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return output
