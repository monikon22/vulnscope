"""Saved scan profile helpers."""

from __future__ import annotations

from vulnscope.config import ScanProfileSettings, Settings
from vulnscope.domain.models import ScanConfig


def profile_from_config(config: ScanConfig) -> ScanProfileSettings:
    """Build a saved profile payload from an effective scan config."""

    return ScanProfileSettings(
        rate_limit=config.rate_limit,
        max_depth=config.max_depth,
        max_pages=config.max_pages,
        enabled_registries=list(config.enabled_registries),
        enabled_categories=list(config.enabled_categories),
        enabled_rule_ids=list(config.enabled_rule_ids),
        enabled_rule_refs=list(config.enabled_rule_refs),
        remote_feeds=list(config.remote_feeds),
    )


def apply_saved_profile(config: ScanConfig, settings: Settings) -> ScanConfig:
    """Apply a user-saved profile to a scan config."""

    profile = settings.profiles.get(config.profile)
    if profile is None:
        return config
    return config.model_copy(
        update={
            "rate_limit": profile.rate_limit,
            "max_depth": profile.max_depth,
            "max_pages": profile.max_pages,
            "enabled_registries": list(profile.enabled_registries),
            "enabled_categories": list(profile.enabled_categories),
            "enabled_rule_ids": list(profile.enabled_rule_ids),
            "enabled_rule_refs": list(profile.enabled_rule_refs),
            "remote_feeds": list(profile.remote_feeds),
        }
    )
