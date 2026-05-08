from pathlib import Path

from vulnscope.config import load_settings


def test_config_loading(tmp_path: Path) -> None:
    config = tmp_path / "vulnscope.yaml"
    config.write_text(
        "scanner:\n  rate_limit: 2\nexport:\n  html_theme: academic\n",
        encoding="utf-8",
    )
    settings = load_settings(config)
    assert settings.scanner.rate_limit == 2
    assert settings.export.html_theme == "academic"
