# Розгортання

Локальна розробка:

```bash
py -3.12 -m venv .venv
..venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Використання pipx:

```bash
pipx install .
vulnscope
```

CI може споживати JSON-звіти, експортовані з історії сканування.