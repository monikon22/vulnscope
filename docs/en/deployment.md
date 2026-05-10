# Deployment

Local development:

```bash
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
vulnscope
```

pipx:

```bash
pipx install .
vulnscope
```

Docker:

```bash
docker build -t vulnscope .
docker run --rm -it vulnscope
```

Docker Compose:

```bash
docker compose run --rm vulnscope
```

CI can consume JSON reports exported from scan history.

