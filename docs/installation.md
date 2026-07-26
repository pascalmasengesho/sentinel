# Installation

Sentinel supports Linux directly and runs on any platform with Python 3.12+ for development and testing.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
sentinel --help
```

The primary runtime dependencies are `httpx`, `dnspython`, `cryptography`, `PyYAML`, `Typer`, `Rich`, and ReportLab. The development extra adds Black, Ruff, mypy, and pytest.

To use the container image, build it from the repository root:

```bash
docker build -t sentinel .
docker run --rm sentinel scan --help
```

