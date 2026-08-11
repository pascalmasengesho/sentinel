# Installation

Sentinel supports Linux directly and runs on any platform with Python 3.12+ for development and testing.

## Install a released version on Linux

Use `pipx` for a self-contained command-line installation. This is the recommended
method once the GitHub release and PyPI publication for the desired version are complete.

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
# Open a new terminal after ensurepath, then:
pipx install sentinel-bounty
sentinel --help
```

To update an existing `pipx` installation after a new PyPI release:

```bash
pipx upgrade sentinel-bounty
sentinel --version
```

For the published container image, replace the version with the release you want:

```bash
docker pull pascalmasengesho/sentinel:0.2.0
docker run --rm pascalmasengesho/sentinel:0.2.0 --help
```

The Docker image becomes available after the `v0.2.0` tag workflow succeeds. Snap
publishing is a separate manual release step; after it is published, update it with
`sudo snap refresh sentinel-bounty`.

## Install the current development branch

Use this only when you need the newest changes before they have been merged and released:

```bash
git clone https://github.com/pascalmasengesho/sentinel.git
cd sentinel
git checkout agent/enterprise-report-ui
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
sentinel --help
```

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
