# Distribution and installation

Sentinel is distributed as the PyPI package `sentinel-bounty`, the Docker Hub image `pascalmasengesho/sentinel`, the Snap `sentinel-bounty`, and the Arch package `sentinel-bounty`.

## PyPI

The recommended Python installation is isolated with [pipx](https://pipx.pypa.io/):

```bash
pipx install sentinel-bounty
sentinel --help
```

Alternatively, download and inspect the repository's `scripts/install.sh`, then run it. It uses `pipx` when present or a venv below `~/.local` otherwise:

```bash
curl -fsSLO https://raw.githubusercontent.com/pascalmasengesho/sentinel/main/scripts/install.sh
less install.sh
bash install.sh
```

To update, run `pipx upgrade sentinel-bounty` or rerun the install script. To remove a scripted installation, run `bash scripts/uninstall.sh` from a checked-out release.

## Docker Hub

The container runs as an unprivileged user and writes reports in `/output`. Mount a local report directory for persisted output:

```bash
docker pull pascalmasengesho/sentinel:latest
mkdir -p reports
docker run --rm -v "$PWD/reports:/output" pascalmasengesho/sentinel:latest \
  scan https://example.com --authorized --output /output/example --format html
```

For a local build, use `docker build -t sentinel-bounty:local .` or `docker compose run --rm sentinel --help`.

## Snap Store

After the maintainer has registered and released the Snap Store name, install it with:

```bash
sudo snap install sentinel-bounty
sentinel --help
```

The strict Snap uses the `network` and `home` interfaces. Connect additional interfaces only when the Snap Store and your local policy require them.

## Arch User Repository

After the AUR package is published, install with an AUR helper:

```bash
yay -S sentinel-bounty
```

The release pipeline generates a checksum-pinned `PKGBUILD` from the exact PyPI source distribution and attaches it to the GitHub release. This avoids an AUR recipe referencing an unpinned moving source.
