#!/usr/bin/env bash
# Install Sentinel from PyPI without requiring root privileges.
set -euo pipefail

PACKAGE="sentinel-bounty"
VERSION=""
PREFIX="${HOME}/.local"

usage() {
  cat <<'EOF'
Usage: install.sh [--version VERSION] [--prefix PATH]

Installs Sentinel from PyPI using pipx when available, or an isolated venv at
PREFIX/share/sentinel-bounty. The command is linked to PREFIX/bin/sentinel.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="==${2:?A version is required after --version}"
      shift 2
      ;;
    --prefix)
      PREFIX="${2:?A path is required after --prefix}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if command -v pipx >/dev/null 2>&1; then
  pipx install --force "${PACKAGE}${VERSION}"
  echo "Sentinel was installed with pipx. Run: sentinel --help"
  exit 0
fi

PYTHON="${PYTHON:-python3}"
if ! command -v "${PYTHON}" >/dev/null 2>&1; then
  echo "Python 3.12 or newer is required. Install Python or pipx first." >&2
  exit 1
fi

"${PYTHON}" - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit("Python 3.12 or newer is required.")
PY

VENV="${PREFIX}/share/sentinel-bounty"
BIN_DIR="${PREFIX}/bin"
"${PYTHON}" -m venv "${VENV}"
"${VENV}/bin/python" -m pip install --upgrade pip
"${VENV}/bin/python" -m pip install --upgrade "${PACKAGE}${VERSION}"
mkdir -p "${BIN_DIR}"
ln -sfn "${VENV}/bin/sentinel" "${BIN_DIR}/sentinel"

echo "Sentinel was installed. Ensure ${BIN_DIR} is on PATH, then run: sentinel --help"

