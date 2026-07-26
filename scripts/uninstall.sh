#!/usr/bin/env bash
# Remove a user-level Sentinel installation created by scripts/install.sh.
set -euo pipefail

PACKAGE="sentinel-bounty"
PREFIX="${HOME}/.local"

if [[ "${1:-}" == "--prefix" ]]; then
  PREFIX="${2:?A path is required after --prefix}"
elif [[ $# -gt 0 ]]; then
  echo "Usage: uninstall.sh [--prefix PATH]" >&2
  exit 2
fi

if command -v pipx >/dev/null 2>&1 && pipx list | grep -q "package ${PACKAGE}"; then
  pipx uninstall "${PACKAGE}"
  echo "Removed Sentinel from pipx."
  exit 0
fi

VENV="${PREFIX}/share/sentinel-bounty"
LINK="${PREFIX}/bin/sentinel"
if [[ -L "${LINK}" ]]; then
  rm "${LINK}"
fi
if [[ -d "${VENV}" ]]; then
  rm -rf "${VENV}"
fi
echo "Removed Sentinel user installation, if present."

