"""Validate version and distribution artifacts before creating a public release."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r'^__version__\s*=\s*"(?P<version>[^\"]+)"$', re.MULTILINE)


def main() -> int:
    """Run release consistency checks and report actionable failures."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--allow-placeholders", action="store_true")
    args = parser.parse_args()

    version = package_version()
    failures = check_versions(version)
    failures.extend(check_distributions(args.dist, version))
    if not args.allow_placeholders:
        failures.extend(check_placeholders())
    if failures:
        print("Release preflight failed:", file=sys.stderr)
        print("\n".join(f"- {failure}" for failure in failures), file=sys.stderr)
        return 1
    print(f"Release preflight passed for v{version}.")
    return 0


def package_version() -> str:
    """Read the single source of Python package versioning."""
    match = VERSION_PATTERN.search((ROOT / "sentinel" / "__init__.py").read_text(encoding="utf-8"))
    if match is None:
        raise RuntimeError("Could not locate sentinel.__version__.")
    return match.group("version")


def check_versions(version: str) -> list[str]:
    """Check release version copies that cannot derive from Python metadata."""
    failures: list[str] = []
    snap = ROOT / "snap" / "snapcraft.yaml"
    snap_version = re.search(
        r'^version:\s*"(?P<version>[^\"]+)"$', snap.read_text(encoding="utf-8"), re.MULTILINE
    )
    if snap_version is None or snap_version.group("version") != version:
        failures.append("snap/snapcraft.yaml version must equal sentinel.__version__.")
    return failures


def check_distributions(dist: Path, version: str) -> list[str]:
    """Ensure an sdist and wheel for the selected version exist and are usable."""
    expected_sdist = dist / f"sentinel_bounty-{version}.tar.gz"
    expected_wheel_prefix = f"sentinel_bounty-{version}-"
    failures: list[str] = []
    if not expected_sdist.is_file():
        failures.append(f"Missing source distribution: {expected_sdist}")
        return failures
    if not any(path.name.startswith(expected_wheel_prefix) for path in dist.glob("*.whl")):
        failures.append(f"Missing wheel matching {expected_wheel_prefix}*.whl")
    with tarfile.open(expected_sdist, "r:gz") as archive:
        members = archive.getnames()
    if not any(member.endswith("/LICENSE") for member in members):
        failures.append("Source distribution does not include LICENSE.")
    return failures


def check_placeholders() -> list[str]:
    """Prevent accidental publication with repository placeholders in public metadata."""
    public_files = [
        ROOT / "README.md",
        ROOT / "pyproject.toml",
        ROOT / "docs" / "packaging.md",
        ROOT / "docs" / "publishing.md",
        ROOT / "packaging" / "aur" / "PKGBUILD.in",
    ]
    placeholders = ("YOUR_GITHUB_ORG", "YOUR_DOCKERHUB_NAMESPACE")
    failures: list[str] = []
    for path in public_files:
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        for placeholder in placeholders:
            if placeholder in content:
                failures.append(f"Replace {placeholder} in {path.relative_to(ROOT)}.")
    return failures


def sha256(path: Path) -> str:
    """Return the hex digest used by the AUR package recipe generator."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
