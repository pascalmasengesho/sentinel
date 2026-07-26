"""Generate a checksum-pinned AUR PKGBUILD from the exact PyPI source artifact."""

from __future__ import annotations

import argparse
from pathlib import Path

from release_preflight import package_version, sha256

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "packaging" / "aur" / "PKGBUILD.in"


def main() -> int:
    """Render a release-specific PKGBUILD with an immutable sdist checksum."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    sdist = args.sdist.resolve()
    version = package_version()
    expected_name = f"sentinel_bounty-{version}.tar.gz"
    if not sdist.is_file() or sdist.name != expected_name:
        raise SystemExit(f"Expected the built sdist named {expected_name}; got {sdist}.")
    content = TEMPLATE.read_text(encoding="utf-8")
    content = content.replace("@VERSION@", version).replace("@SHA256SUM@", sha256(sdist))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
