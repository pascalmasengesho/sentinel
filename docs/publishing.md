# Maintainer publishing guide

## One-time setup

Before the first public release, confirm the publication names in public metadata and documentation, then run `python scripts/release_preflight.py --dist dist` after building distributions.

### PyPI

Create the `sentinel-bounty` project in PyPI and configure GitHub Trusted Publishing for this repository, the `release.yml` workflow, and the `pypi` environment. No long-lived PyPI API token is required. GitHub documents that this flow needs the workflow's `id-token: write` permission and recommends a protected publishing environment. [GitHub’s PyPI publishing guide](https://docs.github.com/en/actions/how-tos/use-cases-and-examples/building-and-testing/building-and-testing-python) describes the setup.

After that setup is complete, create the repository variable `PYPI_PUBLISH_ENABLED` with the value `true`. Release tags then publish to PyPI. Until it is enabled, a release still verifies the distribution and creates the GitHub Release, but safely skips the PyPI job. You can also use the Release workflow's manual `publish_pypi` option for a one-time publication.

### Docker Hub

Create the `pascalmasengesho/sentinel` Docker Hub repository and add a scoped `DOCKERHUB_TOKEN` repository secret. The Docker workflow publishes signed-in multi-architecture images for release tags.

### Snap Store

Register `sentinel-bounty` with the Snap Store, export store credentials with `snapcraft export-login`, and save the resulting credential as the `SNAPCRAFT_STORE_CREDENTIALS` repository secret. The `snap.yml` workflow always builds an artifact for a release tag; manual dispatch with `publish=true` uploads it to the selected channel. Snap Store names are unique and must be registered before publishing. [Snapcraft’s publishing documentation](https://documentation.ubuntu.com/snapcraft/latest/how-to/publishing/publish-a-snap/) covers registration and the `snapcraft upload --release` process.

### AUR

Create an AUR account and package repository named `sentinel-bounty`, then add its SSH deploy key as the `AUR_SSH_PRIVATE_KEY` repository secret. The release workflow then copies the generated `PKGBUILD`, regenerates `.SRCINFO` inside an Arch container, and pushes it to the AUR package repository. `publish-aur.yml` provides a manual replay path for an already-created GitHub release.

After saving a valid multiline private key, create the repository variable `AUR_PUBLISH_ENABLED` with the value `true` to enable AUR publication on release tags. Until then, release tags skip AUR publishing rather than failing. The workflow removes Windows carriage returns and validates the key before connecting, so an invalid key is reported without exposing it in logs.

## Release procedure

1. Update `sentinel/__init__.py` with the new version and `CHANGELOG.md` with user-visible changes.
2. Update the Snap version in `snap/snapcraft.yaml` to match exactly.
3. Replace all release placeholders on the default branch before publishing the first release.
4. Run `make release-preflight` locally. It formats, lints, type-checks, tests, builds, validates metadata, and verifies version/artifact consistency.
5. Commit the version and changelog, create an annotated `vX.Y.Z` tag, and push it.
6. The release workflow creates a GitHub Release with wheel, sdist, and AUR recipe assets. It publishes to PyPI and the AUR only after their corresponding repository variables are enabled; release-tag workflows build the container and Snap artifact.
7. Manually publish the Snap to `edge` first, test it on a separate host, then promote to stable. The Snap Store supports staged channels and progressive releases. [Snapcraft release management](https://documentation.ubuntu.com/snapcraft/latest/how-to/publishing/manage-revisions-and-releases/) documents the workflow.
8. Confirm installation from PyPI, Docker Hub, Snap Store, and the AUR before announcing the release.

## Rollback

Never overwrite a PyPI release. Publish a corrective version instead. Docker tags may be moved only after documenting the change; keep version tags immutable. For Snap releases, close or promote channels using Snapcraft. For the AUR, commit a known-good `PKGBUILD` update.
