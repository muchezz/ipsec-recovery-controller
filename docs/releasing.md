# Building and releasing v0.4.0

Use a clean checkout of the exact main commit and Python 3.12 on Linux. Install `requirements-build.txt` for the pinned build toolchain and install `.[test]` for validation. Run `ruff check .`, `pytest -q -ra`, `python -m compileall -q src/ scripts/` and `python -m pip check`.

Run `python scripts/build_release.py`. It builds wheel and sdist twice with a fixed `SOURCE_DATE_EPOCH` from the commit, compares both SHA256 sets, checks version/Python metadata, and emits `dist/release/first/{wheel,sdist,BUILD-INFO.json,SHA256SUMS}`. It refuses nonempty output directories; retain previous evidence elsewhere before a deliberate repeat. The sdist has an explicit allowlist to exclude local configuration, credentials, unrelated files and build artifacts. For a manual build from the sdist, use the recorded `source_date_epoch`, pinned tools and `python -m build --no-isolation`.

Only after checks pass and all changes exist on main, push an annotated `v0.4.0` tag pointing to the exact main commit. The release workflow verifies tag/main agreement, runs checks again, verifies reproducible builds and publishes the artifacts with `docs/release-v0.4.0.md`. Do not create a release manually in parallel with the workflow. Do not bypass reviews or branch protection.

After publication, verify the remote main SHA, peeled tag SHA, workflow conclusion and release assets. Download assets into a separate ignored directory, run `sha256sum -c SHA256SUMS`, and compare `BUILD-INFO.json.commit` with main. Archive validation evidence outside the source distributions. No release step deploys services or contacts a production gateway.
