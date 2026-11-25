# Releasing

Use SemVer. Before 1.0, bump the minor version for features or breaking changes, and the patch version for fixes alone.

1. Update `Cargo.toml` and run `cargo check` to update `Cargo.lock`. Commit both as `Release X.Y.Z`, push `main`, and wait for CI on that commit.
2. Create and push the annotated tag: `git tag -a vX.Y.Z -m "oauth2-mcp-gateway X.Y.Z"` then `git push origin vX.Y.Z`.
3. Pushing a `v*` tag runs `.github/workflows/release.yml`:
   - `check` (`ubuntu-24.04`) verifies that the tag matches `Cargo.toml` (`v<version>`) and that `HEAD` is on `origin/main`.
   - `ci` runs the full `.github/workflows/ci.yml` suite (triggered only on `push` events).
   - Seven platform jobs compile `--release --locked` binaries and run `scripts/ci/package-release.py` to archive, extract, verify `LICENSE`, `NOTICE`, and `README.md`, check `--version`, and smoke-test `check --config`:
     - `linux-amd64` (`ubuntu-24.04`) and `linux-arm64` (`ubuntu-24.04-arm`): native static musl builds inside `rust:1.92.0-alpine3.23` containers (`.tar.gz`).
     - `macos-amd64` (`macos-15-intel`, `x86_64-apple-darwin`) and `macos-arm64` (`macos-15`, `aarch64-apple-darwin`): native macOS builds on GitHub-hosted runners (`.tar.gz`).
     - `windows-amd64` (`windows-latest`, `x86_64-pc-windows-msvc`) and `windows-arm64` (`windows-11-arm`, `aarch64-pc-windows-msvc`): native MSVC builds with `+crt-static` (`.zip`).
     - `freebsd-amd64` (`ubuntu-24.04` host with `vmactions/freebsd-vm`): native build and guest smoke test inside a FreeBSD 15.1 `x86_64` VM (`.tar.gz`).
   - `bundle` (`ubuntu-24.04`) verifies that all seven archives exist, generates `SHA256SUMS`, and uploads the `verified-bundle` workflow artifact.
   - `release` verifies the live tag commit SHA and creates a draft GitHub release containing the seven archives and `SHA256SUMS`.
4. Review the notes and verify the archives against `SHA256SUMS`. Publish the draft with `gh release edit vX.Y.Z --draft=false`.

Triggering `release.yml` manually via `workflow_dispatch` runs `check`, the seven platform archive and smoke-test jobs, and `bundle` (`verified-bundle` artifact), skipping `ci` and draft GitHub release creation (`ci` and `release` run only on `push` tag events). Never move a published tag; fix a published release in a new version.
