# Releasing

Use SemVer. Before 1.0, bump the minor version for features or breaking changes, and the patch version for fixes alone.

1. Update `Cargo.toml` and run `cargo check` to update `Cargo.lock`. Commit both as `Release X.Y.Z`, push `main`, and wait for CI on that commit.
2. Create and push the annotated tag: `git tag -a vX.Y.Z -m "oauth2-mcp-gateway X.Y.Z"` then `git push origin vX.Y.Z`.
3. On the tag, the release workflow checks the version and source, runs CI, and drafts a GitHub release. It builds and smoke tests Linux musl, macOS and Windows on amd64 and arm64, plus FreeBSD 15.1 amd64. The draft contains seven archives and `SHA256SUMS`.
4. Review the notes and verify the archives against `SHA256SUMS`. Publish the draft with `gh release edit vX.Y.Z --draft=false`.

A manual run of the release workflow builds, smoke tests and bundles the archives without drafting a release. Never move a published tag; fix a published release in a new version.
