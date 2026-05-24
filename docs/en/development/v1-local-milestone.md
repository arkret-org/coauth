# v1.0.0 Local Milestone

This is the local v1.0.0 milestone record. It is deliberately separate from
the real release workflow: do not create a git tag, push an image, publish a
GitHub release, or publish crates from this record.

## Milestone Definition

The local milestone is considered ready when these artifacts exist under
`target/release-artifacts/`:

- `coauth-v1.0.0-local-milestone.json`
- a local OCI archive such as `coauth-v1.0.0-<sha>.oci.tar`
- local SBOM files generated from that OCI archive
- local SLSA provenance and local cosign verification output
- English book output
- Chinese book output

The milestone record names `v1.0.0`, but it does not mutate `Cargo.toml`,
`Cargo.lock`, changelog files, git tags, registries, or GitHub releases.

## Local Scaffold

Generate the local milestone record:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/v1-local-milestone.ps1
```

Attempt local book and image builds only when the workstation is ready:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/v1-local-milestone.ps1 -RunBuilds
```

`-RunBuilds` is still local-only. It builds book output in a temporary source
tree under `target/release-artifacts/` and writes a local OCI archive if Docker
Buildx and the Rust workspace are usable.

## Manual Commands

Build the English book:

```powershell
mdbook build
```

Build the Chinese book through an isolated temporary source tree:

```powershell
$artifactDir = "target/release-artifacts"
$tmp = Join-Path $artifactDir "book-zh-source"
New-Item -ItemType Directory -Force $tmp | Out-Null
Copy-Item docs $tmp -Recurse -Force
Copy-Item book-zh.toml (Join-Path $tmp "book.toml") -Force
mdbook build $tmp
```

Build a local OCI image archive without pushing tags:

```powershell
$short = git rev-parse --short=12 HEAD
$artifactDir = "target/release-artifacts"
New-Item -ItemType Directory -Force $artifactDir | Out-Null
docker buildx build `
  --output "type=oci,dest=$artifactDir/coauth-v1.0.0-$short.oci.tar" `
  --build-arg "VERGEN_GIT_DESCRIBE=v1.0.0-local+$short" `
  .
```

Generate local SBOM and provenance artifacts using the commands in
`docs/en/development/releasing.md`.

## Current Local Status

- The scaffold and record paths are in place.
- The real version bump is intentionally deferred to the release branch/tag
  workflow.
- Local cargo and `dx build` currently depend on resolving the sibling
  `contrix-rust-sdk` version mismatch described in
  `docs/en/development/security-review-readiness.md`.
