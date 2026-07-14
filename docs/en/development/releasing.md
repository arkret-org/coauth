# Releasing

coauth's local release-readiness workflow records build, SBOM, and
provenance evidence without publishing anything. Do not push git tags,
push container images, publish GitHub releases, or upload attestations
from this workspace.

## GitHub Action workflows

The upstream project has GitHub Action workflows for translations,
release branches, version bumps, and external builds. They are not part
of this local readiness workflow and must not be triggered to publish
remote artifacts.

### [`release-branch` workflow]

Do not run this workflow for the local readiness pass. It creates remote
release-branch state and tags in the upstream release strand.

The next major/minor pre-version is computed from the current version on the main branch, so it works as follows:

 - `v1.2.3` will become `v2.0.0-rc.0` for a major release
 - `v1.2.3` will become `v1.3.0-rc.0` for a minor release

Local evidence does not require a release branch or pull request.


### [`release-bump` workflow]

Do not run this workflow for the local readiness pass. It exists for the
upstream remote release strand and can create version/tag state that is
outside the scope of this workspace.

This workflow has three meaningful inputs:

 - The release branch to bump
 - Whether the release is a pre-release or not:
   - If it is a pre-release, `v1.2.3-rc.0` will become `v1.2.3-rc.1`, and `v1.2.3` will become `v1.2.4-rc.0`.
   - If it is not a pre-release, `v1.2.3-rc.0` will become `v1.2.3`, and `v1.2.3` will become `v1.2.4`.
 - Whether the release branch should be merged back into the main branch or not. In most cases, this should be enabled unless doing a release on a previous release branch.

### [`build` workflow]

Do not trigger the remote build workflow for this workspace. The local
artifact path below replaces remote image pushes, GitHub Action assets,
draft releases, PR comments, and unstable release updates.


## Changelog generation

Changelogs are automatically generated from PR titles and labels.

The configuration for those can be found in the `.github/release.yml`, but the main labels to be aware of are:

 - `T-Defect`: Bug fixes
 - `T-Enhancement`: New features
 - `A-Admin-API`: Changes to the admin API
 - `A-Documentation`: Documentation
 - `A-I18n`: Translations
 - `T-Task`: Internal changes
 - `A-Dependencies`: Dependency updates

They are calculated based on the previous release. For release candidates, this includes the previous release candidate.

## Container image signing

The local evidence path signs provenance blobs with a local key and
`--tlog-upload=false`. It does not publish container images, upload to
Rekor, or require verification against GHCR.

## Local SBOM and provenance artifacts

The local artifact path is for release dry-runs and audits only. It must
not push images, create git tags, publish a GitHub release, or upload
attestations to Rekor. Keep all outputs under `target/release-artifacts/`
so they remain local build artifacts.

Prerequisites: Docker Buildx, `jq`, `syft`, and `cosign`.

```sh
ARTIFACT_DIR=target/release-artifacts
SHORT_SHA="$(git rev-parse --short=12 HEAD)"
PLATFORM="${PLATFORM:-linux/amd64}"
IMAGE_TAR="${ARTIFACT_DIR}/coauth-${SHORT_SHA}.oci.tar"
PROVENANCE="${ARTIFACT_DIR}/coauth-${SHORT_SHA}.slsa-provenance.json"

mkdir -p "${ARTIFACT_DIR}"

docker buildx build \
  --platform "${PLATFORM}" \
  --output "type=oci,dest=${IMAGE_TAR}" \
  --build-arg "VERGEN_GIT_DESCRIBE=$(git describe --tags --match 'v*.*.*' --always)" \
  .
```

Generate local SBOM artifacts with Syft:

```sh
syft "oci-archive:${IMAGE_TAR}" -o spdx-json \
  > "${ARTIFACT_DIR}/coauth-${SHORT_SHA}.spdx.json"

syft "oci-archive:${IMAGE_TAR}" -o cyclonedx-json \
  > "${ARTIFACT_DIR}/coauth-${SHORT_SHA}.cdx.json"
```

Generate a local SLSA provenance statement for the OCI archive:

```sh
IMAGE_SHA="$(sha256sum "${IMAGE_TAR}" | awk '{print $1}')"
SOURCE_URI="$(git config --get remote.origin.url || true)"
GIT_SHA="$(git rev-parse HEAD)"
BUILD_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
  --arg image "coauth-${SHORT_SHA}.oci.tar" \
  --arg image_sha "${IMAGE_SHA}" \
  --arg git_sha "${GIT_SHA}" \
  --arg source_uri "${SOURCE_URI}" \
  --arg platform "${PLATFORM}" \
  --arg started "${BUILD_STARTED}" \
  '{
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
      {
        "name": $image,
        "digest": { "sha256": $image_sha }
      }
    ],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
      "buildDefinition": {
        "buildType": "https://github.com/arkret-org/coauth/local-container-build/v1",
        "externalParameters": {
          "gitCommit": $git_sha,
          "gitRemote": $source_uri,
          "platform": $platform
        },
        "internalParameters": {}
      },
      "runDetails": {
        "builder": { "id": "local:docker-buildx" },
        "metadata": {
          "invocationId": $git_sha,
          "startedOn": $started
        }
      }
    }
  }' > "${PROVENANCE}"
```

Sign and verify that provenance file locally with Cosign. The
`--tlog-upload=false` flag keeps this dry-run offline; remote image publication
and registry signing are outside this local workflow.

```sh
KEY_DIR="${ARTIFACT_DIR}/cosign-local"
mkdir -p "${KEY_DIR}"

if [ ! -f "${KEY_DIR}/cosign.key" ]; then
  (cd "${KEY_DIR}" && cosign generate-key-pair)
fi

cosign sign-blob \
  --key "${KEY_DIR}/cosign.key" \
  --tlog-upload=false \
  --bundle "${ARTIFACT_DIR}/coauth-${SHORT_SHA}.slsa.bundle" \
  "${PROVENANCE}"

cosign verify-blob \
  --key "${KEY_DIR}/cosign.pub" \
  --insecure-ignore-tlog \
  --bundle "${ARTIFACT_DIR}/coauth-${SHORT_SHA}.slsa.bundle" \
  "${PROVENANCE}"
```

## Local release process

1. Run the local build and test commands for the current phase.
2. Generate local SBOM and provenance artifacts under
   `target/release-artifacts/`.
3. Record the evidence in the project milestone or release-evidence
   document.
4. Do not undraft releases, publish releases, create tags, push images,
   or upload remote attestations.

[`release-branch` workflow]: https://github.com/arkret-org/coauth/actions/workflows/release-branch.yaml
[`release-bump` workflow]: https://github.com/arkret-org/coauth/actions/workflows/release-bump.yaml
[`release` workflow]: https://github.com/arkret-org/coauth/actions/workflows/release.yaml
[CI to churn]: https://github.com/arkret-org/coauth/actions/workflows/release.yaml?query=event%3Apush
[draft release to appear]: https://github.com/arkret-org/coauth/releases
