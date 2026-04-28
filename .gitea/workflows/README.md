# Gitea workflows

These workflows are for Gitea Actions only. Gitea will use `.gitea/workflows/`,
while GitHub continues to use `.github/workflows/`.

Optional variables and secrets:

- `REGISTRY_USER` / `REGISTRY_TOKEN`: enables pushes to the Gitea container registry
- `DOCKERHUB_USER` / `DOCKERHUB_TOKEN`: enables pushes to Docker Hub
- `DOCKERHUB_NAMESPACE`: optional Docker Hub namespace override
- `CODECOV_TOKEN`: enables coverage upload
- `LOCALAZY_WRITE_KEY`: enables Localazy upload/download workflows

Notes:

- Gitea artifact upload uses `christopherhx/gitea-upload-artifact@v4`
  instead of GitHub's `actions/upload-artifact@v4+`
- Gitea CI restores Cargo registry/git data and the workspace `target/`
  directory via `actions/cache@v3`
- The partitioned Rust test job compiles a `nextest` archive once, uploads it
  as a Gitea artifact, and reuses it across all test partitions
- The Gitea image build currently runs only the release `arm64` image.
  The `amd64` image build is temporarily disabled in Gitea Actions
- Published image tags are pushed directly from the native `arm64` build
  job; the workflow currently does not use Docker Buildx or manifest
  assembly
- The Gitea release image jobs build the Dioxus frontend inside each
  per-architecture Docker build, matching the GitHub release workflow and
  avoiding artifact hand-off failures between jobs
- Each enabled architecture also gets its own published tags such as
  `main-arm64` and `sha-<commit>-arm64`
- The `arm64` image job targets the `ubuntu-24.04-arm64` runner label and
  builds with the runner's native Docker engine on arm64
- Gitea workflows intentionally do not use `mozilla-actions/sccache-action`.
  They rely on the runner's `actions/cache` endpoint instead, because that
  works with standard Gitea Actions runners
- The Gitea docs workflow validates and uploads the generated site artifact,
  but does not try to deploy GitHub Pages
- The Gitea translation download workflow commits changes back to the current
  branch instead of opening a GitHub pull request
