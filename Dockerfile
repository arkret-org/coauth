# syntax = docker/dockerfile:1.7.1
# Builds a minimal image with the binary only. Buildx publishes amd64 and arm64
# variants from this Dockerfile. Frontend assets can either be built in-Docker
# on the native builder platform or injected as a prebuilt named build context,
# while the server binary is compiled on the requested target platform so it
# links against the correct native system libraries.

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=12
ARG DEBIAN_VERSION_NAME=bookworm
ARG RUSTC_VERSION=1.93.0
ARG CARGO_AUDITABLE_VERSION=0.7.0
ARG CARGO_CHEF_VERSION=0.1.77
ARG DIOXUS_CLI_VERSION=0.7.5
ARG FRONTEND_DIST_SOURCE=frontend-build

############################################
## Shared frontend toolchain             ##
############################################
FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS frontend-toolchain

ARG DIOXUS_CLI_VERSION
ARG CARGO_CHEF_VERSION

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HTTP_TIMEOUT=600
ENV CARGO_HTTP_MULTIPLEXING=false
ENV CARGO_NET_RETRY=10
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Install wasm target (with retries for flaky networks) and Dioxus CLI
# Network access: to fetch dependencies
ENV RUSTUP_HTTP_TIMEOUT=600
RUN --network=default \
  --mount=type=cache,id=frontend-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
  --mount=type=cache,id=frontend-cargo-git,target=/usr/local/cargo/git,sharing=locked \
  for i in 1 2 3 4 5; do rustup target add wasm32-unknown-unknown && break || sleep 10; done && \
  cargo install --locked dioxus-cli@${DIOXUS_CLI_VERSION} && \
  cargo install --locked cargo-chef@=${CARGO_CHEF_VERSION}

# Pre-install binaryen (wasm-opt) so dx build doesn't need to download from GitHub
RUN --network=default \
  apt-get update && apt-get install -y binaryen && rm -rf /var/lib/apt/lists/* || true

############################################
## Build stage that builds the frontend   ##
############################################
FROM frontend-toolchain AS frontend-planner

WORKDIR /app
COPY ./ /app

# cargo-chef computes a recipe keyed by workspace manifests so frontend
# dependency compilation can be reused when Rust sources change.
RUN cargo chef prepare --recipe-path frontend-recipe.json

FROM frontend-toolchain AS frontend-build

WORKDIR /app
COPY --from=frontend-planner /app/frontend-recipe.json frontend-recipe.json

RUN --network=default \
  --mount=type=cache,id=frontend-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
  --mount=type=cache,id=frontend-cargo-git,target=/usr/local/cargo/git,sharing=locked \
  --mount=type=cache,id=frontend-target,target=/app/target,sharing=locked \
  cargo chef cook \
    --recipe-path frontend-recipe.json \
    --locked \
    --release \
    --package coauth-frontend \
    --target wasm32-unknown-unknown

COPY ./ /app

# Build the WASM frontend (retry for flaky esbuild downloads)
RUN --network=default \
  --mount=type=cache,id=frontend-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
  --mount=type=cache,id=frontend-cargo-git,target=/usr/local/cargo/git,sharing=locked \
  --mount=type=cache,id=frontend-target,target=/app/target,sharing=locked \
  for i in 1 2 3; do dx build -p coauth-frontend --release && break || echo "Retry $i..." && sleep 10; done \
  && cp -r target/dx/coauth-frontend/release/web/public /frontend-dist

# Export the built frontend assets as a filesystem root so workflows can
# materialize them once and reuse them across architecture-specific image jobs.
FROM scratch AS frontend-dist-export
COPY --from=frontend-build /frontend-dist/ /

# Normalize a named build context containing prebuilt frontend assets to the
# same /frontend-dist path used by the in-Docker frontend build stage.
FROM scratch AS frontend-prebuilt
COPY --from=frontend-dist / /frontend-dist

FROM ${FRONTEND_DIST_SOURCE} AS frontend-assets

########################################
## Build stage that builds the binary ##
########################################
FROM --platform=${TARGETPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS builder-base

ARG CARGO_AUDITABLE_VERSION
ARG CARGO_CHEF_VERSION
ARG RUSTC_VERSION
ARG TARGETARCH

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HTTP_TIMEOUT=600
ENV CARGO_HTTP_MULTIPLEXING=false
ENV CARGO_NET_RETRY=10
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Install pinned versions of cargo-auditable
# Network access: to fetch dependencies
RUN --network=default \
  --mount=type=cache,id=builder-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry,sharing=locked \
  --mount=type=cache,id=builder-cargo-git-${TARGETARCH},target=/usr/local/cargo/git,sharing=locked \
  cargo install --locked cargo-auditable@=${CARGO_AUDITABLE_VERSION} && \
  cargo install --locked cargo-chef@=${CARGO_CHEF_VERSION}

# Install build dependencies
# Network access: to install apt packages
RUN --network=default \
  apt-get update && apt-get install -y \
  libpq-dev \
  g++ \
  && rm -rf /var/lib/apt/lists/*

FROM builder-base AS builder-planner

WORKDIR /app
COPY ./ /app

# cargo-chef keeps the dependency build layer keyed to Cargo manifests so
# source-only changes can reuse compiled dependencies and downloaded crates.
RUN cargo chef prepare --recipe-path backend-recipe.json

FROM builder-base AS builder

ARG TARGETARCH

WORKDIR /app
COPY --from=builder-planner /app/backend-recipe.json backend-recipe.json

RUN --network=default \
  --mount=type=cache,id=builder-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry,sharing=locked \
  --mount=type=cache,id=builder-cargo-git-${TARGETARCH},target=/usr/local/cargo/git,sharing=locked \
  --mount=type=cache,id=builder-target-${TARGETARCH},target=/app/target,sharing=locked \
  cargo chef cook \
    --recipe-path backend-recipe.json \
    --locked \
    --release \
    --bin coauth \
    --no-default-features \
    --features docker,cedar

COPY ./ /app

ARG VERGEN_GIT_DESCRIBE
ENV VERGEN_GIT_DESCRIBE=${VERGEN_GIT_DESCRIBE}

# Network access: cargo auditable needs it
RUN --network=default \
  --mount=type=cache,id=builder-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry,sharing=locked \
  --mount=type=cache,id=builder-cargo-git-${TARGETARCH},target=/usr/local/cargo/git,sharing=locked \
  --mount=type=cache,id=builder-target-${TARGETARCH},target=/app/target,sharing=locked \
  cargo auditable build \
    --locked \
    --release \
    --bin coauth \
    --no-default-features \
    --features docker,cedar \
  && mv "target/release/coauth" "/usr/local/bin/coauth-${TARGETARCH}"

#######################################
## Prepare /usr/local/share/coauth/ ##
#######################################
FROM --platform=${BUILDPLATFORM} scratch AS share

# Cedar policies
COPY ./policies/cedar/ /share/cedar
COPY ./templates/ /share/templates
COPY ./translations/ /share/translations
COPY --from=frontend-assets /frontend-dist/ /share/assets

##########################################################
## Prepare writable runtime state and shared libraries  ##
##########################################################
FROM docker.io/library/debian:${DEBIAN_VERSION_NAME}-slim AS runtime-rootfs

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
  libpq5 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/coauth-${TARGETARCH} /tmp/coauth

RUN set -eux; \
  mkdir -p /var/lib/coauth/data/media /runtime-deps; \
  chown -R 65532:65532 /var/lib/coauth; \
  ldd /tmp/coauth \
    | awk '($2 == "=>") { print $3 } ($1 ~ /^\//) { print $1 }' \
    | sort -u > /tmp/runtime-libs.txt; \
  while read -r lib; do \
    [ -n "$lib" ] || continue; \
    mkdir -p "/runtime-deps$(dirname "$lib")"; \
    cp -L "$lib" "/runtime-deps$lib"; \
  done < /tmp/runtime-libs.txt

##################################
## Runtime stage, debug variant ##
##################################
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:debug-nonroot AS debug

ARG TARGETARCH
COPY --from=runtime-rootfs /runtime-deps/ /
COPY --from=builder /usr/local/bin/coauth-${TARGETARCH} /usr/local/bin/coauth
COPY --from=share /share /usr/local/share/coauth
COPY --from=runtime-rootfs --chown=65532:65532 /var/lib/coauth /var/lib/coauth

WORKDIR /var/lib/coauth
ENTRYPOINT ["/usr/local/bin/coauth"]

###################
## Runtime stage ##
###################
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:nonroot

ARG TARGETARCH
COPY --from=runtime-rootfs /runtime-deps/ /
COPY --from=builder /usr/local/bin/coauth-${TARGETARCH} /usr/local/bin/coauth
COPY --from=share /share /usr/local/share/coauth
COPY --from=runtime-rootfs --chown=65532:65532 /var/lib/coauth /var/lib/coauth

WORKDIR /var/lib/coauth

# `coauth healthcheck` issues a real HTTP GET against the configured
# `/health` listener and exits non-zero on failure, so the same probe
# protects against binary corruption AND a wedged server. Operators
# can still wire a separate orchestrator probe directly to /health.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/coauth", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/coauth"]
