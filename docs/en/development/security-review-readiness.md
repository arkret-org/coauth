# External Security Review Readiness

This is the local readiness record for a future external security review. It
does not contact a vendor, upload artifacts, create issues, or publish a
release.

## Review Scope

The intended external review scope is the v1.0 coauth service:

- OIDC/OAuth flows: authorization code, device authorization, refresh,
  dynamic client registration, introspection, discovery, JWKS, PKCE, DPoP, and
  mTLS conformance plans.
- Account lifecycle: password auth, recovery, email/phone verification,
  invite-claim states, deactivation, lock, and erasure scheduling.
- DID binding: JWS verification, DID document resolution, verification method
  matching, canonical statement matching, and fixture coverage.
- Admin API: `coauth-admin-types` shared DTOs, `sodmin` bridge discovery,
  account mutation workflows, risk-action durable proposal approval/execute,
  audit feed, and policy dry-runs.
- Policy and signing: policy-response signing transcript, policy frontier,
  Cedar/remote policy backends, signed policy decision audit records.
- Operations: `/readyz`, Prometheus metrics binding, OpenTelemetry exporter
  examples, local SBOM, local provenance, release image Trivy scan, and
  Dependabot coverage.

## Local Evidence Pack

| Area | Local evidence |
| --- | --- |
| Architecture | `docs/en/development/architecture.md`, `docs/en/observability.md` |
| Account lifecycle | `docs/en/account-lifecycle.md` |
| Arkret surface rules | `docs/en/reference/arkret-surfaces.md` |
| Admin API | `docs/en/topics/admin-api.md`, `crates/admin-types/` |
| Shared admin DTOs | `crates/admin-types/`, `docs/architecture/contracts-ownership.md` |
| Frontend accessibility | `crates/frontend/A11Y.md` |
| Frontend build/i18n | `crates/frontend/BUILD_CHECKS.md` |
| Local release artifacts | `docs/en/development/releasing.md`, `scripts/v1-local-milestone.ps1` |
| CI and scans | `.github/workflows/ci.yaml`, `.github/workflows/oidc-conformance.yaml`, `.github/workflows/release.yaml`, `.github/dependabot.yml` |

## Reviewer Intake Checklist

- Export a read-only source archive from a clean local commit.
- Include local service run logs and conformance evidence for the relevant API surfaces.
- Include the local SBOM and SLSA provenance files generated under
  `target/release-artifacts/`.
- Include the nightly OIDC conformance run URLs for `plan-basic-op.json`,
  `plan-fapi2-baseline.json`, and `plan-mtls-baseline.json` after they are
  green.
- Include focused notes for high-risk surfaces: DID binding proof validation,
  policy-response signing transcript, risk-action proposal approval/execute,
  and account invite-claim states.
- Explicitly mark out of scope: pushing images, creating tags, publishing a
  GitHub release, publishing crates, or uploading local provenance to Rekor.

## Known Local Blockers

- External vendor scheduling is not performed by this repository change.

## Local Readiness Status

The repository has a local readiness record and an evidence checklist. The
external review can be scheduled once a clean build/conformance evidence bundle
is generated.
