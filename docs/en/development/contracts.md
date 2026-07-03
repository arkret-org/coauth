# External-protocol contracts

coauth interoperates with several sibling projects whose wire formats
evolve independently. Each integration goes through a versioned
contract; this document is the canonical reference for how those
contracts are pinned, evolved, and tested.

## soland webhook contract

soland calls coauth via signed webhooks for circle-state events
(member join / leave, policy update, dispute resolution). The
contract is versioned via a request header:

```http
POST /webhooks/soland
x-cokret-contract-version: 2026-05-01
content-type: application/json
…
```

Rules:

- coauth accepts any `x-cokret-contract-version` it recognises and
  rejects unknown values with `400 unsupported-contract-version`.
- The header is **required** — missing means soland is too old and
  must be upgraded, not silently treated as the oldest supported
  version (that path historically caused a release-day outage).
- New contract versions land in `crates/backend/src/handlers/webhooks/`
  as parallel handler modules so the previous version keeps working
  for at least one minor release. The decision to drop an old version
  lives in the release notes, never in a stealth deploy.
- The version string is calendar-versioned (`YYYY-MM-DD`); pick the
  date the contract was *finalised*, not the day it ships.

When evolving the contract:

1. Add a new module `crates/backend/src/handlers/webhooks/v<date>.rs`.
2. Route on `x-cokret-contract-version` in the dispatch layer.
3. Update soland (separate repo) to advertise the new version.
4. Mark the previous version "deprecated" in this doc and in the
   handler module's top-of-file comment; remove it in a later release.

## starid DID resolution: did:key vs did:webvh

coauth resolves both `did:key:…` and web-hosted identifiers — that is
`did:webvh:…` (the v1 core default method, served by starid) and
`did:web:…` (accepted only when the deployment explicitly declares the
no-history profile, i.e. `history_evidence_kind="none"` — for service
DIDs — or the `personal_node` deployment profile for principal DIDs).
The two go through different resolver paths with different operational
properties:

| Concern             | `did:key`                                   | `did:webvh` / `did:web`                        |
| ------------------- | ------------------------------------------- | ---------------------------------------------- |
| Resolver            | Pure in-process key decode (`multibase`)    | HTTPS GET against the DID method URL           |
| TLS validation      | N/A                                         | Strict — system root store; no `--insecure`    |
| Network egress      | None                                        | Required — coauth must reach the DID host      |
| Cache TTL           | Effectively infinite (identity = key bytes) | Short (default 5 min, configurable per host)   |
| Rotation            | None — rotating the key changes the DID     | Supported — DID doc may rotate `verificationMethod` |
| Offline operation   | Works                                       | Fails — caller sees `resolve-unavailable`      |

Implementation pointers:

- The dispatch lives in
  `crates/backend/src/services/did_resolver.rs`. The resolver
  inspects the DID method prefix and routes to the in-process
  decoder for `did:key:` or the HTTPS resolver for
  `did:webvh:` / `did:web:`.
- TLS validation for `did:webvh` / `did:web` goes through the standard
  `reqwest`-with-rustls path — there is no per-host bypass. If a
  deployment needs to resolve a DID hosted on an internal CA, the CA
  cert must be added to the system trust store.
- The cache TTL is intentionally short for `did:webvh` / `did:web`
  because the DID document is the rotation surface. Production deployments tune it
  via configuration; the default is conservative so a key rotation
  takes at most one TTL window to propagate.

## conformance/ directory

The `conformance/` directory at the repository root holds **test plan
configurations** consumed by the OpenID Foundation conformance suite
(see `conformance/README.md`). These are not contracts coauth
exposes; they are how coauth proves it implements the contracts the
OIDC / FAPI specs define.

The split is intentional:

- This document (and the soland / starid sections above) defines
  contracts **outgoing** from coauth toward sibling Cokret projects.
- `conformance/` exercises contracts coauth must implement to be a
  conforming OpenID Provider — i.e. contracts coming **in** from the
  spec ecosystem.

Both surfaces are pinned in CI: outgoing contracts via the integration
test matrix (`cotest`); incoming spec conformance via the
`oidc-conformance.yaml` workflow.
