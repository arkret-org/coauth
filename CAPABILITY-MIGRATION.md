# Capability preservation — authority-commit migration

coauth is the Account Authority and OAuth/OIDC service. The authority-commit
migration removed Seal, protocol-level Cell/CRDT state, generic frontiers and
the control-proposal plane from the protocol. Shared Realm finality is now the
authority-signed `RealmCommit` produced by a Realm's single current governing
Station (`sync/authority-commit-log.md`), and recovery completes as two
consecutive `CommittedEventRef`s in one PCR Realm stream
(`identity/security-transactions.md` section 2.3).

Every product capability coauth owns — accounts, principal DID binding,
OAuth/OIDC, session grants, agents, admin and authentication support — is
preserved. This file records, per entry point, where the capability lives now
and which test covers it.

## Migrated

| Capability / entry point (before) | Implementation now | Test |
| --- | --- | --- |
| `POST /_arkret/gate/account/recovery-session-grants/issue` accepted a Station attestation whose `first_generation_seal_id` and `terminal_commit_digest` bound recovery completion to a committed Seal. | `crates/backend/src/handlers/arkret/recovery_authority.rs` — `validate_completion_evidence` now joins the two halves of the atomic recovery unit: the replacement device's receipt carries `reanchor_event_id` / `authorization_event_id`, the Station's attestation carries `reanchor_ref` / `device_authorization_ref`, and the handler requires the ids to match the refs, the two refs to share one `commit_id`, and (via `commit_pair_realm`) the stream to be the account's own `principal_control_realm_id` Realm stream. `IssueRecoveryCompletionGrantRequest::validate_structural` in the SDK already rejects a cross-stream or non-consecutive pair. | `crates/backend/src/handlers/arkret/tests.rs` recovery-completion cases; blocked, see "External blockers". |
| The recovery replay ledger recorded a single `device_authorization_event_id`. | `crates/data/src/recovery_authority.rs`, `crates/storage-postgres/src/recovery_authority.rs`, `crates/storage-postgres/src/schema.rs` and the initial migration now record closed `reanchor_ref` and `device_authorization_ref` JSON. The table carries `recovery_completion_grant_issuances_consecutive_pcr_commit`, which refuses to store any pair that is not one `RealmCommit` on one Realm stream at consecutive positions. | `crates/storage-postgres` recovery repository tests; blocked, see below. |
| Session-grant device binding named the authorizing Event by id. | `SessionGrantDeviceBinding.authorization_ref: CommittedEventRef` (SDK-owned) is populated from `request.device_authorization_ref`. | as above |
| Agent runtime scopes carried `ak.self.events.read.describe.v1`, `ak.self.events.read.frontier.v1`, `ak.self.events.read.resolve.v1` and `ak.self.seals.read.frontier.v1`. | Those four operations no longer exist in the service-operation registry. The canonical scope fixtures in `crates/backend/src/handlers/account/agents/session_proof.rs`, `crates/backend/src/handlers/account/agents/key_pair/tests.rs` and `crates/storage-postgres/src/agent_key.rs` now carry only registered operations, matching `agent-runtime-scope-registry.json` (`interactive_chat` = submit / read.scan / stream.subscribe, `e2ee` = keypackage upload / consume / revoke, plus `ak.self.signal.command.send.v1`). | `pairing_scope_precheck_returns_key_reason_before_queueing` in `key_pair/tests.rs`, rewritten so the key-layer deficiency is a missing E2EE mandatory operation instead of a missing Seal-frontier read. |
| Agent key-pair commit job branched on `AgentKeyPairActivationState::AwaitingAcceptedFrontier`. | `crates/tasks/src/agent_key_pair_commit.rs` branches on `AgentKeyPairOutcome.status` (`AgentLifecycleState`). The outcome only exists once the Station has committed the authorize Event, so there is no "awaiting acceptance" retry state; active and paused Agents both complete re-pairing (`key-management.md` section 3.6.1), deactivated is terminal. | `crates/tasks` job tests; blocked, see below. |
| `AgentKeyPairRequestBody.authorize_event` was an `EventCommitSubmission` wrapper. | The SDK's single submission DTO is `EventCommitSubmission { event }`; this body embeds the producer `Event` directly. All call sites in `crates/backend/src/handlers/account/agents/`, `crates/principal` and `crates/tasks` unwrapped accordingly. | as above |
| Organization principal control stored a `pcr_frontier_digest`; organization statements carried `realm_frontier_digest`. | `pcr_commit_ref` / `realm_commit_ref`, typed as `RealmCommitId`, matching the SDK's `RealmOrganizationPayload.realm_commit_ref`. `crates/backend/src/handlers/admin/v1/organizations.rs` parses them with `parse_commit_ref`, and the table enforces `organization_principal_controls_pcr_commit_ref_shape`. Bootstrap, rotate-controller, delegation and statement issuance all keep their routes and behaviour. | `commit_ref_must_be_a_canonical_realm_commit_id`, `controller_proof_transcript_binds_organization_and_pcr_inputs`, `rotation_body_treats_an_absent_commit_ref_as_the_rotated_to_value` in `organizations.rs`; `crates/storage-postgres/src/organization_control.rs` rotation tests. |
| `principal_did_bindings.binding_frontier_digest`. | Renamed to `binding_receipt_digest`, which is what the value has always been: `SHA-256` of the canonical `AccountBindingReceipt`. No frontier was ever involved. Column, domain record and the `principal_did_binding_basis_shape` check were renamed together. | `crates/storage-postgres/src/user/tests.rs` principal-DID binding tests. |
| Peer HTTP-signature test signed a request to `/_arkret/peer/events/frontier`. | `crates/backend/src/services/peer_protocol_client.rs` signs `POST /_arkret/peer/streams/scan` with `ServiceOperationId::PEER_EVENTS_READ_SCAN_V1`. The property under test (signature covers method, target, operation and content digest) is unchanged. | `signed_query_covers_actual_method_target_and_content_digest` |
| Device revocation gate fixtures carried `covering_seal_id` and `blocking_proposal_digest`. | Both members are gone from `device-revocation-state.schema.json#/$defs/device_revocation_gate_decision_receipt`; the fixtures in `session_grant/device_revocation_gate.rs` and `account_handoff/tests/identity_creation.rs` were updated to the current closed shape. The gate capability (origin-Station linearized allow/revoked decision before grant issue) is unchanged. | `crates/backend/src/handlers/arkret/session_grant/device_revocation_gate.rs` tests; blocked, see below. |
| Documentation referring to a "policy frontier" and "Retired role-prefixed ids". | `docs/en/development/security-review-readiness.md`, `docs/{en,zh}/topics/deployment_hardening.md`, `docs/en/topics/handle-claim-ledger.md` reworded to "policy decision basis" / "policy 裁决调用" and a plain rejection statement. | n/a (prose) |

## Unchanged product capability

Accounts and account status, principal DID binding and verification, DID
resolution and freshness, OAuth 2.1 / OIDC, upstream providers and links,
session grants (issue / refresh / revoke / introspect), account handoff, agent
provisioning and pairing, keyring and KeyStore, notifications, admin API,
invites, erasure lifecycle, telemetry and the queue all keep their routes,
storage and tests. No product module was deleted.

`exporter` throughout `crates/backend/src/telemetry.rs` and
`crates/config/src/sections/telemetry.rs` is the OpenTelemetry term, not the
deleted history exporter; `Sealed` in `crates/templates/src/context/ext.rs` is
the Rust sealed-trait pattern; `hyper_util::client::legacy` and the
`#[allow(deprecated)]` shims around `generic-array` are third-party names. None
of these are protocol residue and none were changed.

## Known residue that is blocked upstream

| Residue | Why it is still here |
| --- | --- |
| `crates/backend/src/handlers/account/consent_cell_query.rs` reads an `OrSet` consent Cell from `/_arkret/self/consent/cell` using `arkret_models_collaboration::account_lifecycle::{ConsentCellView, ConsentState}` and `CellFamilyId`. | Consent is a live product capability and the invite gate depends on it, so the module must be migrated, not deleted. The successor surface exists in the spec (`ak.self.consent.resource.get.v1`, `ak.self.consent.read.list.v1` at `GET /_arkret/self/consent/results`, schema `consent-operations.schema.json#/$defs/consent_list`) but the SDK exposes no Rust DTO for it yet. Migrating it now would mean hand-rolling protocol types in coauth, which the migration forbids. |
| `crates/backend/src/handlers/arkret/controller_gate.rs` still writes the gate basis member as `binding_frontier_digest`. | `ControllerAccountGateBasis` is an SDK type that is currently absent; the final member name has to come from regenerated SDK code, not from a guess here. The value passed in is the renamed local `binding_receipt_digest`. |
| `ak.self.authorization_leases.command.issue.v1` appears in the canonical Agent scope fixture in `session_proof.rs`. | The operation is absent from both the spec's HTTP binding and the SDK registry. It belongs to the authz/lease plane rather than this migration's subject, so it is recorded here instead of being removed in the same change. |

## External blockers at the time of this change

`cargo +nightly fmt` succeeds. `cargo check --workspace --all-features` and
therefore `cargo test --workspace --all-features --no-fail-fast` cannot run:
the workspace stops at two crates, both on types that exist in `arkret-spec`
but are missing from the SDK's generated Rust surface.

- `coauth-principal` — 5 errors, all `arkret_models_collaboration::account_lifecycle`:
  `AccountStatusPublicationRequestBody`, `AccountStatusPublicationOutcome`.
- `coauth-data` — 12 errors: the same `account_lifecycle` module plus
  `principal_operations::{PcrGenesisSubmitRequestBody, PcrGenesisSubmitOutcome}`.
- `soland-contracts` (a dependency of `coauth-backend`) — 1 error,
  `arkret_models_collaboration::events_payloads::MediaServiceFocus`.

Further SDK gaps that the build has not yet reached, found by inspection:
`ControllerAccountGateAttestation` and its basis / eligibility / status types,
the whole `DeviceRevocationGate*` family, `SessionGrantIntrospect*`,
`SessionRevokeRequestBody` / `SessionRevokeOutcome`,
`AuthSessionLogoutRequestBody`, `DidBoundSignature`, and the consent types
listed above. `session_grant_introspect` and `auth_session_logout` have no
occurrence in `arkret-spec` at all, so those two need a spec ruling rather than
only a codegen pass.

None of these are caused by this change; the same two crates failed on the same
symbols before it.
