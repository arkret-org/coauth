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
| `POST /_arkret/gate/account/recovery-session-grants/issue` accepted a Station attestation whose `first_generation_seal_id` and `terminal_commit_digest` bound recovery completion to a committed Seal. | `crates/backend/src/handlers/arkret/recovery_authority.rs` — `validate_completion_evidence` now joins the two halves of the atomic recovery unit: the replacement device's receipt carries `reanchor_event_id` / `authorization_event_id`, the Station's attestation carries `reanchor_ref` / `device_authorization_ref`, and the handler requires the ids to match the refs and (via `commit_pair_realm`) the stream to be the account's own `principal_control_realm_id` Realm stream. One `RealmCommit` covers exactly one Event, so the two refs always name two distinct commits; same-stream adjacency and the distinctness of both `commit_id` and `event_id` are enforced by the SDK's `validate_recovery_commit_pair`, reached through `IssueRecoveryCompletionGrantRequest::validate_structural`. The refs are read from `completion_attestation.reanchor_event_ref` / `.device_authorization_event_ref`, which is where the SDK carries them. | `crates/backend/src/handlers/arkret/tests.rs` recovery-completion cases; blocked, see "External blockers". |
| The recovery replay ledger recorded a single `device_authorization_event_id`. | `crates/data/src/recovery_authority.rs`, `crates/storage-postgres/src/recovery_authority.rs`, `crates/storage-postgres/src/schema.rs` and the initial migration now record closed `reanchor_ref` and `device_authorization_ref` JSON. The table carries `recovery_completion_grant_issuances_consecutive_pcr_commit`, which refuses to store any pair that is not two distinct `RealmCommit`s over two distinct Events on one Realm stream at consecutive positions. | `crates/storage-postgres` recovery repository tests; blocked, see below. |
| Session-grant device binding named the authorizing Event by id. | `SessionGrantDeviceBinding.authorization_ref: CommittedEventRef` (SDK-owned) is populated from `completion_attestation.device_authorization_event_ref`. The SDK member name and the spec's `authorization_event_id` disagree; see "SDK / spec conflicts". | blocked, see below |
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

## Second pass — rulings landed

| Ruling | What changed here |
| --- | --- |
| `session_grant_introspect` / `auth_session_logout` are in the spec after all, spelled `ak.gate.account.command.introspect_session_grant.v1` and `ak.gate.account.command.logout_auth_session.v1` (`zh/sync/service-http-binding.md` L202 / L208), with HTTP bindings and OpenAPI entries. | Both implementations are kept. The status vocabulary follows the SDK's decision to reuse `arkret_models_identity::SessionGrantAdminIntrospectionStatus`: 30 occurrences of the old local spelling in `crates/backend/src/handlers/arkret/session_grant/introspection.rs` and `crates/backend/src/handlers/arkret/tests.rs` were renamed, and the DTO import moved from `session_grant_bodies` to `session_grants`. |
| `ak.self.authorization_leases.command.issue.v1` is deleted (zero hits across the 218-operation registry and `service-http-binding.md`), but the `AuthorizationLease` object itself stays in the spec and is now produced inside the security-transaction flow. | coauth never routed the operation; it appeared only in the canonical Agent scope fixture. All three occurrences in `crates/backend/src/handlers/account/agents/session_proof.rs` are gone. No type was deleted: coauth defines and consumes no lease type. |

## Second pass — migrations unblocked by the SDK

| Module | What it is now | Test |
| --- | --- | --- |
| `crates/backend/src/handlers/account/consent_result_query.rs` (was `consent_cell_query.rs`) | Reads `ak.self.consent.resource.get.v1` at `GET /_arkret/self/consent/result` with the same `(peer, consent_scope)` resource key, parses `arkret_models_collaboration::consent_operations::ConsentView`, and calls the view's own `validate()` before trusting it. `ConsentPeer` now comes from `events_payloads::consent`. The local `ConsentState`/`tags` pair became `ConsentGrantState`/`granted_scopes: Vec<ConsentScope>`, so the invite gate compares typed scopes instead of `"scope=…"` strings. Every `cell` in the module name, URL path, function names, log fields and prose is gone. | the module's own 11 tests — 6 wiremock round-trips over the new path and DTO, 5 pure `evaluate_invite_gate` cases — plus the `invite_relay.rs` call-site tests; blocked, see below |
| `crates/backend/src/handlers/arkret/controller_gate.rs` | The gate basis member is written under the SDK's real name, `ControllerAccountGateBasis::AccountBindingDefault { binding_version, binding_receipt_digest }`; SDK member and local column now agree that the value is the digest of the stored `AccountBindingReceipt`. Signing moved off the withdrawn `arkret_signatures::agent_evidence::sign_controller_account_gate_attestation` and onto the two SDK primitives it was built from: `ControllerAccountGateAttestation::signing_bytes()` plus `arkret_signatures::sign_ed25519_detached_jws`. | `crates/backend/src/handlers/arkret/tests.rs` controller-gate cases; blocked, see below |

## Second pass — SDK module and member realignment

Pure re-pointings at the SDK's current layout, applied across the workspace:

| Was | Is |
| --- | --- |
| `account_lifecycle::{AccountRegisterRequestBody, AccountRegisterOutcome}` | `account_operations::…` |
| `account_lifecycle::{AccountStatusRecord, UnsignedAccountStatusRecord}` | `account_status::…` |
| `session_grant_bodies::{SessionGrant*, AgentSessionGrant*, AuthSessionLogout*, SESSION_GRANT_INTROSPECTION_PROOF_CLAIMS_KIND}` | `session_grants::…` — only `RecoverySessionGrantRequest` and the Agent refresh digest stayed in `session_grant_bodies` |
| `agent_operations::agent_runtime_key_binding_digest` | `agent_scope::agent_runtime_key_binding_digest` |
| `agent_operations::AgentKeyPairActivationState::Active` | `AgentKeyPairOutcome.status != agent_operations::AgentLifecycleState::Active` |
| `AgentKeyPairOutcome.authorize_event_ref` | `.authorize_ref.event_id` |
| `IdentityCreationRegistration.pcr_genesis_unit` | `.creation_events.{realm_create, founding_device_authorize}`, recomposed with the SDK's `PcrGenesisUnit::new` for the PCR genesis submit body |
| `AgentKeyPairRequestBody.authorize_event.event` | `.authorize_event` — the body embeds the producer `Event` directly |
| `AccountLifecycleProof.proof_kind` compared as `&str` | matched as the typed `AccountLifecycleProofKind` |
| `IssueRecoveryCompletionGrantRequest.{reanchor_ref, device_authorization_ref}` | `.completion_attestation.{reanchor_event_ref, device_authorization_event_ref}` |
| `CommitStreamRef` match without a wildcard | wildcard arm added; the enum is `#[non_exhaustive]` and non-Realm streams stay refused |

## Verification

| Command | Result |
| --- | --- |
| `just fmt`, then `cargo +nightly fmt -p <the 20 local packages>` | clean; verified the sibling `arkret-rust-sdk` checkout is byte-identical before and after |
| `cargo check --workspace --all-features` | 19 of the 20 local packages compile. `coauth-backend` stops with 39 errors, every one an SDK surface that does not exist — see below. 2 pre-existing `unused import: Hash` warnings, left alone because the crate is red and the import analysis is incomplete. |
| `cargo test --workspace --all-features --no-fail-fast` | cannot run: every test target links `coauth-backend` |
| module reachability self-check | 20 crates; 631 `src/**/*.rs` on disk, 631 reachable by walking `mod` from `src/lib.rs`, `src/main.rs`, `src/bin/*`, `tests/*`, `examples/*` and `benches/*` (`#[path]` and nested inline `mod` handled, `build.rs` excluded); **0 orphans** |
| residue scan | see below |

### Residue scan

`Seal`, `Cell`, `frontier`, `lattice`, `Retired`, `exporter` and `deprecated`
are the only terms with hits, and every hit is a legitimate ordinary-English or
third-party use:

- `trait Sealed` in `crates/templates/src/context/ext.rs` — the Rust sealed-trait pattern.
- `exporter` in `crates/backend/src/telemetry.rs`, `crates/cli/src/main.rs` and `crates/config/src/sections/telemetry.rs` — OpenTelemetry span / metric / Prometheus exporters.
- `deprecated` — RFC 7636's wording about `plain`, the OpenTelemetry note about Jaeger-native propagation, and the `#[allow(deprecated)]` shims around `generic-array` re-exports.
- `module-lattice` in `Cargo.lock` — the ML-KEM third-party crate.
- `lattice-registry` in an archived `artifacts/cargo-adhoc/` build log.
- This file and the history rows above, which have to name what was removed.

`CBS`, `Bottom`, `ControlProposal`, `sequenced_state`, `or_set`,
`causal_register`, `authority_revision`, `auth_context`, `RHRK`,
`history_secret`, `policy_root`, `encryption_floor`, `encryption_profile`,
`Legacy` and `Deprecated` have zero hits.

## Blocked on missing SDK surface — 2026-09-17 复核：全部 12 行已闭合

> **2026-09-17 逐条复核结论（against `arkret-rust-sdk` @ `2293a1fa`）**
>
> 本节记录的是 SDK commit `e309b047`（2026-09-16）过度删除造成的缺口。该删除**已被
> SDK 后续三个提交补回**：`6fff24d2`（authority-commit 面）、`11fc225b`（Agent runtime
> scope 与 session-grant 面）、`eccd53f1`（detached-object 与 controller-gate 签名面）。
> 12 行缺口 + 4 条 SDK/spec 冲突逐条复核后**全部闭合**，且形状与 coauth 调用点对得上
> （不只是同名命中）。原始表格与冲突列表保留在本节末尾的「原始记录」下，不删除。
>
> 复核口径：符号在 `arkret-rust-sdk/crates/` 下查找并排除 `crates/wire/src/generated/`；
> 只有生成常量而无可调用 DTO 的一律判为「仍缺」。

### 缺失 SDK 面（12 行）复核

| # | 原账本条目 | 现状 | 证据（`arkret-rust-sdk/` 相对路径） |
| --- | --- | --- | --- |
| 1 | `arkret_schema::agent_runtime_scope` 整模块 | **已闭合** | `crates/schema/src/agent_runtime_scope.rs`：`AgentRuntimeScopeDeficiency` L29、`AgentRuntimeScopeError` L37、`selected_agent_runtime_capabilities` L46、`complete_agent_runtime_scope` L93、`assess_agent_runtime_scopes` L114、`assess_agent_runtime_provision_scope` L135、`assess_agent_runtime_key_scopes` L142；`AgentRuntimeScopeLayer` 由 L23 `pub use crate::generated::{…}` 重导出。恢复自 `11fc225b`。三个消费者的调用点全部满足：coauth `session_proof.rs:670/678/699`、soland `crates/http/src/routing/identity/agents/common.rs:126/147`、inkson `src/views/agents/model.rs:312` |
| 2 | `agent_operations::KeyState.{requested_scope, active_authorizations, controller_authorization_ref}` | **已闭合** | 三个成员就在 `crates/models-collaboration/src/agent_operations.rs` 的 `pub struct KeyState`（L317）上：`controller_authorization_ref: DidUrl` L320、`requested_scope: AgentKeyScope` L324、`active_authorizations: Vec<AgentKeyAuthorizationState>` L350。`AgentKeyAuthorizationState`（`governance/agent_artifacts.rs:45`）带 `key_id` / `authorized_event_ref`，正是 `key_pair.rs:749-759` 求 supersedes 集合所需 |
| 3 | `SessionGrantRefreshRequestBody::Agent` 与 `validate()` | **已闭合** | `crates/models-collaboration/src/session_grants.rs`：enum L485 有 `Human` / `Agent` 两支，`impl … validate()` L490。coauth `refresh.rs:164/172/180/266/474` 两支都用到 |
| 4 | `SessionGrantRequestBody::Recovery` | **已闭合** | `session_grants.rs:80` enum 为 `Recovery` / `Human` / `Agent` / `PairwiseEndpoint` 四支（`Recovery` 声明在 `Human` 前，untagged 匹配顺序有意为之）。coauth `issue.rs:103` 匹配该分支 |
| 5 | `AgentLifecycleState::as_wire_str` / `AgentRuntimeState::as_wire_str` | **已闭合** | `agent_operations.rs:41`（`AgentLifecycleState`）与 `agent_operations.rs:169`（`AgentRuntimeState`）。coauth `key_pair.rs:481/487/489` |
| 6 | `AgentSessionGrantProof::{validate_at, canonical_signing_bytes}` 与 `AgentSessionGrantRequest::canonical_request_digest` | **已闭合** | `session_grants.rs`：`validate_at` L328、`canonical_signing_bytes` L344、`AgentSessionGrantRequest::canonical_request_digest` L242。窗口常量 `AGENT_SESSION_PROOF_MAX_LIFETIME_SECONDS` L306 / `AGENT_SESSION_PROOF_MAX_CLOCK_SKEW_SECONDS` L308。coauth `session_proof.rs:155/259/331/535` |
| 7 | `SessionGrantDeviceBinding::{as_expected_gate_binding, from_gate_outcome}` 与 `authorization_event_id` 成员 | **已闭合（形状按裁决改回）** | `crates/models-identity/src/session_credential.rs`：`pub struct SessionGrantDeviceBinding` L74 携 `device_id` / `authorization_event_id: EventId` L76 / `model_generation_ref: u64`；`as_expected_gate_binding` L85、`from_gate_outcome` L96、`committed_authorization` L118。L60-68 的 doc 明写 gate receipt「carries no RealmCommit witness … it is not a `CommittedEventRef`」。见下方冲突第 1 条 |
| 8 | `SessionGrantHolderBinding::AgentRuntime.agent_key_authorization_ref` 与请求体不可 join | **已闭合** | 两侧现在同为 `EventId`：`session_credential.rs:44`（`SessionGrantHolderBinding::AgentRuntime.agent_key_authorization_ref: EventId`）与 `session_grants.rs:207`（`AgentSessionGrantRequest.agent_key_authorization_ref: EventId`，doc 明说两面「meet without a boundary reparse」）。coauth `issuance.rs:659/688-691` 直接传递 |
| 9 | `arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey` 及其 `from_event` | **已闭合** | `crates/models-identity/src/agent_signer_evidence.rs`：`AgentAuthorizedSigningKey` L235、`from_event(&Event) -> Result<Self>` L250、伴随 `AgentSigningPublicKey` L222。恢复自 `11fc225b` / `eccd53f1`。消费者：coauth `session_proof.rs:624`、`key_pair/tests.rs:574`；soland `evidence.rs:1129`、`pairing.rs:649`、`sync/signal.rs:676/695` |
| 10 | `agent_operations::agent_key_pairing_request_binding_digest` | **已闭合** | `agent_operations.rs:386`（8 参数：operation_id / controller_principal_id / agent_id / pairing_request_id / approval_request_id / pairing_expires_at / audience / runtime_key_binding_digest），常量 `AGENT_KEY_PAIRING_REQUEST_BINDING_KIND` L28。coauth `key_pair.rs:284` |
| 11 | `session_grant_bodies::session_grant_refresh_request_digest` | **已闭合** | `crates/models-collaboration/src/session_grant_bodies.rs:247`，6 参数 `(grant_jwt, predecessor_session_grant_id, principal_id, device_id, audience_id, holder_jkt)`，与 coauth `refresh.rs:89-96` 的调用逐参对齐。Agent 侧的 `agent_session_refresh_request_digest` 在同文件 L209 |
| 12 | `SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1` | **已闭合（常量 + DTO 都在）** | 常量 `crates/wire/src/generated/schema_ids.rs:868`；对应可调用 DTO `ControllerAccountGateAttestation`（`crates/models-identity/src/agent_signer_evidence.rs:112`），不是「已注册但不可调用」。Spec 侧登记见 `arkret-spec/spec/v1/artifacts/registry/contract-registry.json:3537`。coauth `controller_gate.rs:146` 已改用生成常量。见下方冲突第 2 条 |

### SDK / spec 冲突（4 条）复核

| # | 原冲突 | 现状 | 证据 |
| --- | --- | --- | --- |
| C1 | `SessionGrantDeviceBinding` 声明成 `authorization_ref: CommittedEventRef`，而 gate receipt 不携带 RealmCommit 见证 | **已闭合，按 coauth 主张裁决** | `arkret-spec/spec/v1/artifacts/schemas/device-revocation-state.schema.json#/$defs/device_revocation_gate_decision_receipt` 只出 `target_device_authorize_event_id` + `target_device_generation_ref`，不出 RealmCommit 见证。SDK 已改回 `authorization_event_id: EventId`（`crates/models-identity/src/session_credential.rs:76`），并把「receipt 不带 RealmCommit 见证、所以这里不是 `CommittedEventRef`」写进 L60-68 的规范性 doc |
| C2 | `ak.schema.controller_account_gate_attestation.v1` 未登记 | **已闭合** | Spec 已登记：`arkret-spec/spec/v1/artifacts/registry/contract-registry.json:3537-3541`（`schema_id` + `fragment: #/$defs/controller_account_gate_attestation`），同处 L3544 另登记 `ak.schema.controller_account_gate_attestation_issue_outcome.v1`。SDK 生成常量 `crates/wire/src/generated/schema_ids.rs:868` |
| C3 | `RealmOrganizationControlScope::NotaryControl` 与 spec 的 `realm_authority` 不一致 | **已闭合** | SDK enum 现为 `OfficialBadge / RealmAdmin / RealmAuthority / ModerationPolicy / RetentionPolicy / DirectoryListing / PlaintextVisibleService`（`crates/models-collaboration/src/events_payloads/realm.rs:574-582`），`NotaryControl` 全库零命中；spec `arkret-spec/spec/v1/artifacts/schemas/event-payload.schema.json:7334` 为 `"realm_authority"`，两侧一致 |
| C4 | session-grant union 被收窄 | **已闭合** | issue union 现为四支（`session_grants.rs:80-85`：`Recovery` / `Human` / `Agent` / `PairwiseEndpoint`），refresh union 为两支（`session_grants.rs:485-488`：`Human` / `Agent`），与 `arkret-spec/spec/v1/zh/identity/key-management.md` §6.5 的两支 refresh 描述以及 SDK 自身模块 doc 一致 |

### 复核中新发现、原账本未记的项

1. **SDK 内部有一处过期注释（非阻塞，但会误导下一个读者）**：
   `arkret-rust-sdk/crates/models-identity/src/agent_signer_evidence.rs:130-141` 的
   `ControllerAccountGateAttestation::SCHEMA_ID` 仍把 schema id 硬编码成字符串字面量，
   注释写着「the Spec schema registry has no `controller_account_gate_attestation` row
   yet … When that row lands, this constant becomes
   `SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1`」。该 row **已经 land**
   （`contract-registry.json:3537`），生成常量也已存在
   （`crates/wire/src/generated/schema_ids.rs:868`），coauth 自己已改用生成常量
   （`controller_gate.rs:146`）。SDK 侧应把 `SCHEMA_ID` 改成引用生成常量并删掉该段注释，
   否则同一个字符串在 SDK 与 coauth 有两个来源。
2. **`session_grant_refresh_request_digest`（human 分支）绑定的 operation 常量名是
   `AGENT_SESSION_REFRESH_OPERATION`**（`session_grant_bodies.rs:22`，值
   `"refresh_session_grant"`，L218 与 L256 共用）。值本身是两分支通用的 operation token，
   摘要因此正确；但常量名带 `AGENT_` 前缀，容易让人误判 human 分支复用了 Agent 的
   transcript。属命名问题，不是缺口。
3. **soland 需要的 `agent_signer_evidence` / `agent_evidence` 面远大于本账本所记，且仍缺。**
   本账本只覆盖 coauth，所以这些不在表里，但它们是同一次 `e309b047` 删除的残余：
   `arkret_models_identity::agent_signer_evidence::{AgentLifecycleStatus, AgentKeyCellEntry,
   CurrentAgentSignerEvidence, AgentSignerEvidence}` 与
   `arkret_signatures::agent_evidence::{agent_authorization_cell_ref,
   sign_agent_authority_state_attestation, agent_admission_evidence_digest}`、以及
   `arkret::build_agent_signer_evidence`，在 SDK 当前主干（排除 `generated/`）**全部零命中**。
   消费者：soland `crates/http/src/routing/identity/agents/{evidence.rs, pairing.rs, common.rs}`。
   旧实现可从 `git show e309b047^:crates/signatures/src/agent_evidence.rs`（1470 行、约 40 个
   pub 项）与 `git show e309b047^:crates/models-identity/src/agent_signer_evidence.rs` 取回参考。
   `arkret-spec/spec/v1/zh/identity/key-management.md:182` 明确点名 SDK
   `build_agent_signer_evidence` 为规范要求的构建入口，所以这条是真缺口而非下游自造。
   **建议由 soland 自己的能力账本承接。**
4. **NC-TYPE-001 命名扫描（顺带）**：SDK 非生成代码里末词为 `Result` / `Item` 的类型有
   `SignerKeyQueryResult`（`crates/models-identity/src/signer_key_operations.rs:263`）、
   `AccountSubscribeSnapshotResult`
   （`crates/models-collaboration/src/sync_frames/account_subscribe.rs:1038`）、
   `ModerationQueueItem`（`crates/models-collaboration/src/governance/moderation_queue.rs:61`）。
   按已裁定口径，查询/同步操作的答案应为 `_Outcome`、逐条记录应为 `_Row`。
   `AccountCurrentResult`（`sync_frames/current_results.rs:53`）与 `TypedCurrentResult`
   （`crates/wire/src/authority_commit.rs:732`）是与 `result_kind` 双射的类型化当前结果信封，
   合规。`MlsAddMemberResult` / `MlsAddMembersResult` / `MlsRemoveMemberResult`
   （`crates/mls/src/group.rs:211/218/241`）与 `SdkClauseResult`
   （`crates/schema/src/sdk_conformance.rs:81`）是进程内返回值，不是 wire DTO，
   是否受该规则约束需 spec 侧确认。以上均属 SDK 仓的事，不阻塞 coauth。

### 原始记录（2026-09-16，已整节过期，保留备查）

## [已过期 · 2026-09-16 原文存档] Blocked on missing SDK surface

`coauth-backend` cannot compile. None of these can be worked around without
hand-rolling a protocol type or a normative admission rule inside coauth, which
this migration forbids. Grouped by the absent SDK symbol:

| Missing SDK surface | coauth call sites | Errors |
| --- | --- | --- |
| `arkret_schema::agent_runtime_scope` — the whole module. `AgentRuntimeScopeLayer` survives as `arkret_schema::AgentRuntimeScopeLayer` (generated), but `AgentRuntimeScopeError`, `AgentRuntimeScopeDeficiency` and `assess_agent_runtime_{provision_scope,key_scopes,scopes}` are gone; `crates/schema/src/agent_runtime_scope.rs` was deleted in SDK `e309b047`. soland (`crates/http/src/routing/identity/agents/common.rs`) and inkson (`src/views/agents/model.rs`) call the same module, so this is a three-consumer regression. | `handlers/account/agents/session_proof.rs`, `handlers/account/agents/error_matrix.rs` | 10 |
| `agent_operations::KeyState.{requested_scope, active_authorizations, controller_authorization_ref}` — the SDK's `KeyState` now carries only `current_authorization_ref`. The Agent session and key-pair paths need the requested-scope ceiling and the active authorization set to re-bind cached evidence to the authoritative projection. | `handlers/account/agents/key_pair.rs`, `handlers/account/agents/session_proof.rs` | 7 |
| `SessionGrantRefreshRequestBody::Agent` and `SessionGrantRefreshRequestBody::validate()` — the SDK enum has only `Human`, while `key-management.md` section 6.5 states the refresh body has two branches, "human `device_binding`" and "Agent runtime lifecycle". | `handlers/arkret/session_grant/refresh.rs` | 5 |
| `SessionGrantRequestBody::Recovery` — the SDK enum is `Human` / `Agent` / `PairwiseEndpoint`, yet `RecoverySessionGrantRequest` exists in `session_grant_bodies` and the SDK's own module doc says the operation admits a three-branch union including it. | `handlers/arkret/session_grant/issue.rs` | 3 |
| `AgentLifecycleState::as_wire_str` and `AgentRuntimeState::as_wire_str` — needed to write the two enums into the audit payload under their exact wire spellings. | `handlers/account/agents/key_pair.rs` | 3 |
| `AgentSessionGrantProof::{validate_at, canonical_signing_bytes}` and `AgentSessionGrantRequest::canonical_request_digest` — the SDK kept only `AgentSessionGrantProof::validate_structure`, leaving the proof time-window check and the canonical signature transcript without an owner. | `handlers/account/agents/session_proof.rs` | 3 |
| `SessionGrantDeviceBinding::{as_expected_gate_binding, from_gate_outcome}` and the `authorization_event_id` member — see "SDK / spec conflicts" item 1. | `handlers/arkret/session_grant/device_revocation_gate.rs`, `handlers/arkret/mod.rs` | 3 |
| `SessionGrantHolderBinding::AgentRuntime.agent_key_authorization_ref` is a `CommittedEventRef`, but the only input coauth receives is `AgentSessionGrantRequest.agent_key_authorization_ref`, a bare event-id `String`. The two SDK types cannot be joined. | `handlers/arkret/session_grant/issuance.rs` | 1 |
| `arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey` and its `from_event` — removed with the rest of `agent_evidence` in `e309b047`. | `handlers/account/agents/session_proof.rs` | 1 |
| `agent_operations::agent_key_pairing_request_binding_digest` — the controller-signed pairing approval digest. It existed at `e309b047^`. | `handlers/account/agents/key_pair.rs` | 1 |
| `session_grant_bodies::session_grant_refresh_request_digest` — the human accepted-device refresh intent digest. The SDK has `human_session_grant_intent_digest` (issue) and `agent_session_refresh_request_digest` (Agent refresh); the human refresh transcript has no owner. | `handlers/arkret/session_grant/refresh.rs` | 1 |
| `SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1` — `ControllerAccountGateAttestation.schema` is a required member and the SDK's own fixture pins it to `ak.schema.controller_account_gate_attestation.v1`, but that id is in neither the SDK's generated `SchemaId` nor the spec's schema registry. | `handlers/arkret/controller_gate.rs` | 1 |

## [已过期 · 2026-09-16 原文存档] SDK / spec conflicts to resolve upstream

Reported rather than papered over; coauth changes neither side.

1. **`SessionGrantDeviceBinding` shape.** `service-operation-dtos.schema.json#/$defs/SessionGrantDeviceBinding` requires `{device_id, authorization_event_id, model_generation_ref}` and states the Account Authority MUST populate it verbatim from the allow receipt of `ak.peer.device_revocations.command.check.v1`. `device-revocation-state.schema.json#/$defs/device_revocation_gate_decision_receipt` discloses only `target_device_authorize_event_id` (an `event_id`) and `target_device_generation_ref`, and says explicitly that the receipt "carries no Control Proposal or RealmCommit witness". The SDK's Rust struct instead declares `authorization_ref: CommittedEventRef`. A `CommittedEventRef` cannot be derived from the allow receipt, so the SDK shape makes the spec's own mandated data flow unimplementable. Either the SDK reverts to `authorization_event_id`, or the gate receipt must start carrying a full `CommittedEventRef`.
2. **`ak.schema.controller_account_gate_attestation.v1` is unregistered.** The DTO requires the `schema` member, the SDK fixture pins that value, and it appears in no schema registry on either side.
3. **`RealmOrganizationControlScope::NotaryControl`.** The spec's `control_scope` enum in `event-payload.schema.json` spells this scope `realm_authority`; the SDK enum still says `NotaryControl`. sodmin renders the SDK value verbatim and cannot fix it locally.
4. **Narrowed session-grant unions.** The SDK's own `session_grant_bodies` module doc names a three-branch issue union and `key-management.md` section 6.5 names a two-branch refresh union; both Rust enums are narrower than the text beside them.
