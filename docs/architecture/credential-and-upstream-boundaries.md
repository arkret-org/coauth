# Credential issuance and upstream account association

`services/session_grant` owns signed credential construction and issuer-ledger
mutations. `services/upstream_link` owns upstream association, claim imports,
registration policy checks and registration preparation. Neither production
module imports Salvo, cookies, SessionInfo, or handlers. Their inputs are internal
business values; standard request bodies, claims, canonical issuance preimages,
outcomes and errors remain owned by the Rust SDK.

## Session-grant transaction and proof boundary

The controller validates the typed body and holder possession before exposing a
retained response. It reserves an operation and saves the reservation before an
irreversible external exchange. Existing operation state selects exact replay,
pending, conflict or indeterminate handling. A resumed issuance reconstructs its
nonce, refresh-chain id, time window and signing key id from the durable
reservation; it does not draw fresh issuance material.

Human, recovery and Agent issuance have separate named inputs. Their different
holder bindings, proof kinds, scope details and recovery lifetime cap remain
visible. A shared signer projects the SDK preimage into SDK signed claims, checks
those claims and signs with the reserved KID before selecting the supported
algorithm. The original canonical bytes, digest, JWT and grant identifier remain
the durable outcome; selecting an arbitrary current key would break replay after
key rotation.

`IssuanceCommit` names the operation, authorization checkpoint, canonical response,
browser-session link and signed material together. Its ledger helper calls the
repository inside the caller's current transaction. It never saves or cancels that
transaction. Each controller still visibly consumes the matching handoff and/or
DPoP JTI and commits these with the ledger outcome; failed consumption cancels the
same transaction. Refresh supersession, device revocation locks and retained
replay handling remain in their existing explicit controller/repository paths.

Internal browser-login issuance reserves and commits through this same ledger.
Its signed material is unique to that attempt; passing the same already-committed
material again is a caller invariant violation, not a supported replay API. The
helper comment now states the behavior its existing implementation enforces.

## Upstream association transaction and external calls

The HTTP adapter decodes encrypted cookies and selects the newest matching link
entry. The service receives only link/session identifiers, an optional browser
session identifier and a post-auth action. Lookup order is unchanged: link,
upstream session, matching link owner, unconsumed state, then active browser
session. A missing cookie is rejected before database lookup. An inactive browser
session does not authenticate the caller.

The service returns domain outcomes. GET saves only authentication, login and
registration outcomes; POST saves only association and registration outcomes.
Cookie updates, HTTP rendering, login/registration counters and transaction
save/cancel remain with the adapter. Recording a browser authentication and
consuming the upstream session share the transaction: canceling it removes both.
A committed upstream session cannot be consumed again.

Policy evaluation, Station handle-availability calls and local repository work
are explicit in the service; some external calls occur while the caller's
transaction is open. This extraction does not claim distributed atomicity or
move those calls across a commit. Conflict replacement keeps its concrete
`Pagination::first(100)` loop and repository removals visible. There is no generic
pagination or tracing wrapper: these operations do not share a sufficiently
identical business boundary to justify one.

`upstream_link::attributes` is the existing provider-configured claim-template
engine. Signed ID-token claims keep precedence over userinfo when merging `user`.
It also serves the upstream callback. `services/upstream_oidc_mapping` performs a
different trust/policy function and remains a separate owner. The shared
post-auth destination helper is pure URL policy; the HTTP form wrapper retains
its existing serialization shape.

## Remaining internal error mappings

These cases intentionally remain internal errors rather than becoming caller
validation failures. No macro hides proof checks, SQL, locks or transaction flow.

| Location | Internal failure and reason |
| --- | --- |
| `issue::map_session_grant_material_error` | Missing/unusable reserved signing key, signing failure, and canonical/SDK validation of server-authored material. `PrincipalUnknown` remains the explicit public principal error. Request and possession checks run before this construction. |
| `issue::map_oidc_exchange_error` | Only an exchange error already classified as `internal_error` remains internal. Invalid proof, client, audience, request and discovery binding retain their distinct existing public mappings. |
| Agent issuance | Serialization of an already-validated public JWK into server-authored material; the caller supplied proof is validated separately. |
| Agent refresh | A verification-method identifier returned by validated Station authorization cannot be constructed. The error denotes malformed authority material, not a normal rejected caller proof. |
| Human refresh | A stored grant references a missing browser session. A finished session instead retains the explicit logged-out response. |
| Introspection JWT decode | The input is a locally persisted signed credential. Caller-supplied refresh JWT decode has a separate client-error mapping. |
| Introspection claim validation | Locally persisted signed claims violate the SDK contract. |
| Introspection thumbprint | The persisted signed session public JWK cannot produce its validated thumbprint. |
| Introspection device identifier | The persisted non-Agent device coordinate is malformed. Agent metadata still omits the top-level human device binding. |
| Introspection projection | The server-built closed validation metadata cannot validate. Persisted canonical JWK reconstruction uses the same internal-error conversion. |
| Revoke request digest | Canonicalization of the validated typed request and authenticated actor coordinates fails. A digest mismatch remains an explicit invalid-proof response. |
| Revoke proof transcript | Canonicalization of the validated lifecycle proof fails. Signature and historical authorization rejection keep their explicit public error order. |
| Upstream required template | Provider configuration cannot render a required attribute or renders it empty; optional imports still follow their existing fallback rules. |
| Upstream skip-confirmation configuration | The configured provider skips confirmation without supplying a handle. This now has a named `SkipConfirmationWithoutHandle` error. |
| Upstream policy execution | The policy engine fails to evaluate. This now carries typed `EvaluationError`; normal policy denials retain field-specific caller errors. |
| Upstream stored ID token | Decoding an already-stored upstream token fails. This now carries typed `JwtDecodeError`; exchange verification remains with the existing OIDC service. |
| Upstream Station/repository | A concrete external Station call or repository operation fails. Sources remain attached; handle-unavailable, conflicts, missing links and consumed sessions keep their existing distinct outcomes. |

Lifecycle replay is deliberately not unified into a five-stage template. An
active predecessor can occur in refresh ledger replay, while issue/revoke invoke
the terminal-state mapper only after a non-active guard. Forcing one branch's
response onto the other would change protocol behavior.

## Verification scope

PostgreSQL tests exercise association ownership/missing-state guards, active
browser filtering, consumed-state rejection, caller rollback of authentication
and consumption, and the real HTTP cookie/commit/replay adapter. Existing grant,
DPoP, recovery, OIDC, policy and repository tests validate their unchanged business
contracts. The live owned-process response-loss scenario uses the newly built
Coauth binary and its persistent encrypted key bundle across restart.

These boundaries do not complete the product registration/message scenarios or
Journey recovery wiring owned by the existing integration/recovery tasks. No
storage key, protocol profile, crate version, or schema was added. Single-consumer
crates with independent security or feature boundaries remain in place.
