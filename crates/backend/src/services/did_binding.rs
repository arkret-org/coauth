// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Purpose-aware verified DID bindings (`did-usage-and-verification.md` §4–§6).
//!
//! This module is the **only** place in coauth that turns a
//! [`DidResolution`] into a reusable acceptance. It deliberately owns no
//! data model of its own: `VerifiedDidBinding`, `AcceptedDidBinding`,
//! `DidBindingPurpose`, `DidBindingStatus`, `LimitedTrust`,
//! `FreshnessProfile` and `VerifiedDidBindingStore` all come from
//! `arkret_identity`. Task DID-P0-B01 forbids service repositories from
//! inventing an incompatible parallel binding model, so nothing here
//! re-declares those shapes.
//!
//! ## Why coauth cannot call `arkret_identity::resolve_and_verify_binding`
//!
//! The SDK helper takes a **synchronous** `DidResolver`. coauth's
//! [`DidResolverService::resolve_did_document`] is `async` and additionally
//! needs the outbound `reqwest::Client`, the deployment `ArkretConfig`, the
//! keystore and a `&mut BoxRepository`. Blocking on it from a sync trait
//! method inside the Salvo runtime is not an option, so
//! [`resolve_and_accept_binding`] reproduces the SDK helper's *contract*
//! (store first → resolver at most once → `accept()` back into the same
//! store) over the async resolver, using the SDK types unchanged.
//!
//! The **store** has the identical shape of mismatch — `VerifiedDidBindingStore`
//! is synchronous, coauth's repositories are `async` — and
//! [`store`] resolves it the same way: [`DurableVerifiedDidBindingStore`]
//! implements the SDK trait over a bounded in-process mirror and exposes
//! `async` durable twins (`load` / `persist` / `invalidate_durable`) that every
//! production path uses. See that module's documentation for why the mirror is
//! never authoritative.
//!
//! ## Digests come from the SDK, not from here
//!
//! `policy_digest` and `evidence_digest` are the digests of the SDK's canonical
//! §5 contract objects — [`ResolverPolicySnapshot`] and [`EvidenceReceipt`] —
//! so that five services stop producing five incompatible values for the same
//! inputs. Neither object has an extension map any more: §5.3 makes the
//! resolver policy profile a **schema discriminator**, and v1 registers exactly
//! one profile (`ak.did_resolver_policy_profile.base.v1`) whose `profile_policy`
//! is the empty object. A deployment-local admissibility dimension is therefore
//! not expressible here; it needs a profile registered in the Spec and a
//! corresponding `ResolverPolicyProfile` variant in the SDK. That is why the
//! former `COAUTH_DID_BINDING_DEPLOYMENT_EPOCH` kill switch and the
//! `deployment_profile` / `resolver_allow_loopback` / `did_document_max_bytes`
//! extensions are gone rather than smuggled through a local digest of coauth's
//! own invention.
//!
//! ## What is deliberately NOT here
//!
//! No local `did:webvh` history verifier. `did_resolver.rs` carries the
//! CAU-SPEC-02 ruling that webvh log/history authority belongs to the
//! principal server; this module consumes whatever history evidence the
//! delegated resolver returned and pins it, but never re-derives it.

use std::sync::Arc;

use arkret_identifiers::{Did, Hash, TypedTrustDomainId};
use arkret_identity::{
    AcceptedDidBinding, BindingInvalidation, DidBindingPurpose, DidBindingStatus, EvidenceReceipt,
    FreshnessProfile, FreshnessRequirement, LimitedTrust, MethodEvidence, ResolverFailMode,
    ResolverPolicy, ResolverPolicySnapshot, VerifiedDidBinding, VerifiedDidBindingDocumentInput,
    VerifiedDidBindingKey, VerifiedDidBindingStore,
};
use arkret_wire::DidFreshnessProfileId;
use chrono::{DateTime, Duration, Utc};
use coauth_config::ArkretConfig;
use coauth_data::{BoxRepository, UrlBuilder};
use coauth_keystore::Keystore;

use crate::handlers::arkret::DidDocument as CoauthDidDocument;
use crate::services::did_resolver::{
    DidResolution, DidResolutionIdentityFactRejection, DidResolutionSource, DidResolveError,
    DidResolverService,
};

mod store;

pub use self::store::{
    DurableVerifiedDidBindingStore, decode_row, encode_row, invalidation_columns, key_columns,
};

/// Shared handle type for the process-wide binding store.
pub type VerifiedDidBindingStoreHandle = Arc<DurableVerifiedDidBindingStore>;

/// Depot key for the shared binding store.
pub const DEPOT_KEY: &str = "verified_did_binding_store";

/// Upper bound on the in-process mirror. Eviction is deterministic (oldest
/// `verified_at` first), so a busy deployment degrades into extra durable reads
/// rather than into unbounded memory. The durable table is not bounded by this
/// value; it is bounded by `expires_at` (see [`HARD_EXPIRY`]).
const BINDING_STORE_CAPACITY: usize = 4096;

/// Freshness demanded by high-risk authority writes: recovery completion,
/// session-grant revoke lifecycle proofs, admin risk actions / revocation
/// approvals, organization registry bootstrap, erasure receipts and account
/// DID binding control proofs.
///
/// The registered `authority_high_risk_v1` profile leaves its concrete window
/// to the deployment. Five minutes is the same order as the deployment's other
/// single-shot authority artefacts (`HANDLE_CLAIM_TTL_MINUTES = 5`, the
/// account-handoff and DPoP nonce windows), so an operator reasoning about
/// "how stale can the key material behind an admin action be" gets one number,
/// not two. In practice it means "resolve once per operation" while still
/// de-duplicating the two or three lookups a single multi-step request flow
/// performs against the same DID.
pub const HIGH_RISK_MAX_AGE: Duration = Duration::minutes(5);

/// Freshness demanded by controller / agent-pairing authority paths
/// (`key_pair.rs`).
///
/// The registered `authority_controller_v1` profile leaves its concrete window
/// to the deployment. Fifteen minutes lets agent pairing and `authorize_event`
/// verification
/// resolve the *same* controller DID repeatedly across an interactive approval
/// flow with user-visible retries. §4 row 3 ("new verification method / agent
/// signer epoch") is still an authority trigger — it is served by the
/// `verification_method`-keyed store entry, not by the clock — and rotation /
/// deactivation invalidate the entry explicitly via
/// [`invalidate_did_bindings`]. Extending the window therefore trades network
/// calls, not key freshness.
pub const CONTROLLER_MAX_AGE: Duration = Duration::minutes(15);

/// Hard-expiry offset for every accepted binding.
///
/// §5: crossing `refresh_after` only marks a binding `Stale` and MUST NOT turn
/// an ordinary read into an online resolution; `expires_at` is the point past
/// which the entry stops existing for readers entirely. 24 hours bounds how
/// long a rotated or revoked key could still back a low-risk read if no
/// explicit invalidation ever reached this deployment.
pub const HARD_EXPIRY: Duration = Duration::hours(24);

/// The profile every high-risk authority write references
/// ([`DidFreshnessProfileId::AuthorityHighRiskV1`], see [`HIGH_RISK_MAX_AGE`]).
///
/// The id comes from the generated registry surface: §5.4 registers the id and
/// its tier, and the deployment declares only the numbers. coauth therefore
/// spells neither the token nor the tier.
#[must_use]
pub fn high_risk_freshness() -> FreshnessProfile {
    FreshnessProfile::high_tier(
        DidFreshnessProfileId::AuthorityHighRiskV1,
        HIGH_RISK_MAX_AGE,
        Some(HARD_EXPIRY),
    )
}

/// The profile the controller / agent-pairing authority paths reference
/// ([`DidFreshnessProfileId::AuthorityControllerV1`], see [`CONTROLLER_MAX_AGE`]).
#[must_use]
pub fn controller_freshness() -> FreshnessProfile {
    FreshnessProfile::high_tier(
        DidFreshnessProfileId::AuthorityControllerV1,
        CONTROLLER_MAX_AGE,
        Some(HARD_EXPIRY),
    )
}

// ============================================================================
// Store construction / depot wiring
// ============================================================================

/// Build a fresh binding store.
#[must_use]
pub fn default_verified_did_binding_store() -> VerifiedDidBindingStoreHandle {
    Arc::new(DurableVerifiedDidBindingStore::new(BINDING_STORE_CAPACITY))
}

/// Process-wide binding store handle.
///
/// The Salvo `Depot` is rebuilt for every request, so the in-process mirror has
/// to outlive it: a mirror created during `inject_app_state` would be empty on
/// every call. The handle therefore lives here as a single lazily-initialised
/// value and a cheap `Arc` clone is what gets injected, mirroring how
/// `JWKS_CACHE` is shared in `app_state.rs`. Acceptances themselves survive
/// process restarts because they are rows, not mirror entries.
static BINDING_STORE: std::sync::LazyLock<VerifiedDidBindingStoreHandle> =
    std::sync::LazyLock::new(default_verified_did_binding_store);

/// The shared process-wide binding store handle.
#[must_use]
pub fn shared_verified_did_binding_store() -> VerifiedDidBindingStoreHandle {
    BINDING_STORE.clone()
}

// ============================================================================
// Trust domain / policy digest
// ============================================================================

/// The deployment trust domain this coauth instance accepts bindings for.
///
/// Reuses the existing [`crate::handlers::arkret::trust_domain_for`] derivation
/// — `arkret.trust_domain` when configured, otherwise `ak:trust_domain:<public
/// hostname>` — so a binding's trust domain is exactly the value that already
/// enters cross-signing reset transcripts and DID continuity proof audiences.
/// No new string is invented for the binding layer.
pub fn trust_domain_id(
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
) -> Result<TypedTrustDomainId, DidBindingError> {
    let raw = crate::handlers::arkret::trust_domain_for(url_builder, arkret_config);
    TypedTrustDomainId::new(raw).map_err(|error| DidBindingError::TrustDomain(error.to_string()))
}

/// The [`ResolverPolicy`] this deployment's DID resolver enforces.
///
/// coauth resolves `did:web`, `did:plc` and `did:key` natively and delegates
/// **every** other method — `did:webvh` included, per the CAU-SPEC-02 ruling in
/// `did_resolver.rs` — to `identity_registry.resolver`. A deployment without a
/// delegated resolver therefore accepts exactly the native three and fails
/// closed with `UnsupportedMethod` on anything else.
///
/// The delegated arm is written out as `did:webvh:` rather than as "any
/// method": §5.3 rejects an empty `accepted_did_methods` list outright, because
/// an unrestricted method list is a fail-open policy that a snapshot cannot
/// honestly declare. `did:webvh` is the one method delegation exists for (the
/// CAU-SPEC-02 ruling names it), so this list is what the deployment actually
/// admits today. A future delegated method has to be added here — which changes
/// the policy digest, and therefore retires every acceptance made under the old
/// policy, which is exactly the §5.3 obligation.
fn resolver_policy(arkret_config: &ArkretConfig) -> ResolverPolicy {
    let delegated = delegated_resolver(arkret_config);
    let mut allowed_methods = vec![
        "did:web:".to_owned(),
        "did:plc:".to_owned(),
        "did:key:".to_owned(),
    ];
    if delegated.is_some() {
        allowed_methods.push("did:webvh:".to_owned());
    }
    ResolverPolicy {
        allowed_methods,
        default_principal_method: Some(arkret_config.principal_method.as_str().to_owned()),
        // The delegated resolver is the trust root for every method coauth does
        // not resolve itself.
        trust_roots: delegated.into_iter().collect(),
        // coauth's resolver holds no cache of its own: the binding store is the
        // only reuse layer, and it carries `refresh_after` / `expires_at`.
        ttl: None,
        // Every resolver failure is returned to the caller; no cached answer is
        // ever served on error.
        fail_mode: ResolverFailMode::FailClosed,
    }
}

fn delegated_resolver(arkret_config: &ArkretConfig) -> Option<String> {
    arkret_config
        .identity_registry
        .as_ref()
        .map(|registry| registry.resolver.to_string())
}

/// The §5.3 canonical snapshot of the resolver policy in force.
///
/// # Errors
///
/// Returns [`DidBindingError::Digest`] when the policy is not declarable — the
/// only such case here is a duplicate entry, since [`resolver_policy`] never
/// produces an empty method list.
pub fn policy_snapshot(
    arkret_config: &ArkretConfig,
) -> Result<ResolverPolicySnapshot, DidBindingError> {
    resolver_policy(arkret_config)
        .policy_snapshot()
        .map_err(|error| DidBindingError::Digest(error.to_string()))
}

/// Deterministic digest of the resolver policy in force.
///
/// This is exactly the SDK's §5.3 snapshot digest over [`resolver_policy`] —
/// the accepted method prefixes, the failure-degradation mode and the trust
/// roots, under the one registered `base` profile. coauth adds nothing: an
/// extra admissibility dimension has to be a registered profile (see the module
/// documentation), not a locally invented digest input.
///
/// "A policy change necessarily changes the digest" holds because the digest is
/// a canonical-JSON SHA-256 over exactly that object: any differing field
/// produces different canonical bytes.
///
/// # Errors
///
/// Returns [`DidBindingError::Digest`] when the canonical encoding fails.
pub fn policy_digest(arkret_config: &ArkretConfig) -> Result<Hash, DidBindingError> {
    policy_snapshot(arkret_config)?
        .digest()
        .map_err(|error| DidBindingError::Digest(error.to_string()))
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum DidBindingError {
    #[error("DID resolution failed: {0}")]
    Resolve(#[from] DidResolveError),

    #[error("trust domain is not a typed trust domain id: {0}")]
    TrustDomain(String),

    #[error("digest computation failed: {0}")]
    Digest(String),

    #[error("resolved DID document is not convertible to the shared model: {0}")]
    Document(String),

    #[error("binding construction rejected: {0}")]
    Binding(String),

    #[error("binding store rejected the acceptance: {0}")]
    Store(String),

    /// The resolution carries no authority-grade evidence and MUST NOT be
    /// accepted as a binding (see [`is_storable`]).
    #[error("resolution for {did} is not authority-grade ({reason}) and was not accepted")]
    NotAuthorityGrade { did: String, reason: &'static str },

    /// No accepted binding exists and the call site is not allowed to resolve
    /// (§3 ordinary read path).
    #[error("no accepted DID binding for {did} (purpose {purpose})")]
    NoAcceptedBinding { did: String, purpose: &'static str },
}

// ============================================================================
// DidResolution -> VerifiedDidBinding
// ============================================================================

/// Map a resolution's identity-fact rejection onto a closed binding status.
///
/// | `DidResolutionIdentityFactRejection` | `DidBindingStatus` | why |
/// | --- | --- | --- |
/// | *(none)* | `Active` | full identity fact |
/// | `CacheOnlyDegraded` | `Stale` | the evidence is genuine but the resolver served it from cache while degraded; §5 lets an ordinary read consume a stale binding, and an authority path with `require_fresh` still rejects it |
/// | `DegradedResolverState` | `Stale` | same shape: real evidence, degraded availability |
/// | `WebvhCacheTooStale` | `Stale` | literally an age problem; `Stale` is the status §5 names for it |
/// | `WeakResolverEvidence` | `Stale` | `trust_profile`/`resolver_assurance` says limited/read-only; the document is what the method published, only the assurance level is reduced |
/// | `DidWebFallback` | `Quarantined` | the resolver **substituted a weaker DID method**. §5: "不得在失败时把信任降级到另一个 DID method". Serving it even on a low-risk read would render a document whose control was never demonstrated under the requested method |
/// | `MissingWebvhHistoryEvidence` | `Quarantined` | a `did:webvh` answer with `history_evidence_kind = none` proves nothing about key continuity |
/// | `ControllerProofUnverified` | `Quarantined` | control was explicitly *not* proven; conflicting evidence is exactly what `Quarantined` is for |
///
/// `Stale` entries remain readable (`is_usable_for_ordinary_verification`);
/// `Quarantined` entries are never usable, by either path.
#[must_use]
pub const fn status_for(rejection: Option<DidResolutionIdentityFactRejection>) -> DidBindingStatus {
    match rejection {
        None => DidBindingStatus::Active,
        Some(
            DidResolutionIdentityFactRejection::CacheOnlyDegraded
            | DidResolutionIdentityFactRejection::DegradedResolverState
            | DidResolutionIdentityFactRejection::WebvhCacheTooStale
            | DidResolutionIdentityFactRejection::WeakResolverEvidence,
        ) => DidBindingStatus::Stale,
        Some(
            DidResolutionIdentityFactRejection::DidWebFallback
            | DidResolutionIdentityFactRejection::MissingWebvhHistoryEvidence
            | DidResolutionIdentityFactRejection::ControllerProofUnverified,
        ) => DidBindingStatus::Quarantined,
    }
}

/// Whether a resolution may be persisted as an authority-grade binding.
///
/// A `did:key` answer produced by `did_resolver::local_resolution` carries
/// `verified_local_binding = false` and an **empty** `verificationMethod`
/// array: it is a syntactic echo of the DID string, not a resolution. Storing
/// it would let a later store hit assert an acceptance that pins nothing, so it
/// is rejected here rather than downgraded. Every other source is storable; its
/// trust level is expressed through [`status_for`] and `LimitedTrustReason`.
pub const fn is_storable(resolution: &DidResolution) -> Result<(), &'static str> {
    match (resolution.source, resolution.verified_local_binding) {
        (DidResolutionSource::DidKey, false) => {
            Err("did:key self-describing key material is not an authority-grade resolution")
        }
        _ => Ok(()),
    }
}

/// What the resolved method surfaced, in the SDK's §5.2 shape.
///
/// coauth's delegated resolver returns `method_evidence` as an **opaque**
/// method-specific JSON subtree: it carries degradation flags and a method
/// label, but never the witness set and witness-proof digest a
/// `MethodEvidenceProof::WebvhLog` row requires. §5.2 makes that shape
/// unconstructible on purpose — a receipt row is what the resolver *verified*,
/// not what it reported — so coauth surfaces the history-head pin and no proof
/// rows. The degradation flags are not lost: `identity_fact_rejection` already
/// maps them onto the acceptance [`status_for`], and a `did:webvh` answer with
/// no history evidence is `Quarantined` before it ever reaches here.
fn method_evidence(resolution: &DidResolution) -> MethodEvidence {
    MethodEvidence {
        proofs: Vec::new(),
        history_head: resolution
            .key_log_head
            .as_ref()
            .map(|head| head.as_str().to_owned()),
        // Neither `did:web` / `did:plc` / `did:key` nor coauth's delegated
        // `IdentityResolveOutcome` exposes a method version identifier.
        version_id: None,
    }
}

/// Whether the DID's own method publishes verifiable evidence.
///
/// §5.5 splits an absent pin into `method_unsupported` (terminal property of the
/// method) and `not_surfaced` (a resolver that failed to deliver evidence its
/// method supports). `did:webvh` is the one evidence-bearing method coauth ever
/// sees, and it only ever arrives through the delegated resolver — which does
/// not hand out witness rows — so its missing pins must record `not_surfaced`
/// rather than be laundered into a terminal method property.
fn method_is_evidence_bearing(did: &str) -> bool {
    did.starts_with("did:webvh:")
}

/// The §5.2 canonical evidence receipt an acceptance rests on.
///
/// Its digest is the binding's `evidence_digest`, and the receipt itself is
/// retained by [`AcceptedDidBinding`] so an auditor can recompute that digest.
/// The two degenerate shapes several repositories shipped —
/// `evidence_digest == document_digest` and `H(did ‖ constant)` — are not
/// expressible through this API.
fn evidence_receipt(
    resolution: &DidResolution,
    document: &arkret_models_identity::DidDocument,
) -> Result<EvidenceReceipt, DidBindingError> {
    let document_digest = arkret_identity::document_canonical_digest(document)
        .map_err(|error| DidBindingError::Digest(error.to_string()))?;
    Ok(EvidenceReceipt::new(
        document.id.method(),
        document_digest,
        &method_evidence(resolution),
    ))
}

/// Convert coauth's full-document wire shape into the shared SDK model.
///
/// CAU-DRY-02 keeps the two types distinct on purpose (coauth's carries JWK /
/// Multikey verification methods, `service` entries and holder-preference
/// metadata). The conversion is a JSON round-trip through the SDK's
/// `Deserialize`, which files everything it does not index into
/// `raw_properties`, so the pinned document is loss-free for digest purposes.
pub fn to_shared_document(
    document: &CoauthDidDocument,
) -> Result<arkret_models_identity::DidDocument, DidBindingError> {
    let value = serde_json::to_value(document)
        .map_err(|error| DidBindingError::Document(error.to_string()))?;
    serde_json::from_value(value).map_err(|error| DidBindingError::Document(error.to_string()))
}

/// Inverse of [`to_shared_document`], used to hand a *pinned* document back to
/// the existing coauth verifiers (which need the JWK / Multikey shape, not the
/// SDK's collapsed index).
///
/// The SDK type keeps the wire `verificationMethod` array verbatim in
/// `raw_properties` and re-emits it unchanged when its derived index still
/// matches, so this round-trip is loss-free for documents that entered through
/// [`to_shared_document`]. `did_document_round_trip_is_loss_free` pins that.
pub fn from_shared_document(
    document: &arkret_models_identity::DidDocument,
) -> Result<CoauthDidDocument, DidBindingError> {
    let value = serde_json::to_value(document)
        .map_err(|error| DidBindingError::Document(error.to_string()))?;
    serde_json::from_value(value).map_err(|error| DidBindingError::Document(error.to_string()))
}

/// Full field mapping from a [`DidResolution`] to an [`AcceptedDidBinding`].
///
/// | `DidResolution` | `VerifiedDidBinding` |
/// | --- | --- |
/// | `document` | pinned document + derived `document_digest` (canonical SHA-256, computed by `from_verified_document`) |
/// | `document.id` | `did` + `method` |
/// | `key_log_head` | `history_head` |
/// | *(coauth has no method version identifier)* | `version_id = None` |
/// | the pins above, graded by [`method_is_evidence_bearing`] | `limited_trust` |
/// | [`evidence_receipt`] over the pinned document digest and the surfaced pins | `evidence_digest` + `evidence_dependencies` |
/// | `identity_fact_rejection` | `status` (see [`status_for`]) |
/// | *(caller)* | `trust_domain`, `purpose`, `policy_digest`, `verification_method`, `verified_at` |
/// | *(caller's [`FreshnessProfile`])* | `refresh_after`, `expires_at` |
#[allow(clippy::too_many_arguments)]
pub fn binding_from_resolution(
    resolution: &DidResolution,
    trust_domain: TypedTrustDomainId,
    purpose: DidBindingPurpose,
    policy_digest: Hash,
    verification_method: Option<arkret_wire::DidUrl>,
    freshness: &FreshnessProfile,
    now: DateTime<Utc>,
) -> Result<AcceptedDidBinding, DidBindingError> {
    if let Err(reason) = is_storable(resolution) {
        return Err(DidBindingError::NotAuthorityGrade {
            did: resolution.document.id.clone(),
            reason,
        });
    }

    let document = to_shared_document(&resolution.document)?;
    let receipt = evidence_receipt(resolution, &document)?;
    let evidence_digest = receipt
        .digest()
        .map_err(|error| DidBindingError::Digest(error.to_string()))?;
    let evidence_dependencies = receipt
        .evidence_dependencies()
        .map_err(|error| DidBindingError::Digest(error.to_string()))?;
    let evidence = method_evidence(resolution);
    let pins = (
        evidence.history_head.as_deref(),
        evidence.version_id.as_deref(),
    );
    let limited_trust = if method_is_evidence_bearing(&resolution.document.id) {
        LimitedTrust::for_evidence_bearing_method(pins.0, pins.1)
    } else {
        LimitedTrust::for_proofless_method(pins.0, pins.1)
    };

    let binding = VerifiedDidBinding::from_verified_document(
        &document,
        VerifiedDidBindingDocumentInput {
            trust_domain,
            purpose,
            verification_method,
            history_head: evidence.history_head,
            version_id: evidence.version_id,
            limited_trust: limited_trust.record_for(),
            evidence_digest,
            evidence_dependencies,
            policy_digest,
            verified_at: now,
            refresh_after: freshness.refresh_after(now),
            expires_at: freshness.expires_at(now),
            status: status_for(resolution.identity_fact_rejection),
        },
    )
    .map_err(|error| DidBindingError::Binding(error.to_string()))?;

    AcceptedDidBinding::new(binding, document, receipt)
        .map_err(|error| DidBindingError::Store(error.to_string()))
}

// ============================================================================
// Authority path
// ============================================================================

/// One authority-verification request against coauth's async resolver.
pub struct CoauthBindingRequest<'a> {
    pub did: &'a str,
    pub trust_domain: TypedTrustDomainId,
    pub purpose: DidBindingPurpose,
    pub policy_digest: Hash,
    pub verification_method: Option<arkret_wire::DidUrl>,
    /// The registered §5.4 profile this call site references. It is the single
    /// freshness threshold: it derives the [`FreshnessRequirement`] a reusable
    /// entry has to satisfy *and* the `refresh_after` / `expires_at` an
    /// acceptance is filed with, so the two can no longer drift apart.
    pub freshness: FreshnessProfile,
}

impl CoauthBindingRequest<'_> {
    /// The store key this request reads and writes. Mirrors
    /// `BindingResolveRequest::key`.
    pub fn key(&self) -> Result<VerifiedDidBindingKey, DidBindingError> {
        Ok(VerifiedDidBindingKey {
            did: Did::new(self.did.to_owned())
                .map_err(|error| DidBindingError::Document(error.to_string()))?,
            trust_domain: self.trust_domain.clone(),
            purpose: self.purpose,
            policy_digest: self.policy_digest.clone(),
            verification_method: self.verification_method.clone(),
        })
    }
}

/// Filter an entry down to what a §3 ordinary path may consume.
///
/// **This reads the synchronous face of the store only** — for
/// [`DurableVerifiedDidBindingStore`] that is the in-process mirror, which is
/// populated by `load` and is empty after a restart. Production code must use
/// [`ordinary_read_document`], which reads the durable row and then applies
/// exactly this predicate. Kept as a separate function so the predicate is
/// unit-testable against any [`VerifiedDidBindingStore`] without a live
/// repository.
pub fn accepted_binding(
    store: &dyn VerifiedDidBindingStore,
    key: &VerifiedDidBindingKey,
    now: DateTime<Utc>,
) -> Option<AcceptedDidBinding> {
    store
        .get(key, now)
        .filter(|accepted| accepted.binding().is_usable_for_ordinary_verification())
}

/// Whether an already-accepted binding may be reused for an authority call —
/// i.e. whether [`resolve_and_accept_binding`] will return **without** any
/// network fetch.
///
/// Extracted so the "zero incremental resolver calls on a binding hit"
/// property is unit-testable without a live repository (coauth's resolver
/// trait takes a `&mut BoxRepository`, which has no in-memory double). Like
/// [`accepted_binding`] it reads the synchronous face of the store only, so it
/// is a predicate helper, not a production entry point.
#[must_use]
pub fn reusable_binding(
    store: &dyn VerifiedDidBindingStore,
    key: &VerifiedDidBindingKey,
    freshness: &FreshnessRequirement,
    now: DateTime<Utc>,
) -> Option<AcceptedDidBinding> {
    store
        .get(key, now)
        .filter(|accepted| accepted.binding().is_usable_for_authority(freshness, now))
}

/// Establish or refresh a verified binding — the only function in this module
/// that may reach the network.
///
/// Contract (identical to `arkret_identity::resolve_and_verify_binding`):
///
/// 1. read the **durable** store under [`CoauthBindingRequest::key`];
/// 2. on a hit satisfying the requested freshness, return it and **do not call the resolver**;
/// 3. otherwise call `resolve_did_document` **exactly once**, build the binding and persist it.
///
/// A hard-expired or invalidated entry reads as a miss, so the next authority
/// call resolves again — exactly once. Step 1 is a database read rather than a
/// process-local lookup, which is what makes a restarted (or a second) coauth
/// instance reuse acceptances instead of re-resolving; a row read is not a DID
/// resolution, so the §4 "zero incremental resolver calls" property is
/// unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_and_accept_binding(
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    store: &DurableVerifiedDidBindingStore,
    request: &CoauthBindingRequest<'_>,
    now: DateTime<Utc>,
) -> Result<AcceptedDidBinding, DidBindingError> {
    let key = request.key()?;
    let requirement = request.freshness.requirement();
    let held = store.load(repo, &key, now).await?;
    if let Some(accepted) = held.clone().filter(|accepted| {
        accepted
            .binding()
            .is_usable_for_authority(&requirement, now)
    }) {
        // Step 2: binding hit. `did_resolver` is not touched — this is the
        // "did:web / did:plc / delegated resolver do not re-fetch" guarantee.
        return Ok(accepted);
    }

    // §5 treats `deactivated` / `quarantined` as terminal: a held-back binding
    // must not be re-litigated by the next request. Without this gate the
    // entry would be unusable (so step 2 misses) yet re-resolved and
    // overwritten on every attempt — quarantine would never stick, and an
    // attacker could turn a quarantined DID into an outbound-fetch amplifier.
    // The entry still clears on its own at `expires_at`, which is when a fresh
    // evaluation is allowed again.
    if let Some(held) = held
        && matches!(
            held.binding().status(),
            DidBindingStatus::Deactivated | DidBindingStatus::Quarantined
        )
    {
        return Err(DidBindingError::NotAuthorityGrade {
            did: request.did.to_owned(),
            reason: match held.binding().status() {
                DidBindingStatus::Deactivated => "DID is deactivated",
                _ => "binding is quarantined",
            },
        });
    }

    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            arkret_config,
            key_store,
            repo,
            request.did,
        )
        .await?;

    let accepted = binding_from_resolution(
        &resolution,
        request.trust_domain.clone(),
        request.purpose,
        request.policy_digest.clone(),
        request.verification_method.clone(),
        &request.freshness,
        now,
    )?;
    store.persist(repo, &accepted, now).await?;

    // Fail closed: an acceptance whose status cannot back the requested
    // freshness is stored (so the invalidation index can find it) but is not
    // handed back as if it were usable.
    if !accepted
        .binding()
        .is_usable_for_authority(&requirement, now)
    {
        return Err(DidBindingError::NotAuthorityGrade {
            did: request.did.to_owned(),
            reason: match accepted.binding().status() {
                DidBindingStatus::Quarantined => "resolution is quarantined",
                DidBindingStatus::Deactivated => "DID is deactivated",
                DidBindingStatus::Stale => {
                    "resolution is stale and the call site requires fresh evidence"
                }
                DidBindingStatus::Active => "resolution does not satisfy the requested freshness",
            },
        });
    }

    Ok(accepted)
}

/// Ergonomic wrapper used by the authority call sites.
///
/// Derives the deployment trust domain and policy digest and hands the call
/// site's registered §5.4 [`FreshnessProfile`] to the binding layer — which is
/// what makes the reuse window and the filed `refresh_after` the same number.
/// A second call for the same DID / purpose inside that window reuses the
/// binding and performs **zero** network fetches; a call outside it refreshes
/// exactly once.
///
/// Returns the pinned document in coauth's own wire shape so existing
/// verifiers are untouched.
#[allow(clippy::too_many_arguments)]
pub async fn authority_document(
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    store: &DurableVerifiedDidBindingStore,
    did: &str,
    purpose: DidBindingPurpose,
    freshness: FreshnessProfile,
    now: DateTime<Utc>,
) -> Result<AuthorityDocument, DidBindingError> {
    let request = CoauthBindingRequest {
        did,
        trust_domain: trust_domain_id(url_builder, arkret_config)?,
        purpose,
        policy_digest: policy_digest(arkret_config)?,
        verification_method: None,
        freshness,
    };
    let accepted = resolve_and_accept_binding(
        http_client,
        url_builder,
        arkret_config,
        key_store,
        repo,
        did_resolver,
        store,
        &request,
        now,
    )
    .await?;
    Ok(AuthorityDocument {
        document: from_shared_document(accepted.document())?,
        history_head: history_head_digest(&accepted)?,
        accepted,
    })
}

/// The product of an authority path: the pinned document in coauth's wire
/// shape plus the acceptance it came from.
pub struct AuthorityDocument {
    pub document: CoauthDidDocument,
    pub history_head: Option<Hash>,
    pub accepted: AcceptedDidBinding,
}

/// The acceptance's pinned history head as a typed digest.
///
/// §5 types `history_head` as a plain string because a `did:webvh` `versionId`
/// is not a `<algo>:<hex>` digest. Every head coauth files went in as a
/// [`Hash`] (`DidResolution::key_log_head` is typed that way and
/// `parse_key_log_head` rejects anything else), and the outward
/// `IdentityResolveOutcome` / `IdentityDocumentView` shapes are typed as
/// digests, so the round trip back is total for rows this deployment wrote. A
/// row that somehow carries a non-digest head is reported rather than silently
/// dropped: it means the acceptance was written by something other than this
/// code path.
fn history_head_digest(accepted: &AcceptedDidBinding) -> Result<Option<Hash>, DidBindingError> {
    accepted
        .binding()
        .history_head()
        .map(|head| {
            Hash::new(head.to_owned()).map_err(|error| DidBindingError::Binding(error.to_string()))
        })
        .transpose()
}

/// §3 ordinary read: serve a **previously accepted** binding's pinned document
/// or nothing.
///
/// There is no resolver parameter, so this cannot live-fallback — it takes a
/// repository (to read the durable acceptance) and nothing that can reach the
/// network. Before the acceptance was persisted this was process-local, which
/// meant that between a cold start and the next account-DID registration every
/// session read was factually a not-found; reading the row removes that window.
///
/// # Errors
///
/// Returns [`DidBindingError::NoAcceptedBinding`] when no usable acceptance
/// exists, which every caller maps to its own not-found / blinded response.
pub async fn ordinary_read_document(
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    repo: &mut BoxRepository,
    store: &DurableVerifiedDidBindingStore,
    did: &str,
    purpose: DidBindingPurpose,
    now: DateTime<Utc>,
) -> Result<AuthorityDocument, DidBindingError> {
    let key = VerifiedDidBindingKey {
        did: Did::new(did.to_owned())
            .map_err(|error| DidBindingError::Document(error.to_string()))?,
        trust_domain: trust_domain_id(url_builder, arkret_config)?,
        purpose,
        policy_digest: policy_digest(arkret_config)?,
        verification_method: None,
    };
    let accepted = store
        .load(repo, &key, now)
        .await?
        .filter(|accepted| accepted.binding().is_usable_for_ordinary_verification())
        .ok_or_else(|| DidBindingError::NoAcceptedBinding {
            did: did.to_owned(),
            purpose: purpose.as_str(),
        })?;
    Ok(AuthorityDocument {
        document: from_shared_document(accepted.document())?,
        history_head: history_head_digest(&accepted)?,
        accepted,
    })
}

/// Mint a **second, independently scoped** acceptance for `purpose` from the
/// same verified evidence, without any further network access.
///
/// This is not cross-purpose reuse — the thing the task forbids is one
/// acceptance *serving* several purposes, and that stays impossible: the
/// purpose is part of `VerifiedDidBindingKey`, and a lookup for a purpose the
/// binding was not filed under still misses. What this does is record that the
/// evidence which satisfied one §4 trigger also satisfies another at the same
/// instant.
///
/// The only caller is account-DID registration: `add_account_did` verifies a
/// *current* controller proof over the principal's DID document (§4 row 2),
/// which is simultaneously the moment that principal DID first crosses into
/// this trust domain (§4 row 1). Recording the `Principal` acceptance there is
/// what lets §3 ordinary reads (`identity_resolve` / `identity_document` /
/// `directory_resolve_handle`) serve a pinned document at all — without it they
/// would have no accepted binding to read and would be permanently blind,
/// since none of them is allowed to resolve.
///
/// Every digest, pin, limited-trust reason, status and freshness window is
/// copied verbatim, so the mirrored acceptance can never be *stronger* than the
/// one it was derived from.
///
/// # Errors
///
/// Returns [`DidBindingError`] when the mirrored acceptance cannot be built or
/// persisted.
pub async fn accept_for_additional_purpose(
    repo: &mut BoxRepository,
    store: &DurableVerifiedDidBindingStore,
    source: &AcceptedDidBinding,
    purpose: DidBindingPurpose,
    now: DateTime<Utc>,
) -> Result<(), DidBindingError> {
    let Some(accepted) = mirrored_acceptance(source, purpose)? else {
        return Ok(());
    };
    store.persist(repo, &accepted, now).await
}

/// Build (but do not store) the acceptance [`accept_for_additional_purpose`]
/// would file. `Ok(None)` when `purpose` is the source's own purpose.
///
/// Split out so the "the mirror copies evidence but never authority" property
/// is testable without a live repository.
///
/// # Errors
///
/// Returns [`DidBindingError`] when the copied binding is rejected by the
/// shared constructor.
pub fn mirrored_acceptance(
    source: &AcceptedDidBinding,
    purpose: DidBindingPurpose,
) -> Result<Option<AcceptedDidBinding>, DidBindingError> {
    let binding = source.binding();
    if binding.purpose() == purpose {
        return Ok(None);
    }
    let mirrored = VerifiedDidBinding::new(arkret_identity::VerifiedDidBindingInput {
        did: binding.did().clone(),
        trust_domain: binding.trust_domain().clone(),
        purpose,
        method: binding.method().to_owned(),
        verification_method: binding.verification_method().cloned(),
        document_digest: binding.document_digest().clone(),
        history_head: binding.history_head().map(ToOwned::to_owned),
        version_id: binding.version_id().map(ToOwned::to_owned),
        limited_trust: binding.limited_trust(),
        evidence_digest: binding.evidence_digest().clone(),
        evidence_dependencies: binding.evidence_dependencies().clone(),
        policy_digest: binding.policy_digest().clone(),
        verified_at: binding.verified_at(),
        refresh_after: binding.refresh_after(),
        expires_at: binding.expires_at(),
        status: binding.status(),
    })
    .map_err(|error| DidBindingError::Binding(error.to_string()))?;
    AcceptedDidBinding::new(
        mirrored,
        source.document().clone(),
        source.evidence_receipt().clone(),
    )
    .map(Some)
    .map_err(|error| DidBindingError::Store(error.to_string()))
}

/// Invalidate every binding for `did`, across purposes and trust domains —
/// durably, so a restart or another instance cannot resurrect it.
///
/// §5 requires rotation / deactivation / revocation to make affected bindings
/// disappear. `BindingInvalidation` is a **conjunctive** selector, so
/// `for_did` alone is the widest correct form: it never touches another DID.
///
/// # Errors
///
/// Returns [`DidBindingError::Store`] when the repository fails.
pub async fn invalidate_did_bindings(
    repo: &mut BoxRepository,
    store: &DurableVerifiedDidBindingStore,
    did: &Did,
) -> Result<usize, DidBindingError> {
    store
        .invalidate_durable(repo, &BindingInvalidation::for_did(did.clone()))
        .await
}

/// Invalidate only the bindings that pin a specific verification method.
///
/// # Errors
///
/// Returns [`DidBindingError::Store`] when the repository fails.
pub async fn invalidate_verification_method(
    repo: &mut BoxRepository,
    store: &DurableVerifiedDidBindingStore,
    verification_method: &arkret_wire::DidUrl,
) -> Result<usize, DidBindingError> {
    store
        .invalidate_durable(
            repo,
            &BindingInvalidation::for_verification_method(verification_method.clone()),
        )
        .await
}

#[cfg(test)]
mod tests;

/// Test-only helper: build a resolution with the given evidence shape.
#[cfg(test)]
pub(crate) fn test_resolution(
    did: &str,
    source: DidResolutionSource,
    key_log_head: Option<Hash>,
    rejection: Option<DidResolutionIdentityFactRejection>,
    method_evidence: serde_json::Value,
) -> DidResolution {
    DidResolution {
        document: CoauthDidDocument {
            id: did.to_owned(),
            also_known_as: Vec::new(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
            metadata: None,
        },
        source,
        verified_local_binding: false,
        key_log_head,
        method_evidence,
        identity_fact_rejection: rejection,
    }
}
