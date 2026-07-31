// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Negative and mapping coverage for purpose-aware DID bindings
//! (`did-usage-and-verification.md` §4–§5, task DID-P2-A).

// The source-scanning cases below walk `std::fs::read_dir`, whose entries are
// `std::path::PathBuf`; routing them through camino would convert every entry
// back and forth for no gain in a test that never leaves this crate.
#![allow(clippy::disallowed_types)]

use arkret_identity::BindingFreshness;

/// A protocol instant is millisecond-precision. `VerifiedDidBinding::new`
/// floors the freshness window to it, so a raw `Utc::now()` here would leave
/// the fixture holding sub-millisecond digits the binding cannot round-trip.
fn protocol_now() -> chrono::DateTime<Utc> {
    arkret_canonical::canonical::normalize_timestamp_canonical(Utc::now())
}

use super::*;

fn did() -> Did {
    Did::new("did:web:alice.example").unwrap()
}

fn other_did() -> Did {
    Did::new("did:web:mallory.example").unwrap()
}

fn trust_domain(scope: &str) -> TypedTrustDomainId {
    TypedTrustDomainId::new(format!("ak:trust_domain:{scope}")).unwrap()
}

fn digest(byte: char) -> Hash {
    Hash::new(format!("sha256:{}", String::from(byte).repeat(64))).unwrap()
}

fn document_for(did: &str) -> CoauthDidDocument {
    CoauthDidDocument {
        id: did.to_owned(),
        also_known_as: Vec::new(),
        verification_method: vec![crate::handlers::arkret::VerificationMethod {
            id: format!("{did}#key-1"),
            kind: "Multikey".to_owned(),
            controller: did.to_owned(),
            public_key_jwk: None,
            public_key_multibase: Some(
                "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_owned(),
            ),
        }],
        authentication: Vec::new(),
        assertion_method: Vec::new(),
        capability_delegation: Vec::new(),
        service: Vec::new(),
        metadata: None,
    }
}

fn healthy_resolution(did: &str) -> DidResolution {
    DidResolution {
        document: document_for(did),
        source: DidResolutionSource::DelegatedResolver,
        verified_local_binding: false,
        key_log_head: Some(digest('a')),
        method_evidence: serde_json::json!({
            "method": "did:webvh",
            "history_evidence_kind": "webvh_key_log",
            "controller_proof_verified": true,
        }),
        identity_fact_rejection: None,
    }
}

fn accept(
    store: &dyn VerifiedDidBindingStore,
    resolution: &DidResolution,
    purpose: DidBindingPurpose,
    domain: &TypedTrustDomainId,
    policy: &Hash,
    now: DateTime<Utc>,
) -> AcceptedDidBinding {
    let accepted = binding_from_resolution(
        resolution,
        domain.clone(),
        purpose,
        policy.clone(),
        None,
        HIGH_RISK_MAX_AGE,
        now,
    )
    .expect("healthy resolution should build a binding");
    store.accept(accepted.clone()).expect("store accepts");
    accepted
}

// ------------------------------------------------------------------
// Field mapping
// ------------------------------------------------------------------

#[test]
fn resolution_fields_map_onto_the_shared_binding() {
    let now = protocol_now();
    let resolution = healthy_resolution("did:web:alice.example");
    let accepted = binding_from_resolution(
        &resolution,
        trust_domain("auth.example"),
        DidBindingPurpose::AccountBinding,
        digest('b'),
        None,
        HIGH_RISK_MAX_AGE,
        now,
    )
    .expect("binding builds");
    let binding = accepted.binding();

    assert_eq!(binding.did(), &did());
    assert_eq!(binding.method(), "web");
    assert_eq!(binding.purpose(), DidBindingPurpose::AccountBinding);
    assert_eq!(binding.trust_domain(), &trust_domain("auth.example"));
    assert_eq!(binding.policy_digest(), &digest('b'));
    // key_log_head -> history_head
    assert_eq!(binding.history_head(), Some(&digest('a')));
    // coauth never learns a method version id, so limited trust MUST be recorded
    assert_eq!(binding.version_id(), None);
    assert_eq!(
        binding.limited_trust(),
        Some(LimitedTrustReason::MethodHasNoVersionId)
    );
    assert_eq!(binding.status(), DidBindingStatus::Active);
    assert_eq!(binding.refresh_after(), Some(now + HIGH_RISK_MAX_AGE));
    assert_eq!(binding.expires_at(), Some(now + HARD_EXPIRY));
    // document_digest is recomputed from the pinned document by
    // `AcceptedDidBinding::new`, so this equality is not tautological.
    assert_eq!(
        binding.document_digest(),
        &arkret_identity::document_canonical_digest(accepted.document()).unwrap()
    );
}

#[test]
fn missing_history_head_records_the_wider_limited_trust_reason() {
    let now = protocol_now();
    let mut resolution = healthy_resolution("did:web:alice.example");
    resolution.key_log_head = None;
    let accepted = binding_from_resolution(
        &resolution,
        trust_domain("auth.example"),
        DidBindingPurpose::Principal,
        digest('b'),
        None,
        HIGH_RISK_MAX_AGE,
        now,
    )
    .expect("binding builds");
    assert_eq!(
        accepted.binding().limited_trust(),
        Some(LimitedTrustReason::MethodHasNeitherHistoryNorVersion)
    );
}

#[test]
fn every_identity_fact_rejection_maps_to_a_closed_status() {
    use DidResolutionIdentityFactRejection as R;
    for (rejection, expected) in [
        (None, DidBindingStatus::Active),
        (Some(R::CacheOnlyDegraded), DidBindingStatus::Stale),
        (Some(R::DegradedResolverState), DidBindingStatus::Stale),
        (Some(R::WebvhCacheTooStale), DidBindingStatus::Stale),
        (Some(R::WeakResolverEvidence), DidBindingStatus::Stale),
        (Some(R::DidWebFallback), DidBindingStatus::Quarantined),
        (
            Some(R::MissingWebvhHistoryEvidence),
            DidBindingStatus::Quarantined,
        ),
        (
            Some(R::ControllerProofUnverified),
            DidBindingStatus::Quarantined,
        ),
    ] {
        assert_eq!(status_for(rejection), expected, "rejection {rejection:?}");
    }
}

/// `evidence_digest` over the resolution's own document and a fixed policy
/// digest, so a test varies exactly one input at a time.
fn evidence_digest_of(resolution: &DidResolution, policy: &Hash) -> Hash {
    let document = to_shared_document(&resolution.document).expect("document converts");
    evidence_digest(resolution, &document, policy).expect("evidence digest")
}

#[test]
fn source_and_evidence_both_bind_into_the_evidence_digest() {
    let policy = digest('b');
    let base = healthy_resolution("did:web:alice.example");
    let mut different_source = healthy_resolution("did:web:alice.example");
    different_source.source = DidResolutionSource::DidWeb;
    let mut different_evidence = healthy_resolution("did:web:alice.example");
    different_evidence.method_evidence = serde_json::json!({"method": "did:web"});

    let base_digest = evidence_digest_of(&base, &policy);
    assert_ne!(base_digest, evidence_digest_of(&different_source, &policy));
    assert_ne!(
        base_digest,
        evidence_digest_of(&different_evidence, &policy)
    );
    // Deterministic.
    assert_eq!(
        base_digest,
        evidence_digest_of(&healthy_resolution("did:web:alice.example"), &policy)
    );
}

/// The SDK envelope always commits to the pinned document digest **and** the
/// policy digest, so the two degenerate shapes other repositories shipped —
/// `evidence_digest == document_digest`, and a value independent of the policy
/// — are not reachable through this code path.
#[test]
fn the_evidence_digest_binds_the_document_and_the_policy() {
    let resolution = healthy_resolution("did:web:alice.example");
    let document = to_shared_document(&resolution.document).expect("document converts");
    let document_digest = arkret_identity::document_canonical_digest(&document).unwrap();

    let under_one_policy = evidence_digest_of(&resolution, &digest('b'));
    let under_another_policy = evidence_digest_of(&resolution, &digest('c'));
    assert_ne!(
        under_one_policy, under_another_policy,
        "a policy revision must move the evidence digest"
    );
    assert_ne!(
        under_one_policy, document_digest,
        "the evidence digest must never be the bare document digest"
    );

    let mut other_document = healthy_resolution("did:web:alice.example");
    other_document.document.also_known_as = vec!["at://alice.example".to_owned()];
    assert_ne!(
        under_one_policy,
        evidence_digest_of(&other_document, &digest('b')),
        "a different pinned document must move the evidence digest"
    );
}

#[test]
fn did_key_local_resolution_is_never_stored_as_a_binding() {
    let now = protocol_now();
    let resolution = test_resolution(
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        DidResolutionSource::DidKey,
        None,
        None,
        serde_json::json!({"resolver": "did_key", "verified_local_binding": false}),
    );
    let error = binding_from_resolution(
        &resolution,
        trust_domain("auth.example"),
        DidBindingPurpose::Controller,
        digest('b'),
        None,
        HIGH_RISK_MAX_AGE,
        now,
    )
    .expect_err("did:key echo must not become an authority-grade binding");
    assert!(matches!(error, DidBindingError::NotAuthorityGrade { .. }));
}

// ------------------------------------------------------------------
// Purpose / trust-domain isolation
// ------------------------------------------------------------------

#[test]
fn a_binding_accepted_for_one_purpose_does_not_serve_another() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let domain = trust_domain("auth.example");
    let policy = digest('b');
    let accepted = accept(
        &store,
        &healthy_resolution("did:web:alice.example"),
        DidBindingPurpose::AccountBinding,
        &domain,
        &policy,
        now,
    );

    let mut key = accepted.binding().key();
    assert!(accepted_binding(&store, &key, now).is_some());

    key.purpose = DidBindingPurpose::AdminAction;
    assert!(
        accepted_binding(&store, &key, now).is_none(),
        "an account-binding acceptance must not authorize an admin action"
    );
    key.purpose = DidBindingPurpose::Recovery;
    assert!(accepted_binding(&store, &key, now).is_none());
    key.purpose = DidBindingPurpose::OrganizationRegistry;
    assert!(accepted_binding(&store, &key, now).is_none());
}

#[test]
fn a_binding_accepted_in_one_trust_domain_does_not_serve_another() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let accepted = accept(
        &store,
        &healthy_resolution("did:web:alice.example"),
        DidBindingPurpose::Principal,
        &trust_domain("auth.example"),
        &digest('b'),
        now,
    );

    let mut key = accepted.binding().key();
    key.trust_domain = trust_domain("other.example");
    assert!(
        accepted_binding(&store, &key, now).is_none(),
        "a cross-trust-domain lookup must miss"
    );
}

#[test]
fn a_policy_change_retires_every_existing_binding() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let accepted = accept(
        &store,
        &healthy_resolution("did:web:alice.example"),
        DidBindingPurpose::Principal,
        &trust_domain("auth.example"),
        &digest('b'),
        now,
    );

    let mut key = accepted.binding().key();
    key.policy_digest = digest('c');
    assert!(accepted_binding(&store, &key, now).is_none());
}

// ------------------------------------------------------------------
// Rotation / deactivation / stale
// ------------------------------------------------------------------

#[test]
fn rotation_invalidation_clears_only_the_rotated_did() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let domain = trust_domain("auth.example");
    let policy = digest('b');
    let alice = accept(
        &store,
        &healthy_resolution("did:web:alice.example"),
        DidBindingPurpose::Principal,
        &domain,
        &policy,
        now,
    );
    let mallory = accept(
        &store,
        &healthy_resolution("did:web:mallory.example"),
        DidBindingPurpose::Principal,
        &domain,
        &policy,
        now,
    );

    assert_eq!(store.invalidate(&BindingInvalidation::for_did(did())), 1);
    assert!(accepted_binding(&store, &alice.binding().key(), now).is_none());
    assert!(
        accepted_binding(&store, &mallory.binding().key(), now).is_some(),
        "invalidating one DID must not clear another"
    );
    assert_eq!(mallory.binding().did(), &other_did());
}

#[test]
fn a_deactivated_binding_is_never_usable_even_for_ordinary_reads() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let accepted = accept(
        &store,
        &healthy_resolution("did:web:alice.example"),
        DidBindingPurpose::Principal,
        &trust_domain("auth.example"),
        &digest('b'),
        now,
    );
    let key = accepted.binding().key();
    store
        .accept(accepted.with_binding_status(DidBindingStatus::Deactivated))
        .expect("status update stores");

    assert!(
        accepted_binding(&store, &key, now).is_none(),
        "a deactivated binding must not back an ordinary read"
    );
}

#[test]
fn a_quarantined_resolution_is_stored_but_never_served() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let mut resolution = healthy_resolution("did:web:alice.example");
    resolution.identity_fact_rejection =
        Some(DidResolutionIdentityFactRejection::ControllerProofUnverified);
    let accepted = binding_from_resolution(
        &resolution,
        trust_domain("auth.example"),
        DidBindingPurpose::Principal,
        digest('b'),
        None,
        HIGH_RISK_MAX_AGE,
        now,
    )
    .expect("quarantined resolutions are still representable");
    assert_eq!(accepted.binding().status(), DidBindingStatus::Quarantined);
    store.accept(accepted.clone()).unwrap();

    assert!(accepted_binding(&store, &accepted.binding().key(), now).is_none());
    assert!(
        !accepted
            .binding()
            .is_usable_for_authority(&FreshnessRequirement::any_accepted(), now)
    );
    // Terminal, not merely unusable: `resolve_and_accept_binding` refuses
    // before reaching the resolver, so quarantine cannot be re-litigated (and
    // cannot be turned into an outbound-fetch amplifier) until `expires_at`.
    assert!(
        !is_refreshable(&store, &accepted.binding().key(), now),
        "a quarantined binding must not trigger another resolve"
    );
    assert!(
        is_refreshable(
            &store,
            &accepted.binding().key(),
            now + HARD_EXPIRY + Duration::seconds(1)
        ),
        "quarantine lifts at hard expiry so a fresh evaluation can happen"
    );
}

/// Mirrors the terminal-status gate inside `resolve_and_accept_binding`:
/// whether a miss would be followed by an actual resolver call.
fn is_refreshable(
    store: &dyn VerifiedDidBindingStore,
    key: &VerifiedDidBindingKey,
    now: DateTime<Utc>,
) -> bool {
    !store.get(key, now).is_some_and(|held| {
        matches!(
            held.binding().status(),
            DidBindingStatus::Deactivated | DidBindingStatus::Quarantined
        )
    })
}

#[test]
fn stale_is_readable_for_low_risk_but_rejected_by_high_risk_freshness() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let accepted = accept(
        &store,
        &healthy_resolution("did:web:alice.example"),
        DidBindingPurpose::Principal,
        &trust_domain("auth.example"),
        &digest('b'),
        now,
    );
    let key = accepted.binding().key();

    // Past `refresh_after`, before `expires_at`.
    let later = now + HIGH_RISK_MAX_AGE + Duration::seconds(1);
    let (hit, freshness) = store.get_with_freshness(&key, later);
    let hit = hit.expect("stale entries stay readable");
    assert!(matches!(freshness, BindingFreshness::Stale { .. }));
    assert_eq!(hit.binding().status(), DidBindingStatus::Stale);
    assert!(
        hit.binding()
            .is_usable_for_authority(&FreshnessRequirement::any_accepted(), later),
        "an ordinary read must not be blocked by TTL expiry (spec §5)"
    );
    assert!(
        !hit.binding().is_usable_for_authority(
            &FreshnessRequirement::fresh_within(HIGH_RISK_MAX_AGE),
            later
        ),
        "a high-risk write must refresh or fail closed"
    );
}

#[test]
fn hard_expiry_makes_the_entry_disappear_for_readers() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let accepted = accept(
        &store,
        &healthy_resolution("did:web:alice.example"),
        DidBindingPurpose::Principal,
        &trust_domain("auth.example"),
        &digest('b'),
        now,
    );
    let key = accepted.binding().key();
    let later = now + HARD_EXPIRY + Duration::seconds(1);
    assert!(accepted_binding(&store, &key, later).is_none());
}

// ------------------------------------------------------------------
// "no repeated network fetch" contract
// ------------------------------------------------------------------

/// The authority path returns from the store — i.e. never reaches
/// `resolve_did_document` — while the acceptance is fresh, for every DID
/// method coauth resolves over the network (`did:web`, `did:plc` and the
/// delegated resolver).
#[test]
fn a_fresh_binding_hit_short_circuits_before_the_resolver() {
    let now = protocol_now();
    for (did, source) in [
        ("did:web:alice.example", DidResolutionSource::DidWeb),
        (
            "did:plc:z72i7hdynmk6r22z27h6tvur",
            DidResolutionSource::DidPlc,
        ),
        (
            "did:webvh:ztest:resolver.example:users:alice",
            DidResolutionSource::DelegatedResolver,
        ),
    ] {
        let store = DurableVerifiedDidBindingStore::new(16);
        let mut resolution = healthy_resolution(did);
        resolution.source = source;
        let accepted = accept(
            &store,
            &resolution,
            DidBindingPurpose::AccountBinding,
            &trust_domain("auth.example"),
            &digest('b'),
            now,
        );
        let key = accepted.binding().key();
        let freshness = FreshnessRequirement::fresh_within(HIGH_RISK_MAX_AGE);

        // Inside the window: reused, so `resolve_and_accept_binding` returns
        // at step 2 and performs no fetch.
        assert!(
            reusable_binding(&store, &key, &freshness, now).is_some(),
            "{did} should be reused without a resolver call"
        );
        assert!(
            reusable_binding(
                &store,
                &key,
                &freshness,
                now + HIGH_RISK_MAX_AGE - Duration::seconds(1)
            )
            .is_some()
        );

        // Past the refresh point: not reusable, so exactly one refresh follows.
        assert!(
            reusable_binding(
                &store,
                &key,
                &freshness,
                now + HIGH_RISK_MAX_AGE + Duration::seconds(1)
            )
            .is_none()
        );

        // An invalidation (rotation / deactivation / revocation) reads as a
        // miss immediately, again causing exactly one refresh.
        store.invalidate(&BindingInvalidation::for_did(
            accepted.binding().did().clone(),
        ));
        assert!(reusable_binding(&store, &key, &freshness, now).is_none());
    }
}

/// The whole crate must funnel every network resolution through
/// [`resolve_and_accept_binding`]. If a handler ever calls
/// `resolve_did_document` directly again, this fails.
#[test]
fn resolve_did_document_is_called_in_exactly_one_place() {
    // Assembled at runtime so this file's own source does not match the scan.
    let needle = format!(".{}_did_document(", "resolve");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits: Vec<String> = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("backend src is readable") {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source file is UTF-8");
            for (index, line) in text.lines().enumerate() {
                // Only method invocations, not the trait declaration and not
                // prose in doc comments.
                if line.contains(needle.as_str()) && !line.trim_start().starts_with("//") {
                    hits.push(format!("{}:{}", path.display(), index + 1));
                }
            }
        }
    }
    assert_eq!(
        hits.len(),
        1,
        "resolve_did_document must only be invoked by \
         services::did_binding::resolve_and_accept_binding, found {hits:?}"
    );
    assert!(
        hits[0]
            .replace('\\', "/")
            .contains("services/did_binding.rs:"),
        "unexpected call site: {}",
        hits[0]
    );
}

/// `primary_did_for_user` — the lookup behind every ordinary session /
/// account read — must keep serving only the persisted, verified principal
/// binding. It takes no `reqwest::Client` and performs no resolution, and this
/// pins that: an ordinary account read can never become an authority path.
#[test]
fn primary_did_for_user_never_resolves() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/services/did_resolver.rs"),
    )
    .expect("did_resolver.rs is readable");

    // The default implementation's body, from its signature to the closing
    // brace of the function (the next `    }` at method indentation).
    // `rfind`: the trait declaration comes first, the `impl` block after it.
    let start = source
        .rfind("    async fn primary_did_for_user(")
        .expect("default primary_did_for_user implementation exists");
    let body = &source[start..];
    let end = body
        .find("\n    fn delegated_resolver(")
        .expect("the implementation is followed by delegated_resolver");
    let body = &body[..end];

    for forbidden in [
        "resolve_did_document",
        "reqwest",
        "http_client",
        "did_binding::",
        "authority_document",
    ] {
        assert!(
            !body.contains(forbidden),
            "primary_did_for_user must not reference `{forbidden}`: an ordinary \
             account read must consume the persisted accepted binding only"
        );
    }
    assert!(
        body.contains("principal_did()"),
        "primary_did_for_user must read the persisted principal binding"
    );
}

#[test]
fn mirroring_a_purpose_copies_the_evidence_but_not_the_authority() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let source = accept(
        &store,
        &healthy_resolution("did:web:alice.example"),
        DidBindingPurpose::AccountBinding,
        &trust_domain("auth.example"),
        &digest('b'),
        now,
    );

    let mirrored = mirrored_acceptance(&source, DidBindingPurpose::Principal)
        .expect("mirroring succeeds")
        .expect("a different purpose yields a new acceptance");
    store.accept(mirrored).expect("store accepts");

    let mut principal_key = source.binding().key();
    principal_key.purpose = DidBindingPurpose::Principal;
    let mirrored = accepted_binding(&store, &principal_key, now).expect("principal read hits");

    // Same evidence, verbatim.
    assert_eq!(
        mirrored.binding().document_digest(),
        source.binding().document_digest()
    );
    assert_eq!(
        mirrored.binding().evidence_digest(),
        source.binding().evidence_digest()
    );
    assert_eq!(
        mirrored.binding().history_head(),
        source.binding().history_head()
    );
    assert_eq!(mirrored.binding().status(), source.binding().status());
    assert_eq!(
        mirrored.binding().expires_at(),
        source.binding().expires_at()
    );

    // Still no cross-purpose authority: a third purpose remains a miss.
    let mut admin_key = source.binding().key();
    admin_key.purpose = DidBindingPurpose::AdminAction;
    assert!(accepted_binding(&store, &admin_key, now).is_none());
}

#[test]
fn mirroring_never_upgrades_a_quarantined_acceptance() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let mut resolution = healthy_resolution("did:web:alice.example");
    resolution.identity_fact_rejection = Some(DidResolutionIdentityFactRejection::DidWebFallback);
    let source = binding_from_resolution(
        &resolution,
        trust_domain("auth.example"),
        DidBindingPurpose::AccountBinding,
        digest('b'),
        None,
        HIGH_RISK_MAX_AGE,
        now,
    )
    .expect("quarantined resolutions are representable");

    let mirrored = mirrored_acceptance(&source, DidBindingPurpose::Principal)
        .expect("mirroring succeeds")
        .expect("a different purpose yields a new acceptance");
    store.accept(mirrored).expect("store accepts");

    let mut principal_key = source.binding().key();
    principal_key.purpose = DidBindingPurpose::Principal;
    assert!(
        accepted_binding(&store, &principal_key, now).is_none(),
        "a quarantined acceptance must not become a readable principal binding"
    );
}

// ------------------------------------------------------------------
// Document round-trip
// ------------------------------------------------------------------

#[test]
fn did_document_round_trip_is_loss_free() {
    let original = document_for("did:web:alice.example");
    let shared = to_shared_document(&original).expect("coauth -> shared");
    let restored = from_shared_document(&shared).expect("shared -> coauth");

    assert_eq!(
        serde_json::to_value(&original).unwrap(),
        serde_json::to_value(&restored).unwrap(),
        "pinning a document must not lose JWK / Multikey / service detail"
    );
    // Digest stability: the acceptance's digest is computed over the shared
    // form, so re-deriving it from a round-tripped document must agree.
    assert_eq!(
        arkret_identity::document_canonical_digest(&shared).unwrap(),
        arkret_identity::document_canonical_digest(&to_shared_document(&restored).unwrap())
            .unwrap()
    );
}

// ------------------------------------------------------------------
// Policy digest
// ------------------------------------------------------------------

#[test]
fn policy_digest_is_deterministic_and_moves_with_the_policy() {
    let mut config = ArkretConfig::default();
    let base = policy_digest(&config).unwrap();
    assert_eq!(base, policy_digest(&config).unwrap());

    config.identity_registry = Some(coauth_config::IdentityRegistryConfig {
        resolver: "https://resolver.example/_arkret/root/identity/resolve"
            .parse()
            .unwrap(),
        proof_required_for_pairwise: false,
    });
    let with_resolver = policy_digest(&config).unwrap();
    assert_ne!(base, with_resolver);

    let mut flipped = config.clone();
    if let Some(registry) = flipped.identity_registry.as_mut() {
        registry.proof_required_for_pairwise = !registry.proof_required_for_pairwise;
    }
    assert_ne!(with_resolver, policy_digest(&flipped).unwrap());
}

/// The digest is the SDK's, not a coauth-local recipe: it carries the shared
/// [`arkret_identity::POLICY_DIGEST_VERSION`] tag and coauth's own dimensions
/// live in the `deployment` extension object the SDK reserves for them.
#[test]
fn the_policy_digest_uses_the_shared_sdk_encoding() {
    let config = ArkretConfig::default();
    let policy = resolver_policy(&config);
    let value = PolicyDigestInput::new(&policy)
        .with_extension("resolver_allow_loopback", false)
        .canonical_value();

    assert_eq!(
        value["version"],
        serde_json::json!(arkret_identity::POLICY_DIGEST_VERSION)
    );
    assert_eq!(value["fail_mode"], serde_json::json!("fail_closed"));
    assert_eq!(
        value["deployment"]["resolver_allow_loopback"],
        serde_json::json!(false)
    );
    // Without a delegated resolver the allow list is exactly the three methods
    // coauth resolves natively; CAU-SPEC-02 keeps `did:webvh` out of it.
    assert_eq!(
        value["allowed_methods"],
        serde_json::json!(["did:key:", "did:plc:", "did:web:"])
    );
}

/// The deployment epoch replaces the removed local `POLICY_DIGEST_VERSION`
/// constant as the one-step "retire every binding here" switch, and it is
/// deployment-local: it does not require an SDK release.
#[test]
fn the_deployment_epoch_retires_every_binding_in_one_step() {
    let config = ArkretConfig::default();
    let policy = resolver_policy(&config);
    let without_epoch = PolicyDigestInput::new(&policy).digest().unwrap();
    let with_epoch = PolicyDigestInput::new(&policy)
        .with_deployment_epoch("2026-07-31-incident")
        .digest()
        .unwrap();
    let with_other_epoch = PolicyDigestInput::new(&policy)
        .with_deployment_epoch("2026-08-01-incident")
        .digest()
        .unwrap();

    assert_ne!(without_epoch, with_epoch);
    assert_ne!(with_epoch, with_other_epoch);
}

/// Switching the digest algorithm makes every previously stored acceptance
/// unreachable rather than unreadable: the lookup simply misses, no code path
/// panics, and the next authority call rebuilds the acceptance. This is the
/// expected upgrade behaviour, not a fault.
#[test]
fn an_acceptance_stored_under_an_older_policy_digest_misses_without_panicking() {
    let now = protocol_now();
    let store = DurableVerifiedDidBindingStore::new(16);
    let accepted = accept(
        &store,
        &healthy_resolution("did:web:alice.example"),
        DidBindingPurpose::Principal,
        &trust_domain("auth.example"),
        &digest('b'),
        now,
    );

    let mut under_new_algorithm = accepted.binding().key();
    under_new_algorithm.policy_digest = digest('c');
    assert!(accepted_binding(&store, &under_new_algorithm, now).is_none());
    // The stale entry is still addressable under its own (old) key, which is
    // what makes an explicit sweep possible.
    assert_eq!(
        store.invalidate(&BindingInvalidation::for_policy_digest(digest('b'))),
        1
    );
}

// ------------------------------------------------------------------
// Durable rows: key projection and tamper rejection
// ------------------------------------------------------------------

fn stored_acceptance(now: DateTime<Utc>) -> AcceptedDidBinding {
    binding_from_resolution(
        &healthy_resolution("did:web:alice.example"),
        trust_domain("auth.example"),
        DidBindingPurpose::Principal,
        digest('b'),
        None,
        HIGH_RISK_MAX_AGE,
        now,
    )
    .expect("binding builds")
}

/// Every one of the six `VerifiedDidBindingKey` dimensions reaches its own
/// column, and changing any one of them produces a different row key. §5
/// requires exact invalidation along each dimension, which is impossible if two
/// distinct keys collapse onto one row.
#[test]
fn all_six_key_dimensions_project_onto_distinct_columns() {
    let base = VerifiedDidBindingKey {
        did: did(),
        trust_domain: trust_domain("auth.example"),
        purpose: DidBindingPurpose::Principal,
        policy_digest: digest('b'),
        verification_method: None,
        version_id: None,
    };
    let columns = key_columns(&base);
    assert_eq!(columns.did, "did:web:alice.example");
    assert_eq!(columns.trust_domain, "ak:trust_domain:auth.example");
    assert_eq!(columns.purpose, "principal");
    assert_eq!(columns.policy_digest, digest('b').as_str());
    assert_eq!(columns.verification_method, None);
    assert_eq!(columns.version_id, None);

    let method = arkret_wire::DidUrl::new("did:web:alice.example#key-1".to_owned()).unwrap();
    /// A named single-dimension mutation of the binding key.
    type NamedKeyMutation = (&'static str, Box<dyn Fn(&mut VerifiedDidBindingKey)>);

    let variants: [NamedKeyMutation; 6] = [
        ("did", Box::new(|key| key.did = other_did())),
        (
            "trust_domain",
            Box::new(|key| key.trust_domain = trust_domain("other.example")),
        ),
        (
            "purpose",
            Box::new(|key| key.purpose = DidBindingPurpose::AdminAction),
        ),
        (
            "policy_digest",
            Box::new(|key| key.policy_digest = digest('c')),
        ),
        (
            "verification_method",
            Box::new(move |key| key.verification_method = Some(method.clone())),
        ),
        (
            "version_id",
            Box::new(|key| key.version_id = Some("1-abc".to_owned())),
        ),
    ];
    for (dimension, mutate) in variants {
        let mut variant = base.clone();
        mutate(&mut variant);
        assert_ne!(
            key_columns(&variant),
            columns,
            "changing `{dimension}` must produce a different row key"
        );
    }
}

/// An untouched row decodes back into the same acceptance. Round-tripping is
/// not `==` on the document (`DidDocument` rebuilds `raw_properties`), so the
/// invariant asserted here is the one that matters: the canonical digest and
/// the store key survive.
#[test]
fn an_untouched_row_decodes_back_into_the_same_acceptance() {
    let now = protocol_now();
    let accepted = stored_acceptance(now);
    let key = accepted.binding().key();
    let row = encode_row(&accepted).expect("row encodes");

    assert_eq!(row.key, key_columns(&key));
    assert_eq!(row.expires_at, accepted.binding().expires_at());
    assert_eq!(
        row.history_head.as_deref(),
        accepted.binding().history_head().map(Hash::as_str)
    );

    let decoded = decode_row(&key, row).expect("an untouched row decodes");
    assert_eq!(decoded.binding().key(), key);
    assert_eq!(
        decoded.binding().document_digest(),
        accepted.binding().document_digest()
    );
}

/// Tampering with a stored row must make the acceptance *disappear*, never
/// come back as trusted. Each case below edits exactly one thing.
#[test]
fn a_tampered_row_is_discarded_rather_than_trusted() {
    let now = protocol_now();
    let accepted = stored_acceptance(now);
    let key = accepted.binding().key();
    let pristine = encode_row(&accepted).expect("row encodes");

    // 1. The pinned document was edited: its canonical digest no longer equals the digest the
    //    binding recorded.
    let mut edited_document = pristine.clone();
    edited_document.accepted["document"]["verificationMethod"][0]["publicKeyMultibase"] =
        serde_json::json!("z6MkfXVRWQNbmDmzZTQ5JuBLTzHtGSCXhhYm8pLTfNfPnYzM");
    assert!(
        decode_row(&key, edited_document).is_none(),
        "an edited pinned document must be discarded"
    );

    // 2. The document was swapped for one belonging to another DID.
    let mut swapped_subject = pristine.clone();
    swapped_subject.accepted["document"]["id"] = serde_json::json!("did:web:mallory.example");
    assert!(
        decode_row(&key, swapped_subject).is_none(),
        "a document belonging to another DID must be discarded"
    );

    // 3. The acceptance was relocated by editing a key column — here, promoting a principal
    //    acceptance into an admin-action one.
    let mut relocated = pristine.clone();
    relocated.key.purpose = "admin_action".to_owned();
    assert!(
        decode_row(&key, relocated).is_none(),
        "a row whose key columns disagree with its payload must be discarded"
    );

    // 4. Same, along the trust-domain dimension.
    let mut cross_domain = pristine.clone();
    cross_domain.key.trust_domain = "ak:trust_domain:other.example".to_owned();
    assert!(
        decode_row(&key, cross_domain).is_none(),
        "a row moved into another trust domain must be discarded"
    );

    // 5. A structurally valid row that simply does not answer the key that was asked for.
    let mut other_key = key.clone();
    other_key.purpose = DidBindingPurpose::AdminAction;
    assert!(
        decode_row(&other_key, pristine.clone()).is_none(),
        "a row must not answer a key it was not filed under"
    );

    // 6. Unparseable payload.
    let mut garbage = pristine.clone();
    garbage.accepted = serde_json::json!({"binding": "not a binding"});
    assert!(decode_row(&key, garbage).is_none());

    // Control: the pristine row still decodes, so the cases above failed for
    // the reason under test and not because the fixture was already broken.
    assert!(decode_row(&key, pristine).is_some());
}

/// The conjunctive / never-catch-all semantics of `BindingInvalidation` survive
/// the projection onto columns. A selector that matched nothing in memory must
/// not become a table wipe in SQL.
#[test]
fn the_invalidation_selector_keeps_its_semantics_in_columns() {
    assert!(invalidation_columns(&BindingInvalidation::default()).is_empty());

    let selector = BindingInvalidation::for_did(did())
        .with_trust_domain(trust_domain("auth.example"))
        .with_purpose(DidBindingPurpose::Principal)
        .with_policy_digest(digest('b'))
        .with_history_head(digest('a'))
        .with_verification_method(
            arkret_wire::DidUrl::new("did:web:alice.example#key-1".to_owned()).unwrap(),
        );
    let columns = invalidation_columns(&selector);
    assert!(!columns.is_empty());
    assert_eq!(columns.did.as_deref(), Some("did:web:alice.example"));
    assert_eq!(
        columns.trust_domain.as_deref(),
        Some("ak:trust_domain:auth.example")
    );
    assert_eq!(columns.purpose.as_deref(), Some("principal"));
    assert_eq!(columns.policy_digest.as_deref(), Some(digest('b').as_str()));
    assert_eq!(columns.history_head.as_deref(), Some(digest('a').as_str()));
    assert_eq!(
        columns.verification_method.as_deref(),
        Some("did:web:alice.example#key-1")
    );
}
