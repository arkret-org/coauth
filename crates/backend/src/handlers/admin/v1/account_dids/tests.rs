use std::sync::Arc;

use arkret_identifiers::{Did, DidCoreId, Hash, RequestId, TrustDomainId, WebOrigin};
use arkret_identity::VerifiedDidBindingStore as _;
use arkret_identity::test_material::{
    PublicKeyFingerprintInput, is_published_test_key, reserved_identifier_matches,
};
use arkret_models_identity::{
    AccountRegistrationControlProof, AccountRegistrationControlProofKind, DidBindingPurpose,
    IdentityMethodEvidence,
};
use arkret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use coauth_config::ArkretConfig;
use coauth_data::{
    BoxRepository, DidBindingChallengeInput, DidBindingChallengeIssue, RepositoryAccess as _,
    UrlBuilder, User,
};
use coauth_keyring::Keyring;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz};
use diesel_async::RunQueryDsl as _;
use ed25519_dalek::Signer as _;
use hyper::{Request, StatusCode};

use crate::handlers::arkret::{DidDocument, VerificationMethod};
use crate::handlers::test_utils::{RequestBuilderExt as _, ResponseExt as _, TestState, setup};
use crate::services::did_resolver::{
    DidResolution, DidResolutionSource, DidResolveError, DidResolverService,
    DidResolverServiceHandle, ResolverEgressPolicy,
};

struct FixedBindingResolver {
    base: DidResolverServiceHandle,
    resolution: DidResolution,
}

#[async_trait]
impl DidResolverService for FixedBindingResolver {
    fn service_id(&self, config: &ArkretConfig) -> DidCoreId {
        self.base.service_id(config)
    }
    fn issuer_did(&self, config: &ArkretConfig) -> Did {
        self.base.issuer_did(config)
    }
    fn resolver_egress_policy(&self) -> &ResolverEgressPolicy {
        self.base.resolver_egress_policy()
    }
    async fn primary_did_for_user(
        &self,
        repo: &mut BoxRepository,
        config: &ArkretConfig,
        user: &User,
    ) -> Result<Did, crate::handlers::arkret::SessionGrantError> {
        self.base.primary_did_for_user(repo, config, user).await
    }
    fn delegated_resolver(&self, config: &ArkretConfig) -> Option<String> {
        self.base.delegated_resolver(config)
    }
    fn proof_required_for_pairwise(&self, config: &ArkretConfig) -> bool {
        self.base.proof_required_for_pairwise(config)
    }
    async fn resolve_did_document(
        &self,
        _client: &reqwest::Client,
        _url: &UrlBuilder,
        _config: &ArkretConfig,
        _keyring: &Keyring,
        _repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError> {
        if did == self.resolution.document.id {
            Ok(self.resolution.clone())
        } else {
            Err(DidResolveError::NotFound)
        }
    }
    async fn resolve_did_binding_evidence(
        &self,
        client: &reqwest::Client,
        url: &UrlBuilder,
        config: &ArkretConfig,
        keyring: &Keyring,
        repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError> {
        self.resolve_did_document(client, url, config, keyring, repo, did)
            .await
    }
}

#[derive(diesel::QueryableByName)]
struct ChallengeState {
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<chrono::DateTime<Utc>>,
}
#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn persisted_state(state: &TestState, challenge_id: &str, did: &Did) -> (bool, i64) {
    let mut conn = state.repository_factory.pool().get().await.unwrap();
    let challenge =
        diesel::sql_query("SELECT consumed_at FROM did_binding_challenges WHERE challenge_id = $1")
            .bind::<Text, _>(challenge_id)
            .get_result::<ChallengeState>(&mut conn)
            .await
            .unwrap();
    let bindings = diesel::sql_query(
        "SELECT count(*)::bigint AS count FROM verified_did_bindings WHERE did = $1",
    )
    .bind::<Text, _>(did.as_str())
    .get_result::<CountRow>(&mut conn)
    .await
    .unwrap();
    (challenge.consumed_at.is_some(), bindings.count)
}

#[allow(clippy::too_many_arguments)]
async fn exercise_handler(
    state: &mut TestState,
    token: &str,
    account: &User,
    did_text: &str,
    fragment: &str,
    challenge_id: &str,
    request_id: &str,
    expect_denied: bool,
    expected_did_rule: bool,
) {
    let did = Did::new(did_text.to_owned()).unwrap();
    let principal_id = arkret_identifiers::project_did_to_core_id(&did).unwrap();
    let method = arkret_wire::DidUrl::new(format!("{did}#{fragment}")).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
    let public_key = signer.verifying_key().to_bytes();
    let key_digest = Hash::new(format!(
        "sha256:{}",
        arkret_canonical::sha256_hex(public_key)
    ))
    .unwrap();
    let log_head = Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap();
    let request_digest = Hash::new(format!(
        "sha256:{}",
        arkret_canonical::sha256_hex(request_id.as_bytes())
    ))
    .unwrap();
    let audience = crate::handlers::arkret::owning_station_id_for(&state.arkret_config);
    let subject = crate::handlers::arkret::account_subject(&audience, account.id).unwrap();
    let origin =
        WebOrigin::new(state.url_builder.http_base().origin().ascii_serialization()).unwrap();
    let trust_domain = TrustDomainId::new(crate::handlers::arkret::trust_domain_for(
        &state.url_builder,
        &state.arkret_config,
    ))
    .unwrap();
    assert!(
        !is_published_test_key(&PublicKeyFingerprintInput::Ed25519Rfc8032(&public_key)).unwrap()
    );
    let rules = reserved_identifier_matches(Some(&did), Some(&method), Some(&trust_domain));
    assert!(!rules.trust_domain);
    if expect_denied {
        assert_eq!(rules.did, expected_did_rule);
        assert_eq!(rules.key_id, !expected_did_rule);
    } else {
        assert!(
            !rules.any(),
            "the ordinary control must match no reserved rule"
        );
    }
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let expires = now + Duration::minutes(5);
    let input = DidBindingChallengeInput {
        request_id: RequestId::new(request_id).unwrap(),
        request_digest: request_digest.clone(),
        issuing_handoff_grant_id: coauth_data::Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCN")
            .unwrap(),
        local_account_id: account.id,
        account_subject: subject.clone(),
        principal_id: principal_id.clone(),
        did: did.clone(),
        did_version_id: "2-QmHead".to_owned(),
        log_head_digest: log_head.clone(),
        control_key_digest: key_digest.clone(),
        witness_evidence: None,
        challenge_id: challenge_id.to_owned(),
        challenge: "Y2hhbGxlbmdlLXdpdGgtMTI4LWJpdHM".to_owned(),
        dpop_jkt: "A".repeat(43),
        audience_id: audience.clone(),
        origin: origin.clone(),
        trust_domain: trust_domain.clone(),
        issued_at: now,
        expires_at: expires,
    };
    let mut repo = state.repository().await.unwrap();
    assert!(matches!(
        repo.account_handoff()
            .issue_did_binding_challenge(input.clone())
            .await
            .unwrap(),
        DidBindingChallengeIssue::Issued(_)
    ));
    repo.save().await.unwrap();

    let mut proof = AccountRegistrationControlProof {
        proof_kind: AccountRegistrationControlProofKind::DidBoundSignature,
        challenge_id: challenge_id.to_owned(),
        challenge: input.challenge,
        purpose: DidBindingPurpose::AccountBindingForPublishedDid,
        request_canonical_digest: request_digest,
        account_subject: subject,
        principal_id,
        did: did.clone(),
        did_version_id: input.did_version_id,
        control_key_digest: key_digest.clone(),
        dpop_jkt: input.dpop_jkt,
        audience_id: audience,
        origin,
        trust_domain,
        issued_at: now,
        expires_at: expires,
        verification_method: method.clone(),
        witness_evidence: None,
        signature: "pending".to_owned(),
    };
    proof.signature = arkret_canonical::base64url_encode(
        signer
            .sign(&proof.canonical_signing_bytes().unwrap())
            .to_bytes(),
    );
    assert!(verify_detached_ed25519_signature(
        &PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_vec()
        },
        &proof.canonical_signing_bytes().unwrap(),
        &proof.signature,
    ));

    let resolution = DidResolution {
        document: DidDocument {
            id: did.to_string(),
            also_known_as: Vec::new(),
            verification_method: vec![VerificationMethod {
                id: method.to_string(),
                kind: "JsonWebKey2020".to_owned(),
                controller: did.to_string(),
                public_key_jwk: Some(serde_json::from_value(serde_json::json!({
                    "kty": "OKP", "crv": "Ed25519", "x": arkret_canonical::base64url_encode(public_key)
                })).unwrap()),
                public_key_multibase: None,
            }],
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            service: Vec::new(),
            metadata: None,
        },
        source: DidResolutionSource::DelegatedResolver,
        verified_local_binding: false,
        key_log_head: Some(log_head),
        method_evidence: serde_json::json!({"kind": "did_webvh"}),
        closed_method_evidence: Some(IdentityMethodEvidence::DidWebvh {
            version_id: arkret_wire::NonEmptyString::new("2-QmHead").unwrap(),
            control_key_digest: key_digest,
        }),
        identity_fact_rejection: None,
    };
    state.did_resolver_service_override = Some(Arc::new(FixedBindingResolver {
        base: crate::services::did_resolver::default_did_resolver_service(&state.arkret_config),
        resolution,
    }));
    let response = state
        .request(
            Request::post(format!("/_coauth/admin/accounts/{}/dids", account.id))
                .bearer(token)
                .json(serde_json::json!({
                    "did": did,
                    "kind": "primary",
                    "control_proof": proof,
                    "make_primary": false,
                })),
        )
        .await;
    if expect_denied {
        response.assert_status(StatusCode::BAD_REQUEST);
        assert!(
            response.body().contains("test_signing_material_denied"),
            "{}",
            response.body()
        );
        let (consumed, bindings) = persisted_state(state, challenge_id, &did).await;
        assert!(!consumed, "the challenge consume escaped its transaction");
        assert_eq!(bindings, 0, "a refused key was durably bound");
        assert!(
            crate::services::did_binding::shared_verified_did_binding_store()
                .mirror()
                .snapshot()
                .iter()
                .all(|accepted| accepted.binding().did() != &did)
        );
    } else {
        response.assert_status(StatusCode::CREATED);
        let (consumed, bindings) = persisted_state(state, challenge_id, &did).await;
        assert!(consumed, "ordinary proof did not consume its challenge");
        assert!(bindings > 0, "ordinary proof did not persist its binding");
    }
}

#[tokio::test]
async fn reserved_did_and_key_id_roll_back_real_admin_binding_transaction() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool_with_station(pool.clone())
        .await
        .unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut repo = state.repository().await.unwrap();
    let mut rng = state.rng();
    let account = repo
        .user()
        .add(&mut rng, &*state.clock, "alice".to_owned())
        .await
        .unwrap();
    repo.save().await.unwrap();

    exercise_handler(
        &mut state,
        &token,
        &account,
        "did:webvh:z6mkfixture123:real.company",
        "runtime-1",
        "Y2hhbGxlbmdlLWlkLWZpeHR1cmUtMDAwMQ",
        "ak:request:0196419b-0000-7000-8000-000000000001",
        true,
        true,
    )
    .await;
    exercise_handler(
        &mut state,
        &token,
        &account,
        "did:webvh:z6mklive123:real.company",
        "runtime-fixture",
        "Y2hhbGxlbmdlLWlkLWZpeHR1cmUtMDAwMg",
        "ak:request:0196419b-0000-7000-8000-000000000002",
        true,
        false,
    )
    .await;
    exercise_handler(
        &mut state,
        &token,
        &account,
        "did:webvh:z6mklive123:real.company",
        "runtime-1",
        "Y2hhbGxlbmdlLWlkLWZpeHR1cmUtMDAwMw",
        "ak:request:0196419b-0000-7000-8000-000000000003",
        false,
        false,
    )
    .await;
}
