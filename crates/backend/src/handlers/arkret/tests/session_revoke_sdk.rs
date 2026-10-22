//! Typed SDK calls against the production Coauth router and real Postgres.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use arkret_http_client::{Auth, Client, DpopAuth, Error as ClientError};
use arkret_models_collaboration::account_lifecycle::{
    AccountLifecycleProof, AccountLifecycleProofKind, SessionRevokeRequestBody,
};
use arkret_wire::{DeviceId, SessionGrantId};
use salvo::conn::Listener as _;

use super::*;

#[derive(Clone)]
struct LoseResponse {
    armed: Arc<AtomicBool>,
    hits: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl salvo::Handler for LoseResponse {
    async fn handle(
        &self,
        req: &mut salvo::Request,
        depot: &mut salvo::Depot,
        res: &mut salvo::Response,
        ctrl: &mut salvo::FlowCtrl,
    ) {
        ctrl.call_next(req, depot, res).await;
        if res.status_code == Some(StatusCode::OK)
            && req.uri().path() == "/_arkret/gate/account/session-grants/revoke"
            && self.armed.swap(false, Ordering::SeqCst)
        {
            self.hits.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

async fn footprint(
    pool: &diesel_async::pooled_connection::deadpool::Pool<diesel_async::AsyncPgConnection>,
) -> String {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Snapshot {
        #[diesel(sql_type = diesel::sql_types::Text)]
        body: String,
    }
    let mut connection = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY to_jsonb(g)::text) FROM oauth_session_grants g),'operations',(SELECT jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text) FROM oauth_session_grant_operations o),'dpop',(SELECT jsonb_agg(to_jsonb(d) ORDER BY to_jsonb(d)::text) FROM dpop_jti_replay d))::text AS body")
        .get_result::<Snapshot>(&mut connection).await.unwrap().body
}

const DEVICE: &str = "ak:device:01964137-0000-7000-8000-000000000001";

fn empty() -> SessionRevokeRequestBody {
    SessionRevokeRequestBody {
        target_session_grant_id: None,
        target_device_id: None,
        all_sessions: None,
        proof: None,
    }
}

fn client(base: &str, token: &str, key: &PrivateKey) -> Client {
    let PrivateKey::OkpEd25519(key) = key else {
        panic!("Ed25519 holder")
    };
    let key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&key.to_bytes());
    Client::builder(base.parse().unwrap())
        .allow_insecure_localhost()
        .timeout(std::time::Duration::from_secs(2))
        .retry(arkret_http_client::RetryConfig::standard(1))
        .auth(Auth::Dpop(DpopAuth::with_dpop_token(
            token,
            move |request| {
                arkret_signatures::dpop::build_dpop_proof(&request, &key)
                    .map(|proof| proof.header_value)
                    .map_err(|error| ClientError::Protocol(error.to_string()))
            },
        )))
        .build()
        .unwrap()
}

async fn mint(
    state: &TestState,
    user: &User,
    principal: &str,
    device: &str,
) -> (SessionGrant, PrivateKey) {
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let session = repo
        .browser_session()
        .add(&mut rng, &*state.clock, user, None)
        .await
        .unwrap();
    let key = PrivateKey::generate_ed25519(&mut rng);
    let account = test_account_id(
        principal,
        &required_audience_for(&state.url_builder, &state.arkret_config),
    );
    let material = issue_session_grant(
        &mut rng,
        &SystemClock::default(),
        &state.url_builder,
        &state.arkret_config,
        &state.keyring,
        crate::services::session_grant::TestGrantIssuance {
            browser_session: &session,
            session_public_key: test_session_public_jwk(&key, format!("holder-{}", session.id)),
            subject_id: principal,
            account_id: &account,
            device_id: DeviceId::new(device).unwrap(),
            scopes: vec![STATION_SESSION_BIND_SCOPE.into()],
        },
    )
    .unwrap();
    let grant = persist_session_grant(
        &mut repo,
        &mut rng,
        &SystemClock::default(),
        &session,
        &material,
    )
    .await
    .unwrap();
    repo.save().await.unwrap();
    (grant, key)
}

fn sign_request(
    grant: &SessionGrant,
    did: &str,
    method: &str,
    request: &mut SessionRevokeRequestBody,
    salt: &str,
) {
    let now = Utc::now();
    let mut proof = AccountLifecycleProof {
        proof_kind: AccountLifecycleProofKind::DidBoundSignature,
        challenge: format!("session-revoke-sdk-{salt}"),
        request_canonical_digest: AccountLifecycleProof::session_revoke_request_digest(
            &grant.subject_id,
            &grant.issuer_id,
            &DeviceId::new(DEVICE).unwrap(),
            request.target_session_grant_id.as_ref(),
            request.target_device_id.as_ref(),
            request.all_sessions.unwrap_or(false),
        )
        .unwrap(),
        audience_id: grant.audience_id.clone(),
        issued_at: now,
        expires_at: now + Duration::minutes(4),
        verification_method: Some(arkret_wire::DidUrl::new(method).unwrap()),
        signature: String::new(),
    };
    assert!(method.starts_with(did));
    let proof_seed = if salt == "wrong-signature" {
        [84; 32]
    } else {
        [81; 32]
    };
    proof.signature = crate::arkret_key_bridge::sdk_detached_jws_for_test(
        &proof_seed,
        method,
        &proof.canonical_signing_bytes().unwrap(),
    );
    request.proof = Some(proof);
}

fn refusal(
    error: ClientError,
    expected_status: u16,
    expected_code: &str,
    expected_reason: Option<&str>,
) {
    let ClientError::Api { status, error } = error else {
        panic!("expected structured refusal, got {error:?}")
    };
    assert_eq!(status, expected_status, "{error:?}");
    assert_eq!(error.code(), expected_code, "{error:?}");
    assert_eq!(
        error
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str),
        expected_reason,
        "{error:?}"
    );
}

async fn active(state: &TestState, id: &SessionGrantId) -> bool {
    let mut repo = state.repository().await.unwrap();
    let grant = repo
        .oauth_session_grant()
        .lookup_by_grant_id(id)
        .await
        .unwrap()
        .unwrap();
    repo.cancel().await.unwrap();
    grant.is_active(&SystemClock::default())
}

#[tokio::test]
async fn session_revoke_sdk_real_http_pg_selectors_replay_and_isolation() {
    setup();
    let pool = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("real Postgres required");
    let mut state = TestState::from_pool_with_station(pool.clone())
        .await
        .unwrap();
    state.arkret_config.admin_audience =
        Some(crate::handlers::test_utils::TEST_STATION_AUDIENCE.into());
    state.arkret_config.stations[0].internal_authority_shared_secret =
        Some(INTERNAL_AUTHORITY_SHARED_SECRET.to_owned().into());
    let listener = salvo::conn::TcpListener::new("127.0.0.1:0").bind().await;
    let address = listener.local_addr().unwrap();
    let base = format!("http://{address}/");
    state.url_builder = coauth_data::UrlBuilder::new(base.parse().unwrap(), None, None);
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let user = repo
        .user()
        .add(&mut rng, &*state.clock, "revoke-sdk-alice".into())
        .await
        .unwrap();
    let other = repo
        .user()
        .add(&mut rng, &*state.clock, "revoke-sdk-bob".into())
        .await
        .unwrap();
    repo.save().await.unwrap();

    // A previously accepted external DID with an independent lifecycle key.
    // Reuse the SDK's signed method-document builder; this creates no Applet,
    // Realm Actor or runtime, and does not exercise fresh account registration.
    let endpoint = "https://registration.example/".parse().unwrap();
    let lifecycle_key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[81; 32]);
    let inception = arkret_signatures::webvh::prepare_realm_actor_inception(
        &arkret_signatures::webvh::RealmActorInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "revoke-sdk",
            version_time: Utc::now(),
            root_seed: &[82; 32],
            next_root_public_key_multibase: "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
            controller_public_key: &lifecycle_key.verifying_key().to_bytes(),
        },
    )
    .unwrap();
    let did = inception.did.clone();
    let principal =
        arkret_identifiers::project_did_to_core_id(&arkret_wire::Did::new(did.clone()).unwrap())
            .unwrap();
    let head =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&inception.log_entry).unwrap())
            .unwrap();
    let accepted_document: crate::handlers::arkret::DidDocument =
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap();
    let method = accepted_document.verification_method[0].id.clone();
    let mut input = coauth_storage_postgres::test_utils::verified_principal_binding_input(
        "did:web:example.com",
        required_audience_for(&state.url_builder, &state.arkret_config),
        principal.to_string(),
        head.clone(),
    );
    input.verified_did = arkret_wire::Did::new(did.clone()).unwrap();
    input.verified_version_id = inception.version_id.clone();
    input.binding_receipt.did_version_id = inception.version_id;
    input.binding_receipt.did = input.verified_did.clone();
    state.seed_accepted_principal_binding(&user, input).await;
    let mut resolution = crate::services::did_binding::test_resolution(
        &did,
        crate::services::did_resolver::DidResolutionSource::DelegatedResolver,
        Some(head),
        None,
        serde_json::json!({}),
    );
    resolution.document = accepted_document;
    let binding = crate::services::did_binding::binding_from_resolution(
        &resolution,
        crate::services::did_binding::trust_domain_id(&state.url_builder, &state.arkret_config)
            .unwrap(),
        arkret_identity::DidBindingPurpose::AccountBinding,
        crate::services::did_binding::policy_digest(&state.arkret_config).unwrap(),
        None,
        &crate::services::did_binding::high_risk_freshness(),
        Utc::now(),
    )
    .unwrap();
    let mut repo = state.repository().await.unwrap();
    crate::services::did_binding::shared_verified_did_binding_store()
        .persist(&mut repo, &binding, Utc::now())
        .await
        .unwrap();
    repo.save().await.unwrap();

    let (grant, key) = mint(&state, &user, principal.as_str(), DEVICE).await;
    let (target, _) = mint(&state, &user, principal.as_str(), DEVICE).await;
    let (foreign, _) = mint(&state, &other, "ak:did_core:web:other.example", DEVICE).await;
    let sdk = client(&base, &grant.grant_jwt, &key);
    let loss = LoseResponse {
        armed: Arc::new(AtomicBool::new(false)),
        hits: Arc::new(AtomicUsize::new(0)),
    };
    let router = salvo::Router::new()
        .hoop(loss.clone())
        .push(state.build_test_router());
    let server = tokio::spawn(salvo::Server::new(listener).serve(router));

    let mut request = empty();
    request.target_session_grant_id = Some(foreign.grant_id.clone());
    sign_request(&grant, &did, &method, &mut request, "foreign-selector");
    let before = footprint(&pool).await;
    refusal(
        sdk.session_grant_revoke(&grant.grant_id, &request)
            .await
            .unwrap_err(),
        404,
        "session_grant_not_found",
        None,
    );
    assert_eq!(footprint(&pool).await, before);
    assert!(active(&state, &foreign.grant_id).await);
    assert!(active(&state, &grant.grant_id).await);

    request.target_session_grant_id = Some(target.grant_id.clone());
    sign_request(&grant, &did, &method, &mut request, "wrong-signature");
    let before = footprint(&pool).await;
    refusal(
        sdk.session_grant_revoke(&grant.grant_id, &request)
            .await
            .unwrap_err(),
        401,
        "signature_invalid",
        Some("proof_invalid"),
    );
    assert_eq!(footprint(&pool).await, before);
    assert!(active(&state, &target.grant_id).await);

    sign_request(&grant, &did, &method, &mut request, "exact-target");
    let attempt = sdk
        .prepare_session_grant_revoke(&grant.grant_id, &request)
        .unwrap();
    let first = attempt.send().await.unwrap();
    assert_eq!(
        first.revoked_session_grant_ids,
        vec![target.grant_id.clone()]
    );
    let committed = footprint(&pool).await;
    assert_eq!(attempt.send().await.unwrap(), first);
    assert_eq!(footprint(&pool).await, committed);
    assert!(!active(&state, &target.grant_id).await);
    assert!(active(&state, &grant.grant_id).await);
    let mut conflict = request.clone();
    conflict.target_session_grant_id = Some(grant.grant_id.clone());
    let before = footprint(&pool).await;
    refusal(
        sdk.session_grant_revoke(&grant.grant_id, &conflict)
            .await
            .unwrap_err(),
        409,
        "duplicate_conflict",
        None,
    );
    assert!(active(&state, &grant.grant_id).await);

    assert_eq!(footprint(&pool).await, before);
    let current = sdk
        .prepare_session_grant_revoke(&grant.grant_id, &empty())
        .unwrap();
    loss.armed.store(true, Ordering::SeqCst);
    let result = current.send().await.unwrap();
    assert_eq!(loss.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        result.revoked_session_grant_ids,
        vec![grant.grant_id.clone()]
    );
    let committed = footprint(&pool).await;
    assert_eq!(current.send().await.unwrap(), result);
    assert_eq!(footprint(&pool).await, committed);
    assert!(!active(&state, &grant.grant_id).await);

    let (device_grant, device_key) = mint(&state, &user, principal.as_str(), DEVICE).await;
    let (device_peer, _) = mint(&state, &user, principal.as_str(), DEVICE).await;
    let (spared, _) = mint(
        &state,
        &user,
        principal.as_str(),
        "ak:device:01964137-0000-7000-8000-000000000002",
    )
    .await;
    let device_sdk = client(&base, &device_grant.grant_jwt, &device_key);
    let mut device_request = empty();
    device_request.target_device_id = Some(DeviceId::new(DEVICE).unwrap());
    sign_request(
        &device_grant,
        &did,
        &method,
        &mut device_request,
        "device-selector",
    );
    let result = device_sdk
        .session_grant_revoke(&device_grant.grant_id, &device_request)
        .await
        .unwrap();
    assert_eq!(result.revoked_count, 2);
    assert!(!active(&state, &device_peer.grant_id).await);
    assert!(active(&state, &spared.grant_id).await);

    let (all_grant, all_key) = mint(&state, &user, principal.as_str(), DEVICE).await;
    let all_sdk = client(&base, &all_grant.grant_jwt, &all_key);
    let mut all_request = empty();
    all_request.all_sessions = Some(true);
    sign_request(&all_grant, &did, &method, &mut all_request, "all-selector");
    let result = all_sdk
        .session_grant_revoke(&all_grant.grant_id, &all_request)
        .await
        .unwrap();
    assert_eq!(result.revoked_count, 2);
    assert!(!active(&state, &spared.grant_id).await);
    assert!(active(&state, &foreign.grant_id).await);

    let response = state.request(Request::post("/_coauth/internal/session-grants/introspect")
        .bearer(INTERNAL_AUTHORITY_SHARED_SECRET).json(serde_json::json!({"grant_jwt": target.grant_jwt, "audience_id": target.audience_id}))).await;
    response.assert_status(StatusCode::OK);
    let value: serde_json::Value = response.json();
    assert_eq!(value["active"], false);
    assert_eq!(value["status"], "revoked");
    server.abort();
    let _ = server.await;
}
