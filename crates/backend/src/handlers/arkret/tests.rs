use arkret_models_collaboration::session_grants::{
    AuthSessionTerminationResult, SESSION_GRANT_HOLDER_PROOF_CLAIMS_KIND,
    SessionGrantHolderProofClaims, SessionGrantValidationResult,
};
use arkret_models_identity::{
    SessionGrantAdminIntrospectionStatus, SessionGrantCredentialClass, SessionGrantHolderBinding,
    SignedSessionGrantClaims,
};
use chrono::{Duration, Utc};
use coauth_config::{ArkretConfig, DeploymentProfileConfig, PrincipalMethodConfig, StationConfig};
use coauth_data::{BrowserSession, Clock, RepositoryAccess, SessionGrant, SystemClock, User};
use coauth_iana::jose::{JsonWebKeyOperation, JsonWebKeyUse, JsonWebSignatureAlg};
use coauth_jose::jwk::{JsonWebKey, JsonWebKeyPublicParameters, PublicJsonWebKey};
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keyring::{JsonWebKeySet, Keyring, PrivateKey};
use hyper::{Request, StatusCode};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::test::{ResponseExt as SalvoResponseExt, TestClient};
use ulid::Ulid;

use super::*;
use crate::handlers::test_utils::{
    CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
};
use crate::salvo_utils::SessionInfoExt;

#[salvo::handler]
async fn human_approval_error_fixture() -> Result<(), ArkretRouteError> {
    Err(ArkretRouteError::HumanApprovalRequired(
        arkret_wire::AgentHumanApprovalProblem::new("approval-opaque-01").unwrap(),
    ))
}

#[salvo::handler]
async fn rate_limited_error_fixture() -> Result<(), ArkretRouteError> {
    Err(ArkretRouteError::rate_limited("slow down", 59_728))
}

#[test]
fn internal_error_details_are_development_only() {
    let error = std::io::Error::other("database exploded");
    let production = internal_error_envelope(&error, false);
    assert_eq!(production.detail, "internal server error");
    assert!(production.extensions.is_empty());

    let development = internal_error_envelope(&error, true);
    assert_eq!(
        development.detail,
        "internal server error: database exploded"
    );
    assert_eq!(
        development.extensions.get("cause"),
        Some(&serde_json::json!("database exploded"))
    );
}

#[tokio::test]
async fn arkret_errors_receive_a_server_generated_request_id() {
    let service = salvo::Service::new(
        Router::with_path("rate-limited-error")
            .hoop(crate::server::arkret_request_id_middleware)
            .get(rate_limited_error_fixture),
    );
    let mut response = TestClient::get("http://127.0.0.1:8698/rate-limited-error")
        .send(&service)
        .await;

    let response_request_id = response
        .headers()
        .get(crate::server::ARKRET_REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_owned();
    let body: serde_json::Value =
        serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
    assert!(response_request_id.starts_with("ak:request:"));
    assert_eq!(body["instance"], response_request_id);
}

#[tokio::test]
async fn rate_limited_endpoint_renders_canonical_retry_hints() {
    let service = salvo::Service::new(
        Router::with_path("rate-limited-error").get(rate_limited_error_fixture),
    );
    let mut response = TestClient::get("http://127.0.0.1:8698/rate-limited-error")
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::TOO_MANY_REQUESTS));
    assert_eq!(
        response
            .headers()
            .get(http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("60")
    );
    let body: serde_json::Value =
        serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
    assert_eq!(body["type"], "https://arkret.org/problems/rate_limited");
    assert_eq!(body["retry_after_ms"], 59_728);
}

#[tokio::test]
async fn human_approval_endpoint_renders_closed_claim_required_details() {
    let service = salvo::Service::new(
        Router::with_path("human-approval-error").get(human_approval_error_fixture),
    );
    let mut response = TestClient::get("http://127.0.0.1:8698/human-approval-error")
        .send(&service)
        .await;

    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    assert!(
        response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_none()
    );
    let body: serde_json::Value =
        serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
    assert_eq!(body["type"], "https://arkret.org/problems/claim_required");
    assert_eq!(body["detail"], "controller approval required");
    assert_eq!(body["reason_code"], "human_approval_required");
    assert_eq!(body["approval_request_id"], "approval-opaque-01");
    let serialized = body.to_string();
    for forbidden in ["captcha", "otp", "password", "redirect"] {
        assert!(!serialized.contains(forbidden));
    }
}

fn test_keyring() -> Keyring {
    let mut rng = ChaChaRng::seed_from_u64(42);
    let ed25519 = coauth_keyring::JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
        .with_kid(coauth_keyring::SESSION_GRANT_SIGNING_KEY_ID);
    Keyring::new(JsonWebKeySet::new(vec![ed25519]))
}

fn test_account_authority_keyring() -> Keyring {
    let mut rng = ChaChaRng::seed_from_u64(43);
    let account_authority = coauth_keyring::JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
        .with_kid(coauth_keyring::ACCOUNT_AUTHORITY_KEY_ID);
    Keyring::new(JsonWebKeySet::new(vec![account_authority]))
}

/// The `cnf_jkt` introspection reports.
///
/// `introspection.rs` derives it from the signed `session_public_key`
/// ("it is not duplicated as an independently authorable claim or database
/// column"), so a fixture cannot pin an arbitrary string here and a test that
/// did was asserting against a value the endpoint never had a way to return.
fn expected_cnf_jkt(session_public_key: &str) -> String {
    arkret_models_identity::CanonicalSessionPublicJwk::new(session_public_key)
        .expect("fixture session public key is a canonical JWK")
        .thumbprint_sha256()
        .expect("a canonical session public key has a thumbprint")
}

fn test_account_id(principal_id: &str, station_id: &str) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(principal_id).unwrap(),
        arkret_identifiers::DidCoreId::new(station_id).unwrap(),
    )
}

fn test_session_public_jwk(session_key: &PrivateKey, kid: impl Into<String>) -> PublicJsonWebKey {
    JsonWebKey::new(JsonWebKeyPublicParameters::from(session_key))
        .with_use(JsonWebKeyUse::Sig)
        .with_key_ops(vec![JsonWebKeyOperation::Verify])
        .with_kid(kid)
}

fn jwt_payload_value(jwt: &str) -> serde_json::Value {
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    let payload = jwt
        .split('.')
        .nth(1)
        .expect("compact JWT must contain a payload segment");
    let bytes = Base64UrlUnpadded::decode_vec(payload).expect("payload must be base64url");
    serde_json::from_slice(&bytes).expect("payload must be JSON")
}

fn assert_session_grant_jwt_omits_server_identity_metadata(raw_payload: &serde_json::Value) {
    for field in [
        "principal_id",
        "provenance_anchor",
        "provenanceAnchor",
        "browser_session_id",
        "device_id",
        "revocation_ref",
        "proof",
    ] {
        assert!(
            raw_payload.get(field).is_none(),
            "session grant JWT must not inline redundant `{field}`"
        );
    }
}

fn assert_principal_id_occurs_once(raw_payload: &serde_json::Value, principal_id: &str) {
    assert_eq!(
        raw_payload["account_id"]["principal_id"].as_str(),
        Some(principal_id)
    );
    let serialized = serde_json::to_string(raw_payload).expect("payload JSON must serialize");
    assert_eq!(
        serialized.matches(principal_id).count(),
        1,
        "session grant JWT must carry the principal id exactly once"
    );
}

#[test]
fn debug_dpop_grant_outcome_carries_typed_local_account_id() {
    let local_account_id = coauth_data::LocalAccountId::new("test-account").unwrap();
    let outcome = DebugIssueDpopGrantOutcome {
        grant_id: "ak:session_grant:test".to_owned(),
        grant_jwt: "header.payload.signature".to_owned(),
        dpop_jkt: "test-jkt".to_owned(),
        local_account_id: local_account_id.clone(),
        account_id: test_account_id(
            "ak:did_core:web:test-principal",
            "ak:did_core:web:test-audience",
        ),
        audience_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:test-audience").unwrap(),
        scopes: vec!["ak.self.account.read.describe.v1".to_owned()],
        expires_at: "2026-08-29T12:00:00.000Z".to_owned(),
        principal_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:test-principal").unwrap(),
    };

    let encoded = serde_json::to_value(&outcome).unwrap();
    assert_eq!(encoded["local_account_id"], local_account_id.as_str());
    assert_eq!(
        encoded["account_id"]["principal_id"],
        "ak:did_core:web:test-principal"
    );
    assert_eq!(
        encoded["account_id"]["station_id"],
        "ak:did_core:web:test-audience"
    );
    let decoded: DebugIssueDpopGrantOutcome = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded.local_account_id, local_account_id);

    let mut invalid = encoded;
    invalid["local_account_id"] = serde_json::Value::String(String::new());
    assert!(serde_json::from_value::<DebugIssueDpopGrantOutcome>(invalid).is_err());
}

/// Shared per-edge secret the configured Station presents as a Bearer token on
/// registered internal-authority operations.
const INTERNAL_AUTHORITY_SHARED_SECRET: &str = "principal-example-introspection";

fn personal_node_did_web_config() -> ArkretConfig {
    let config = ArkretConfig {
        // Personal-node no-history profile legitimately advertises a did:web
        // service DID (spec identity-did.md §3.1 personal_node exception).
        runtime_owning_station_identity: coauth_config::RuntimeOwningStationIdentity::fixture(
            "did:web:auth.example.com",
        ),
        // Session-grant audiences are Station core DIDs.
        admin_audience: Some("ak:did_core:web:principal.example.com".to_owned()),
        trust_domain: Some("ak:trust_domain:auth.example.com".to_owned()),
        // Introspection is a server-to-server surface: the caller must be the
        // Station that owns the grant's audience.
        stations: vec![StationConfig {
            name: "principal-example".to_owned(),
            endpoint: "https://principal.example.com/".parse().unwrap(),
            internal_authority_shared_secret: Some(
                INTERNAL_AUTHORITY_SHARED_SECRET.to_owned().into(),
            ),
            embedded_webvh_registration_bearer: None,
            trust_domain: Some("ak:trust_domain:principal.example.com".to_owned()),
        }],
        deployment_profile: DeploymentProfileConfig::PersonalNode,
        principal_method: PrincipalMethodConfig::DidWeb,
        ..ArkretConfig::default()
    };
    crate::services::station_trust::shared().insert_for_test(
        &config.stations[0].endpoint,
        "ak:did_core:web:principal.example.com",
    );
    config
}

/// Test config with a delegated owning-Station runtime identity.
fn test_arkret_config() -> ArkretConfig {
    ArkretConfig {
        runtime_owning_station_identity: coauth_config::RuntimeOwningStationIdentity::fixture(
            "did:webvh:ztest:auth.example.com:webvh:service",
        ),
        ..ArkretConfig::default()
    }
}

#[test]
fn service_and_user_identifiers_follow_arkret_shape() {
    let url_builder = UrlBuilder::new(
        "https://auth.example.com/coauth/".parse().unwrap(),
        None,
        None,
    );
    let mut rng = ChaChaRng::seed_from_u64(7);
    let now = Utc::now();
    let user = User::samples(now, &mut rng).into_iter().next().unwrap();

    // There is no host-derived `did:web` fallback: the owning Station DID is
    // the identity delegated only after verified durable binding.
    let arkret_config = ArkretConfig {
        runtime_owning_station_identity: coauth_config::RuntimeOwningStationIdentity::fixture(
            "did:webvh:ztest:auth.example.com:webvh:service",
        ),
        ..ArkretConfig::default()
    };
    assert_eq!(
        owning_station_id_for(&arkret_config).as_str(),
        "ak:did_core:webvh:ztest"
    );
    assert_eq!(oidc_subject_for_user(&arkret_config, &user), user.sub);
    // Spec 7157ee8 §3.1 — canonical handle form is
    // `<localpart>:<domain>` (was `<localpart>@<domain>` pre-R3.1).
    assert_eq!(
        user_handle(&url_builder, &user),
        format!("{}:auth.example.com", user.localpart.to_lowercase())
    );
    // Display form is still available via `user_handle_display`.
    assert_eq!(
        user_handle_display(&url_builder, &user),
        format!("{}@auth.example.com", user.localpart)
    );
}

fn config_with_internal_authority_shared_secret(bearer: &str) -> ArkretConfig {
    let config = ArkretConfig {
        runtime_owning_station_identity: coauth_config::RuntimeOwningStationIdentity::fixture(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:local.host:webvh:coauth",
        ),
        trust_domain: Some("ak:trust_domain:auth.example".to_owned()),
        stations: vec![StationConfig {
            name: "soland-dev".to_owned(),
            endpoint: "https://session-grant-static.test/".parse().unwrap(),
            internal_authority_shared_secret: Some(bearer.to_owned().into()),
            embedded_webvh_registration_bearer: None,
            trust_domain: Some("ak:trust_domain:station.example".to_owned()),
        }],
        ..ArkretConfig::default()
    };
    crate::services::station_trust::shared().insert_for_test(
        &config.stations[0].endpoint,
        "ak:did_core:web:session-grant-static.test",
    );
    config
}

#[test]
fn station_internal_authority_shared_secret_matches_exact_token() {
    let config = config_with_internal_authority_shared_secret("local-coauth-session-grant");
    assert!(station_internal_authority_shared_secret_matches(
        &config,
        "local-coauth-session-grant"
    ));
}

#[test]
fn shared_static_bearer_is_rejected_as_ambiguous() {
    let mut config = config_with_internal_authority_shared_secret("shared-cluster-token");
    config.stations.push(StationConfig {
        name: "soland-beta".to_owned(),
        endpoint: "https://session-grant-static-beta.test/".parse().unwrap(),
        internal_authority_shared_secret: Some("shared-cluster-token".to_owned().into()),
        embedded_webvh_registration_bearer: None,
        trust_domain: Some("ak:trust_domain:station-beta.example".to_owned()),
    });
    crate::services::station_trust::shared().insert_for_test(
        &config.stations[1].endpoint,
        "ak:did_core:web:session-grant-static-beta.test",
    );
    assert!(station_internal_channel_caller(&config, "shared-cluster-token").is_none());
}

#[test]
fn station_internal_authority_shared_secret_rejects_other_tokens() {
    let config = config_with_internal_authority_shared_secret("local-coauth-session-grant");
    assert!(!station_internal_authority_shared_secret_matches(
        &config,
        "other-token"
    ));
    assert!(!station_internal_authority_shared_secret_matches(
        &config, ""
    ));
    assert!(!station_internal_authority_shared_secret_matches(
        &config, "   "
    ));
}

#[test]
fn station_internal_authority_shared_secret_ignores_unset_field() {
    let mut config = config_with_internal_authority_shared_secret("placeholder");
    config.stations[0].internal_authority_shared_secret = None;
    assert!(!station_internal_authority_shared_secret_matches(
        &config,
        "placeholder"
    ));
}

#[test]
fn internal_authority_peer_requires_verified_identity_and_domains() {
    let mut config = config_with_internal_authority_shared_secret("channel-key");
    assert_eq!(
        station_internal_channel_caller(&config, "channel-key"),
        Some("ak:did_core:web:session-grant-static.test".to_owned())
    );

    config.stations[0].trust_domain = None;
    assert!(station_internal_channel_caller(&config, "channel-key").is_none());

    let mut config = config_with_internal_authority_shared_secret("channel-key");
    config.trust_domain = None;
    assert!(station_internal_channel_caller(&config, "channel-key").is_none());

    let mut config = config_with_internal_authority_shared_secret("channel-key");
    config.stations[0].endpoint = "https://unverified-station.test/".parse().unwrap();
    assert!(station_internal_channel_caller(&config, "channel-key").is_none());
}

#[test]
fn session_grant_is_signed_for_the_bound_principal_id() {
    let clock = SystemClock::default();
    let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
    let arkret_config = personal_node_did_web_config();
    let keyring = test_keyring();
    let now = clock.now();
    let mut fixture_rng = ChaChaRng::seed_from_u64(9);
    let browser_session = BrowserSession::samples(now, &mut fixture_rng)
        .into_iter()
        .next()
        .unwrap();
    let mut signing_rng = ChaChaRng::seed_from_u64(11);
    let session_key = PrivateKey::generate_ed25519(&mut signing_rng);
    let session_public_key = test_session_public_jwk(&session_key, "test-session-key");
    let principal_id = format!(
        "ak:did_core:web:auth.example.com:users:{}",
        browser_session.user.id
    );
    let account_id = test_account_id(
        &principal_id,
        &required_audience_for(&url_builder, &arkret_config),
    );

    let device_scope = "urn:arkret:client:device:ak:device:01964137-0000-7000-8000-000000000001";
    let grant = issue_session_grant(
        &mut signing_rng,
        &clock,
        &url_builder,
        &arkret_config,
        &keyring,
        &browser_session,
        session_public_key,
        &principal_id,
        &account_id,
        arkret_identifiers::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001")
            .unwrap(),
        vec![
            STATION_SESSION_BIND_SCOPE.to_owned(),
            device_scope.to_owned(),
        ],
    )
    .unwrap();

    let jwt = Jwt::<SignedSessionGrantClaims>::try_from(grant.grant_jwt.as_str()).unwrap();
    jwt.verify_with_jwks(&keyring.public_jwks()).unwrap();

    let payload = jwt.payload();
    assert_eq!(payload.kind, "ak.session.grant");
    assert_eq!(payload.grant_id, grant.grant_id);
    assert_eq!(payload.account_id.principal_id.as_str(), principal_id);
    assert_eq!(
        payload.audience_id.as_str(),
        required_audience_for(&url_builder, &arkret_config)
    );
    assert_eq!(
        payload.scopes,
        vec![device_scope, STATION_SESSION_BIND_SCOPE]
    );
    assert_eq!(payload.session_id, browser_session.id.to_string());
    assert_eq!(
        grant.device_id.as_deref(),
        Some("ak:device:01964137-0000-7000-8000-000000000001")
    );
    assert_eq!(
        payload.expires_at - payload.not_before,
        Duration::try_hours(8).unwrap()
    );
    let raw_payload = jwt_payload_value(&grant.grant_jwt);
    assert_session_grant_jwt_omits_server_identity_metadata(&raw_payload);
    assert_principal_id_occurs_once(&raw_payload, payload.account_id.principal_id.as_str());
    assert!(raw_payload.get("session_public_key").is_some());
    assert!(raw_payload.get("cnf").is_none());
    assert!(
        grant
            .session_public_key
            .contains("\"kid\":\"test-session-key\"")
    );
}

#[test]
fn recovery_session_grant_is_candidate_bound_short_lived_and_scope_closed() {
    let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
    let arkret_config = personal_node_did_web_config();
    let keyring = test_keyring();
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let seed = SessionGrantIssuanceSeed::new(
        arkret_canonical::base64url_encode([0x33; 32]),
        "recovery-session-chain-1",
        now,
        now + Duration::minutes(15),
        coauth_keyring::SESSION_GRANT_SIGNING_KEY_ID,
    )
    .unwrap();
    let mut signing_rng = ChaChaRng::seed_from_u64(77);
    let holder_key = PrivateKey::generate_ed25519(&mut signing_rng);
    let holder_jwk = test_session_public_jwk(&holder_key, "recovery-holder-key");
    let audience = required_audience_for(&url_builder, &arkret_config);
    let principal_id = "ak:did_core:web:alice.example";
    let principal_core_id = arkret_identifiers::DidCoreId::new(principal_id).unwrap();
    let authority = test_account_id(principal_id, &audience);
    let device_id =
        arkret_identifiers::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000077")
            .unwrap();

    let material = issue_recovery_session_grant_for_audience(
        &seed,
        &arkret_config,
        &keyring,
        holder_jwk,
        arkret_identifiers::DidCoreId::new(audience).unwrap(),
        device_id.clone(),
        arkret_models_identity::RECOVERY_SESSION_GRANT_OPERATIONS
            .map(str::to_owned)
            .to_vec(),
        &principal_core_id,
        coauth_data::LocalAccountId::new("test-account").unwrap(),
        &authority,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
    )
    .unwrap();

    let jwt = Jwt::<SignedSessionGrantClaims>::try_from(material.grant_jwt.as_str()).unwrap();
    jwt.verify_with_jwks(&keyring.public_jwks()).unwrap();
    let payload = jwt.payload();
    assert_eq!(
        payload.credential_class,
        SessionGrantCredentialClass::RecoverySession
    );
    assert_eq!(
        payload.holder_binding,
        SessionGrantHolderBinding::RecoveryCandidateDevice { device_id }
    );
    assert!(payload.device_binding.is_none());
    assert!(payload.scope_details.is_none());
    assert_eq!(
        payload.expires_at - payload.not_before,
        Duration::minutes(15)
    );
    assert_eq!(
        payload.scopes,
        arkret_models_identity::RECOVERY_SESSION_GRANT_OPERATIONS.map(str::to_owned)
    );

    let overlong_seed = SessionGrantIssuanceSeed::new(
        arkret_canonical::base64url_encode([0x44; 32]),
        "recovery-session-chain-2",
        now,
        now + Duration::minutes(15) + Duration::milliseconds(1),
        coauth_keyring::SESSION_GRANT_SIGNING_KEY_ID,
    )
    .unwrap();
    assert!(
        issue_recovery_session_grant_for_audience(
            &overlong_seed,
            &arkret_config,
            &keyring,
            test_session_public_jwk(&holder_key, "recovery-holder-key"),
            arkret_identifiers::DidCoreId::new(
                required_audience_for(&url_builder, &arkret_config,)
            )
            .unwrap(),
            arkret_identifiers::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000077",)
                .unwrap(),
            arkret_models_identity::RECOVERY_SESSION_GRANT_OPERATIONS
                .map(str::to_owned)
                .to_vec(),
            &principal_core_id,
            coauth_data::LocalAccountId::new("test-account").unwrap(),
            &authority,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        )
        .is_err()
    );
}

#[test]
fn session_grant_uses_configured_ttl() {
    let clock = SystemClock::default();
    let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
    let arkret_config = ArkretConfig {
        // Personal-node no-history profile legitimately advertises a did:web
        // service DID (spec identity-did.md §3.1 personal_node exception).
        runtime_owning_station_identity: coauth_config::RuntimeOwningStationIdentity::fixture(
            "did:web:auth.example.com",
        ),
        deployment_profile: DeploymentProfileConfig::PersonalNode,
        principal_method: PrincipalMethodConfig::DidWeb,
        admin_audience: Some("ak:did_core:web:principal.example.com".to_owned()),
        session_grant_ttl: Duration::try_minutes(15).unwrap(),
        ..ArkretConfig::default()
    };
    let keyring = test_keyring();
    let now = clock.now();
    let mut fixture_rng = ChaChaRng::seed_from_u64(9);
    let browser_session = BrowserSession::samples(now, &mut fixture_rng)
        .into_iter()
        .next()
        .unwrap();
    let mut signing_rng = ChaChaRng::seed_from_u64(11);
    let session_key = PrivateKey::generate_ed25519(&mut signing_rng);
    let session_public_key = test_session_public_jwk(&session_key, "ttl-session-key");
    let principal_id = format!(
        "ak:did_core:web:auth.example.com:users:{}",
        browser_session.user.id
    );
    let account_id = test_account_id(
        &principal_id,
        &required_audience_for(&url_builder, &arkret_config),
    );

    let grant = issue_session_grant(
        &mut signing_rng,
        &clock,
        &url_builder,
        &arkret_config,
        &keyring,
        &browser_session,
        session_public_key,
        &principal_id,
        &account_id,
        arkret_identifiers::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001")
            .unwrap(),
        vec![
            STATION_SESSION_BIND_SCOPE.to_owned(),
            "urn:arkret:client:device:ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
        ],
    )
    .unwrap();

    let jwt = Jwt::<SignedSessionGrantClaims>::try_from(grant.grant_jwt.as_str()).unwrap();
    let payload = jwt.payload();
    assert_eq!(
        payload.expires_at - payload.not_before,
        Duration::try_minutes(15).unwrap()
    );
    assert_eq!(grant.expires_at_timestamp, payload.expires_at);
}

#[test]
fn session_grant_record_exposes_metadata_without_secrets() {
    let now = Utc::now();
    let grant = SessionGrant {
        id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCM").unwrap(),
        grant_id: arkret_identifiers::SessionGrantId::new(
            "ak:session_grant:AbmggbDOpDR8J1xRW3EU4354odEGafHu4vk9FVv4vimH".to_owned(),
        )
        .unwrap(),
        browser_session_id: Some(Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCN").unwrap()),
        issuer_id: arkret_identifiers::DidCoreId::new(
            "ak:did_core:web:auth.example.com".to_owned(),
        )
        .unwrap(),
        subject_id: arkret_identifiers::DidCoreId::new(
            "ak:did_core:web:auth.example.com:users:01J44Q10GR4AMTFZEEF936DTCP",
        )
        .unwrap(),
        local_account_id: coauth_data::LocalAccountId::new("test-account").unwrap(),
        device_id: Some("device-1".to_owned()),
        audience_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:soland.example.com")
            .unwrap(),
        scope: Scope::from_iter([STATION_SESSION_BIND_SCOPE.parse().unwrap()]),
        grant_jwt: "header.payload.signature".to_owned(),
        session_id: "test-session".to_owned(),
        issuance_nonce: arkret_canonical::base64url_encode([0x11; 32]),
        issuance_preimage: Vec::new(),
        issuance_digest: [0_u8; 32],
        signing_key_id: coauth_keyring::SESSION_GRANT_SIGNING_KEY_ID.to_owned(),
        session_public_key: "{\"kty\":\"OKP\"}".to_owned(),
        credential_class: "standard".to_owned(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        lifecycle_state: coauth_data::SessionGrantLifecycleState::Active,
        revoked_at: None,
        superseded_at: None,
        successor_grant_id: None,
        issuance_operation_id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCQ").unwrap(),
    };

    let body = serde_json::to_value(SessionGrantRecord::from(grant)).unwrap();

    assert_eq!(body["audience_id"], "ak:did_core:web:soland.example.com");
    assert_eq!(
        body["scopes"],
        serde_json::json!([STATION_SESSION_BIND_SCOPE])
    );
    assert!(body.get("grant_jwt").is_none());
    assert!(body.get("session_public_key").is_none());
    assert!(body.get("session_private_key_pem").is_none());
}

#[test]
fn session_grant_introspection_statuses_are_minimal_and_standardized() {
    let now = Utc::now();
    let mut rng = ChaChaRng::seed_from_u64(14);
    let mut user = User::samples(now, &mut rng).into_iter().next().unwrap();
    let mut grant = SessionGrant {
        id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCM").unwrap(),
        grant_id: arkret_identifiers::SessionGrantId::new(
            "ak:session_grant:AYBAST92B1EGBqtdtlrlJuiZM2Ck4_22_a2eeLbVSQku".to_owned(),
        )
        .unwrap(),
        browser_session_id: Some(Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCN").unwrap()),
        issuer_id: arkret_identifiers::DidCoreId::new(
            "ak:did_core:web:auth.example.com".to_owned(),
        )
        .unwrap(),
        subject_id: arkret_identifiers::DidCoreId::new(format!(
            "ak:did_core:web:auth.example.com:users:{}",
            user.id
        ))
        .unwrap(),
        local_account_id: coauth_data::LocalAccountId::new(user.id.to_string()).unwrap(),
        device_id: Some("device-1".to_owned()),
        audience_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:soland.example.com")
            .unwrap(),
        scope: Scope::from_iter([STATION_SESSION_BIND_SCOPE.parse().unwrap()]),
        grant_jwt: "header.payload.signature".to_owned(),
        session_id: "test-session".to_owned(),
        issuance_nonce: arkret_canonical::base64url_encode([0x22; 32]),
        issuance_preimage: Vec::new(),
        issuance_digest: [0_u8; 32],
        signing_key_id: coauth_keyring::SESSION_GRANT_SIGNING_KEY_ID.to_owned(),
        session_public_key: "{\"kty\":\"OKP\"}".to_owned(),
        credential_class: "standard".to_owned(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        lifecycle_state: coauth_data::SessionGrantLifecycleState::Active,
        revoked_at: None,
        superseded_at: None,
        successor_grant_id: None,
        issuance_operation_id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCR").unwrap(),
    };

    assert_eq!(
        introspection_status(
            &grant,
            Some(&user),
            now,
            Some("ak:did_core:web:soland.example.com")
        ),
        SessionGrantAdminIntrospectionStatus::Active
    );
    assert_eq!(
        introspection_status(
            &grant,
            Some(&user),
            now,
            Some("ak:did_core:web:other.example.com")
        ),
        SessionGrantAdminIntrospectionStatus::AudienceMismatch
    );

    user.locked_at = Some(now);
    assert_eq!(
        introspection_status(&grant, Some(&user), now, None),
        SessionGrantAdminIntrospectionStatus::Locked
    );

    user.locked_at = None;
    user.deactivated_at = Some(now);
    assert_eq!(
        introspection_status(&grant, Some(&user), now, None),
        SessionGrantAdminIntrospectionStatus::Suspended
    );

    grant.revoked_at = Some(now);
    grant.lifecycle_state = coauth_data::SessionGrantLifecycleState::Revoked;
    assert_eq!(
        introspection_status(&grant, Some(&user), now, None),
        SessionGrantAdminIntrospectionStatus::Revoked
    );
}

async fn seed_persisted_session_grant(
    state: &mut TestState,
) -> (
    BrowserSession,
    SessionGrant,
    SessionGrantMaterial,
    PrivateKey,
) {
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let user = repo
        .user()
        .add(&mut rng, &*state.clock, "alice".to_owned())
        .await
        .unwrap();
    let browser_session = repo
        .browser_session()
        .add(
            &mut rng,
            &*state.clock,
            &user,
            Some("Mozilla/5.0".to_owned()),
        )
        .await
        .unwrap();
    let session_key = PrivateKey::generate_ed25519(&mut rng);
    let grant_config = personal_node_did_web_config();
    // The HTTP layer authorizes introspection against `state.arkret_config`,
    // so it has to carry the same Station the grant is issued for.
    state.arkret_config = grant_config.clone();
    // Grant liveness is evaluated against the wall clock the handlers read; a
    // grant minted at the mock epoch is already expired.
    let grant_clock = coauth_data::SystemClock::default();
    let principal_id = format!("ak:did_core:web:auth.example.com:users:{}", user.id);
    let account_id = test_account_id(
        &principal_id,
        &required_audience_for(&state.url_builder, &grant_config),
    );
    let material = issue_session_grant(
        &mut rng,
        &grant_clock,
        &state.url_builder,
        &grant_config,
        &state.keyring,
        &browser_session,
        test_session_public_jwk(&session_key, format!("session-{}", browser_session.id)),
        &principal_id,
        &account_id,
        arkret_identifiers::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001")
            .unwrap(),
        vec![STATION_SESSION_BIND_SCOPE.to_owned()],
    )
    .unwrap();
    let raw_payload = jwt_payload_value(&material.grant_jwt);
    assert_session_grant_jwt_omits_server_identity_metadata(&raw_payload);
    assert!(raw_payload.get("session_public_key").is_some());
    // The grant JWT carries its DPoP holder binding as the canonical public
    // key; refresh and introspection derive the thumbprint from that one source.
    // (spec zh/sync/service-http-binding.md, session-grants surface).
    assert!(raw_payload.get("cnf").is_none());
    let grant = persist_session_grant(
        &mut repo,
        &mut rng,
        &grant_clock,
        &browser_session,
        &material,
    )
    .await
    .unwrap();
    repo.save().await.unwrap();

    (browser_session, grant, material, session_key)
}

#[tokio::test]
async fn auth_session_logout_revokes_exact_grant_finishes_browser_session_and_replays() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let (browser_session, grant, material, _session_key) =
        seed_persisted_session_grant(&mut state).await;
    let logout_body = serde_json::json!({
        "grant_jwt": material.grant_jwt,
        "reason_code": "account_logout",
    });

    let response = state
        .request(
            Request::post("/_coauth/internal/auth-sessions/logout")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(&logout_body),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let outcome: AuthSessionTerminationResult = response.json();
    assert!(outcome.grant_chain_terminated);
    assert!(outcome.auth_session_logged_out);

    let (first_revoked_at, first_finished_at) = {
        let mut repo = state.repository().await.unwrap();
        let stored_grant = repo
            .oauth_session_grant()
            .lookup_by_grant_jwt(&material.grant_jwt)
            .await
            .unwrap()
            .expect("logout keeps the exact grant ledger row");
        let stored_session = repo
            .browser_session()
            .lookup(browser_session.id)
            .await
            .unwrap()
            .expect("logout keeps the finished browser session row");
        repo.cancel().await.unwrap();
        assert_eq!(
            stored_grant.lifecycle_state,
            coauth_data::SessionGrantLifecycleState::Revoked
        );
        assert!(stored_grant.revoked_at.is_some());
        assert!(stored_session.finished_at.is_some());
        (stored_grant.revoked_at, stored_session.finished_at)
    };

    // The same exact-token authority surface immediately observes the terminal
    // state written by logout; there is no second local session truth.
    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "grant_jwt": material.grant_jwt,
                    "audience_id": grant.audience_id,
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let introspection: serde_json::Value = response.json();
    assert_eq!(introspection["active"], false);
    assert_eq!(introspection["status"], "revoked");

    // A retry after a lost response is terminal success and must not rewrite
    // either revocation timestamp.
    let response = state
        .request(
            Request::post("/_coauth/internal/auth-sessions/logout")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(&logout_body),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let replay: AuthSessionTerminationResult = response.json();
    assert!(replay.grant_chain_terminated);
    assert!(replay.auth_session_logged_out);

    let mut repo = state.repository().await.unwrap();
    let replayed_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&material.grant_jwt)
        .await
        .unwrap()
        .unwrap();
    let replayed_session = repo
        .browser_session()
        .lookup(browser_session.id)
        .await
        .unwrap()
        .unwrap();
    repo.cancel().await.unwrap();
    assert_eq!(replayed_grant.revoked_at, first_revoked_at);
    assert_eq!(replayed_session.finished_at, first_finished_at);
}

#[tokio::test]
async fn auth_session_logout_rejects_unbound_bearers_without_state_change() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let (browser_session, _grant, material, _session_key) =
        seed_persisted_session_grant(&mut state).await;
    state.arkret_config.stations.push(StationConfig {
        name: "other-station".to_owned(),
        endpoint: "https://other-station.example/".parse().unwrap(),
        internal_authority_shared_secret: Some("other-station-channel".to_owned().into()),
        embedded_webvh_registration_bearer: None,
        trust_domain: Some("ak:trust_domain:other-station.example".to_owned()),
    });
    crate::services::station_trust::shared().insert_for_test(
        &state.arkret_config.stations.last().unwrap().endpoint,
        "ak:did_core:web:other-station.example",
    );
    let logout_body = serde_json::json!({
        "grant_jwt": material.grant_jwt,
        "reason_code": "account_logout",
    });

    let missing = state
        .request(Request::post("/_coauth/internal/auth-sessions/logout").json(&logout_body))
        .await;
    missing.assert_status(StatusCode::UNAUTHORIZED);

    let wrong = state
        .request(
            Request::post("/_coauth/internal/auth-sessions/logout")
                .bearer("wrong-channel")
                .json(&logout_body),
        )
        .await;
    wrong.assert_status(StatusCode::UNAUTHORIZED);

    let other_station = state
        .request(
            Request::post("/_coauth/internal/auth-sessions/logout")
                .bearer("other-station-channel")
                .json(&logout_body),
        )
        .await;
    other_station.assert_status(StatusCode::FORBIDDEN);

    let mut repo = state.repository().await.unwrap();
    let stored_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&material.grant_jwt)
        .await
        .unwrap()
        .unwrap();
    let stored_session = repo
        .browser_session()
        .lookup(browser_session.id)
        .await
        .unwrap()
        .unwrap();
    repo.cancel().await.unwrap();
    assert_eq!(
        stored_grant.lifecycle_state,
        coauth_data::SessionGrantLifecycleState::Active
    );
    assert!(stored_grant.revoked_at.is_none());
    assert!(stored_session.finished_at.is_none());
}

fn session_grant_introspection_proof(
    grant: &SessionGrant,
    material: &SessionGrantMaterial,
    session_key: &PrivateKey,
    challenge: &str,
) -> String {
    let now = Utc::now();
    let signer = session_key
        .signing_key_for_alg(&JsonWebSignatureAlg::Ed25519)
        .unwrap();
    let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Ed25519);
    let claims = SessionGrantHolderProofClaims {
        kind: SESSION_GRANT_HOLDER_PROOF_CLAIMS_KIND.to_owned(),
        session_grant_id: grant.grant_id.to_string(),
        grant_jwt_digest: session_grant_jwt_digest(&material.grant_jwt),
        audience_id: grant.audience_id.clone(),
        challenge: challenge.to_owned(),
        issued_at: now,
        expires_at: now + Duration::try_minutes(1).unwrap(),
    };
    Jwt::sign(header, claims, &signer).unwrap().into_string()
}

#[tokio::test]
async fn session_grant_http_list_and_filter_work() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let (browser_session, grant, _material, _session_key) =
        seed_persisted_session_grant(&mut state).await;
    let station_token = state.token_with_scope(STATION_SESSION_BIND_SCOPE).await;

    // The deployment-internal shared secret does not authorize the product
    // listing route; a live Station-scoped token does.
    let internal_secret = state
        .request(
            Request::get("/_coauth/account/session-grants")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .empty(),
        )
        .await;
    internal_secret.assert_status(StatusCode::UNAUTHORIZED);

    // Session-grant listing is pinned to the calling Station's own audience.
    let response = state
        .request(
            Request::get("/_coauth/account/session-grants")
                .bearer(&station_token)
                .empty(),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["grants"].as_array().unwrap().len(), 1);
    assert_eq!(body["grants"][0]["id"], grant.id.to_string());
    assert_eq!(
        body["grants"][0]["browser_session_id"],
        browser_session.id.to_string()
    );
    assert_eq!(
        body["grants"][0]["scopes"],
        serde_json::json!([STATION_SESSION_BIND_SCOPE])
    );

    let response = state
        .request(
            Request::get(format!(
                "/_coauth/account/session-grants?browser_session_id={}&active_only=true",
                browser_session.id
            ))
            .bearer(&station_token)
            .empty(),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["grants"].as_array().unwrap().len(), 1);

    let response = state
        .request(
            Request::get("/_coauth/account/session-grants?browser_session_id=not-a-ulid")
                .bearer(&station_token)
                .empty(),
        )
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: arkret_wire::problem_details::Problem = response.json();
    assert_eq!(body.code(), "json_invalid");
    assert_eq!(body.detail, "invalid browser_session_id");
}

#[tokio::test]
async fn session_grant_http_introspection_returns_minimal_metadata() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let (_browser_session, grant, material, session_key) =
        seed_persisted_session_grant(&mut state).await;

    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "grant_jwt": material.grant_jwt,
                    "audience_id": grant.audience_id,
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["status"], "active");
    assert_eq!(body["proof_required"], true);
    // Introspection is READ-ONLY: it MUST NOT consume the grant (consumption /
    // single-use rotation is the refresh endpoint's job). So one_time_use is
    // never reported as already-consumed here, and a follow-up introspect of
    // the same grant still sees it active.
    assert_eq!(body["one_time_use_consumed"], false);
    assert_eq!(body["grant"]["id"], grant.grant_id.to_string());
    // `service-operation-dtos.schema.json#/$defs/SessionGrantValidationMetadata`
    // carries the complete `account_id`; it has no bare `subject_id` member.
    assert_eq!(
        body["grant"]["account_id"]["principal_id"],
        grant.subject_id.as_str()
    );
    assert_eq!(body["grant"]["audience_id"], grant.audience_id.as_str());
    assert_eq!(body["grant"]["revoked_at"], serde_json::Value::Null);
    assert!(body["grant"].get("grant_jwt").is_none());
    // Server-to-server introspection MUST expose session_public_key so the
    // Station can verify RFC 9421 PoP presentations (SPEC-CR-001).
    assert_eq!(
        body["grant"]["session_public_key"],
        grant.session_public_key
    );
    assert_eq!(
        body["grant"]["cnf_jkt"],
        expected_cnf_jkt(&grant.session_public_key)
    );

    // A second introspection of the same grant: still active (read-only — the
    // first call did not revoke it).
    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "id": grant.grant_id.to_string(),
                    "audience_id": grant.audience_id,
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["status"], "active");
    assert_eq!(body["proof_required"], true);
    assert_eq!(body["grant"]["revoked_at"], serde_json::Value::Null);

    let challenge = format!("introspect-{}", grant.grant_id);
    let proof_jwt = session_grant_introspection_proof(&grant, &material, &session_key, &challenge);
    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "id": grant.grant_id.to_string(),
                    "audience_id": grant.audience_id,
                    "proof": {
                        "challenge": challenge,
                        "proof_jwt": proof_jwt,
                    }
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["status"], "active");
    assert_eq!(body["proof_required"], false);

    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "id": grant.grant_id.to_string(),
                    "audience_id": "ak:did_core:web:other.example.com",
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], false);
    assert_eq!(body["status"], "audience_mismatch");
    assert_eq!(body["grant"], serde_json::Value::Null);
}

/// ② contract D4: a DPoP-bound grant MUST surface its `cnf.jkt` to the
/// Station through introspection so it can verify the per-request DPoP
/// proof. The thumbprint is not a stored column — it is read back out of the
/// signed grant JWT — so this exercises the full persist → introspect round-trip.
#[tokio::test]
async fn session_grant_http_introspection_exposes_cnf_jkt_for_dpop_bound_grant() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();

    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let user = repo
        .user()
        .add(&mut rng, &*state.clock, "alice".to_owned())
        .await
        .unwrap();
    let browser_session = repo
        .browser_session()
        .add(
            &mut rng,
            &*state.clock,
            &user,
            Some("Mozilla/5.0".to_owned()),
        )
        .await
        .unwrap();
    let session_key = PrivateKey::generate_ed25519(&mut rng);
    let bound_jkt = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_owned();
    let grant_config = personal_node_did_web_config();
    // The HTTP layer authorizes introspection against `state.arkret_config`.
    state.arkret_config = grant_config.clone();
    // Grant liveness is evaluated against the wall clock the handlers read.
    let grant_clock = coauth_data::SystemClock::default();
    let issued_at = coauth_data::Clock::now(&grant_clock);
    let issuance_seed = SessionGrantIssuanceSeed::new(
        arkret_models_identity::SessionGrantIssuanceNonce::from_bytes([0x31; 32]).to_string(),
        browser_session.id.to_string(),
        issued_at,
        issued_at + grant_config.session_grant_ttl,
        coauth_keyring::SESSION_GRANT_SIGNING_KEY_ID,
    )
    .unwrap();
    let principal_id = arkret_identifiers::DidCoreId::new(format!(
        "ak:did_core:web:auth.example.com:users:{}",
        user.id
    ))
    .unwrap();
    let audience = required_audience_for(&state.url_builder, &grant_config);
    let account_id = test_account_id(principal_id.as_str(), &audience);
    let material = issue_session_grant_for_audience(
        &issuance_seed,
        &grant_clock,
        &grant_config,
        &state.keyring,
        &browser_session,
        test_session_public_jwk(&session_key, format!("session-{}", browser_session.id)),
        arkret_identifiers::DidCoreId::new(audience).unwrap(),
        arkret_identifiers::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001")
            .unwrap(),
        vec![STATION_SESSION_BIND_SCOPE.to_owned()],
        Some(&principal_id),
        &account_id,
        bound_jkt.clone(),
        arkret_models_identity::SessionGrantDeviceBinding {
            device_id: arkret_identifiers::DeviceId::new(
                "ak:device:01964137-0000-7000-8000-000000000001",
            )
            .unwrap(),
            authorization_event_id: arkret_identifiers::EventId::new(
                "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
            )
            .unwrap(),
            model_generation_ref: 1,
        },
        arkret_models_identity::SessionGrantProofKind::AccountHandoff,
    )
    .unwrap();
    let raw_payload = jwt_payload_value(&material.grant_jwt);
    assert_session_grant_jwt_omits_server_identity_metadata(&raw_payload);
    assert!(raw_payload.get("session_public_key").is_some());
    assert!(raw_payload.get("cnf").is_none());
    let grant = persist_session_grant(
        &mut repo,
        &mut rng,
        &grant_clock,
        &browser_session,
        &material,
    )
    .await
    .unwrap();
    repo.save().await.unwrap();

    // ① A `cnf`-bound grant introspected WITHOUT a client-carried grant-binding DPoP proof
    // still reports active WITH metadata over the authenticated S2S channel:
    // the Station binds the request DPoP to the returned `cnf_jkt`
    // itself (service-operation-dtos.schema.json). `proof_required` is an
    // advisory flag only — the default grant+DPoP path ignores it.
    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "grant_jwt": material.grant_jwt,
                    "audience_id": grant.audience_id,
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["status"], "active");
    assert_eq!(body["proof_required"], true);
    assert_eq!(
        body["grant"]["cnf_jkt"],
        expected_cnf_jkt(&grant.session_public_key)
    );

    // ② With a grant-binding DPoP proof the bound grant introspects active
    // and exposes `cnf.jkt` to the Station.
    let challenge = format!("introspect-{}", grant.grant_id);
    let proof_jwt = session_grant_introspection_proof(&grant, &material, &session_key, &challenge);
    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "grant_jwt": material.grant_jwt,
                    "audience_id": grant.audience_id,
                    "proof": {
                        "challenge": challenge,
                        "proof_jwt": proof_jwt,
                    }
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], true);
    assert_eq!(body["proof_required"], false);
    assert_eq!(
        body["grant"]["cnf_jkt"],
        expected_cnf_jkt(&grant.session_public_key)
    );
}

#[tokio::test]
async fn session_grant_http_introspection_accepts_persisted_agent_grant() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let bearer = "agent-session-grant-introspection";
    state.arkret_config = ArkretConfig {
        deployment_profile: DeploymentProfileConfig::PersonalNode,
        principal_method: PrincipalMethodConfig::DidWeb,
        ..config_with_internal_authority_shared_secret(bearer)
    };

    // The agent use-time gate (key-management §3.6.1) resolves the
    // authoritative AgentView from the configured Station; stub it
    // with wiremock so the lifecycle reads `active` (loopback egress is
    // permitted by the test HTTP client).
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let station = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/_arkret/self/agents/ak:did_core:web:agent.example",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent": {
                "agent_id": "ak:did_core:web:agent.example",
                "slug": "agent",
                "lifecycle": "active",
                "readiness": {
                    "state": "not_ready",
                    "blockers": ["runtime_key_missing", "pairing_open"]
                },
                "presence": {
                    "state": "unknown",
                    "expires_at": "2099-01-01T00:00:00.000Z",
                    "refresh_after": "2098-12-31T23:59:00.000Z"
                }
            },
            "key_state": {
                "agent_id": "ak:did_core:web:agent.example",
                "controller_account_id": {
                    "principal_id": "ak:did_core:web:controller.example",
                    "station_id": "ak:did_core:web:station.example"
                },
                "principal_control_realm_id": "ak:realm:Aa0HGvOq8Bsl1PLw19X-9sJ3Zdu6M7N-HDm-MebQoQcG",
                "controller_authorization_ref": "did:web:agent.example#managed-controller",
                "requested_scope": {
                    "actions": ["ak.message.create"],
                    "resources": []
                },
                "pairing_request_id": "agent-pairing-request",
                "pairing_expires_at": "2099-01-01T00:00:00.000Z",
                "active_authorizations": []
            }
        })))
        .mount(&station)
        .await;
    state.arkret_config.stations[0].endpoint = station.uri().parse().unwrap();
    crate::services::station_trust::shared().insert_for_test(
        &state.arkret_config.stations[0].endpoint,
        "ak:did_core:web:session-grant-static.test",
    );

    let mut rng = ChaChaRng::seed_from_u64(0xa9e17);
    let session_key = PrivateKey::generate_ed25519(&mut rng);
    let session_public_key =
        serde_json::to_string(&test_session_public_jwk(&session_key, "agent-session-key")).unwrap();
    // Both the agent subject and the audience are core DIDs on the wire (the
    // grant claims are typed `DidCoreId`), and the audience must be the
    // Station whose internal-authority shared secret is configured above.
    let audience =
        arkret_identifiers::DidCoreId::new("ak:did_core:web:session-grant-static.test").unwrap();
    // Grant liveness is evaluated against the wall clock the handlers read.
    let now = chrono::Utc::now();
    // The issuing authorization ref rides the signed payload's
    // `scope_details`; introspection's use-time gate re-reads the row by it.
    let authorization_event_id = "ak:event:AQilOsNi6WF7kBMfOVLw4LjFp75pXSq5WJ0WMmJw3kgK";
    let scope_details = serde_json::Map::from_iter([
        (
            "controller_principal_id".to_owned(),
            serde_json::json!("ak:did_core:web:alice.example"),
        ),
        (
            "agent_key_authorization_ref".to_owned(),
            serde_json::json!(authorization_event_id),
        ),
        (
            "resources".to_owned(),
            serde_json::json!({
                "realm_refs": ["ak:realm:team"],
            }),
        ),
    ]);
    let issuance_seed = SessionGrantIssuanceSeed::new(
        arkret_models_identity::SessionGrantIssuanceNonce::from_bytes([0x41; 32]).to_string(),
        "agent-test-session",
        now,
        now + Duration::try_minutes(15).unwrap(),
        coauth_keyring::SESSION_GRANT_SIGNING_KEY_ID,
    )
    .unwrap();
    let material = mint_agent_session_grant(
        &issuance_seed,
        &state.arkret_config,
        &state.keyring,
        &arkret_identifiers::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
        coauth_data::LocalAccountId::new("test-account").unwrap(),
        audience.clone(),
        vec!["ak.agent.action:message.send".to_owned()],
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_owned(),
        session_public_key.clone(),
        scope_details.clone(),
        arkret_identifiers::EventId::new(authorization_event_id).unwrap(),
        arkret_wire::DidUrl::new("did:web:agent.example#runtime-key").unwrap(),
        now,
        now + Duration::try_minutes(15).unwrap(),
    )
    .unwrap();
    let raw_payload = jwt_payload_value(&material.grant_jwt);
    assert_session_grant_jwt_omits_server_identity_metadata(&raw_payload);
    // Unlike a human grant, an agent grant names the agent twice by contract:
    // once as the credential `subject_id` and once inside the agent-runtime
    // holder binding, which is what binds the runtime key to it.
    assert_eq!(
        raw_payload["account_id"]["principal_id"].as_str(),
        Some("ak:did_core:web:agent.example")
    );
    assert_eq!(
        raw_payload["holder_binding"]["agent_id"].as_str(),
        Some("ak:did_core:web:agent.example")
    );
    assert!(raw_payload.get("session_public_key").is_some());
    assert!(raw_payload.get("cnf").is_none());
    // `proof_kind` and `scope_details` ride the signed grant payload; the
    // wire introspection grant record omits them (spec
    // SessionGrantValidationMetadata is additionalProperties:false without
    // these members), so they are asserted here rather than on the response.
    assert_eq!(raw_payload["proof_kind"], "agent_key_proof");
    assert_eq!(
        raw_payload["scope_details"],
        serde_json::Value::Object(scope_details.clone())
    );
    let mut repo = state.repository().await.unwrap();
    // Seed the key authorization the use-time gate re-reads by event id; the
    // gate only requires the row to exist, unrevoked and unexpired.
    repo.agent_key_authorization()
        .add(
            &mut rng,
            &coauth_data::SystemClock::default(),
            coauth_data::agent_key::NewAgentKeyAuthorization {
                authorized_event_id: authorization_event_id.to_owned(),
                agent_id: "ak:did_core:web:agent.example".to_owned(),
                key_id: "runtime-key".to_owned(),
                verification_method: "did:web:agent.example#runtime-key".to_owned(),
                public_key: serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                }),
                accountable_principal_id: arkret_identifiers::DidCoreId::new(
                    "ak:did_core:web:alice.example",
                )
                .unwrap(),
                agent_key_scope: serde_json::json!({
                    "actions": ["ak.agent.action:message.send"],
                    "resources": [],
                })
                .to_string(),
                audience: vec![audience.to_string()],
                issued_at: now,
                expires_at: None,
                pairing_request_id: "agent-pairing-request".to_owned(),
                request_canonical_digest: format!("sha256:{}", "a".repeat(64)),
                raw_payload_digest: format!("sha256:{}", "b".repeat(64)),
                soland_fanout_state:
                    coauth_data::accountability::AccountabilityGrantFanoutState::Queued,
                soland_fanout_idempotency_key: authorization_event_id.to_owned(),
                soland_fanout_payload: serde_json::json!({}),
                soland_fanout_attempt: 0,
                soland_fanout_next_retry_at: None,
                soland_fanout_dead_letter_reason: None,
            },
        )
        .await
        .unwrap();
    let persisted = persist_unbound_session_grant(
        &mut repo,
        &mut rng,
        &coauth_data::SystemClock::default(),
        &material,
    )
    .await
    .unwrap();
    repo.save().await.unwrap();

    // The agent grant is `cnf`-bound, so a proofless introspection reports
    // `proof_required` — present the runtime grant-binding proof.
    let challenge = format!("introspect-{}", persisted.grant_id);
    let proof_jwt =
        session_grant_introspection_proof(&persisted, &material, &session_key, &challenge);
    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(bearer)
                .json(serde_json::json!({
                    "grant_jwt": material.grant_jwt,
                    "audience_id": audience,
                    "proof": {
                        "challenge": challenge,
                        "proof_jwt": proof_jwt,
                    }
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["status"], "active");
    assert_eq!(body["proof_required"], false);
    assert_eq!(
        body["grant"]["account_id"]["principal_id"],
        "ak:did_core:web:agent.example"
    );
    // Agent-runtime grants carry no device coordinate at all (decision 0088):
    // the closed `agent_runtime` holder binding is exactly the Agent endpoint
    // triple, and top-level `device_id`/`device_binding` stay reserved for
    // human accepted-device grants.
    assert_eq!(body["grant"]["device_id"], serde_json::Value::Null);
    assert_eq!(body["grant"]["device_binding"], serde_json::Value::Null);
    assert_eq!(
        body["grant"]["holder_binding"],
        serde_json::json!({
            "kind": "agent_runtime",
            "agent_id": "ak:did_core:web:agent.example",
            "agent_key_authorization_ref": authorization_event_id,
            "verification_method": "did:web:agent.example#runtime-key",
        })
    );
    // `proof_kind`/`scope_details` were asserted on the signed payload above:
    // the spec introspection grant record (additionalProperties:false) omits
    // them, and `freshness_state` is likewise absent from the wire record.
    assert_eq!(body["grant"]["freshness_state"], serde_json::Value::Null);
    assert_eq!(
        body["grant"]["cnf_jkt"],
        expected_cnf_jkt(&persisted.session_public_key)
    );
    // The wire record re-serializes the embedded JWK canonically, so compare
    // the parsed key material rather than byte-level JSON member order.
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            body["grant"]["session_public_key"].as_str().unwrap()
        )
        .unwrap(),
        serde_json::from_str::<serde_json::Value>(&session_public_key).unwrap()
    );
    assert_eq!(body["grant"]["id"], persisted.grant_id.to_string());
    serde_json::from_value::<SessionGrantValidationResult>(body)
        .expect("agent introspection response must satisfy the shared closed wire model");
}

/// `id` and `grant_jwt` are an exactly-one selector: rejecting both-missing
/// AND both-present, rather than silently preferring `id`.
#[tokio::test]
async fn session_grant_introspection_rejects_ambiguous_selector() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let (_browser_session, grant, material, _session_key) =
        seed_persisted_session_grant(&mut state).await;

    // Hits the deployment-private Account Authority introspection adapter.
    // (the surface soland calls). The selector check runs before auth, so an
    // ambiguous selector is rejected regardless of bearer.

    // Both present → 422 schema_violation: the body parsed, and it fails the
    // oneOf selector constraint, which is not json_invalid (400).
    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "id": grant.grant_id.to_string(),
                    "grant_jwt": material.grant_jwt,
                    "audience_id": grant.audience_id,
                })),
        )
        .await;
    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    let body: arkret_wire::problem_details::Problem = response.json();
    assert_eq!(body.code(), "schema_violation");

    // Neither present → 422 schema_violation.
    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({ "audience_id": grant.audience_id })),
        )
        .await;
    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    let body: arkret_wire::problem_details::Problem = response.json();
    assert_eq!(body.code(), "schema_violation");
}

#[tokio::test]
async fn session_grant_http_revoke_updates_followup_introspection() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let (_browser_session, grant, _material, _session_key) =
        seed_persisted_session_grant(&mut state).await;
    // Revocation is destructive, so the read-only Station bearer is
    // not enough: it requires admin scope.
    let admin_token = state.token_with_scope("urn:coauth:admin").await;

    let response = state
        .request(
            Request::post(format!(
                "/_coauth/account/session-grants/{}/revoke",
                grant.id
            ))
            .bearer(&admin_token)
            .empty(),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["grant"]["id"], grant.id.to_string());
    assert!(body["grant"]["revoked_at"].is_string());

    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "id": grant.grant_id.to_string(),
                    "audience_id": grant.audience_id,
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], false);
    assert_eq!(body["status"], "revoked");
    assert_eq!(body["grant"]["id"], grant.grant_id.to_string());
    assert!(body["grant"]["revoked_at"].is_string());
}

#[tokio::test]
async fn canonical_session_revoke_commits_exact_grant_to_issuer_ledger() {
    use arkret_signatures::dpop::{DpopProofRequest, build_dpop_proof};

    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let (_, grant, material, session_key) = seed_persisted_session_grant(&mut state).await;
    let coauth_keyring::PrivateKey::OkpEd25519(signing_key) = session_key else {
        panic!("seeded session holder must be Ed25519");
    };
    let sdk_signing_key =
        crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&signing_key.to_bytes());
    let path = "/_arkret/gate/account/session-grants/revoke";
    let htu = format!("https://example.com{path}");
    let proof = build_dpop_proof(
        &DpopProofRequest::new("POST", &htu).access_token(&material.grant_jwt),
        &sdk_signing_key,
    )
    .unwrap();

    let missing_proof = state
        .request(
            Request::post(path)
                .header("authorization", format!("DPoP {}", material.grant_jwt))
                .empty(),
        )
        .await;
    assert_eq!(missing_proof.status(), StatusCode::UNAUTHORIZED);

    let response = state
        .request(
            Request::post(path)
                .header("authorization", format!("DPoP {}", material.grant_jwt))
                .header("dpop", proof.header_value)
                .empty(),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["revoked_count"], 1);
    assert_eq!(
        body["revoked_session_grant_ids"],
        serde_json::json!([grant.grant_id])
    );

    let response = state
        .request(
            Request::post("/_coauth/internal/session-grants/introspect")
                .bearer(INTERNAL_AUTHORITY_SHARED_SECRET)
                .json(serde_json::json!({
                    "grant_jwt": material.grant_jwt,
                    "audience_id": grant.audience_id,
                })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], false);
    assert_eq!(body["status"], "revoked");

    let retry_proof = build_dpop_proof(
        &DpopProofRequest::new("POST", &htu).access_token(&material.grant_jwt),
        &sdk_signing_key,
    )
    .unwrap();
    let retry = state
        .request(
            Request::post(path)
                .header("authorization", format!("DPoP {}", material.grant_jwt))
                .header("dpop", retry_proof.header_value)
                .empty(),
        )
        .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
}

/// Field names of a JSON object response, sorted.
///
/// `body["field"]` yields `Value::Null` for a field that is absent as well as
/// for one that is present and null, so `is_null()` cannot tell a deleted
/// field from an empty one. Asserting the whole set does.
fn sorted_field_names(body: &serde_json::Value) -> Vec<&str> {
    let mut names: Vec<&str> = body
        .as_object()
        .expect("response body is a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    names
}

#[tokio::test]
async fn primary_handle_patch_validates_claims() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let unique = unique_test_nonce();
    let alice_handle = format!("alice{unique}");
    let bob_handle = format!("bob{unique}");

    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();
    let alice = repo
        .user()
        .add(&mut rng, &*state.clock, alice_handle)
        .await
        .unwrap();
    let bob = repo
        .user()
        .add(&mut rng, &*state.clock, bob_handle)
        .await
        .unwrap();
    let alice_session = repo
        .browser_session()
        .add(
            &mut rng,
            &*state.clock,
            &alice,
            Some("Mozilla/5.0".to_owned()),
        )
        .await
        .unwrap();
    let bob_session = repo
        .browser_session()
        .add(
            &mut rng,
            &*state.clock,
            &bob,
            Some("Mozilla/5.0".to_owned()),
        )
        .await
        .unwrap();

    let handle = user_handle(&state.url_builder, &alice);
    repo.handle_audit()
        .record(
            &mut rng,
            &*state.clock,
            coauth_data::audit::NewHandleAuditEvent::new(
                coauth_data::audit::HandleAuditEventType::ClaimIssued,
            )
            .with_user(alice.id)
            .with_handle(&handle),
        )
        .await
        .unwrap();
    repo.save().await.unwrap();

    // NOTE: coauth no longer hosts `/users/{id}/did.json` (no DID-document
    // serving); the preference endpoint below is the only surface left.
    let alice_cookies = CookieHelper::new();
    alice_cookies.import(state.cookie_jar().set_session(&alice_session));
    let response = state
        .request(alice_cookies.with_cookies(
            Request::patch("/_coauth/account/identity/primary-handle").json(serde_json::json!({
                "primary_handle": handle,
            })),
        ))
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["primary_handle"], handle);
    assert_eq!(
        sorted_field_names(&body),
        ["effective_at", "primary_handle", "source_claim_id"],
        "the outcome carries exactly this field set, and no more"
    );
    assert!(
        !body["source_claim_id"].is_null(),
        "setting a handle records the audit claim that authorised it"
    );

    let response = state
        .request(alice_cookies.with_cookies(
            Request::patch("/_coauth/account/identity/primary-handle").json(serde_json::json!({
                "primary_handle": "unknown:example.com",
            })),
        ))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: arkret_wire::problem_details::Problem = response.json();
    assert_eq!(body.detail, "primary_handle_not_verified_for_holder");

    let bob_cookies = CookieHelper::new();
    bob_cookies.import(state.cookie_jar().set_session(&bob_session));
    let response = state
        .request(bob_cookies.with_cookies(
            Request::patch("/_coauth/account/identity/primary-handle").json(serde_json::json!({
                "primary_handle": handle,
            })),
        ))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);

    let response = state
        .request(alice_cookies.with_cookies(
            Request::patch("/_coauth/account/identity/primary-handle").json(serde_json::json!({
                "primary_handle": null,
            })),
        ))
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["primary_handle"], serde_json::Value::Null);
    assert_eq!(
        sorted_field_names(&body),
        ["effective_at", "primary_handle", "source_claim_id"]
    );
    assert_eq!(
        body["source_claim_id"],
        serde_json::Value::Null,
        "clearing the preference carries no source claim"
    );
}

#[test]
fn parse_local_handle_round_trips_local_user_handle() {
    let url_builder = UrlBuilder::new(
        "https://auth.example.com/coauth/".parse().unwrap(),
        None,
        None,
    );
    let mut rng = ChaChaRng::seed_from_u64(12);
    let now = Utc::now();
    let user = User::samples(now, &mut rng).into_iter().next().unwrap();

    // Canonical `<localpart>:<domain>` form (spec 7157ee8 §3.1).
    let canonical = user_handle(&url_builder, &user);
    assert_eq!(
        parse_local_handle(&url_builder, &canonical),
        Some(user.localpart.clone())
    );

    // Removed `<localpart>@<domain>` display form.
    let display = user_handle_display(&url_builder, &user);
    assert_eq!(parse_local_handle(&url_builder, &display), None);

    assert_eq!(
        parse_local_handle(&url_builder, "alice@elsewhere.example"),
        None
    );
    assert_eq!(
        parse_local_handle(&url_builder, "alice:elsewhere.example"),
        None
    );
}

#[test]
fn require_canonical_handle_rejects_acct_aliases() {
    let err = require_canonical_handle("acct:alice@example.com").unwrap_err();
    match err {
        ArkretRouteError::Coded { code, message, .. } => {
            assert_eq!(code, arkret_wire::ErrorCode::PARAM_INVALID);
            assert!(
                message.contains("reason_code=handle_not_canonical"),
                "expected canonical-handle reason code, got {message}"
            );
        }
        other => panic!("expected Coded, got {other:?}"),
    }
}

#[test]
fn require_canonical_handle_rejects_non_canonical_inputs() {
    require_canonical_handle("alice@example.com")
        .expect_err("display `local@host` form MUST be rejected as canonical");
    require_canonical_handle("@alice:example.com")
        .expect_err("leading @ display marker MUST be rejected");
    require_canonical_handle(":example.com").expect_err("empty localpart MUST be rejected");
    require_canonical_handle("alice:").expect_err("empty domain MUST be rejected");
    require_canonical_handle("Alice:example.com")
        .expect_err("uppercase localpart MUST be rejected");
    require_canonical_handle("").expect_err("empty input MUST be rejected");
}

#[test]
fn require_canonical_handle_accepts_canonical_form() {
    let result = require_canonical_handle("alice:example.com").unwrap();
    assert_eq!(result, "alice:example.com");
}

#[test]
fn issue_handle_claim_emits_canonical_handle_and_aliases() {
    use coauth_data::clock::MockClock;
    let url_builder = UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None);
    let arkret_config = test_arkret_config();
    let mut rng = ChaChaRng::seed_from_u64(0xc15a);
    let clock = MockClock::default();
    let now = clock.now();
    let user = User::samples(now, &mut rng).into_iter().next().unwrap();
    let keyring = test_account_authority_keyring();

    // Subject is the client-created webvh principal DID, passed by the caller.
    let subject_id = "ak:did_core:webvh:zQmExampleScid:soland.example";
    let account_id = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(subject_id).unwrap(),
        owning_station_id_for(&arkret_config),
    );
    let material = issue_handle_claim(
        &clock,
        &url_builder,
        &arkret_config,
        &keyring,
        &user,
        &account_id,
        arkret_models_identity::HandleClaimKind::HandleBinding,
        "did:web:space.example".to_owned(),
    )
    .expect("handle claim must mint with the test keyring");
    assert_eq!(
        material
            .payload
            .claim
            .subject_account_id
            .principal_id
            .as_str(),
        subject_id
    );

    let canonical = user_handle(&url_builder, &user);
    let acct = arkret_models_identity::Handle::parse(&canonical)
        .unwrap()
        .to_acct();
    // Spec 7157ee8 §3.1 — canonical `<localpart>:<domain>` form on
    // the wire `handle` field.
    assert_eq!(material.payload.schema, "ak.schema.handle_claim.v1");
    let payload_value = serde_json::to_value(&material.payload).unwrap();
    assert!(payload_value.get("type").is_none());
    let handle = &material.payload.claim.handle;
    assert_eq!(handle.canonical(), canonical);
    assert!(
        handle.canonical().contains(':'),
        "handle MUST be the canonical `<localpart>:<domain>` form"
    );
    assert!(
        !handle.canonical().starts_with("arkret://"),
        "handle MUST NOT carry the forbidden arkret:// URI form"
    );
    assert!(
        !handle.canonical().starts_with("acct:"),
        "handle MUST NOT be an acct: alias"
    );
    assert!(
        material.payload.claim.handle_aliases.contains(&acct),
        "handle_aliases MUST carry the acct: interop form"
    );
    assert_eq!(
        material.payload.claim.audience.as_deref(),
        Some("did:web:space.example")
    );
    assert!(material.claim_digest.starts_with("sha256:"));
    // The status view carries no digest mirror; it is recomputed from `claim`.
    assert_eq!(
        material.payload.claim_digest().unwrap().as_str(),
        material.claim_digest
    );
    assert!(material.expires_at > now);
    assert_eq!(material.payload.claim.proofs.len(), 2);
    assert_eq!(
        material.payload.claim.proofs[0].audience,
        Some(arkret_wire::Audience::Single(
            "did:web:space.example".to_owned()
        ))
    );
    assert!(
        material
            .payload
            .claim
            .proofs
            .iter()
            .all(|proof| !proof.jws.is_empty())
    );
    assert!(matches!(
        material.payload.claim.claim,
        arkret_models_identity::HandleClaimVariant::HandleBinding
    ));
}

#[test]
fn issue_handle_claim_rejects_organization_kind_without_organization_id() {
    use coauth_data::clock::MockClock;
    let url_builder = UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None);
    let arkret_config = test_arkret_config();
    let mut rng = ChaChaRng::seed_from_u64(0xc15b);
    let clock = MockClock::default();
    let now = clock.now();
    let user = User::samples(now, &mut rng).into_iter().next().unwrap();
    let keyring = test_keyring();

    let account_id = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:zQmExampleScid:soland.example")
            .unwrap(),
        owning_station_id_for(&arkret_config),
    );
    let error = issue_handle_claim(
        &clock,
        &url_builder,
        &arkret_config,
        &keyring,
        &user,
        &account_id,
        arkret_models_identity::HandleClaimKind::OrganizationHandle,
        "did:web:space.example".to_owned(),
    )
    .expect_err("organization_handle requires its closed organization_id variant");
    assert!(error.to_string().contains("organization_id"));
}
