use chrono::{Duration, Utc};
use coauth_config::{
    CokretConfig, IdentityRegistryConfig, IdentityRegistryKind, PrincipalServerConfig,
};
use coauth_data::{BrowserSession, Clock, RepositoryAccess, SessionGrant, SystemClock, User};
use coauth_iana::jose::{JsonWebKeyOperation, JsonWebKeyUse, JsonWebSignatureAlg};
use coauth_jose::jwk::{JsonWebKey, JsonWebKeyPublicParameters, PublicJsonWebKey};
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keystore::{JsonWebKeySet, PrivateKey};
use cokret_core::SessionGrantIntrospectStatus as SessionGrantIntrospectionStatus;
use hyper::{Request, StatusCode};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use super::*;
use crate::handlers::test_utils::{
    CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
};
use crate::salvo_utils::SessionInfoExt;

fn test_keystore() -> Keystore {
    let mut rng = ChaChaRng::seed_from_u64(42);
    let eddsa = coauth_keystore::JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
        .with_kid("test-eddsa");
    Keystore::new(JsonWebKeySet::new(vec![eddsa]))
}

fn test_session_public_jwk(session_key: &PrivateKey, kid: impl Into<String>) -> PublicJsonWebKey {
    JsonWebKey::new(JsonWebKeyPublicParameters::from(session_key))
        .with_use(JsonWebKeyUse::Sig)
        .with_key_ops(vec![JsonWebKeyOperation::Verify])
        .with_alg(JsonWebSignatureAlg::EdDsa)
        .with_kid(kid)
}

#[test]
fn service_and_user_identifiers_follow_cokret_shape() {
    let url_builder = UrlBuilder::new(
        "https://auth.example.com/coauth/".parse().unwrap(),
        None,
        None,
    );
    let mut rng = ChaChaRng::seed_from_u64(7);
    let now = Utc::now();
    let user = User::samples(now, &mut rng).into_iter().next().unwrap();

    assert_eq!(service_did(&url_builder), "did:web:auth.example.com:coauth");
    assert_eq!(
        user_did(&url_builder, &user),
        format!("did:web:auth.example.com:coauth:users:{}", user.id)
    );
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

#[test]
fn service_describe_exposes_auth_account_boundary_profile() {
    let url_builder = UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None);
    let cokret_config = CokretConfig {
        service_did: Some("did:web:auth.example.com".to_owned()),
        issuer_did: Some("did:web:issuer.example.com".to_owned()),
        admin_audience: Some("https://auth.example.com/api/admin".to_owned()),
        principal_servers: vec![PrincipalServerConfig {
            name: "soland-prod".to_owned(),
            audience: "https://soland.example.com/api".to_owned(),
            endpoint: "https://soland.example.com/cokret".parse().unwrap(),
            did: Some("did:web:soland.example.com".to_owned()),
            oauth_introspection_bearer: None,
            session_grant_introspection_bearer: None,
            embedded_webvh_registration_bearer: None,
        }],
        identity_registry: Some(IdentityRegistryConfig {
            kind: IdentityRegistryKind::PublicDidResolver,
            resolver: "https://resolver.example.com/resolve".parse().unwrap(),
            proof_required_for_pairwise: true,
        }),
        starid: None,
        session_grant_ttl: Duration::try_minutes(5).unwrap(),
        principal_server_url: None,
        high_risk_threshold: 2,
        trust_domain: None,
        oob_code_kind: CokretConfig::default().oob_code_kind,
        password_login_session_grants_enabled: false,
        admin_org_id: None,
        verification_service_did: None,
        verification_service_dids: Vec::new(),
        audit_signature_fail_closed: false,
    };

    let body =
        serde_json::to_value(service_describe_response(&url_builder, &cokret_config, &[])).unwrap();

    assert_eq!(body["service_did"], "did:web:auth.example.com");
    assert_eq!(body["trust_domain"], "ck:trust_domain:auth.example.com");
    assert_eq!(body["service_type"], "auth_server");
    assert_eq!(body["admin_audience"], "https://auth.example.com/api/admin");
    assert_eq!(
        body["auth_metadata"]["issuer_did"],
        "did:web:issuer.example.com"
    );
    assert_eq!(
        body["auth_metadata"]["session_grant_scope"],
        PRINCIPAL_SERVER_SESSION_BIND_SCOPE
    );
    assert_eq!(
        body["principal_server_delegation_targets"][0]["audience"],
        "https://soland.example.com/api"
    );
    assert_eq!(
        body["identity_registry_resolver"]["mode"],
        "delegated_resolver"
    );
    assert_eq!(
        body["identity_registry_resolver"]["endpoint"],
        "https://auth.example.com/api/v1/identity/resolve"
    );
    assert_eq!(
        body["identity_registry_resolver"]["delegated_resolver"]["kind"],
        "public_did_resolver"
    );
    assert_eq!(
        body["identity_registry_resolver"]["delegated_resolver"]["resolver"],
        "https://resolver.example.com/resolve"
    );
    assert_eq!(
        body["standard_error_envelope"]["example"],
        serde_json::json!({
            "ok": false,
            "error": {
                "code": "machine_readable_code",
                "message": "human-readable message"
            },
            "request_id": "ck:request:01964137-0000-7000-8000-000000000000"
        })
    );

    let supported_profiles = body["supported_profiles"].as_array().unwrap();
    assert!(supported_profiles.is_empty());
    let supported_reducer_profiles = body["supported_reducer_profiles"].as_array().unwrap();
    assert!(supported_reducer_profiles.contains(&serde_json::json!("ck.reducer.v1")));
    // T6.3 — `ck.schema.v1` was a coauth-only placeholder. The actual
    // schemas this surface emits are `ck.schema.core.v1` (umbrella
    // core schemas, soland / SDK convention) and
    // `ck.schema.service_describe.v1` (this very payload).
    let supported_schema_profiles = body["supported_schema_profiles"].as_array().unwrap();
    assert!(supported_schema_profiles.contains(&serde_json::json!("ck.schema.core.v1")));
    assert!(
        supported_schema_profiles.contains(&serde_json::json!("ck.schema.service_describe.v1"))
    );
    assert!(
        !supported_schema_profiles.contains(&serde_json::json!("ck.schema.v1")),
        "the removed `ck.schema.v1` placeholder MUST NOT be advertised"
    );
    let supported_operations = body["supported_operations"].as_array().unwrap();
    assert!(
        supported_operations.contains(&serde_json::json!("ck.self.policy.query.check")),
        "implemented POST /api/v1/policy/check MUST be advertised as ck.self.policy.query.check"
    );
    let not_authoritative_for = body["service_boundary"]["not_authoritative_for"]
        .as_array()
        .unwrap();
    assert!(not_authoritative_for.contains(&serde_json::json!("did_key_log")));
    assert!(not_authoritative_for.contains(&serde_json::json!("identity_registry_receipt")));

    // T6.3 — service_roles must list every role coauth carries.
    // Boundary check: account_registry + auth_server + identity_resolver.
    let service_roles = body["service_roles"]
        .as_array()
        .expect("service_roles array present");
    assert!(service_roles.contains(&serde_json::json!("auth_server")));
    assert!(service_roles.contains(&serde_json::json!("identity_resolver")));
    assert!(service_roles.contains(&serde_json::json!("account_registry")));

    // T6.3 — ck.identity.* operations MUST be declared as
    // schema-valid external interop while preserving their delegated-
    // resolver boundary in notes, not as canonical identity registry
    // surface.
    let compat: Vec<(&str, &str)> = body["compat_surfaces"]
        .as_array()
        .expect("compat_surfaces array present")
        .iter()
        .filter(|entry| entry["kind"].as_str() == Some("external_interop"))
        .filter_map(|entry| Some((entry["name"].as_str()?, entry["notes"].as_str()?)))
        .collect();
    assert!(compat.iter().any(|(name, notes)| {
        *name == "ck.root.identity.query.resolve" && notes.contains("delegated-resolver")
    }));
    assert!(compat.iter().any(|(name, notes)| {
        *name == "ck.root.identity.document.resource.get" && notes.contains("delegated-resolver")
    }));
    assert!(compat.iter().any(|(name, notes)| {
        *name == "ck.root.identity.registry.query.describe" && notes.contains("delegated-resolver")
    }));
    // verified_profiles MUST NOT include ck.profile.identity_registry.v1
    // because coauth is a delegated resolver, not a registry.
    let verified = body["verified_profiles"]
        .as_array()
        .expect("verified_profiles array present");
    for entry in verified {
        assert_ne!(
            entry["profile_id"], "ck.profile.identity_registry.v1",
            "coauth MUST NOT advertise canonical identity registry conformance"
        );
    }
}

fn config_with_static_session_grant_bearer(bearer: &str) -> CokretConfig {
    CokretConfig {
        principal_servers: vec![PrincipalServerConfig {
            name: "soland-dev".to_owned(),
            audience: "did:web:local.host".to_owned(),
            endpoint: "https://local.host/".parse().unwrap(),
            did: Some("did:web:local.host".to_owned()),
            oauth_introspection_bearer: None,
            session_grant_introspection_bearer: Some(bearer.to_owned()),
            embedded_webvh_registration_bearer: None,
        }],
        ..CokretConfig::default()
    }
}

#[test]
fn principal_server_static_session_grant_bearer_matches_exact_token() {
    let config = config_with_static_session_grant_bearer("local-coauth-session-grant");
    assert!(principal_server_static_session_grant_bearer_matches(
        &config,
        "local-coauth-session-grant"
    ));
}

#[test]
fn principal_server_static_session_grant_bearer_rejects_other_tokens() {
    let config = config_with_static_session_grant_bearer("local-coauth-session-grant");
    assert!(!principal_server_static_session_grant_bearer_matches(
        &config,
        "other-token"
    ));
    assert!(!principal_server_static_session_grant_bearer_matches(
        &config, ""
    ));
    assert!(!principal_server_static_session_grant_bearer_matches(
        &config, "   "
    ));
}

#[test]
fn principal_server_static_session_grant_bearer_ignores_unset_field() {
    let mut config = config_with_static_session_grant_bearer("placeholder");
    config.principal_servers[0].session_grant_introspection_bearer = None;
    assert!(!principal_server_static_session_grant_bearer_matches(
        &config,
        "placeholder"
    ));
}

#[test]
fn describe_separates_claim_levels() {
    // T6.1 — describe response MUST partition into
    // supported_operations (wire-callable) and the new claim-level
    // arrays. coauth has no dev toggle, but the spec invariant
    // (development_mode=true => verified_profiles=[]) is still
    // exercised: when development_mode is reported as `false`, the
    // assertion below ensures we never lazily populate verified
    // entries from self-claimed input.
    let url_builder = UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None);
    let body = serde_json::to_value(service_describe_response(
        &url_builder,
        &CokretConfig::default(),
        &[],
    ))
    .unwrap();

    // verified_profiles MUST be present and (with no cotest run wired
    // in) empty.
    let verified = body["verified_profiles"]
        .as_array()
        .expect("verified_profiles array present");
    assert!(
        verified.is_empty(),
        "coauth must not advertise cotest_verified profiles without a verifier"
    );

    // claimed_profiles entries MUST carry claim_kind=self_claimed.
    for entry in body["claimed_profiles"]
        .as_array()
        .expect("claimed_profiles array present")
    {
        assert_eq!(
            entry["claim_kind"], "self_claimed",
            "claimed_profiles entries MUST be self_claimed"
        );
    }

    // implemented_features must be a non-empty subset of "code
    // exists" features.
    let implemented = body["implemented_features"]
        .as_array()
        .expect("implemented_features array present");
    assert!(!implemented.is_empty());

    // experimental_features and verified_profiles MUST NOT
    // intersect.
    let experimental: std::collections::HashSet<&str> = body["experimental_features"]
        .as_array()
        .expect("experimental_features array present")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let verified_ids: std::collections::HashSet<&str> = verified
        .iter()
        .filter_map(|v| v["profile_id"].as_str())
        .collect();
    assert!(experimental.is_disjoint(&verified_ids));

    // compat_surfaces entries must declare a schema-known kind.
    // T6.3 — coauth's `ck.identity.*` proxy operations are NOT a
    // canonical identity registry; the delegated-resolver semantics
    // are carried in notes while kind stays schema-valid.
    for surface in body["compat_surfaces"]
        .as_array()
        .expect("compat_surfaces array present")
    {
        let kind = surface["kind"].as_str().expect("compat surface kind");
        assert!(
            matches!(
                kind,
                "matrix_passthrough" | "mimi_passthrough" | "external_interop" | "deprecated_alias"
            ),
            "unknown compat_surface kind {kind}"
        );
        assert_ne!(
            kind, "delegated_resolver",
            "service-describe schema does not allow delegated_resolver as compat_surface kind"
        );
        assert!(
            surface["notes"]
                .as_str()
                .is_some_and(|notes| notes.contains("delegated-resolver")),
            "delegated-resolver semantics must remain in compat_surface notes"
        );
    }

    // development_mode field must be present so downstream tools
    // (sodmin / cotest) can render the dev banner.
    assert!(body["development_mode"].is_boolean());
    let supported_operations = body["supported_operations"]
        .as_array()
        .expect("supported_operations array present");
    assert!(supported_operations.contains(&serde_json::json!("ck.self.policy.query.check")));
}

#[test]
fn service_describe_emits_trust_domain_when_configured() {
    // Round 4 (spec a77b995) — trust_domain MUST surface on the
    // wire when the deployment sets it. Mirrors the SDK's
    // `Realm.trust_domain` / `ServiceDescribe.trust_domain`
    // requirement so federation peers can bind their canonical
    // transcript.
    let url_builder = UrlBuilder::new(
        "https://auth.example.com/coauth/".parse().unwrap(),
        None,
        None,
    );
    let config = CokretConfig {
        trust_domain: Some("ck:trust_domain:example.net".to_owned()),
        ..Default::default()
    };

    let body = serde_json::to_value(service_describe_response(&url_builder, &config, &[])).unwrap();
    assert_eq!(body["trust_domain"], "ck:trust_domain:example.net");
}

#[test]
fn service_describe_derives_trust_domain_from_public_host_when_unset() {
    let url_builder = UrlBuilder::new(
        "https://auth.example.com/coauth/".parse().unwrap(),
        None,
        None,
    );
    let body = serde_json::to_value(service_describe_response(
        &url_builder,
        &CokretConfig::default(),
        &[],
    ))
    .unwrap();
    assert_eq!(body["trust_domain"], "ck:trust_domain:auth.example.com");
}

#[test]
fn service_describe_derives_valid_trust_domain_for_ipv6_host() {
    let url_builder = UrlBuilder::new("https://[::1]/coauth/".parse().unwrap(), None, None);
    let body = serde_json::to_value(service_describe_response(
        &url_builder,
        &CokretConfig::default(),
        &[],
    ))
    .unwrap();
    assert_eq!(body["trust_domain"], "ck:trust_domain:host-::1");
    CokretConfig::validate_trust_domain(body["trust_domain"].as_str().unwrap()).unwrap();
}

#[test]
fn service_describe_defaults_to_local_identity_binding_resolver() {
    let url_builder = UrlBuilder::new(
        "https://auth.example.com/coauth/".parse().unwrap(),
        None,
        None,
    );

    let body = serde_json::to_value(service_describe_response(
        &url_builder,
        &CokretConfig::default(),
        &[],
    ))
    .unwrap();

    assert_eq!(body["identity_registry_resolver"]["mode"], "local_bindings");
    assert_eq!(
        body["identity_registry_resolver"]["endpoint"],
        "https://auth.example.com/coauth/api/v1/identity/resolve"
    );
    assert!(body["identity_registry_resolver"]["delegated_resolver"].is_null());
}

#[test]
fn service_describe_advertises_configured_session_grant_ttl() {
    let url_builder = UrlBuilder::new(
        "https://auth.example.com/coauth/".parse().unwrap(),
        None,
        None,
    );
    let config = CokretConfig {
        session_grant_ttl: Duration::try_minutes(15).unwrap(),
        ..CokretConfig::default()
    };

    let body = serde_json::to_value(service_describe_response(&url_builder, &config, &[])).unwrap();

    assert_eq!(body["limits"]["session_grant_ttl_seconds"], 900);
}

#[test]
fn session_grant_is_signed_for_the_user_did() {
    let clock = SystemClock::default();
    let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
    let cokret_config = CokretConfig::default();
    let key_store = test_keystore();
    let now = clock.now();
    let mut fixture_rng = ChaChaRng::seed_from_u64(9);
    let browser_session = BrowserSession::samples(now, &mut fixture_rng)
        .into_iter()
        .next()
        .unwrap();
    let mut signing_rng = ChaChaRng::seed_from_u64(11);
    let session_key = PrivateKey::generate_ed25519(&mut signing_rng);
    let session_public_key = test_session_public_jwk(&session_key, "test-session-key");

    let grant = issue_session_grant(
        &mut signing_rng,
        &clock,
        &url_builder,
        &cokret_config,
        &key_store,
        &browser_session,
        session_public_key,
        vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
    )
    .unwrap();

    let jwt = Jwt::<SessionGrantPayload>::try_from(grant.grant_jwt.as_str()).unwrap();
    jwt.verify_with_jwks(&key_store.public_jwks()).unwrap();

    let payload = jwt.payload();
    assert_eq!(payload.kind, "ck.session.grant");
    assert_eq!(
        payload.subject,
        user_did_for(&url_builder, &cokret_config, &browser_session.user)
    );
    assert_eq!(
        payload.service_account_id,
        browser_session.user.id.to_string()
    );
    assert_eq!(payload.issuer, issuer_did_for(&url_builder, &cokret_config));
    assert_eq!(
        payload.audience,
        required_audience_for(&url_builder, &cokret_config)
    );
    assert_eq!(payload.scopes, vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE]);
    assert_eq!(payload.session_id, browser_session.id.to_string());
    assert_eq!(payload.device_id, None);
    assert_eq!(
        payload.expires_at - payload.not_before,
        Duration::try_hours(8).unwrap()
    );
    assert_eq!(payload.proof.kind, "ck.session.grant.proof.v1");
    assert_eq!(payload.proof.alg, "EdDSA");
    assert_eq!(payload.proof.key_id, "test-eddsa");
    assert_eq!(payload.proof.payload_digest_alg, "sha-256");
    assert_eq!(
        payload.proof.payload_digest,
        session_grant_claims_hash(&session_grant_claims_from_payload(payload)).unwrap()
    );
    assert!(
        payload
            .session_public_key
            .contains("\"kid\":\"test-session-key\"")
    );
}

#[test]
fn session_grant_uses_configured_ttl() {
    let clock = SystemClock::default();
    let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
    let cokret_config = CokretConfig {
        session_grant_ttl: Duration::try_minutes(15).unwrap(),
        ..CokretConfig::default()
    };
    let key_store = test_keystore();
    let now = clock.now();
    let mut fixture_rng = ChaChaRng::seed_from_u64(9);
    let browser_session = BrowserSession::samples(now, &mut fixture_rng)
        .into_iter()
        .next()
        .unwrap();
    let mut signing_rng = ChaChaRng::seed_from_u64(11);
    let session_key = PrivateKey::generate_ed25519(&mut signing_rng);
    let session_public_key = test_session_public_jwk(&session_key, "ttl-session-key");

    let grant = issue_session_grant(
        &mut signing_rng,
        &clock,
        &url_builder,
        &cokret_config,
        &key_store,
        &browser_session,
        session_public_key,
        vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
    )
    .unwrap();

    let jwt = Jwt::<SessionGrantPayload>::try_from(grant.grant_jwt.as_str()).unwrap();
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
        browser_session_id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCN").unwrap(),
        issuer: "did:web:auth.example.com".to_owned(),
        subject: "did:web:auth.example.com:users:01J44Q10GR4AMTFZEEF936DTCP".to_owned(),
        device_id: Some("device-1".to_owned()),
        audience: "https://soland.example.com/api".to_owned(),
        scope: Scope::from_iter([PRINCIPAL_SERVER_SESSION_BIND_SCOPE.parse().unwrap()]),
        grant_jwt: "header.payload.signature".to_owned(),
        session_public_key: "{\"kty\":\"OKP\"}".to_owned(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        revoked_at: None,
    };

    let body = serde_json::to_value(SessionGrantRecord::from(grant)).unwrap();

    assert_eq!(body["audience"], "https://soland.example.com/api");
    assert_eq!(
        body["scopes"],
        serde_json::json!([PRINCIPAL_SERVER_SESSION_BIND_SCOPE])
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
        browser_session_id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCN").unwrap(),
        issuer: "did:web:auth.example.com".to_owned(),
        subject: format!("did:web:auth.example.com:users:{}", user.id),
        device_id: Some("device-1".to_owned()),
        audience: "https://soland.example.com/api".to_owned(),
        scope: Scope::from_iter([PRINCIPAL_SERVER_SESSION_BIND_SCOPE.parse().unwrap()]),
        grant_jwt: "header.payload.signature".to_owned(),
        session_public_key: "{\"kty\":\"OKP\"}".to_owned(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        revoked_at: None,
    };

    assert_eq!(
        introspection_status(
            &grant,
            Some(&user),
            now,
            Some("https://soland.example.com/api")
        ),
        SessionGrantIntrospectionStatus::Active
    );
    assert_eq!(
        introspection_status(
            &grant,
            Some(&user),
            now,
            Some("https://other.example.com/api")
        ),
        SessionGrantIntrospectionStatus::AudienceMismatch
    );

    user.locked_at = Some(now);
    assert_eq!(
        introspection_status(&grant, Some(&user), now, None),
        SessionGrantIntrospectionStatus::Locked
    );

    user.locked_at = None;
    user.deactivated_at = Some(now);
    assert_eq!(
        introspection_status(&grant, Some(&user), now, None),
        SessionGrantIntrospectionStatus::Suspended
    );

    grant.revoked_at = Some(now);
    assert_eq!(
        introspection_status(&grant, Some(&user), now, None),
        SessionGrantIntrospectionStatus::Revoked
    );
}

async fn seed_persisted_session_grant(
    state: &TestState,
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
    let material = issue_session_grant(
        &mut rng,
        &*state.clock,
        &state.url_builder,
        &state.cokret_config,
        &state.key_store,
        &browser_session,
        test_session_public_jwk(&session_key, format!("session-{}", browser_session.id)),
        vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
    )
    .unwrap();
    let grant = persist_session_grant(
        &mut repo,
        &mut rng,
        &*state.clock,
        &browser_session,
        &material,
    )
    .await
    .unwrap();
    repo.save().await.unwrap();

    (browser_session, grant, material, session_key)
}

fn session_grant_introspection_proof(
    grant: &SessionGrant,
    material: &SessionGrantMaterial,
    session_key: &PrivateKey,
    challenge: &str,
) -> String {
    let now = Utc::now();
    let signer = session_key
        .signing_key_for_alg(&JsonWebSignatureAlg::EdDsa)
        .unwrap();
    let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::EdDsa);
    let claims = SessionGrantIntrospectionProofClaims {
        kind: "ck.session_grant.introspection_proof.v1".to_owned(),
        grant_id: grant.id.to_string(),
        grant_jwt_hash: session_grant_jwt_hash(&material.grant_jwt),
        audience: grant.audience.clone(),
        challenge: challenge.to_owned(),
        issued_at: now,
        expires_at: now + Duration::try_minutes(1).unwrap(),
    };
    Jwt::sign(header, claims, &signer).unwrap().into_string()
}

#[tokio::test]
async fn session_grant_http_list_and_filter_work() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
        return;
    };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let (browser_session, grant, _material, _session_key) =
        seed_persisted_session_grant(&state).await;

    let response = state
        .request(Request::get("/api/v1/session-grants").empty())
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
        serde_json::json!([PRINCIPAL_SERVER_SESSION_BIND_SCOPE])
    );

    let response = state
        .request(
            Request::get(format!(
                "/api/v1/session-grants?browser_session_id={}&active_only=true",
                browser_session.id
            ))
            .empty(),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["grants"].as_array().unwrap().len(), 1);

    let response = state
        .request(Request::get("/api/v1/session-grants?browser_session_id=not-a-ulid").empty())
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"]["code"], "bad_json");
    assert_eq!(body["error"]["message"], "invalid browser_session_id");
}

#[tokio::test]
async fn session_grant_http_introspection_returns_minimal_metadata() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
        return;
    };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let (_browser_session, grant, material, session_key) =
        seed_persisted_session_grant(&state).await;
    let challenge = format!("introspect-{}", grant.id);
    let proof_jwt = session_grant_introspection_proof(&grant, &material, &session_key, &challenge);

    let response = state
        .request(
            Request::post("/api/v1/session-grants/introspect").json(serde_json::json!({
                "grant_jwt": material.grant_jwt,
                "audience": grant.audience,
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
    assert_eq!(body["status"], "active");
    assert_eq!(body["proof_required"], true);
    // Introspection is READ-ONLY: it MUST NOT consume the grant (consumption /
    // single-use rotation is the refresh endpoint's job). So one_time_use is
    // never reported as already-consumed here, and a follow-up introspect of
    // the same grant still sees it active.
    assert_eq!(body["one_time_use_consumed"], false);
    assert_eq!(body["grant"]["id"], grant.id.to_string());
    assert_eq!(body["grant"]["subject"], grant.subject);
    assert_eq!(body["grant"]["audience"], grant.audience);
    assert_eq!(body["grant"]["revoked_at"], serde_json::Value::Null);
    assert!(body["grant"].get("grant_jwt").is_none());
    // Server-to-server introspection MUST expose session_public_key so the
    // Principal Server can verify RFC 9421 PoP presentations (SPEC-CR-001).
    assert_eq!(
        body["grant"]["session_public_key"],
        grant.session_public_key
    );
    // This grant was seeded without a DPoP binding (`issue_session_grant`
    // passes no `dpop_jkt`), so it has no `cnf` and `cnf_jkt` is omitted.
    assert!(body["grant"].get("cnf_jkt").is_none());

    // A second introspection of the same grant: still active (read-only — the
    // first call did not revoke it).
    let response = state
        .request(
            Request::post("/api/v1/session-grants/introspect").json(serde_json::json!({
                "id": grant.id,
                "audience": grant.audience,
            })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], true);
    assert_eq!(body["status"], "active");
    assert_eq!(body["grant"]["revoked_at"], serde_json::Value::Null);

    let response = state
        .request(
            Request::post("/api/v1/session-grants/introspect").json(serde_json::json!({
                "id": grant.id,
                "audience": "https://other.example.com/api",
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
/// Principal Server through introspection so it can verify the per-request DPoP
/// proof. The thumbprint is not a stored column — it is read back out of the
/// signed grant JWT — so this exercises the full persist → introspect round-trip.
#[tokio::test]
async fn session_grant_http_introspection_exposes_cnf_jkt_for_dpop_bound_grant() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
        return;
    };
    let state = TestState::from_pool(pool.clone()).await.unwrap();

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
    let bound_jkt = "test-dpop-jkt-thumbprint".to_owned();
    let material = issue_session_grant_for_audience(
        &*state.clock,
        &state.url_builder,
        &state.cokret_config,
        &state.key_store,
        &browser_session,
        test_session_public_jwk(&session_key, format!("session-{}", browser_session.id)),
        required_audience_for(&state.url_builder, &state.cokret_config),
        vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
        None,
        Some(bound_jkt.clone()),
    )
    .unwrap();
    let grant = persist_session_grant(
        &mut repo,
        &mut rng,
        &*state.clock,
        &browser_session,
        &material,
    )
    .await
    .unwrap();
    repo.save().await.unwrap();

    let challenge = format!("introspect-{}", grant.id);
    let proof_jwt = session_grant_introspection_proof(&grant, &material, &session_key, &challenge);
    let response = state
        .request(
            Request::post("/api/v1/session-grants/introspect").json(serde_json::json!({
                "grant_jwt": material.grant_jwt,
                "audience": grant.audience,
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
    assert_eq!(body["grant"]["cnf_jkt"], bound_jkt);
}

/// `id` and `grant_jwt` are an exactly-one selector: rejecting both-missing
/// AND both-present, rather than silently preferring `id`.
#[tokio::test]
async fn session_grant_introspection_rejects_ambiguous_selector() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
        return;
    };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let (_browser_session, grant, material, _session_key) =
        seed_persisted_session_grant(&state).await;

    // Hits the canonical spec path `/_cokret/gate/account/session-grants/introspect`
    // (the surface soland calls). The selector check runs before auth, so an
    // ambiguous selector is a 400 schema_violation regardless of bearer.

    // Both present → 400 schema_violation (the body parsed; it fails the
    // oneOf selector constraint, which is not bad_json).
    let response = state
        .request(
            Request::post("/_cokret/gate/account/session-grants/introspect").json(
                serde_json::json!({
                    "id": grant.id,
                    "grant_jwt": material.grant_jwt,
                    "audience": grant.audience,
                }),
            ),
        )
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"]["code"], "schema_violation");

    // Neither present → 400 schema_violation.
    let response = state
        .request(
            Request::post("/_cokret/gate/account/session-grants/introspect")
                .json(serde_json::json!({ "audience": grant.audience })),
        )
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"]["code"], "schema_violation");
}

#[tokio::test]
async fn session_grant_http_revoke_updates_followup_introspection() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
        return;
    };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let (_browser_session, grant, _material, _session_key) =
        seed_persisted_session_grant(&state).await;

    let response = state
        .request(Request::post(format!("/api/v1/session-grants/{}/revoke", grant.id)).empty())
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["grant"]["id"], grant.id.to_string());
    assert!(body["grant"]["revoked_at"].is_string());

    let response = state
        .request(
            Request::post("/api/v1/session-grants/introspect").json(serde_json::json!({
                "id": grant.id,
                "audience": grant.audience,
            })),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["active"], false);
    assert_eq!(body["status"], "revoked");
    assert_eq!(body["grant"]["id"], grant.id.to_string());
    assert!(body["grant"]["revoked_at"].is_string());
}

#[tokio::test]
async fn primary_handle_patch_validates_claims() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
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
            .with_handle(&handle)
            .with_claim_digest("sha256:alice-primary"),
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
            Request::patch("/api/v1/identity/primary-handle").json(serde_json::json!({
                "primary_handle": handle,
            })),
        ))
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["primary_handle"], handle);
    assert_eq!(body["source_claim_digest"], "sha256:alice-primary");

    let response = state
        .request(alice_cookies.with_cookies(
            Request::patch("/api/v1/identity/primary-handle").json(serde_json::json!({
                "primary_handle": "unknown:example.com",
            })),
        ))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["error"]["message"],
        "primary_handle_not_verified_for_holder"
    );

    let bob_cookies = CookieHelper::new();
    bob_cookies.import(state.cookie_jar().set_session(&bob_session));
    let response =
        state
            .request(bob_cookies.with_cookies(
                Request::patch("/api/v1/identity/primary-handle").json(serde_json::json!({
                    "primary_handle": handle,
                })),
            ))
            .await;
    response.assert_status(StatusCode::BAD_REQUEST);

    let response = state
        .request(alice_cookies.with_cookies(
            Request::patch("/api/v1/identity/primary-handle").json(serde_json::json!({
                "primary_handle": null,
            })),
        ))
        .await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["primary_handle"], serde_json::Value::Null);
}

// Removed: `did_document_resolution_uses_primary_handle_preference_as_of_query`
// exercised coauth-fabricated local user DID documents (`/users/{id}/did.json`
// + the identity resolve/document short-circuits). coauth hosts no DID
// documents any more - user principal DIDs are `did:webvh:...` served by the
// principal server.

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

// Removed: `identity_document_exposes_user_handle_binding` — it asserted the
// shape of coauth-fabricated user DID documents (`user_did_document`), which
// were deleted along with all coauth DID-document hosting.

#[test]
fn require_canonical_handle_rejects_acct_aliases() {
    let err = require_canonical_handle("acct:alice@example.com").unwrap_err();
    match err {
        CokretRouteError::BadRequest(message) => {
            assert!(
                message.starts_with(HANDLE_NOT_CANONICAL_CODE),
                "expected code prefix, got {message}"
            );
            assert!(
                message.contains("acct:"),
                "expected acct: in reason, got {message}"
            );
        }
        other => panic!("expected BadRequest, got {other:?}"),
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
    let cokret_config = CokretConfig::default();
    let mut rng = ChaChaRng::seed_from_u64(0xc15a);
    let clock = MockClock::default();
    let now = clock.now();
    let user = User::samples(now, &mut rng).into_iter().next().unwrap();
    let key_store = test_keystore();

    let hint = cokret_core::DeliveryBindingHint {
        recipient_service_did: cokret_core::Did::new("did:web:soland.example").unwrap(),
        recipient_service_type: cokret_core::RecipientServiceType::PrincipalServer,
        binding_source: cokret_core::HandleHintBindingSource::OrganizationPolicy,
        delivery_modes: [cokret_core::DeliveryMode::Events].into_iter().collect(),
        service_acceptance_ref: None,
        policy_event_ref: None,
    };

    // Subject is the soland-minted webvh principal DID, passed by the caller.
    let subject_did = "did:webvh:zQmExampleScid:soland.example:webvh:01arz3ndektsv4rrffq69g5fav";
    let material = issue_handle_claim(
        &clock,
        &url_builder,
        &cokret_config,
        &key_store,
        &user,
        subject_did,
        cokret_core::HandleClaimKind::HandleBinding,
        "did:web:space.example".to_owned(),
        hint.clone(),
    )
    .expect("handle claim must mint with the test keystore");
    assert_eq!(
        material
            .payload
            .subject
            .as_ref()
            .map(cokret_core::Did::as_str),
        Some(subject_did)
    );

    let canonical = user_handle(&url_builder, &user);
    let acct = user_handle_acct_alias(&url_builder, &user);
    // Spec 7157ee8 §3.1 — canonical `<localpart>:<domain>` form on
    // the wire `handle` field.
    assert_eq!(material.payload.schema, "ck.schema.handle_claim.v1");
    let payload_value = serde_json::to_value(&material.payload).unwrap();
    assert!(payload_value.get("type").is_none());
    let handle = material.payload.handle.as_ref().unwrap();
    assert_eq!(handle.canonical(), canonical);
    assert!(
        handle.canonical().contains(':'),
        "handle MUST be the canonical `<localpart>:<domain>` form"
    );
    assert!(
        !handle.canonical().starts_with("cokret://"),
        "handle MUST NOT carry the retired cokret:// URI form"
    );
    assert!(
        !handle.canonical().starts_with("acct:"),
        "handle MUST NOT be an acct: alias"
    );
    assert!(
        material.payload.handle_aliases.contains(&acct),
        "handle_aliases MUST carry the acct: interop form"
    );
    assert_eq!(
        material.payload.audience.as_deref(),
        Some("did:web:space.example")
    );
    assert_eq!(
        material
            .payload
            .member_delivery_binding
            .as_ref()
            .unwrap()
            .binding_source,
        hint.binding_source
    );
    // `claim_digest` moved off the spec-aligned payload onto the
    // material wrapper (audit-chain anchor only).
    assert!(material.claim_digest.starts_with("sha256:"));
    assert!(payload_value.get("claim_digest").is_none());
    assert!(material.expires_at > now);
    assert_eq!(material.payload.proofs.len(), 1);
    assert_eq!(
        material.payload.proofs[0].audience,
        Some(cokret_core::Audience::Single(
            "did:web:space.example".to_owned()
        ))
    );
    assert_eq!(material.payload.proofs[0].jws, material.claim_jwt);
    // HC-COAUTH-1 — coauth only stamps allow-listed claim_kind values.
    assert_eq!(
        material.payload.claim_kind,
        Some(cokret_core::HandleClaimKind::HandleBinding)
    );
}

#[test]
fn issue_handle_claim_accepts_organization_handle_claim_kind() {
    use coauth_data::clock::MockClock;
    let url_builder = UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None);
    let cokret_config = CokretConfig::default();
    let mut rng = ChaChaRng::seed_from_u64(0xc15b);
    let clock = MockClock::default();
    let now = clock.now();
    let user = User::samples(now, &mut rng).into_iter().next().unwrap();
    let key_store = test_keystore();

    let hint = cokret_core::DeliveryBindingHint {
        recipient_service_did: cokret_core::Did::new("did:web:soland.example").unwrap(),
        recipient_service_type: cokret_core::RecipientServiceType::PrincipalServer,
        binding_source: cokret_core::HandleHintBindingSource::OrganizationPolicy,
        delivery_modes: [cokret_core::DeliveryMode::Events].into_iter().collect(),
        service_acceptance_ref: None,
        policy_event_ref: None,
    };

    let material = issue_handle_claim(
        &clock,
        &url_builder,
        &cokret_config,
        &key_store,
        &user,
        "did:webvh:zQmExampleScid:soland.example:webvh:01arz3ndektsv4rrffq69g5fav",
        cokret_core::HandleClaimKind::OrganizationHandle,
        "did:web:space.example".to_owned(),
        hint,
    )
    .expect("organization_handle claim_kind must be accepted");
    assert_eq!(
        material.payload.claim_kind,
        Some(cokret_core::HandleClaimKind::OrganizationHandle)
    );
}
