use coauth_config::{CokretConfig, IdentityRegistryKind};
use coauth_data::{SiteConfig, UrlBuilder};
use coauth_iana::oauth::{
    OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod,
    PkceCodeChallengeMethod,
};
use coauth_jose::jwa::SUPPORTED_SIGNING_ALGORITHMS;
use coauth_keystore::Keystore;
use oauth_types::oidc::{ClaimType, ProviderMetadata, SubjectType};
use oauth_types::requests::{Display, GrantType, Prompt, ResponseMode};
use oauth_types::scope;
use salvo::prelude::*;
use serde::Serialize;

use crate::handlers::cokret;

#[derive(Debug, Serialize)]
struct DiscoveryDocument {
    #[serde(flatten)]
    standard: ProviderMetadata,

    // Account management actions supported by this server.
    account_management_uri: url::Url,
    account_management_actions_supported: Vec<String>,

    #[serde(rename = "org.cokret.api_endpoint")]
    cokret_api_endpoint: String,

    #[serde(rename = "org.cokret.server_describe")]
    cokret_server_describe: String,

    #[serde(rename = "org.cokret.service_did")]
    cokret_service_did: String,

    #[serde(rename = "org.cokret.did_binding_methods")]
    cokret_did_binding_methods: Vec<String>,

    #[serde(rename = "org.cokret.supported_scopes")]
    cokret_supported_scopes: Vec<String>,

    #[serde(rename = "org.cokret.admin_audience")]
    cokret_admin_audience: String,

    #[serde(rename = "org.cokret.principal_servers")]
    cokret_principal_servers: Vec<PrincipalServerMetadata>,

    #[serde(rename = "org.cokret.identity_registry")]
    #[serde(skip_serializing_if = "Option::is_none")]
    cokret_identity_registry: Option<IdentityRegistryMetadata>,
}

#[derive(Debug, Serialize)]
struct PrincipalServerMetadata {
    name: String,
    audience: String,
    endpoint: String,
    did: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdentityRegistryMetadata {
    kind: &'static str,
    resolver: String,
    proof_required_for_pairwise: bool,
}

/// Process-wide cache of the serialized OIDC discovery document.
///
/// Every input to the discovery document — the URL builder, site config,
/// cokret config and the keystore's available signing algorithms — is fixed
/// for the lifetime of the process (a single config per process). So the
/// document only needs to be built once; subsequent requests clone the cached
/// JSON value instead of rebuilding the whole `DiscoveryDocument` and
/// re-serializing it.
///
/// We cache the serialized `serde_json::Value` (rather than the
/// `DiscoveryDocument`, which is not `Clone`) and hand it back wrapped in
/// [`Json`], which preserves the `application/json` content type and exact
/// response shape.
static DISCOVERY: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();

#[handler]
#[tracing::instrument(name = "handlers.oauth.discovery.get", skip_all)]
pub async fn get(depot: &Depot) -> Json<serde_json::Value> {
    // Populate the cache from the depot values on first request; clone the
    // cached JSON value on every subsequent request.
    let value = DISCOVERY.get_or_init(|| {
        let Json(response) = build_response(depot);
        serde_json::to_value(response)
            .expect("serializing the discovery document into a Value should never fail")
    });
    Json(value.clone())
}

/// Build the discovery document from the depot values, without caching.
///
/// Kept separate from [`get`] so the unit tests can exercise the full document
/// construction directly without going through the process-wide
/// [`OnceLock`](std::sync::OnceLock) cache.
fn build_response(depot: &Depot) -> Json<DiscoveryDocument> {
    let key_store = depot
        .get::<Keystore>("keystore")
        .expect("Keystore not found in depot");
    let url_builder = depot
        .get::<UrlBuilder>("url_builder")
        .expect("UrlBuilder not found in depot");
    let site_config = depot
        .get::<SiteConfig>("site_config")
        .expect("SiteConfig not found in depot");
    let cokret_config = depot
        .get::<CokretConfig>("cokret_config")
        .cloned()
        .unwrap_or_default();

    // This is how clients can authenticate
    let client_auth_methods_supported = Some(vec![
        OAuthClientAuthenticationMethod::ClientSecretBasic,
        OAuthClientAuthenticationMethod::ClientSecretPost,
        OAuthClientAuthenticationMethod::ClientSecretJwt,
        OAuthClientAuthenticationMethod::PrivateKeyJwt,
        OAuthClientAuthenticationMethod::None,
    ]);

    // Those are the algorithms supported by `coauth-jose`
    let client_auth_signing_alg_values_supported = Some(SUPPORTED_SIGNING_ALGORITHMS.to_vec());

    // This is how we can sign stuff
    let jwt_signing_alg_values_supported = Some(key_store.available_signing_algorithms());

    // Prepare all the endpoints
    let issuer = Some(url_builder.oidc_issuer().into());
    let authorization_endpoint = Some(url_builder.oauth_authorization_endpoint());
    let token_endpoint = Some(url_builder.oauth_token_endpoint());
    let device_authorization_endpoint = Some(url_builder.oauth_device_authorization_endpoint());
    let jwks_uri = Some(url_builder.jwks_uri());
    let introspection_endpoint = Some(url_builder.oauth_introspection_endpoint());
    let revocation_endpoint = Some(url_builder.oauth_revocation_endpoint());
    let userinfo_endpoint = Some(url_builder.oidc_userinfo_endpoint());
    let registration_endpoint = Some(url_builder.oauth_registration_endpoint());

    // `scopes_supported`: only advertise scopes whose backing claim is
    // actually emitted by `/oidc/userinfo`. The `email` standard scope is
    // intentionally NOT advertised here — coauth's userinfo response does
    // not include `email` / `email_verified`, so advertising them would
    // surface always-null claims to relying parties (round 25 OIDC
    // discovery production-stability audit).
    let scopes_supported = Some(vec![
        scope::OPENID.to_string(),
        scope::PROFILE.to_string(),
        scope::COAUTH_ADMIN.to_string(),
        scope::COKRET_ADMIN.to_string(),
        scope::COKRET_CLIENT.to_string(),
        scope::COKRET_PRINCIPAL_SERVER.to_string(),
        scope::COKRET_PRINCIPAL_SERVER_SESSION_BIND.to_string(),
    ]);

    let response_types_supported = Some(vec![
        OAuthAuthorizationEndpointResponseType::Code.into(),
        OAuthAuthorizationEndpointResponseType::IdToken.into(),
        OAuthAuthorizationEndpointResponseType::CodeIdToken.into(),
    ]);

    let response_modes_supported = Some(vec![
        ResponseMode::FormPost,
        ResponseMode::Query,
        ResponseMode::Fragment,
    ]);

    let grant_types_supported = Some(vec![
        GrantType::AuthorizationCode,
        GrantType::RefreshToken,
        GrantType::ClientCredentials,
        GrantType::DeviceCode,
    ]);

    let token_endpoint_auth_methods_supported = client_auth_methods_supported.clone();
    let token_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported.clone();

    let revocation_endpoint_auth_methods_supported = client_auth_methods_supported.clone();
    let revocation_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported.clone();

    let introspection_endpoint_auth_methods_supported =
        client_auth_methods_supported.map(|v| v.into_iter().map(Into::into).collect());
    let introspection_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported;

    // SECURITY: advertise only `S256` — `plain` is rejected at the
    // token endpoint (see `required_pkce_method_is_allowed`), so the
    // discovery document MUST NOT claim otherwise. RFC 7636 §4.2
    // marks `plain` as deprecated and OAuth 2.1 §7.5 outright bans it.
    let code_challenge_methods_supported = Some(vec![PkceCodeChallengeMethod::S256]);

    let subject_types_supported = Some(vec![SubjectType::Public]);

    let id_token_signing_alg_values_supported = jwt_signing_alg_values_supported.clone();
    let userinfo_signing_alg_values_supported = jwt_signing_alg_values_supported;

    let display_values_supported = Some(vec![Display::Page]);

    let claim_types_supported = Some(vec![ClaimType::Normal]);

    // `claims_supported`: every entry here MUST be backed by an actual
    // emit-site (id_token, /oidc/userinfo, or signed userinfo JWT). Round
    // 25 audit removed `email` / `email_verified` since coauth does not
    // surface email claims today; if email backing is added later, the
    // claims (and the `email` scope above) come back together.
    let claims_supported = Some(vec![
        "iss".to_owned(),
        "sub".to_owned(),
        "aud".to_owned(),
        "iat".to_owned(),
        "exp".to_owned(),
        "nonce".to_owned(),
        "auth_time".to_owned(),
        "at_hash".to_owned(),
        "c_hash".to_owned(),
        // Profile claims emitted by /oidc/userinfo.
        "preferred_username".to_owned(),
        "name".to_owned(),
        "picture".to_owned(),
        "locale".to_owned(),
        cokret::CLAIM_PRINCIPAL_DID.to_owned(),
        cokret::CLAIM_DEVICE_ID.to_owned(),
        cokret::CLAIM_SESSION_ID.to_owned(),
    ]);

    let claims_parameter_supported = Some(false);
    let request_parameter_supported = Some(false);
    let request_uri_parameter_supported = Some(false);

    let prompt_values_supported = Some({
        let mut v = vec![Prompt::Login];
        // Advertise for prompt=create if password registration is enabled
        // TODO: we may want to be able to forward that to upstream providers if they
        // support it
        if site_config.password_registration_enabled {
            v.push(Prompt::Create);
        }
        v
    });

    let standard = ProviderMetadata {
        issuer,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        registration_endpoint,
        scopes_supported,
        response_types_supported,
        response_modes_supported,
        grant_types_supported,
        token_endpoint_auth_methods_supported,
        token_endpoint_auth_signing_alg_values_supported,
        revocation_endpoint,
        revocation_endpoint_auth_methods_supported,
        revocation_endpoint_auth_signing_alg_values_supported,
        introspection_endpoint,
        introspection_endpoint_auth_methods_supported,
        introspection_endpoint_auth_signing_alg_values_supported,
        code_challenge_methods_supported,
        userinfo_endpoint,
        subject_types_supported,
        id_token_signing_alg_values_supported,
        userinfo_signing_alg_values_supported,
        display_values_supported,
        claim_types_supported,
        claims_supported,
        claims_parameter_supported,
        request_parameter_supported,
        request_uri_parameter_supported,
        prompt_values_supported,
        device_authorization_endpoint,
        ..ProviderMetadata::default()
    };

    let cokret_principal_servers = cokret_config
        .principal_servers
        .iter()
        .map(|server| PrincipalServerMetadata {
            name: server.name.clone(),
            audience: server.audience.clone(),
            endpoint: server.endpoint.to_string(),
            did: server.did.clone(),
        })
        .collect();
    let cokret_identity_registry =
        cokret_config
            .identity_registry
            .as_ref()
            .map(|registry| IdentityRegistryMetadata {
                kind: match registry.kind {
                    IdentityRegistryKind::PublicDidResolver => "public_did_resolver",
                    IdentityRegistryKind::External => "external",
                },
                resolver: registry.resolver.to_string(),
                proof_required_for_pairwise: registry.proof_required_for_pairwise,
            });

    Json(DiscoveryDocument {
        standard,
        account_management_uri: url_builder.account_management_uri(),
        account_management_actions_supported: vec![
            "profile".to_owned(),
            "sessions_list".to_owned(),
            "session_view".to_owned(),
            "session_end".to_owned(),
        ],
        cokret_api_endpoint: url_builder.absolute_url("/_cokret").to_string(),
        cokret_server_describe: url_builder.absolute_url("/_cokret/describe").to_string(),
        cokret_service_did: cokret::service_did_for(url_builder, &cokret_config),
        cokret_did_binding_methods: vec!["session_grant".to_owned()],
        cokret_supported_scopes: vec![
            scope::COAUTH_ADMIN.to_string(),
            scope::COKRET_ADMIN.to_string(),
            scope::COKRET_CLIENT.to_string(),
            scope::COKRET_PRINCIPAL_SERVER.to_string(),
            scope::COKRET_PRINCIPAL_SERVER_SESSION_BIND.to_string(),
        ],
        cokret_admin_audience: cokret::required_audience_for(url_builder, &cokret_config),
        cokret_principal_servers,
        cokret_identity_registry,
    })
}

#[cfg(test)]
mod tests {
    use coauth_data::UrlBuilder;
    use coauth_keystore::{JsonWebKey, JsonWebKeySet, PrivateKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    fn test_keystore() -> Keystore {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let es512 = JsonWebKey::new(PrivateKey::generate_ec_p521(&mut rng)).with_kid("test-es512");
        let eddsa = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng)).with_kid("test-eddsa");
        Keystore::new(JsonWebKeySet::new(vec![es512, eddsa]))
    }

    fn test_depot() -> Depot {
        let mut depot = Depot::new();
        depot.insert("keystore", test_keystore());
        depot.insert(
            "url_builder",
            UrlBuilder::new("https://example.com/".parse().unwrap(), None, None),
        );
        depot.insert(
            "site_config",
            crate::handlers::test_utils::test_site_config(),
        );
        depot.insert("cokret_config", CokretConfig::default());
        depot
    }

    #[tokio::test]
    async fn discovery_reports_extended_signing_algorithms() {
        crate::handlers::test_utils::setup();

        let Json(response) = build_response(&test_depot());
        let body = serde_json::to_value(response).unwrap();

        let id_token_algs: Vec<_> = body["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert_eq!(id_token_algs.len(), 2);
        assert!(id_token_algs.contains(&"ES512"));
        assert!(id_token_algs.contains(&"EdDSA"));

        let userinfo_algs: Vec<_> = body["userinfo_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert_eq!(userinfo_algs.len(), 2);
        assert!(userinfo_algs.contains(&"ES512"));
        assert!(userinfo_algs.contains(&"EdDSA"));
    }

    #[tokio::test]
    async fn discovery_advertises_cokret_scopes_and_claims() {
        crate::handlers::test_utils::setup();

        let Json(response) = build_response(&test_depot());
        let body = serde_json::to_value(response).unwrap();

        let scopes = body["scopes_supported"].as_array().unwrap();
        assert!(scopes.iter().any(|scope| scope == "urn:coauth:admin"));
        assert!(scopes.iter().any(|scope| scope == "urn:cokret:admin:*"));
        assert!(scopes.iter().any(|scope| scope == "urn:cokret:client:*"));
        assert!(
            scopes
                .iter()
                .any(|scope| scope == "urn:cokret:principal-server:*")
        );
        assert!(
            scopes
                .iter()
                .any(|scope| scope == "urn:cokret:principal-server:session.bind")
        );

        let cokret_scopes = body["org.cokret.supported_scopes"].as_array().unwrap();
        assert!(
            cokret_scopes
                .iter()
                .any(|scope| scope == "urn:cokret:principal-server:session.bind")
        );

        let claims = body["claims_supported"].as_array().unwrap();
        assert!(
            claims
                .iter()
                .any(|claim| claim == cokret::CLAIM_PRINCIPAL_DID)
        );
        assert!(claims.iter().any(|claim| claim == cokret::CLAIM_DEVICE_ID));
        assert!(claims.iter().any(|claim| claim == cokret::CLAIM_SESSION_ID));
    }

    /// Round 25 production-stability audit: `email` scope and
    /// `email_verified` claim must NOT appear, because no emit site backs
    /// them. Tightening keeps the discovery contract honest.
    #[tokio::test]
    async fn discovery_does_not_advertise_unbacked_email_claims() {
        crate::handlers::test_utils::setup();

        let Json(response) = build_response(&test_depot());
        let body = serde_json::to_value(response).unwrap();

        let scopes = body["scopes_supported"].as_array().unwrap();
        assert!(
            scopes.iter().all(|scope| scope != "email"),
            "discovery must not advertise the `email` scope when no userinfo backing exists"
        );

        let claims = body["claims_supported"].as_array().unwrap();
        for forbidden in ["email", "email_verified"] {
            assert!(
                claims.iter().all(|claim| claim != forbidden),
                "discovery must not advertise `{forbidden}` without an emit site"
            );
        }
    }

    /// Snapshot the full set of scopes and claims so accidental drift in
    /// either direction surfaces as a test diff. Endpoint URLs / signing
    /// algorithms are intentionally excluded — they are environment- and
    /// keystore-specific and covered by other tests.
    #[tokio::test]
    async fn discovery_scopes_and_claims_snapshot() {
        crate::handlers::test_utils::setup();

        let Json(response) = build_response(&test_depot());
        let body = serde_json::to_value(response).unwrap();

        let mut scopes: Vec<String> = body["scopes_supported"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        scopes.sort();

        let mut claims: Vec<String> = body["claims_supported"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        claims.sort();

        let snapshot = serde_json::json!({
            "scopes_supported": scopes,
            "claims_supported": claims,
        });

        insta::assert_json_snapshot!("discovery_scopes_and_claims", snapshot,);
    }
}
