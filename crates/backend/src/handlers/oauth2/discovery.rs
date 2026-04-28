use oauth2_types::{
    oidc::{ClaimType, ProviderMetadata, SubjectType},
    requests::{Display, GrantType, Prompt, ResponseMode},
    scope,
};
use coauth_data::{SiteConfig, UrlBuilder};
use coauth_iana::oauth::{
    OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod,
    PkceCodeChallengeMethod,
};
use coauth_jose::jwa::SUPPORTED_SIGNING_ALGORITHMS;
use coauth_keystore::Keystore;
use salvo::prelude::*;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct DiscoveryResponse {
    #[serde(flatten)]
    standard: ProviderMetadata,

    #[serde(rename = "org.matrix.coauth.api_endpoint")]
    api_endpoint: String,

    // As per MSC2965
    account_management_uri: url::Url,
    account_management_actions_supported: Vec<String>,
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.discovery.get", skip_all)]
pub async fn get(depot: &Depot) -> Json<DiscoveryResponse> {
    get_inner(depot)
}

fn get_inner(depot: &Depot) -> Json<DiscoveryResponse> {
    let key_store = depot
        .get::<Keystore>("keystore")
        .expect("Keystore not found in depot");
    let url_builder = depot
        .get::<UrlBuilder>("url_builder")
        .expect("UrlBuilder not found in depot");
    let site_config = depot
        .get::<SiteConfig>("site_config")
        .expect("SiteConfig not found in depot");

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

    let scopes_supported = Some(vec![scope::OPENID.to_string(), scope::EMAIL.to_string()]);

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

    let code_challenge_methods_supported = Some(vec![
        PkceCodeChallengeMethod::Plain,
        PkceCodeChallengeMethod::S256,
    ]);

    let subject_types_supported = Some(vec![SubjectType::Public]);

    let id_token_signing_alg_values_supported = jwt_signing_alg_values_supported.clone();
    let userinfo_signing_alg_values_supported = jwt_signing_alg_values_supported;

    let display_values_supported = Some(vec![Display::Page]);

    let claim_types_supported = Some(vec![ClaimType::Normal]);

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

    Json(DiscoveryResponse {
        standard,
        api_endpoint: format!("{}/api/v1", url_builder.prefix().unwrap_or_default()),
        account_management_uri: url_builder.account_management_uri(),
        // This needs to be kept in sync with what is supported in the frontend,
        // see frontend/src/routes/__root.tsx
        account_management_actions_supported: vec![
            "org.matrix.profile".to_owned(),
            "org.matrix.sessions_list".to_owned(),
            "org.matrix.session_view".to_owned(),
            "org.matrix.session_end".to_owned(),
            "org.matrix.cross_signing_reset".to_owned(),
        ],
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
        depot
    }

    #[tokio::test]
    async fn discovery_reports_extended_signing_algorithms() {
        crate::handlers::test_utils::setup();

        let Json(response) = get_inner(&test_depot());
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
}
