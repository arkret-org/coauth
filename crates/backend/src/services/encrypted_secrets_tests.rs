use coauth_data::clock::MockClock;
use coauth_data::oauth::OAuthClientRepository as _;
use coauth_data::upstream_oauth::{
    UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository as _, provider,
};
use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_keyring::{Encrypter, JsonWebKeySet, Keyring};
use coauth_oauth_types::scope::{OPENID, Scope};
use coauth_storage_postgres::PgRepositoryFactory;
use rand_core::SeedableRng as _;
use ulid::Ulid;

use crate::handlers::upstream_oauth::client_credentials_for_provider;
use crate::oidc_client::types::client_credentials::ClientCredentials;

fn provider_params(
    secret: String,
    method: provider::TokenAuthMethod,
) -> UpstreamOAuthProviderParams {
    UpstreamOAuthProviderParams {
        oidc_issuer_uri: Some("https://provider.example/".to_owned()),
        human_name: None,
        brand_name: None,
        scope: Scope::from_iter([OPENID]),
        token_endpoint_auth_method: method,
        id_token_signed_response_alg: JsonWebSignatureAlg::Ed25519,
        fetch_userinfo: false,
        userinfo_signed_response_alg: None,
        token_endpoint_signing_alg: None,
        client_id: "r06-client".to_owned(),
        encrypted_client_secret: Some(secret),
        claims_imports: provider::ClaimsImports::default(),
        token_endpoint_override: None,
        authorization_endpoint_override: None,
        userinfo_endpoint_override: None,
        jwks_uri_override: None,
        discovery_mode: provider::DiscoveryMode::Oidc,
        pkce_mode: provider::PkceMode::Auto,
        response_mode: None,
        additional_authorization_parameters: Vec::new(),
        forward_login_hint: false,
        ui_order: 0,
        on_backchannel_logout: provider::OnBackchannelLogout::DoNothing,
        source: provider::ProviderSource::Config,
    }
}

#[tokio::test]
async fn legacy_and_fresh_encrypted_rows_are_read_by_actual_secret_consumers() {
    let pool = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("isolated PostgreSQL database required");
    let factory = PgRepositoryFactory::new(pool.clone());
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../keyring/tests/fixtures/encrypted_secrets.json"
    ))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    let encrypter = Encrypter::new(&[0x42; 32]);
    let keyring = Keyring::new(JsonWebKeySet::new(Vec::new()));
    let endpoint = "https://provider.example/token".parse().unwrap();
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(906);
    let clock = MockClock::default();
    let client_id = Ulid::from(906_u128);
    let mut repo = factory.create().await.unwrap();
    repo.oauth_client()
        .upsert_static(
            client_id,
            None,
            OAuthClientAuthenticationMethod::ClientSecretBasic,
            Some(cases[1]["frame_base64"].as_str().unwrap().to_owned()),
            None,
            None,
            Vec::new(),
        )
        .await
        .unwrap();
    let mut ids = Vec::new();
    for (case, method) in [
        (&cases[0], provider::TokenAuthMethod::ClientSecretBasic),
        (&cases[2], provider::TokenAuthMethod::SignInWithApple),
    ] {
        let stored = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &clock,
                provider_params(case["frame_base64"].as_str().unwrap().to_owned(), method),
            )
            .await
            .unwrap();
        ids.push(stored.id);
    }
    let fresh_secret = encrypter
        .encrypt_to_string(b"fresh-provider-secret")
        .unwrap();
    let fresh = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &clock,
            provider_params(fresh_secret, provider::TokenAuthMethod::ClientSecretBasic),
        )
        .await
        .unwrap();
    ids.push(fresh.id);
    repo.save().await.unwrap();

    // A new repository transaction reads committed rows; values came from
    // the pre-upgrade fixture or the current runtime's normal writer.
    let mut repo = factory.create().await.unwrap();
    let client = repo
        .oauth_client()
        .lookup(client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client.encrypted_client_secret.as_deref(),
        cases[1]["frame_base64"].as_str()
    );
    assert_eq!(
        encrypter
            .decrypt_string(client.encrypted_client_secret.as_deref().unwrap())
            .unwrap(),
        cases[1]["plaintext"].as_str().unwrap().as_bytes()
    );
    let http_client = reqwest::Client::new();
    let replay_store = crate::services::dpop::DpopVerifier::new();
    let credentials = crate::salvo_utils::client_authorization::Credentials::ClientSecretBasic {
        client_id: client_id.to_string(),
        client_secret: cases[1]["plaintext"].as_str().unwrap().to_owned(),
    };
    let wrong_key = Encrypter::new(&[0x43; 32]);
    for (key, accepted) in [(&encrypter, true), (&wrong_key, false)] {
        let result = credentials
            .verify(
                crate::salvo_utils::client_authorization::CredentialsVerificationParams {
                    http_client: &http_client,
                    encrypter: key,
                    method: &OAuthClientAuthenticationMethod::ClientSecretBasic,
                    client: &client,
                    expected_audience: "https://auth.example/token",
                    now: chrono::Utc::now(),
                    replay_store: &replay_store,
                },
            )
            .await;
        assert_eq!(result.is_ok(), accepted);
    }
    for (index, id) in ids.into_iter().enumerate() {
        let stored = repo
            .upstream_oauth_provider()
            .lookup(id)
            .await
            .unwrap()
            .unwrap();
        let credentials =
            client_credentials_for_provider(&stored, &endpoint, &keyring, &encrypter).unwrap();
        match (index, credentials) {
            (0, ClientCredentials::ClientSecretBasic { client_secret, .. }) => {
                assert_eq!(client_secret, cases[0]["plaintext"]);
            }
            (
                1,
                ClientCredentials::SignInWithApple {
                    key_id, team_id, ..
                },
            ) => {
                assert_eq!(key_id, "KEYR06");
                assert_eq!(team_id, "TEAMR06");
            }
            (2, ClientCredentials::ClientSecretBasic { client_secret, .. }) => {
                assert_eq!(client_secret, "fresh-provider-secret");
            }
            _ => panic!("unexpected credential mode for row {index}"),
        }
        assert!(
            client_credentials_for_provider(
                &stored,
                &endpoint,
                &keyring,
                &Encrypter::new(&[0x43; 32])
            )
            .is_err()
        );
    }
    repo.cancel().await.unwrap();
}
