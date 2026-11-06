use std::sync::Arc;
use std::time::Duration;

use coauth_config::http::Resource;
use coauth_config::{ArkretConfig, RateLimitingConfig, StationConfig};
use coauth_data::UrlBuilder;
use coauth_keyring::{Encrypter, JsonWebKey, JsonWebKeySet, Keyring, PrivateKey};
use coauth_storage_postgres::PgRepositoryFactory;
use coauth_templates::{SiteConfigExt as _, Templates};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng as _;
use salvo::prelude::*;
use salvo::test::{ResponseExt as _, TestClient};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::build_router;
use crate::app_state::AppState;
use crate::handlers::passwords::PasswordManager;
use crate::handlers::test_utils::{policy_factory, setup, test_site_config};
use crate::handlers::{ActivityTracker, CookieManager, Limiter, MetadataCache};
use crate::services::principal_facade::DbConnectorAdmin;

async fn cold_start_state() -> (AppState, CancellationToken, TaskTracker) {
    static VERSION_INIT: std::sync::Once = std::sync::Once::new();
    VERSION_INIT.call_once(|| crate::set_version(env!("CARGO_PKG_VERSION")));
    let site_config = test_site_config();
    let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
    let workspace = camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let templates = Templates::load(
        workspace.join("templates"),
        url_builder.clone(),
        workspace.join("translations"),
        site_config.templates_branding(),
        site_config.templates_features(),
        true,
    )
    .await
    .unwrap();
    // Public bootstrap documents must work without opening a database connection.
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(
        "postgresql://unused:unused@127.0.0.1:1/unused",
    );
    let repository_factory = PgRepositoryFactory::new(Pool::builder(manager).build().unwrap());
    let arkret_config = ArkretConfig {
        stations: vec![StationConfig {
            name: "unverified".to_owned(),
            endpoint: "https://unverified.example/".parse().unwrap(),
            internal_authority_shared_secret: None,
            embedded_webvh_registration_bearer: None,
            trust_domain: None,
        }],
        ..ArkretConfig::default()
    };
    let http_client = crate::outbound_http::reqwest_client_for_tests();
    let station_admin = Arc::new(DbConnectorAdmin::new(
        &site_config.server_name,
        repository_factory.clone().boxed(),
        arkret_config.clone(),
        http_client.clone(),
    ));
    let key = JsonWebKey::new(PrivateKey::generate_ed25519(ChaChaRng::seed_from_u64(42)))
        .with_kid(coauth_keyring::ACCOUNT_AUTHORITY_KEY_ID);
    let cancellation = CancellationToken::new();
    let tasks = TaskTracker::new();
    let activity_tracker = ActivityTracker::new(
        repository_factory.clone().boxed(),
        Duration::from_secs(60),
        &tasks,
        cancellation.clone(),
    );
    let state = AppState {
        repository_factory,
        templates,
        arkret_config,
        keyring: Keyring::new(JsonWebKeySet::new(vec![key])),
        cookie_manager: CookieManager::derive_from(url_builder.http_base(), &[0x42; 32]),
        encrypter: Encrypter::new(&[0x42; 32]),
        url_builder,
        station_admin,
        connector_registry: coauth_principal::ConnectorRegistry::default(),
        policy_factory: policy_factory(&site_config.server_name, serde_json::json!({}))
            .await
            .unwrap(),
        http_client,
        password_manager: PasswordManager::disabled(),
        metadata_cache: MetadataCache::new(),
        site_config,
        activity_tracker,
        trusted_proxies: Vec::new(),
        limiter: Limiter::new(&RateLimitingConfig::default()).unwrap(),
        frontend_script_src: "/assets/bootstrap.js".to_owned(),
        email_webhook_service: None,
        max_body_bytes: 1024 * 1024,
        request_timeout_seconds: 5,
        shutdown_grace_seconds: 5,
        hsts_header: None,
        csp_html_header: None,
        verified_profiles: Arc::default(),
        development_mode: false,
    };
    (state, cancellation, tasks)
}

#[tokio::test]
async fn bootstrap_routes_receive_app_state_with_and_without_prefix() {
    setup();
    let (state, cancellation, tasks) = cold_start_state().await;
    assert!(!crate::services::station_trust::is_ready(
        &state.arkret_config
    ));

    for prefix in [
        None,
        Some(""),
        Some("/"),
        Some("/auth"),
        Some("/auth/"),
        Some("auth"),
    ] {
        let path_prefix = super::middleware::DeploymentPrefix::new(prefix);
        let base = format!("https://example.com{}/", path_prefix.0);
        let mut state = state.clone();
        state.url_builder = UrlBuilder::new(base.parse().unwrap(), None, None);
        let service = Service::new(build_router(
            state,
            &[
                Resource::Discovery,
                Resource::OAuth,
                Resource::ConnectionInfo,
            ],
            prefix,
            None,
        ));

        let mut discovery = TestClient::get(format!("{base}.well-known/openid-configuration"))
            .send(&service)
            .await;
        assert_eq!(discovery.status_code, Some(StatusCode::OK), "{prefix:?}");
        let document = discovery.take_json::<serde_json::Value>().await.unwrap();
        assert_eq!(document["jwks_uri"], format!("{base}oauth/keys.json"));

        let mut keys = TestClient::get(document["jwks_uri"].as_str().unwrap())
            .send(&service)
            .await;
        assert_eq!(keys.status_code, Some(StatusCode::OK), "{prefix:?}");
        let jwks = keys.take_json::<serde_json::Value>().await.unwrap();
        assert_eq!(
            jwks["keys"][0]["kid"],
            coauth_keyring::ACCOUNT_AUTHORITY_KEY_ID
        );
        assert_eq!(jwks["keys"][0]["crv"], "Ed25519");
        assert!(jwks["keys"][0].get("d").is_none());

        // Fixing bootstrap must not bypass the Station trust gate for business routes.
        let mut gated = TestClient::get(format!("{base}connection-info"))
            .send(&service)
            .await;
        assert_eq!(gated.status_code, Some(StatusCode::SERVICE_UNAVAILABLE));
        let error = gated.take_json::<serde_json::Value>().await.unwrap();
        assert_eq!(error["errcode"], "station_trust_unavailable");
    }

    drop(state);
    cancellation.cancel();
    tasks.close();
    tasks.wait().await;
}

#[tokio::test]
async fn mounted_protocol_routes_reach_authentication_and_keep_route_errors() {
    setup();
    let (mut state, cancellation, tasks) = cold_start_state().await;
    state.arkret_config.stations.clear();

    for prefix in [
        None,
        Some("/"),
        Some("/auth"),
        Some("/auth/"),
        Some("/tenant/auth"),
        Some("auth"),
        Some("tenant/auth/"),
    ] {
        let mount = super::middleware::DeploymentPrefix::new(prefix).0;
        let base = format!("https://example.com{mount}");
        let service = Service::new(build_router(
            state.clone(),
            &[Resource::RestApi],
            prefix,
            None,
        ));
        let handoff = format!("{base}/_arkret/gate/account/authentication-handoffs");
        let selector = "ak.gate.account.exchange.create_handoff.v1";

        let mut response = TestClient::post(&handoff)
            .add_header("Arkret-Operation", selector, true)
            .add_header("Content-Type", "application/json", true)
            .body("{}")
            .send(&service)
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "{prefix:?}"
        );
        let problem = response.take_json::<serde_json::Value>().await.unwrap();
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/signature_invalid"
        );
        assert!(
            problem["detail"]
                .as_str()
                .unwrap()
                .contains("requires a DPoP proof")
        );

        for (selectors, expected) in [
            (vec![], "operation_selector_required"),
            (
                vec!["ak.gate.account.command.logout.v1"],
                "unsupported_operation_version",
            ),
            (vec![selector, selector], "unsupported_operation_version"),
        ] {
            let mut request = TestClient::post(&handoff);
            for value in selectors {
                request = request.add_header("Arkret-Operation", value, false);
            }
            let mut response = request.body("{}").send(&service).await;
            let problem = response.take_json::<serde_json::Value>().await.unwrap();
            assert_eq!(
                problem["type"],
                format!("https://arkret.org/problems/{expected}"),
                "{prefix:?}"
            );
        }

        let mut wrong_method = TestClient::get(&handoff)
            .add_header("Arkret-Operation", selector, true)
            .send(&service)
            .await;
        assert_eq!(
            wrong_method.status_code,
            Some(StatusCode::METHOD_NOT_ALLOWED)
        );
        assert_eq!(wrong_method.headers()[http::header::ALLOW], "OPTIONS, POST");
        let problem = wrong_method.take_json::<serde_json::Value>().await.unwrap();
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/method_not_allowed"
        );

        let preflight = TestClient::options(&handoff)
            .add_header("Origin", "https://client.example", true)
            .add_header("Access-Control-Request-Method", "POST", true)
            .add_header(
                "Access-Control-Request-Headers",
                "content-type,dpop,arkret-operation",
                true,
            )
            .send(&service)
            .await;
        assert_eq!(preflight.status_code, Some(StatusCode::NO_CONTENT));
        assert_eq!(
            preflight.headers()[http::header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "*"
        );

        for path in [
            "/_arkret/missing",
            "/_arkret/describe",
            "/_arkret/gate/account/authentication-handoffs/extra",
        ] {
            let mut response = TestClient::post(format!("{base}{path}"))
                .add_header("Arkret-Operation", selector, true)
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
            let problem = response.take_json::<serde_json::Value>().await.unwrap();
            assert_eq!(
                problem["type"],
                "https://arkret.org/problems/unrecognized_endpoint"
            );
        }

        let outside = TestClient::post(format!(
            "https://example.com{mount}/other/_arkret/gate/account/authentication-handoffs"
        ))
        .add_header("Arkret-Operation", selector, true)
        .send(&service)
        .await;
        assert_eq!(outside.status_code, Some(StatusCode::NOT_FOUND));
    }

    drop(state);
    cancellation.cancel();
    tasks.close();
    tasks.wait().await;
}
