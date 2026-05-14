//! Integration tests for the password-login flow.
//!
//! Was the larger half of the original `views/login.rs`. Wrapping the
//! body in a single `mod tests` keeps the original 4-space indentation
//! and the original `use crate::handlers::...` paths intact, so the move
//! is purely textual.

#[cfg(test)]
mod tests {
    use hyper::{
        Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };
    use oauth_types::scope::OPENID;
    use coauth_data::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_data::{
        RepositoryAccess,
        upstream_oauth::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
    };
    use coauth_templates::escape_html;
    use zeroize::Zeroizing;

    use coauth_data::SiteConfig;

    use crate::handlers::account::DepotExt;
    use crate::handlers::test_utils::{
        CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
    };

    #[tokio::test]
    async fn test_password_disabled() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool_with_site_config(
            pool.clone(),
            SiteConfig {
                password_login_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let mut rng = state.rng();

        // Without password login and no upstream providers, we should get an error
        // message
        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(
            response.body().contains("No login methods available"),
            "Response body: {}",
            response.body()
        );

        // Adding an upstream provider should redirect to it
        let mut repo = state.repository().await.unwrap();
        let first_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://first.com/".to_owned()),
                    human_name: Some("First Ltd.".to_owned()),
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let first_provider_path = format!("/upstream/authorize/{}", first_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, &first_provider_path);

        // Adding a second provider should show a login page with both providers
        let mut repo = state.repository().await.unwrap();
        let second_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://second.com/".to_owned()),
                    human_name: None,
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 1,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let second_provider_path = format!("/upstream/authorize/{}", second_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains(&escape_html("First Ltd.")));
        assert!(
            response
                .body()
                .contains(&escape_html(&first_provider_path))
        );
        assert!(response.body().contains(&escape_html("second.com")));
        assert!(
            response
                .body()
                .contains(&escape_html(&second_provider_path))
        );
    }

    async fn user_with_password(
        state: &TestState,
        username: &str,
        password: &str,
    ) -> coauth_data::User {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.to_owned())
            .await
            .unwrap();
        let (version, hash) = state
            .password_manager
            .hash(&mut rng, Zeroizing::new(password.to_owned()))
            .await
            .unwrap();
        repo.user_password()
            .add(&mut rng, &state.clock, &user, version, hash, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        user
    }

    #[tokio::test]
    async fn test_password_login() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        user_with_password(&state, "john", "hunter2").await;

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Now if we get to the home page, we should see the user's username
        let request = Request::get("/").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("john"));
    }

    #[tokio::test]
    async fn test_password_login_with_principal_id() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        user_with_password(&state, "john", "hunter2").await;

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "@john:example.com",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Now if we get to the home page, we should see the user's username
        let request = Request::get("/").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("john"));
    }

    #[tokio::test]
    async fn test_password_login_with_principal_id_wrong_server() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        user_with_password(&state, "john", "hunter2").await;

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "@john:something.corp",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;

        // This shouldn't have worked, we're back on the login page
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Invalid credentials"));
    }

    #[tokio::test]
    async fn test_password_login_rate_limit() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        // Provision a user without a password.
        // We don't give that user a password, so that we skip hashing it in this test.
        // It will still be rate-limited
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);

        // First three attempts should just tell about the invalid credentials
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        // The fourth attempt should be rate-limited
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(!body.contains("Invalid credentials"));
        assert!(body.contains("too many requests"));
    }

    #[tokio::test]
    async fn test_password_login_locked_account() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        let user = user_with_password(&state, "john", "hunter2").await;

        // Lock the user
        let mut repo = state.repository().await.unwrap();
        repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("Account locked"));

        // A bad password should not disclose that the account is locked
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "badpassword",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(!response.body().contains("Account locked"));
        assert!(response.body().contains("Invalid credentials"));
    }

    #[tokio::test]
    async fn test_password_login_deactivated_account() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        let user = user_with_password(&state, "john", "hunter2").await;

        // Deactivate the user
        let mut repo = state.repository().await.unwrap();
        repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("Account deleted"));

        // A bad password should not disclose that the account is deleted
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "badpassword",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(!response.body().contains("Account deleted"));
        assert!(response.body().contains("Invalid credentials"));
    }
}
