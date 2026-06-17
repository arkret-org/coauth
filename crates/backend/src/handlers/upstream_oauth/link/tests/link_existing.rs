use super::*;

#[tokio::test]
async fn test_link_existing_account() {
    let existing_username = "john";
    let subject = "subject";

    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let mut rng = state.rng();
    let cookies = CookieHelper::new();

    let claims_imports = UpstreamOAuthProviderClaimsImports {
        handle: UpstreamOAuthProviderHandlePreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
            // This is the important bit: this will automatically link
            // existing accounts if the username matches
            on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::Add,
        },
        email: UpstreamOAuthProviderImportPreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
        },
        ..UpstreamOAuthProviderClaimsImports::default()
    };

    //`preferred_username` matches an existing user's username
    let id_token_claims = serde_json::json!({
        "preferred_username": existing_username,
        "email": "any@example.com",
        "email_verified": true,
    });

    let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

    // Provision a provider and a link
    let mut repo = state.repository().await.unwrap();
    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            UpstreamOAuthProviderParams {
                issuer: Some("https://example.com/".to_owned()),
                human_name: Some("Example Ltd.".to_owned()),
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                client_id: "client".to_owned(),
                encrypted_client_secret: None,
                claims_imports,
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                userinfo_endpoint_override: None,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                jwks_uri_override: None,
                discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                on_backchannel_logout:
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                ui_order: 0,
                source: coauth_data::UpstreamOAuthProviderSource::Config,
            },
        )
        .await
        .unwrap();

    //provision upstream authorization session to setup cookies
    let (link, session) = add_linked_upstream_session(
        &mut rng,
        &state.clock,
        &mut repo,
        &provider,
        subject,
        &id_token.into_string(),
        id_token_claims,
    )
    .await
    .unwrap();

    let cookie_jar = state.cookie_jar();
    let upstream_sessions = UpstreamSessionsCookie::default()
        .add(session.id, provider.id, "state".to_owned(), None)
        .add_link_to_session(session.id, link.id)
        .unwrap();
    let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
    cookies.import(cookie_jar);

    let user = repo
        .user()
        .add(&mut rng, &state.clock, existing_username.to_owned())
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request =
        Request::get(&format!("/upstream/link/{}", link.id)).empty();
    let request = cookies.with_cookies(request);
    let response = state.request(request).await;
    cookies.save_cookies(&response);
    response.assert_status(StatusCode::SEE_OTHER);

    // Check that the existing user has the oidc link
    let mut repo = state.repository().await.unwrap();

    let link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, subject)
        .await
        .unwrap()
        .expect("link exists");

    assert_eq!(link.user_id, Some(user.id));
}

#[tokio::test]
async fn test_link_existing_account_when_not_allowed_by_default() {
    let existing_username = "john";

    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let mut rng = state.rng();
    let cookies = CookieHelper::new();

    let claims_imports = UpstreamOAuthProviderClaimsImports {
        handle: UpstreamOAuthProviderHandlePreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
            on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::default(),
        },
        email: UpstreamOAuthProviderImportPreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
        },
        ..UpstreamOAuthProviderClaimsImports::default()
    };

    // `preferred_username` matches an existing user's username
    let id_token_claims = serde_json::json!({
        "preferred_username": existing_username,
        "email": "any@example.com",
        "email_verified": true,
    });

    let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

    // Provision a provider and a link
    let mut repo = state.repository().await.unwrap();
    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            UpstreamOAuthProviderParams {
                issuer: Some("https://example.com/".to_owned()),
                human_name: Some("Example Ltd.".to_owned()),
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                client_id: "client".to_owned(),
                encrypted_client_secret: None,
                claims_imports,
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                userinfo_endpoint_override: None,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                jwks_uri_override: None,
                discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                on_backchannel_logout:
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                ui_order: 0,
                source: coauth_data::UpstreamOAuthProviderSource::Config,
            },
        )
        .await
        .unwrap();

    let (link, session) = add_linked_upstream_session(
        &mut rng,
        &state.clock,
        &mut repo,
        &provider,
        "subject",
        &id_token.into_string(),
        id_token_claims,
    )
    .await
    .unwrap();

    // Provision an user
    repo.user()
        .add(&mut rng, &state.clock, existing_username.to_owned())
        .await
        .unwrap();

    repo.save().await.unwrap();

    let cookie_jar = state.cookie_jar();
    let upstream_sessions = UpstreamSessionsCookie::default()
        .add(session.id, provider.id, "state".to_owned(), None)
        .add_link_to_session(session.id, link.id)
        .unwrap();
    let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
    cookies.import(cookie_jar);

    let request =
        Request::get(&format!("/upstream/link/{}", link.id)).empty();
    let request = cookies.with_cookies(request);
    let response = state.request(request).await;
    cookies.save_cookies(&response);
    response.assert_status(StatusCode::OK);
    response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

    assert!(response.body().contains("Unexpected error"));
}

#[tokio::test]
async fn test_link_existing_account_replace_conflict() {
    let existing_username = "john";
    let subject = "subject";
    let old_subject = "old_subject";

    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let mut rng = state.rng();
    let cookies = CookieHelper::new();

    let claims_imports = UpstreamOAuthProviderClaimsImports {
        handle: UpstreamOAuthProviderHandlePreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
            // This will replace any existing links for this provider and user
            on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::Replace,
        },
        email: UpstreamOAuthProviderImportPreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
        },
        ..UpstreamOAuthProviderClaimsImports::default()
    };

    let id_token_claims = serde_json::json!({
        "preferred_username": existing_username,
        "email": "any@example.com",
        "email_verified": true,
    });

    let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

    // Provision a provider and a link
    let mut repo = state.repository().await.unwrap();
    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            UpstreamOAuthProviderParams {
                issuer: Some("https://example.com/".to_owned()),
                human_name: Some("Example Ltd.".to_owned()),
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                client_id: "client".to_owned(),
                encrypted_client_secret: None,
                claims_imports,
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                userinfo_endpoint_override: None,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                jwks_uri_override: None,
                discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                on_backchannel_logout:
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                ui_order: 0,
                source: coauth_data::UpstreamOAuthProviderSource::Config,
            },
        )
        .await
        .unwrap();

    // Create an existing user
    let user = repo
        .user()
        .add(&mut rng, &state.clock, existing_username.to_owned())
        .await
        .unwrap();

    // Create an existing link for this user and provider with a different subject
    let old_link = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            old_subject.to_owned(),
            None,
        )
        .await
        .unwrap();

    repo.upstream_oauth_link()
        .associate_to_user(&old_link, &user)
        .await
        .unwrap();

    // Provision upstream authorization session to setup cookies
    let (link, session) = add_linked_upstream_session(
        &mut rng,
        &state.clock,
        &mut repo,
        &provider,
        subject,
        &id_token.into_string(),
        id_token_claims,
    )
    .await
    .unwrap();

    repo.save().await.unwrap();

    let cookie_jar = state.cookie_jar();
    let upstream_sessions = UpstreamSessionsCookie::default()
        .add(session.id, provider.id, "state".to_owned(), None)
        .add_link_to_session(session.id, link.id)
        .unwrap();
    let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
    cookies.import(cookie_jar);

    let request =
        Request::get(&format!("/upstream/link/{}", link.id)).empty();
    let request = cookies.with_cookies(request);
    let response = state.request(request).await;
    cookies.save_cookies(&response);
    response.assert_status(StatusCode::SEE_OTHER);

    // Check that the new link is associated with the existing user
    let mut repo = state.repository().await.unwrap();

    let new_link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, subject)
        .await
        .unwrap()
        .expect("new link exists");

    assert_eq!(new_link.user_id, Some(user.id));

    // Check that the old link was removed
    let old_link_result = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, old_subject)
        .await
        .unwrap();

    assert!(
        old_link_result.is_none(),
        "Old link should have been removed"
    );
}

#[tokio::test]
async fn test_link_existing_account_set_conflict_success() {
    let existing_username = "john";
    let subject = "subject";

    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let mut rng = state.rng();
    let cookies = CookieHelper::new();

    let claims_imports = UpstreamOAuthProviderClaimsImports {
        handle: UpstreamOAuthProviderHandlePreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
            // This will only link if there are no existing links for this provider and user
            on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::Set,
        },
        email: UpstreamOAuthProviderImportPreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
        },
        ..UpstreamOAuthProviderClaimsImports::default()
    };

    let id_token_claims = serde_json::json!({
        "preferred_username": existing_username,
        "email": "any@example.com",
        "email_verified": true,
    });

    let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

    // Provision a provider and a link
    let mut repo = state.repository().await.unwrap();
    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            UpstreamOAuthProviderParams {
                issuer: Some("https://example.com/".to_owned()),
                human_name: Some("Example Ltd.".to_owned()),
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                client_id: "client".to_owned(),
                encrypted_client_secret: None,
                claims_imports,
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                userinfo_endpoint_override: None,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                jwks_uri_override: None,
                discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                on_backchannel_logout:
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                ui_order: 0,
                source: coauth_data::UpstreamOAuthProviderSource::Config,
            },
        )
        .await
        .unwrap();

    // Create an existing user (with no existing links for this provider)
    let user = repo
        .user()
        .add(&mut rng, &state.clock, existing_username.to_owned())
        .await
        .unwrap();

    // Provision upstream authorization session to setup cookies
    let (link, session) = add_linked_upstream_session(
        &mut rng,
        &state.clock,
        &mut repo,
        &provider,
        subject,
        &id_token.into_string(),
        id_token_claims,
    )
    .await
    .unwrap();

    repo.save().await.unwrap();

    let cookie_jar = state.cookie_jar();
    let upstream_sessions = UpstreamSessionsCookie::default()
        .add(session.id, provider.id, "state".to_owned(), None)
        .add_link_to_session(session.id, link.id)
        .unwrap();
    let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
    cookies.import(cookie_jar);

    let request =
        Request::get(&format!("/upstream/link/{}", link.id)).empty();
    let request = cookies.with_cookies(request);
    let response = state.request(request).await;
    cookies.save_cookies(&response);
    response.assert_status(StatusCode::SEE_OTHER);

    // Check that the new link is associated with the existing user
    let mut repo = state.repository().await.unwrap();

    let new_link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, subject)
        .await
        .unwrap()
        .expect("new link exists");

    assert_eq!(new_link.user_id, Some(user.id));
}

#[tokio::test]
async fn test_link_existing_account_set_conflict_failure() {
    let existing_username = "john";
    let subject = "subject";
    let old_subject = "old_subject";

    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let mut rng = state.rng();
    let cookies = CookieHelper::new();

    let claims_imports = UpstreamOAuthProviderClaimsImports {
        handle: UpstreamOAuthProviderHandlePreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
            // This will only link if there are no existing links for this provider and user
            on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::Set,
        },
        email: UpstreamOAuthProviderImportPreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
        },
        ..UpstreamOAuthProviderClaimsImports::default()
    };

    let id_token_claims = serde_json::json!({
        "preferred_username": existing_username,
        "email": "any@example.com",
        "email_verified": true,
    });

    let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

    // Provision a provider and a link
    let mut repo = state.repository().await.unwrap();
    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            UpstreamOAuthProviderParams {
                issuer: Some("https://example.com/".to_owned()),
                human_name: Some("Example Ltd.".to_owned()),
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                client_id: "client".to_owned(),
                encrypted_client_secret: None,
                claims_imports,
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                userinfo_endpoint_override: None,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                jwks_uri_override: None,
                discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                on_backchannel_logout:
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                ui_order: 0,
                source: coauth_data::UpstreamOAuthProviderSource::Config,
            },
        )
        .await
        .unwrap();

    // Create an existing user
    let user = repo
        .user()
        .add(&mut rng, &state.clock, existing_username.to_owned())
        .await
        .unwrap();

    // Create an existing link for this user and provider with a different subject
    let old_link = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            old_subject.to_owned(),
            None,
        )
        .await
        .unwrap();

    repo.upstream_oauth_link()
        .associate_to_user(&old_link, &user)
        .await
        .unwrap();

    // Provision upstream authorization session to setup cookies
    let (link, session) = add_linked_upstream_session(
        &mut rng,
        &state.clock,
        &mut repo,
        &provider,
        subject,
        &id_token.into_string(),
        id_token_claims,
    )
    .await
    .unwrap();

    repo.save().await.unwrap();

    let cookie_jar = state.cookie_jar();
    let upstream_sessions = UpstreamSessionsCookie::default()
        .add(session.id, provider.id, "state".to_owned(), None)
        .add_link_to_session(session.id, link.id)
        .unwrap();
    let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
    cookies.import(cookie_jar);

    let request =
        Request::get(&format!("/upstream/link/{}", link.id)).empty();
    let request = cookies.with_cookies(request);
    let response = state.request(request).await;
    cookies.save_cookies(&response);

    // Should return an error page because the user already has a link for this
    // provider
    response.assert_status(StatusCode::OK);
    response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

    // Verify the error message is displayed
    assert!(response.body().contains("User exists"));
    assert!(response.body().contains("replacing upstream account links"));

    // Check that the new link was NOT associated with the existing user
    let mut repo = state.repository().await.unwrap();

    let new_link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, subject)
        .await
        .unwrap()
        .expect("new link exists");

    // The new link should still not be associated with the user
    assert_eq!(new_link.user_id, None);

    // Check that the old link is still there
    let old_link_result = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, old_subject)
        .await
        .unwrap();

    assert!(old_link_result.is_some(), "Old link should still exist");
    assert_eq!(old_link_result.unwrap().user_id, Some(user.id));
}
