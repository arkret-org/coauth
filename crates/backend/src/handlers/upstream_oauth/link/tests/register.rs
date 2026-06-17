use super::*;

#[tokio::test]
async fn test_register() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let mut rng = state.rng();
    let cookies = CookieHelper::new();

    let claims_imports = UpstreamOAuthProviderClaimsImports {
        handle: UpstreamOAuthProviderHandlePreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Force,
            template: None,
            on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::default(),
        },
        email: UpstreamOAuthProviderImportPreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Force,
            template: None,
        },
        ..UpstreamOAuthProviderClaimsImports::default()
    };

    let id_token_claims = serde_json::json!({
        "preferred_username": "john",
        "email": "john@example.com",
        "email_verified": true,
    });

    // Grab a key to sign the id_token
    // We could generate a key on the fly, but because we have one available here,
    // why not use it?
    let signer = state
        .key_store
        .signer_for_algorithm(&JsonWebSignatureAlg::Rs256)
        .unwrap();
    let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);
    let id_token =
        Jwt::sign_with_rng(&mut rng, header, id_token_claims.clone(), &*signer).unwrap();

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
                ui_order: 0,
                on_backchannel_logout:
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                source: coauth_data::UpstreamOAuthProviderSource::Config,
            },
        )
        .await
        .unwrap();

    let session = repo
        .upstream_oauth_session()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            "state".to_owned(),
            None,
            None,
        )
        .await
        .unwrap();

    let link = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            "subject".to_owned(),
            None,
        )
        .await
        .unwrap();

    let session = repo
        .upstream_oauth_session()
        .complete_with_link(
            &state.clock,
            session,
            &link,
            Some(id_token.into_string()),
            Some(id_token_claims),
            None,
            None,
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

    let request = Request::post(&format!("/upstream/link/{}", link.id)).form(
        serde_json::json!({
            "csrf": csrf_token,
            "action": "register",
            "import_email": "on",
            "accept_terms": "on",
        }),
    );
    let request = cookies.with_cookies(request);
    let response = state.request(request).await;
    cookies.save_cookies(&response);
    response.assert_status(StatusCode::SEE_OTHER);
    let location = response.headers().get(hyper::header::LOCATION).unwrap();
    // Grab the registration ID from the redirected URL:
    //   /register/steps/{id}/finish
    let registration_id: Ulid = str::from_utf8(location.as_bytes())
        .unwrap()
        .rsplit('/')
        .nth(1)
        .expect("Location to have two slashes")
        .parse()
        .expect("last segment of location to be a ULID");

    // Check that we have a registered user, with the email imported
    let mut repo = state.repository().await.unwrap();
    let registration: UserRegistration = repo
        .user_registration()
        .lookup(registration_id)
        .await
        .unwrap()
        .expect("user registration exists");

    assert_eq!(registration.password, None);
    assert_eq!(registration.completed_at, None);
    assert_eq!(registration.handle, "john");

    let email_auth_id = registration
        .email_authentication_id
        .expect("registration should have an email authentication");
    let email_auth: UserEmailAuthentication = repo
        .user_email()
        .lookup_authentication(email_auth_id)
        .await
        .unwrap()
        .expect("email authentication should exist");
    assert_eq!(email_auth.email, "john@example.com");
    assert!(email_auth.completed_at.is_some());
}

#[tokio::test]
async fn test_register_skip_confirmation() {
    // Same test as test_register, but checks that we get straight to the
    // registration strand skipping the confirmation
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
    let state = TestState::from_pool(pool.clone()).await.unwrap();
    let mut rng = state.rng();
    let cookies = CookieHelper::new();

    let claims_imports = UpstreamOAuthProviderClaimsImports {
        skip_confirmation: true,
        handle: UpstreamOAuthProviderHandlePreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Require,
            template: None,
            on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::default(),
        },
        email: UpstreamOAuthProviderImportPreference {
            action: coauth_data::UpstreamOAuthProviderImportAction::Force,
            template: None,
        },
        ..UpstreamOAuthProviderClaimsImports::default()
    };

    let id_token_claims = serde_json::json!({
        "preferred_username": "john",
        "email": "john@example.com",
        "email_verified": true,
    });

    // Grab a key to sign the id_token
    // We could generate a key on the fly, but because we have one available here,
    // why not use it?
    let signer = state
        .key_store
        .signer_for_algorithm(&JsonWebSignatureAlg::Rs256)
        .unwrap();
    let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);
    let id_token =
        Jwt::sign_with_rng(&mut rng, header, id_token_claims.clone(), &*signer).unwrap();

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
                ui_order: 0,
                on_backchannel_logout:
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                source: coauth_data::UpstreamOAuthProviderSource::Config,
            },
        )
        .await
        .unwrap();

    let session = repo
        .upstream_oauth_session()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            "state".to_owned(),
            None,
            None,
        )
        .await
        .unwrap();

    let link = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            "subject".to_owned(),
            None,
        )
        .await
        .unwrap();

    let session = repo
        .upstream_oauth_session()
        .complete_with_link(
            &state.clock,
            session,
            &link,
            Some(id_token.into_string()),
            Some(id_token_claims),
            None,
            None,
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
    let location = response.headers().get(hyper::header::LOCATION).unwrap();
    // Grab the registration ID from the redirected URL:
    //   /register/steps/{id}/finish
    let registration_id: Ulid = str::from_utf8(location.as_bytes())
        .unwrap()
        .rsplit('/')
        .nth(1)
        .expect("Location to have two slashes")
        .parse()
        .expect("last segment of location to be a ULID");

    // Check that we have a registered user, with the email imported
    let mut repo = state.repository().await.unwrap();
    let registration: UserRegistration = repo
        .user_registration()
        .lookup(registration_id)
        .await
        .unwrap()
        .expect("user registration exists");

    assert_eq!(registration.password, None);
    assert_eq!(registration.completed_at, None);
    assert_eq!(registration.handle, "john");

    let email_auth_id = registration
        .email_authentication_id
        .expect("registration should have an email authentication");
    let email_auth: UserEmailAuthentication = repo
        .user_email()
        .lookup_authentication(email_auth_id)
        .await
        .unwrap()
        .expect("email authentication should exist");
    assert_eq!(email_auth.email, "john@example.com");
    assert!(email_auth.completed_at.is_some());
}
