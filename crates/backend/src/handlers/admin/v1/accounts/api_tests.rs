// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the admin accounts endpoints that were folded in
//! from the removed `/_coauth/admin/users/*` tree (create / batch-invite /
//! profile patch / set-password). The pre-existing accounts lifecycle and
//! risk-action workflow tests live inline in `accounts.rs`.

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use chrono::Duration;
    use coauth_data::RepositoryAccess;
    use coauth_data::user::{UserPasswordRepository, UserRepository};
    use coauth_principal::{ConnectorAdmin, ConnectorProvisionRequest};
    use hyper::{Request, StatusCode};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ulid::Ulid;
    use zeroize::Zeroizing;

    use crate::handlers::passwords::{PasswordManager, PasswordVerificationResult};
    use crate::handlers::test_utils::{
        RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
    };

    #[tokio::test]
    async fn test_add_account() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post("/_coauth/admin/accounts")
            .bearer(&token)
            .json(serde_json::json!({
                "handle": "alice",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "account");
        let id = body["data"]["id"].as_str().unwrap();
        assert_eq!(body["data"]["attributes"]["handle"], "alice");

        // Check that the user was created in the database
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .lookup(id.parse().unwrap())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.localpart, "alice");

        // Check that the user was created on the Station
        let result = state.station_admin.query_user("alice").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_add_account_invalid_username() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post("/_coauth/admin/accounts")
            .bearer(&token)
            .json(serde_json::json!({
                "handle": "this is invalid",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "Username is not valid");
    }

    #[tokio::test]
    async fn test_add_account_exists() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post("/_coauth/admin/accounts")
            .bearer(&token)
            .json(serde_json::json!({
                "handle": "alice",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "account");
        assert_eq!(body["data"]["attributes"]["handle"], "alice");

        let request = Request::post("/_coauth/admin/accounts")
            .bearer(&token)
            .json(serde_json::json!({
                "handle": "alice",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "User already exists");
    }

    #[tokio::test]
    async fn test_set_password() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Create a user
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        // Double-check that the user doesn't have a password
        let user_password = repo.user_password().active(&user).await.unwrap();
        assert!(user_password.is_none());

        repo.save().await.unwrap();

        let user_id = user.id;

        // Set the password through the API
        let request = Request::post(format!("/_coauth/admin/accounts/{user_id}/set-password"))
            .bearer(&token)
            .json(serde_json::json!({
                "password": "this is a good enough password",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Check that the user now has a password
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap().unwrap();
        let password = Zeroizing::new(String::from("this is a good enough password"));
        let res = state
            .password_manager
            .verify(
                user_password.version,
                password,
                user_password.hashed_password,
            )
            .await
            .unwrap();
        assert_eq!(res, PasswordVerificationResult::Matched(()));
    }

    #[tokio::test]
    async fn test_weak_password() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Create a user
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let user_id = user.id;

        // Set a weak password through the API
        let request = Request::post(format!("/_coauth/admin/accounts/{user_id}/set-password"))
            .bearer(&token)
            .json(serde_json::json!({
                "password": "password",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        // Check that the user still has a password
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap();
        assert!(user_password.is_none());
        repo.save().await.unwrap();

        // Now try with the skip_password_check flag
        let request = Request::post(format!("/_coauth/admin/accounts/{user_id}/set-password"))
            .bearer(&token)
            .json(serde_json::json!({
                "password": "password",
                "skip_password_check": true,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Check that the user now has a password
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap().unwrap();
        let password = Zeroizing::new("password".to_owned());
        let res = state
            .password_manager
            .verify(
                user_password.version,
                password,
                user_password.hashed_password,
            )
            .await
            .unwrap();
        assert_eq!(res, PasswordVerificationResult::Matched(()));
    }

    #[tokio::test]
    async fn test_unknown_account() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Set the password through the API
        let request =
            Request::post("/_coauth/admin/accounts/01040G2081040G2081040G2081/set-password")
                .bearer(&token)
                .json(serde_json::json!({
                    "password": "this is a good enough password",
                }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);

        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Account ID 01040G2081040G2081040G2081 not found"
        );
    }

    #[tokio::test]
    async fn test_disabled() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        state.password_manager = PasswordManager::disabled();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request =
            Request::post("/_coauth/admin/accounts/01040G2081040G2081040G2081/set-password")
                .bearer(&token)
                .json(serde_json::json!({
                    "password": "hunter2",
                }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "Password auth is disabled");
    }

    #[tokio::test]
    async fn test_patch_account_profile_and_state() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        // Patching `locked` is an account-status transition: it needs a single
        // configured Station as the publication destination and an
        // accepted principal binding for the account.
        let mut state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:coauth:admin").await;
        let username = format!("alice{}", Ulid::generate().to_string().to_lowercase());
        let mut rng = ChaChaRng::seed_from_u64(unique);

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.clone())
            .await
            .unwrap();
        state
            .station_admin
            .provision_user(&ConnectorProvisionRequest::new(&user.localpart, &user.sub))
            .await
            .unwrap();
        repo.save().await.unwrap();
        state.seed_principal_binding(&user, "patchprofile").await;

        let request = Request::patch(format!("/_coauth/admin/accounts/{}", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "display_name": "Alice Admin",
                "preferred_locale": "zh-CN",
                "admin": true,
                "locked": true
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["attributes"]["display_name"], "Alice Admin");
        // The locale is stored as a supported language tag, so a regional
        // request tag is narrowed to the language it resolves to.
        assert_eq!(body["data"]["attributes"]["preferred_locale"], "zh");
        assert_eq!(body["data"]["attributes"]["admin"], true);
        assert!(body["data"]["attributes"]["locked_at"].is_string());

        let user = state.station_admin.query_user(&username).await.unwrap();
        assert_eq!(user.displayname.as_deref(), Some("Alice Admin"));
    }

    #[tokio::test]
    async fn test_patch_account_rejects_deactivated_to_active() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:coauth:admin").await;
        let username = format!("alice{}", Ulid::generate().to_string().to_lowercase());
        let mut rng = ChaChaRng::seed_from_u64(unique);

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username)
            .await
            .unwrap();
        let user = repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        state
            .station_admin
            .provision_user(&ConnectorProvisionRequest::new(&user.localpart, &user.sub))
            .await
            .unwrap();

        let request = Request::patch(format!("/_coauth/admin/accounts/{}", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "deactivated": false
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let principal_user = state
            .station_admin
            .query_user(&user.localpart)
            .await
            .unwrap();
        assert!(principal_user.deactivated);
    }
}
