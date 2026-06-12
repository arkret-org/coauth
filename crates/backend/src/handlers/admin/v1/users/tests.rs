// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the admin users endpoints.
//!
//! Was the larger half of the original `admin/v1/users.rs`. Wrapping the
//! body in a single `mod tests` keeps the original imports and helper
//! visibility intact, so the move is purely textual.

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use chrono::Duration;
    use coauth_data::RepositoryAccess;
    use coauth_data::user::{UserPasswordRepository, UserRepository};
    use coauth_principal::{PrincipalProvisionRequest, PrincipalServerAdmin};
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
    async fn test_add_user() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request =
            Request::post("/_coauth/admin/users")
                .bearer(&token)
                .json(serde_json::json!({
                    "username": "alice",
                }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "user");
        let id = body["data"]["id"].as_str().unwrap();
        assert_eq!(body["data"]["attributes"]["username"], "alice");

        // Check that the user was created in the database
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .lookup(id.parse().unwrap())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.localpart, "alice");

        // Check that the user was created on the PrincipalServer
        let result = state.principal_server_admin.query_user("alice").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_add_user_invalid_username() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request =
            Request::post("/_coauth/admin/users")
                .bearer(&token)
                .json(serde_json::json!({
                    "username": "this is invalid",
                }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "Username is not valid");
    }

    #[tokio::test]
    async fn test_add_user_exists() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request =
            Request::post("/_coauth/admin/users")
                .bearer(&token)
                .json(serde_json::json!({
                    "username": "alice",
                }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "user");
        assert_eq!(body["data"]["attributes"]["username"], "alice");

        let request =
            Request::post("/_coauth/admin/users")
                .bearer(&token)
                .json(serde_json::json!({
                    "username": "alice",
                }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "User already exists");
    }

    #[tokio::test]
    async fn test_add_user_reserved() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Reserve a username on the PrincipalServer and try to add it
        state.principal_server_admin.reserve_handle("bob").await;

        let request =
            Request::post("/_coauth/admin/users")
                .bearer(&token)
                .json(serde_json::json!({
                    "username": "bob",
                }));

        let response = state.request(request).await;

        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Username is reserved by the PrincipalServer"
        );

        // But we can force it with the skip_principal_server_check flag
        let request =
            Request::post("/_coauth/admin/users")
                .bearer(&token)
                .json(serde_json::json!({
                    "username": "bob",
                    "skip_principal_server_check": true,
                }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();
        let id = body["data"]["id"].as_str().unwrap();
        assert_eq!(body["data"]["attributes"]["username"], "bob");

        // Check that the user was created in the database
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .lookup(id.parse().unwrap())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.localpart, "bob");
    }

    #[tokio::test]
    async fn test_list_users() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision two users
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Test default behavior (count=true)
        let request = Request::get("/_coauth/admin/users").bearer(&token).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "attributes": {
                "username": "bob",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false
              },
              "links": {
                "self": "/_coauth/admin/users/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AJ6AC5HQ9X6H4RP4"
                }
              }
            },
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false
              },
              "links": {
                "self": "/_coauth/admin/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/users?page[first]=10",
            "first": "/_coauth/admin/users?page[first]=10",
            "last": "/_coauth/admin/users?page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/_coauth/admin/users?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "attributes": {
                "username": "bob",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false
              },
              "links": {
                "self": "/_coauth/admin/users/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AJ6AC5HQ9X6H4RP4"
                }
              }
            },
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false
              },
              "links": {
                "self": "/_coauth/admin/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/users?count=false&page[first]=10",
            "first": "/_coauth/admin/users?count=false&page[first]=10",
            "last": "/_coauth/admin/users?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/_coauth/admin/users?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/_coauth/admin/users?count=only"
          }
        }
        "###);

        // Test count=false with filtering
        let request = Request::get("/_coauth/admin/users?count=false&filter[search]=alice")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false
              },
              "links": {
                "self": "/_coauth/admin/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/users?filter[search]=alice&count=false&page[first]=10",
            "first": "/_coauth/admin/users?filter[search]=alice&count=false&page[first]=10",
            "last": "/_coauth/admin/users?filter[search]=alice&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get("/_coauth/admin/users?count=only&filter[search]=alice")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/_coauth/admin/users?filter[search]=alice&count=only"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_set_password() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
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
        let request = Request::post(format!("/_coauth/admin/users/{user_id}/set-password"))
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
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
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
        let request = Request::post(format!("/_coauth/admin/users/{user_id}/set-password"))
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
        let request = Request::post(format!("/_coauth/admin/users/{user_id}/set-password"))
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
    async fn test_unknown_user() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Set the password through the API
        let request = Request::post("/_coauth/admin/users/01040G2081040G2081040G2081/set-password")
            .bearer(&token)
            .json(serde_json::json!({
                "password": "this is a good enough password",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);

        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "User ID 01040G2081040G2081040G2081 not found"
        );
    }

    #[tokio::test]
    async fn test_disabled() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        state.password_manager = PasswordManager::disabled();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post("/_coauth/admin/users/01040G2081040G2081040G2081/set-password")
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
    async fn test_patch_user_profile_and_state() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:coauth:admin").await;
        let username = format!("alice{}", Ulid::new().to_string().to_lowercase());
        let mut rng = ChaChaRng::seed_from_u64(unique);

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.clone())
            .await
            .unwrap();
        state
            .principal_server_admin
            .provision_user(&PrincipalProvisionRequest::new(&user.localpart, &user.sub))
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::patch(format!("/_coauth/admin/users/{}", user.id))
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
        assert_eq!(body["data"]["attributes"]["preferred_locale"], "zh-CN");
        assert_eq!(body["data"]["attributes"]["admin"], true);
        assert!(body["data"]["attributes"]["locked_at"].is_string());

        let user = state
            .principal_server_admin
            .query_user(&username)
            .await
            .unwrap();
        assert_eq!(user.displayname.as_deref(), Some("Alice Admin"));
    }

    #[tokio::test]
    async fn test_patch_user_reactivate() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:coauth:admin").await;
        let username = format!("alice{}", Ulid::new().to_string().to_lowercase());
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
            .principal_server_admin
            .provision_user(&PrincipalProvisionRequest::new(&user.localpart, &user.sub))
            .await
            .unwrap();
        state
            .principal_server_admin
            .delete_user(&user.localpart, true)
            .await
            .unwrap();

        let request = Request::patch(format!("/_coauth/admin/users/{}", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "deactivated": false
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["data"]["attributes"]["deactivated_at"],
            serde_json::Value::Null
        );

        let principal_user = state
            .principal_server_admin
            .query_user(&user.localpart)
            .await
            .unwrap();
        assert!(!principal_user.deactivated);
    }
}
