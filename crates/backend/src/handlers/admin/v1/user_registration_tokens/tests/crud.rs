// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[tokio::test]
async fn test_create() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let request = Request::post("/_coauth/admin/user-registration-tokens")
        .bearer(&token)
        .json(serde_json::json!({
            "token": "test_token_123",
            "usage_limit": 5,
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::CREATED);
    let body: serde_json::Value = response.json();

    assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00.000Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
}

#[tokio::test]
async fn test_create_auto_token() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let request = Request::post("/_coauth/admin/user-registration-tokens")
        .bearer(&token)
        .json(serde_json::json!({
            "usage_limit": 1
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::CREATED);

    let body: serde_json::Value = response.json();

    assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0QMGC989M0XSFVF2X",
            "attributes": {
              "token": "42oTpLoieH5I",
              "valid": true,
              "usage_limit": 1,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00.000Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
            }
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
          }
        }
        "#);
}

#[tokio::test]
async fn test_create_conflict() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let request = Request::post("/_coauth/admin/user-registration-tokens")
        .bearer(&token)
        .json(serde_json::json!({
            "token": "test_token_123",
            "usage_limit": 5
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::CREATED);

    let body: serde_json::Value = response.json();

    assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00.000Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);

    let request = Request::post("/_coauth/admin/user-registration-tokens")
        .bearer(&token)
        .json(serde_json::json!({
            "token": "test_token_123",
            "usage_limit": 5
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_get_token() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let mut repo = state.repository().await.unwrap();
    let reg_token = repo
        .user_registration_token()
        .add(
            &mut state.rng(),
            &state.clock,
            "test_token_123".to_owned(),
            Some(5),
            None,
        )
        .await
        .unwrap();
    repo.save().await.unwrap();

    let request = Request::get(format!(
        "/_coauth/admin/user-registration-tokens/{}",
        reg_token.id
    ))
    .bearer(&token)
    .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00.000Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
}

#[tokio::test]
async fn test_get_nonexistent_token() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let missing_id = Ulid::from_string("00000000000000000000000000").unwrap();
    let request = Request::get(format!(
        "/_coauth/admin/user-registration-tokens/{missing_id}"
    ))
    .bearer(&token)
    .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json();

    assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Registration token with ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
}
