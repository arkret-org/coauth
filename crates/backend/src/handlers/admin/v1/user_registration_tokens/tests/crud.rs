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

    assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_token_123",
          "valid": true,
          "usage_limit": 5,
          "times_used": 0,
          "created_at": "[timestamp-1]",
          "last_used_at": null,
          "expires_at": null,
          "revoked_at": null
        },
        "links": {
          "self": "/_coauth/admin/user-registration-tokens/[id-1]"
        }
      },
      "links": {
        "self": "/_coauth/admin/user-registration-tokens/[id-1]"
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

    let mut body: serde_json::Value = response.json();
    // The auto-generated token string comes from the process RNG: assert its
    // shape here and keep the snapshot free of it.
    let generated = body["data"]["attributes"]["token"]
        .as_str()
        .expect("auto-generated registration token")
        .to_owned();
    assert_eq!(generated.len(), 12, "{generated}");
    assert!(
        generated.chars().all(|c| c.is_ascii_alphanumeric()),
        "{generated}"
    );
    body["data"]["attributes"]["token"] = serde_json::Value::String("[token]".to_owned());

    assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "[token]",
          "valid": true,
          "usage_limit": 1,
          "times_used": 0,
          "created_at": "[timestamp-1]",
          "last_used_at": null,
          "expires_at": null,
          "revoked_at": null
        },
        "links": {
          "self": "/_coauth/admin/user-registration-tokens/[id-1]"
        }
      },
      "links": {
        "self": "/_coauth/admin/user-registration-tokens/[id-1]"
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

    assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_token_123",
          "valid": true,
          "usage_limit": 5,
          "times_used": 0,
          "created_at": "[timestamp-1]",
          "last_used_at": null,
          "expires_at": null,
          "revoked_at": null
        },
        "links": {
          "self": "/_coauth/admin/user-registration-tokens/[id-1]"
        }
      },
      "links": {
        "self": "/_coauth/admin/user-registration-tokens/[id-1]"
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

    assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_token_123",
          "valid": true,
          "usage_limit": 5,
          "times_used": 0,
          "created_at": "[timestamp-1]",
          "last_used_at": null,
          "expires_at": null,
          "revoked_at": null
        },
        "links": {
          "self": "/_coauth/admin/user-registration-tokens/[id-1]"
        }
      },
      "links": {
        "self": "/_coauth/admin/user-registration-tokens/[id-1]"
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

    assert_json_snapshot!(body, @r#"
    {
      "errors": [
        {
          "title": "Registration token with ID 00000000000000000000000000 not found"
        }
      ]
    }
    "#);
}
