// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[tokio::test]
async fn test_revoke_token() {
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
            "test_token_456".to_owned(),
            Some(5),
            None,
        )
        .await
        .unwrap();
    repo.save().await.unwrap();

    let request = Request::post(format!(
        "/_coauth/admin/user-registration-tokens/{}/revoke",
        reg_token.id
    ))
    .bearer(&token)
    .empty();
    let before = chrono::Utc::now();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    assert_stamped_since(
        &body["data"]["attributes"]["revoked_at"],
        before,
        "revoked_at",
    );
}

#[tokio::test]
async fn test_revoke_already_revoked_token() {
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
            "test_token_789".to_owned(),
            None,
            None,
        )
        .await
        .unwrap();

    let revoked_entry = repo
        .user_registration_token()
        .revoke(&state.clock, reg_token)
        .await
        .unwrap();

    repo.save().await.unwrap();

    state.clock.advance(Duration::try_minutes(1).unwrap());

    let request = Request::post(format!(
        "/_coauth/admin/user-registration-tokens/{}/revoke",
        revoked_entry.id
    ))
    .bearer(&token)
    .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["errors"][0]["title"],
        format!(
            "Registration token with ID {} is already revoked",
            revoked_entry.id
        )
    );
}

#[tokio::test]
async fn test_revoke_unknown_token() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let request =
        Request::post("/_coauth/admin/user-registration-tokens/01040G2081040G2081040G2081/revoke")
            .bearer(&token)
            .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["errors"][0]["title"],
        "Registration token with ID 01040G2081040G2081040G2081 not found"
    );
}

#[tokio::test]
async fn test_unrevoke_token() {
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
            "test_token_456".to_owned(),
            Some(5),
            None,
        )
        .await
        .unwrap();

    let revoked_entry = repo
        .user_registration_token()
        .revoke(&state.clock, reg_token)
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request = Request::post(format!(
        "/_coauth/admin/user-registration-tokens/{}/unrevoke",
        revoked_entry.id
    ))
    .bearer(&token)
    .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_token_456",
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
        "self": "/_coauth/admin/user-registration-tokens/[id-1]/unrevoke"
      }
    }
    "#);
}

#[tokio::test]
async fn test_unrevoke_not_revoked_token() {
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
            "test_token_789".to_owned(),
            None,
            None,
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request = Request::post(format!(
        "/_coauth/admin/user-registration-tokens/{}/unrevoke",
        reg_token.id
    ))
    .bearer(&token)
    .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["errors"][0]["title"],
        format!("Registration token with ID {} is not revoked", reg_token.id)
    );
}

#[tokio::test]
async fn test_unrevoke_unknown_token() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let request = Request::post(
        "/_coauth/admin/user-registration-tokens/01040G2081040G2081040G2081/unrevoke",
    )
    .bearer(&token)
    .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["errors"][0]["title"],
        "Registration token with ID 01040G2081040G2081040G2081 not found"
    );
}

#[tokio::test]
async fn test_update_expiry() {
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
            "test_update_expiry".to_owned(),
            None,
            None,
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    // Set an expiry date
    let new_expiry = state.clock.now() + Duration::days(30);
    let request = Request::put(format!(
        "/_coauth/admin/user-registration-tokens/{}",
        reg_token.id
    ))
    .bearer(&token)
    .json(json!({
        "expires_at": new_expiry
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_update_expiry",
          "valid": false,
          "usage_limit": null,
          "times_used": 0,
          "created_at": "[timestamp-1]",
          "last_used_at": null,
          "expires_at": "[timestamp-2]",
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

    // Clear the expiry
    let request = Request::put(format!(
        "/_coauth/admin/user-registration-tokens/{}",
        reg_token.id
    ))
    .bearer(&token)
    .json(json!({
        "expires_at": null
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_update_expiry",
          "valid": true,
          "usage_limit": null,
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
async fn test_update_usage_limit() {
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
            "test_update_limit".to_owned(),
            Some(5),
            None,
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    // Increase the limit
    let request = Request::put(format!(
        "/_coauth/admin/user-registration-tokens/{}",
        reg_token.id
    ))
    .bearer(&token)
    .json(json!({
        "usage_limit": 10
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_update_limit",
          "valid": true,
          "usage_limit": 10,
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

    // Remove the limit entirely
    let request = Request::put(format!(
        "/_coauth/admin/user-registration-tokens/{}",
        reg_token.id
    ))
    .bearer(&token)
    .json(json!({
        "usage_limit": null
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_update_limit",
          "valid": true,
          "usage_limit": null,
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
async fn test_update_multiple_fields() {
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
            "test_update_multiple".to_owned(),
            None,
            None,
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    let new_expiry = state.clock.now() + Duration::days(30);
    let request = Request::put(format!(
        "/_coauth/admin/user-registration-tokens/{}",
        reg_token.id
    ))
    .bearer(&token)
    .json(json!({
        "expires_at": new_expiry,
        "usage_limit": 20
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_update_multiple",
          "valid": false,
          "usage_limit": 20,
          "times_used": 0,
          "created_at": "[timestamp-1]",
          "last_used_at": null,
          "expires_at": "[timestamp-2]",
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
async fn test_update_no_fields() {
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
            "test_update_none".to_owned(),
            Some(5),
            Some(state.clock.now() + Duration::days(30)),
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    // Empty body -- nothing changes
    let request = Request::put(format!(
        "/_coauth/admin/user-registration-tokens/{}",
        reg_token.id
    ))
    .bearer(&token)
    .json(json!({}));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "user-registration_token",
        "id": "[id-1]",
        "attributes": {
          "token": "test_update_none",
          "valid": false,
          "usage_limit": 5,
          "times_used": 0,
          "created_at": "[timestamp-1]",
          "last_used_at": null,
          "expires_at": "[timestamp-2]",
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
async fn test_update_unknown_token() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let request =
        Request::put("/_coauth/admin/user-registration-tokens/01040G2081040G2081040G2081")
            .bearer(&token)
            .json(json!({
                "usage_limit": 5
            }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json();

    assert_eq!(
        body["errors"][0]["title"],
        "Registration token with ID 01040G2081040G2081040G2081 not found"
    );
}
