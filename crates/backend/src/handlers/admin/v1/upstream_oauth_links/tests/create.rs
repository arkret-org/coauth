use super::*;

#[tokio::test]
async fn test_create() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();

    let alice = repo
        .user()
        .add(&mut rng, &state.clock, "alice".to_owned())
        .await
        .unwrap();

    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            test_utils::oidc_provider_params("provider1"),
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request = Request::post("/_coauth/admin/upstream-oauth-links")
        .bearer(&token)
        .json(serde_json::json!({
            "user_id": alice.id,
            "provider_id": provider.id,
            "subject": "subject1"
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::CREATED);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "upstream-oauth-link",
        "id": "[id-1]",
        "attributes": {
          "created_at": "[timestamp-1]",
          "updated_at": "[timestamp-1]",
          "provider_id": "[id-2]",
          "subject": "subject1",
          "user_id": "[id-3]",
          "human_account_name": null
        },
        "links": {
          "self": "/_coauth/admin/upstream-oauth-links/[id-1]"
        }
      },
      "links": {
        "self": "/_coauth/admin/upstream-oauth-links/[id-1]"
      }
    }
    "#);
}

#[tokio::test]
async fn test_association() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();

    let alice = repo
        .user()
        .add(&mut rng, &state.clock, "alice".to_owned())
        .await
        .unwrap();

    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            test_utils::oidc_provider_params("provider1"),
        )
        .await
        .unwrap();

    // Existing unfinished link
    repo.upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            String::from("subject1"),
            None,
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request = Request::post("/_coauth/admin/upstream-oauth-links")
        .bearer(&token)
        .json(serde_json::json!({
            "user_id": alice.id,
            "provider_id": provider.id,
            "subject": "subject1"
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
    {
      "data": {
        "type": "upstream-oauth-link",
        "id": "01FSHN9AG0E669W4K48J05MWG5",
        "attributes": {
          "created_at": "2022-01-16T14:40:00Z",
          "updated_at": "2022-01-16T14:40:00Z",
          "provider_id": "01FSHN9AG0FKTSFY9K4CCVASWV",
          "subject": "subject1",
          "user_id": "01FSHN9AG0FH5TJ4F8G4T9XCET",
          "human_account_name": null
        },
        "links": {
          "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0E669W4K48J05MWG5"
        }
      },
      "links": {
        "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0E669W4K48J05MWG5"
      }
    }
    "#);
}

#[tokio::test]
async fn test_link_already_exists() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();

    let alice = repo
        .user()
        .add(&mut rng, &state.clock, "alice".to_owned())
        .await
        .unwrap();

    let bob = repo
        .user()
        .add(&mut rng, &state.clock, "bob".to_owned())
        .await
        .unwrap();

    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            test_utils::oidc_provider_params("provider1"),
        )
        .await
        .unwrap();

    let link = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            String::from("subject1"),
            None,
        )
        .await
        .unwrap();

    repo.upstream_oauth_link()
        .associate_to_user(&link, &alice)
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request = Request::post("/_coauth/admin/upstream-oauth-links")
        .bearer(&token)
        .json(serde_json::json!({
            "user_id": bob.id,
            "provider_id": provider.id,
            "subject": "subject1"
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::CONFLICT);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(stable_json(&body), @r#"
    {
      "errors": [
        {
          "title": "Upstream OAuth 2.0 Provider ID [id-1] with subject subject1 is already linked to a user"
        }
      ]
    }
    "#);
}

#[tokio::test]
async fn test_user_not_found() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();

    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            test_utils::oidc_provider_params("provider1"),
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request = Request::post("/_coauth/admin/upstream-oauth-links")
        .bearer(&token)
        .json(serde_json::json!({
            "user_id": Ulid::nil(),
            "provider_id": provider.id,
            "subject": "subject1"
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
    {
      "errors": [
        {
          "title": "User ID 00000000000000000000000000 not found"
        }
      ]
    }
    "#);
}

#[tokio::test]
async fn test_provider_not_found() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();

    let alice = repo
        .user()
        .add(&mut rng, &state.clock, "alice".to_owned())
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request = Request::post("/_coauth/admin/upstream-oauth-links")
        .bearer(&token)
        .json(serde_json::json!({
            "user_id": alice.id,
            "provider_id": Ulid::nil(),
            "subject": "subject1"
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
    {
      "errors": [
        {
          "title": "Upstream OAuth Provider ID 00000000000000000000000000 not found"
        }
      ]
    }
    "#);
}
