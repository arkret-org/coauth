use super::*;

#[tokio::test]
async fn test_get() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut rng = state.rng();

    // Provision a provider and a link
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
    let user = repo
        .user()
        .add(&mut rng, &state.clock, "alice".to_owned())
        .await
        .unwrap();
    let link = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            "subject1".to_owned(),
            None,
        )
        .await
        .unwrap();
    repo.upstream_oauth_link()
        .associate_to_user(&link, &user)
        .await
        .unwrap();
    repo.save().await.unwrap();

    let link_id = link.id;
    let request = Request::get(format!("/_coauth/admin/upstream-oauth-links/{link_id}"))
        .bearer(&token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": {
        "type": "upstream-oauth-link",
        "id": "[id-1]",
        "attributes": {
          "created_at": "[timestamp-1]",
          "updated_at": "[timestamp-2]",
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
async fn test_get_not_found() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let link_id = Ulid::nil();
    let request = Request::get(format!("/_coauth/admin/upstream-oauth-links/{link_id}"))
        .bearer(&token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::NOT_FOUND);
}
