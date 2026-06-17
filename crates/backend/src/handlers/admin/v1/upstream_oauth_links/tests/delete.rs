use super::*;

#[tokio::test]
async fn test_delete() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
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

    // Pretend it was linked by an authorization session
    let session = repo
        .upstream_oauth_session()
        .add(&mut rng, &state.clock, &provider, String::new(), None, None)
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

    let session = repo
        .upstream_oauth_session()
        .complete_with_link(&state.clock, session, &link, None, None, None, None)
        .await
        .unwrap();

    repo.upstream_oauth_link()
        .associate_to_user(&link, &alice)
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request = Request::delete(format!("/_coauth/admin/upstream-oauth-links/{}", link.id))
        .bearer(&token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::NO_CONTENT);

    // Verify that the link was deleted
    let request = Request::get(format!("/_coauth/admin/upstream-oauth-links/{}", link.id))
        .bearer(&token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::NOT_FOUND);

    // Verify that the session was marked as unlinked
    let mut repo = state.repository().await.unwrap();
    let session = repo
        .upstream_oauth_session()
        .lookup(session.id)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        session.state,
        UpstreamOAuthAuthorizationSessionState::Unlinked { .. }
    ));
}

#[tokio::test]
async fn test_delete_not_found() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;

    let link_id = Ulid::nil();
    let request = Request::delete(format!("/_coauth/admin/upstream-oauth-links/{link_id}"))
        .bearer(&token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::NOT_FOUND);
}
