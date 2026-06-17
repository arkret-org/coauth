use super::*;

#[tokio::test]
async fn test_patch_upstream_oauth_link_updates_subject_user_and_name() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let unique = unique_test_nonce();
    state.clock.advance(Duration::seconds(unique as i64));
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut rng = ChaChaRng::seed_from_u64(unique);
    let mut repo = state.repository().await.unwrap();
    let suffix = Ulid::new().to_string().to_lowercase();

    let alice = repo
        .user()
        .add(&mut rng, &state.clock, format!("alice{suffix}"))
        .await
        .unwrap();
    let bob = repo
        .user()
        .add(&mut rng, &state.clock, format!("bob{suffix}"))
        .await
        .unwrap();
    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            test_utils::oidc_provider_params(&format!("provider-{suffix}")),
        )
        .await
        .unwrap();
    let link = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            format!("subject-{suffix}-1"),
            Some("Alice Provider".to_owned()),
        )
        .await
        .unwrap();
    repo.save().await.unwrap();

    let request = Request::patch(format!("/_coauth/admin/upstream-oauth-links/{}", link.id))
        .bearer(&token)
        .json(serde_json::json!({
            "user_id": bob.id,
            "subject": format!("subject-{suffix}-2"),
            "human_account_name": "Bob Provider"
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();

    assert_eq!(
        body["data"]["attributes"]["subject"],
        format!("subject-{suffix}-2")
    );
    assert_eq!(body["data"]["attributes"]["user_id"], bob.id.to_string());
    assert_eq!(
        body["data"]["attributes"]["human_account_name"],
        "Bob Provider"
    );

    let mut repo = state.repository().await.unwrap();
    let updated = repo
        .upstream_oauth_link()
        .lookup(link.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated.user_id, Some(bob.id));
    assert_eq!(updated.subject, format!("subject-{suffix}-2"));
    assert_eq!(updated.human_account_name.as_deref(), Some("Bob Provider"));

    let _ = alice;
}

#[tokio::test]
async fn test_patch_upstream_oauth_link_rejects_duplicate_subject() {
    setup();
    let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let unique = unique_test_nonce();
    state.clock.advance(Duration::seconds(unique as i64));
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut rng = ChaChaRng::seed_from_u64(unique);
    let mut repo = state.repository().await.unwrap();
    let suffix = Ulid::new().to_string().to_lowercase();

    let alice = repo
        .user()
        .add(&mut rng, &state.clock, format!("alice{suffix}"))
        .await
        .unwrap();
    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            test_utils::oidc_provider_params(&format!("provider-{suffix}")),
        )
        .await
        .unwrap();
    let first = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            format!("subject-{suffix}-1"),
            None,
        )
        .await
        .unwrap();
    let second = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider,
            format!("subject-{suffix}-2"),
            None,
        )
        .await
        .unwrap();
    repo.upstream_oauth_link()
        .associate_to_user(&first, &alice)
        .await
        .unwrap();
    repo.upstream_oauth_link()
        .associate_to_user(&second, &alice)
        .await
        .unwrap();
    repo.save().await.unwrap();

    let request = Request::patch(format!("/_coauth/admin/upstream-oauth-links/{}", second.id))
        .bearer(&token)
        .json(serde_json::json!({
            "subject": format!("subject-{suffix}-1")
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::CONFLICT);
}
