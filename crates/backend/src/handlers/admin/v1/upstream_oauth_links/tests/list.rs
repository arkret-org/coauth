use super::*;

#[tokio::test]
async fn test_list() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;
    let mut rng = state.rng();

    // Provision users and providers
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
    let provider1 = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            test_utils::oidc_provider_params("acme"),
        )
        .await
        .unwrap();
    let provider2 = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &state.clock,
            test_utils::oidc_provider_params("example"),
        )
        .await
        .unwrap();

    // Create some links
    let link1 = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider1,
            "subject1".to_owned(),
            Some("alice@acme".to_owned()),
        )
        .await
        .unwrap();
    repo.upstream_oauth_link()
        .associate_to_user(&link1, &alice)
        .await
        .unwrap();
    let link2 = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider2,
            "subject2".to_owned(),
            Some("alice@example".to_owned()),
        )
        .await
        .unwrap();
    repo.upstream_oauth_link()
        .associate_to_user(&link2, &alice)
        .await
        .unwrap();
    let link3 = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &state.clock,
            &provider1,
            "subject3".to_owned(),
            Some("bob@acme".to_owned()),
        )
        .await
        .unwrap();
    repo.upstream_oauth_link()
        .associate_to_user(&link3, &bob)
        .await
        .unwrap();

    repo.save().await.unwrap();

    let request = Request::get("/_coauth/admin/upstream-oauth-links")
        .bearer(&token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0PJZ6DZNTAA1XKPT4"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-links?page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-links?page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-links?page[last]=10"
          }
        }
        "#);

    // Filter by user ID
    let request = Request::get(format!(
        "/_coauth/admin/upstream-oauth-links?filter[user]={}",
        alice.id
    ))
    .bearer(&token)
    .empty();

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[last]=10"
          }
        }
        "#);

    // Filter by provider
    let request = Request::get(format!(
        "/_coauth/admin/upstream-oauth-links?filter[provider]={}",
        provider1.id
    ))
    .bearer(&token)
    .empty();

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0PJZ6DZNTAA1XKPT4"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[last]=10"
          }
        }
        "#);

    // Filter by subject
    let request = Request::get(format!(
        "/_coauth/admin/upstream-oauth-links?filter[subject]={}",
        "subject1"
    ))
    .bearer(&token)
    .empty();

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-links?filter[subject]=subject1&page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-links?filter[subject]=subject1&page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-links?filter[subject]=subject1&page[last]=10"
          }
        }
        "#);

    // Test count=false
    let request = Request::get("/_coauth/admin/upstream-oauth-links?count=false")
        .bearer(&token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0PJZ6DZNTAA1XKPT4"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-links?count=false&page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-links?count=false&page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-links?count=false&page[last]=10"
          }
        }
        "#);

    // Test count=only
    let request = Request::get("/_coauth/admin/upstream-oauth-links?count=only")
        .bearer(&token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 3
          },
          "links": {
            "self": "/_coauth/admin/upstream-oauth-links?count=only"
          }
        }
        "###);

    // Test count=false with filtering
    let request = Request::get(format!(
        "/_coauth/admin/upstream-oauth-links?count=false&filter[user]={}",
        alice.id
    ))
    .bearer(&token)
    .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[last]=10"
          }
        }
        "#);

    // Test count=only with filtering
    let request = Request::get(format!(
        "/_coauth/admin/upstream-oauth-links?count=only&filter[provider]={}",
        provider1.id
    ))
    .bearer(&token)
    .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/_coauth/admin/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&count=only"
          }
        }
        "#);
}
