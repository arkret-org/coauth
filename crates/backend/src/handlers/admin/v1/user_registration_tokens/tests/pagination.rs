// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[tokio::test]
async fn test_pagination() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let admin_token = state.token_with_scope("urn:coauth:admin").await;
    seed_tokens(&mut state).await;

    // First page of 2
    let request = Request::get("/_coauth/admin/user-registration-tokens?page[first]=2")
        .bearer(&admin_token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);

    let body: serde_json::Value = response.json();
    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "meta": {
        "count": 5
      },
      "data": [
        {
          "type": "user-registration_token",
          "id": "[id-1]",
          "attributes": {
            "token": "token_used",
            "valid": true,
            "usage_limit": 10,
            "times_used": 1,
            "created_at": "[timestamp-1]",
            "last_used_at": "[timestamp-1]",
            "expires_at": null,
            "revoked_at": null
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-1]"
          },
          "meta": {
            "page": {
              "cursor": "[id-1]"
            }
          }
        },
        {
          "type": "user-registration_token",
          "id": "[id-2]",
          "attributes": {
            "token": "token_revoked",
            "valid": false,
            "usage_limit": 10,
            "times_used": 0,
            "created_at": "[timestamp-1]",
            "last_used_at": null,
            "expires_at": null,
            "revoked_at": "[timestamp-1]"
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-2]"
          },
          "meta": {
            "page": {
              "cursor": "[id-2]"
            }
          }
        }
      ],
      "links": {
        "self": "/_coauth/admin/user-registration-tokens?page[first]=2",
        "first": "/_coauth/admin/user-registration-tokens?page[first]=2",
        "last": "/_coauth/admin/user-registration-tokens?page[last]=2",
        "next": "/_coauth/admin/user-registration-tokens?page[after]=[id-2]&page[first]=2"
      }
    }
    "#);

    // Second page
    let request = Request::get("/_coauth/admin/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2")
            .bearer(&admin_token)
            .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);

    let body: serde_json::Value = response.json();
    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "meta": {
        "count": 5
      },
      "data": [
        {
          "type": "user-registration_token",
          "id": "[id-1]",
          "attributes": {
            "token": "token_used",
            "valid": true,
            "usage_limit": 10,
            "times_used": 1,
            "created_at": "[timestamp-1]",
            "last_used_at": "[timestamp-1]",
            "expires_at": null,
            "revoked_at": null
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-1]"
          },
          "meta": {
            "page": {
              "cursor": "[id-1]"
            }
          }
        },
        {
          "type": "user-registration_token",
          "id": "[id-2]",
          "attributes": {
            "token": "token_revoked",
            "valid": false,
            "usage_limit": 10,
            "times_used": 0,
            "created_at": "[timestamp-1]",
            "last_used_at": null,
            "expires_at": null,
            "revoked_at": "[timestamp-1]"
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-2]"
          },
          "meta": {
            "page": {
              "cursor": "[id-2]"
            }
          }
        }
      ],
      "links": {
        "self": "/_coauth/admin/user-registration-tokens?page[after]=[id-3]&page[first]=2",
        "first": "/_coauth/admin/user-registration-tokens?page[first]=2",
        "last": "/_coauth/admin/user-registration-tokens?page[last]=2",
        "next": "/_coauth/admin/user-registration-tokens?page[after]=[id-2]&page[first]=2"
      }
    }
    "#);

    // Last item via page[last]=1
    let request = Request::get("/_coauth/admin/user-registration-tokens?page[last]=1")
        .bearer(&admin_token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);

    let body: serde_json::Value = response.json();
    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "meta": {
        "count": 5
      },
      "data": [
        {
          "type": "user-registration_token",
          "id": "[id-1]",
          "attributes": {
            "token": "token_unused",
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
          },
          "meta": {
            "page": {
              "cursor": "[id-1]"
            }
          }
        }
      ],
      "links": {
        "self": "/_coauth/admin/user-registration-tokens?page[last]=1",
        "first": "/_coauth/admin/user-registration-tokens?page[first]=1",
        "last": "/_coauth/admin/user-registration-tokens?page[last]=1",
        "prev": "/_coauth/admin/user-registration-tokens?page[before]=[id-1]&page[last]=1"
      }
    }
    "#);
}

#[tokio::test]
async fn test_invalid_filter() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let admin_token = state.token_with_scope("urn:coauth:admin").await;

    let request = Request::get("/_coauth/admin/user-registration-tokens?filter[used]=invalid")
        .bearer(&admin_token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json();
    assert!(
        body["errors"][0]["title"]
            .as_str()
            .unwrap()
            .contains("Invalid filter parameters")
    );
}

#[tokio::test]
async fn test_count_parameter() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let admin_token = state.token_with_scope("urn:coauth:admin").await;
    seed_tokens(&mut state).await;

    // count=false -- no meta.count in the response
    let request = Request::get("/_coauth/admin/user-registration-tokens?count=false")
        .bearer(&admin_token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": [
        {
          "type": "user-registration_token",
          "id": "[id-1]",
          "attributes": {
            "token": "token_used",
            "valid": true,
            "usage_limit": 10,
            "times_used": 1,
            "created_at": "[timestamp-1]",
            "last_used_at": "[timestamp-1]",
            "expires_at": null,
            "revoked_at": null
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-1]"
          },
          "meta": {
            "page": {
              "cursor": "[id-1]"
            }
          }
        },
        {
          "type": "user-registration_token",
          "id": "[id-2]",
          "attributes": {
            "token": "token_revoked",
            "valid": false,
            "usage_limit": 10,
            "times_used": 0,
            "created_at": "[timestamp-1]",
            "last_used_at": null,
            "expires_at": null,
            "revoked_at": "[timestamp-1]"
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-2]"
          },
          "meta": {
            "page": {
              "cursor": "[id-2]"
            }
          }
        },
        {
          "type": "user-registration_token",
          "id": "[id-3]",
          "attributes": {
            "token": "token_expired",
            "valid": false,
            "usage_limit": 5,
            "times_used": 0,
            "created_at": "[timestamp-1]",
            "last_used_at": null,
            "expires_at": "[timestamp-2]",
            "revoked_at": null
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-3]"
          },
          "meta": {
            "page": {
              "cursor": "[id-3]"
            }
          }
        },
        {
          "type": "user-registration_token",
          "id": "[id-4]",
          "attributes": {
            "token": "token_used_revoked",
            "valid": false,
            "usage_limit": 10,
            "times_used": 1,
            "created_at": "[timestamp-1]",
            "last_used_at": "[timestamp-1]",
            "expires_at": null,
            "revoked_at": "[timestamp-1]"
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-4]"
          },
          "meta": {
            "page": {
              "cursor": "[id-4]"
            }
          }
        },
        {
          "type": "user-registration_token",
          "id": "[id-5]",
          "attributes": {
            "token": "token_unused",
            "valid": true,
            "usage_limit": 10,
            "times_used": 0,
            "created_at": "[timestamp-1]",
            "last_used_at": null,
            "expires_at": null,
            "revoked_at": null
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-5]"
          },
          "meta": {
            "page": {
              "cursor": "[id-5]"
            }
          }
        }
      ],
      "links": {
        "self": "/_coauth/admin/user-registration-tokens?count=false&page[first]=10",
        "first": "/_coauth/admin/user-registration-tokens?count=false&page[first]=10",
        "last": "/_coauth/admin/user-registration-tokens?count=false&page[last]=10"
      }
    }
    "#);

    // count=only -- just the total
    let request = Request::get("/_coauth/admin/user-registration-tokens?count=only")
        .bearer(&admin_token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "meta": {
        "count": 5
      },
      "links": {
        "self": "/_coauth/admin/user-registration-tokens?count=only"
      }
    }
    "#);

    // count=false combined with a filter
    let request =
        Request::get("/_coauth/admin/user-registration-tokens?count=false&filter[valid]=true")
            .bearer(&admin_token)
            .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "data": [
        {
          "type": "user-registration_token",
          "id": "[id-1]",
          "attributes": {
            "token": "token_used",
            "valid": true,
            "usage_limit": 10,
            "times_used": 1,
            "created_at": "[timestamp-1]",
            "last_used_at": "[timestamp-1]",
            "expires_at": null,
            "revoked_at": null
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-1]"
          },
          "meta": {
            "page": {
              "cursor": "[id-1]"
            }
          }
        },
        {
          "type": "user-registration_token",
          "id": "[id-2]",
          "attributes": {
            "token": "token_unused",
            "valid": true,
            "usage_limit": 10,
            "times_used": 0,
            "created_at": "[timestamp-1]",
            "last_used_at": null,
            "expires_at": null,
            "revoked_at": null
          },
          "links": {
            "self": "/_coauth/admin/user-registration-tokens/[id-2]"
          },
          "meta": {
            "page": {
              "cursor": "[id-2]"
            }
          }
        }
      ],
      "links": {
        "self": "/_coauth/admin/user-registration-tokens?filter[valid]=true&count=false&page[first]=10",
        "first": "/_coauth/admin/user-registration-tokens?filter[valid]=true&count=false&page[first]=10",
        "last": "/_coauth/admin/user-registration-tokens?filter[valid]=true&count=false&page[last]=10"
      }
    }
    "#);

    // count=only combined with a filter
    let request =
        Request::get("/_coauth/admin/user-registration-tokens?count=only&filter[revoked]=true")
            .bearer(&admin_token)
            .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let body: serde_json::Value = response.json();
    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "meta": {
        "count": 2
      },
      "links": {
        "self": "/_coauth/admin/user-registration-tokens?filter[revoked]=true&count=only"
      }
    }
    "#);
}
