// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[tokio::test]
async fn test_list_all_tokens() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let admin_token = state.token_with_scope("urn:coauth:admin").await;
    seed_tokens(&mut state).await;

    let request = Request::get("/_coauth/admin/user-registration-tokens")
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
        "self": "/_coauth/admin/user-registration-tokens?page[first]=10",
        "first": "/_coauth/admin/user-registration-tokens?page[first]=10",
        "last": "/_coauth/admin/user-registration-tokens?page[last]=10"
      }
    }
    "#);
}

#[tokio::test]
async fn test_filter_by_used() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let admin_token = state.token_with_scope("urn:coauth:admin").await;
    seed_tokens(&mut state).await;

    // used=true
    let request = Request::get("/_coauth/admin/user-registration-tokens?filter[used]=true")
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
        "self": "/_coauth/admin/user-registration-tokens?filter[used]=true&page[first]=10",
        "first": "/_coauth/admin/user-registration-tokens?filter[used]=true&page[first]=10",
        "last": "/_coauth/admin/user-registration-tokens?filter[used]=true&page[last]=10"
      }
    }
    "#);

    // used=false
    let request = Request::get("/_coauth/admin/user-registration-tokens?filter[used]=false")
        .bearer(&admin_token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);

    let body: serde_json::Value = response.json();
    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "meta": {
        "count": 3
      },
      "data": [
        {
          "type": "user-registration_token",
          "id": "[id-1]",
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
            "self": "/_coauth/admin/user-registration-tokens/[id-3]"
          },
          "meta": {
            "page": {
              "cursor": "[id-3]"
            }
          }
        }
      ],
      "links": {
        "self": "/_coauth/admin/user-registration-tokens?filter[used]=false&page[first]=10",
        "first": "/_coauth/admin/user-registration-tokens?filter[used]=false&page[first]=10",
        "last": "/_coauth/admin/user-registration-tokens?filter[used]=false&page[last]=10"
      }
    }
    "#);
}

#[tokio::test]
async fn test_filter_by_revoked() {
    setup();
    let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
        return;
    };
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let admin_token = state.token_with_scope("urn:coauth:admin").await;
    seed_tokens(&mut state).await;

    // revoked=true
    let request = Request::get("/_coauth/admin/user-registration-tokens?filter[revoked]=true")
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
      "data": [
        {
          "type": "user-registration_token",
          "id": "[id-1]",
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
        "self": "/_coauth/admin/user-registration-tokens?filter[revoked]=true&page[first]=10",
        "first": "/_coauth/admin/user-registration-tokens?filter[revoked]=true&page[first]=10",
        "last": "/_coauth/admin/user-registration-tokens?filter[revoked]=true&page[last]=10"
      }
    }
    "#);

    // revoked=false
    let request = Request::get("/_coauth/admin/user-registration-tokens?filter[revoked]=false")
        .bearer(&admin_token)
        .empty();
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);

    let body: serde_json::Value = response.json();
    insta::assert_json_snapshot!(stable_json(&body), @r#"
    {
      "meta": {
        "count": 3
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
            "self": "/_coauth/admin/user-registration-tokens/[id-3]"
          },
          "meta": {
            "page": {
              "cursor": "[id-3]"
            }
          }
        }
      ],
      "links": {
        "self": "/_coauth/admin/user-registration-tokens?filter[revoked]=false&page[first]=10",
        "first": "/_coauth/admin/user-registration-tokens?filter[revoked]=false&page[first]=10",
        "last": "/_coauth/admin/user-registration-tokens?filter[revoked]=false&page[last]=10"
      }
    }
    "#);
}
