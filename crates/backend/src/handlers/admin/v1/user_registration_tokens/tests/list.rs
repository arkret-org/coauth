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
    insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00.000Z",
                "revoked_at": null
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": "2022-01-16T14:40:00.000Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": "2022-01-16T14:40:00.000Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
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
    insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": "2022-01-16T14:40:00.000Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": "2022-01-16T14:40:00.000Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
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
    insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00.000Z",
                "revoked_at": null
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
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
    insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": "2022-01-16T14:40:00.000Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
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
    insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00.000Z",
                "revoked_at": null
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": "2022-01-16T14:40:00.000Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00.000Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/_coauth/admin/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
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
