// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use chrono::{DateTime, Utc};
use coauth_data::{RepositoryAccess, audit::AdminOperation, user::UserRegistrationTokenFilter};
use rand::distr::{Alphanumeric, SampleString};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};

use crate::{
    AppError, CreatedJsonResult, JsonResult,
    handlers::admin::{
        CreatedJson,
        call_context::extract_call_context,
        model::{Resource, UserRegistrationToken},
        params::{IncludeCount, extract_pagination, extract_ulid_param},
        response::{PaginatedResponse, SingleResponse},
    },
};

/// Payload for `POST /api/admin/v1/user-registration-tokens`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRegistrationTokenRequest")]
pub struct AddRequest {
    /// Explicit token string. A random one is generated when omitted.
    token: Option<String>,

    /// Cap on how many times this token may be redeemed. Unlimited when absent.
    usage_limit: Option<u32>,

    /// Point in time after which the token is no longer valid. Never expires
    /// when absent.
    expires_at: Option<DateTime<Utc>>,
}

/// Create a new user-registration token.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.post", skip_all)]
pub async fn add_token(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let body: AddRequest = req.parse_json().await.map_err(AppError::internal)?;

    // Fall back to a randomly generated token string
    let token_str = body
        .token
        .unwrap_or_else(|| Alphanumeric.sample_string(&mut rand::rng(), 12));

    // Guard against duplicate token values
    let duplicate = repo
        .user_registration_token()
        .find_by_token(&token_str)
        .await?;
    if duplicate.is_some() {
        return Err(AppError::conflict(
            "A registration token with the same token already exists",
        ));
    }

    let entry = repo
        .user_registration_token()
        .add(
            &mut rng,
            &clock,
            token_str,
            body.usage_limit,
            body.expires_at,
        )
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::RegistrationTokenCreated,
        "registration_token",
        Some(entry.id),
        serde_json::json!({}),
    )
    .await?;

    repo.save().await?;

    Ok(CreatedJson(SingleResponse::new_canonical(
        UserRegistrationToken::new(entry, clock.now()),
    )))
}

/// Fetch a single registration token by its ULID.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.get", skip_all)]
pub async fn get_token(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let target_id = extract_ulid_param(req)?;

    let entry = repo
        .user_registration_token()
        .lookup(target_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Registration token with ID {target_id} not found"))
        })?;

    Ok(Json(SingleResponse::new_canonical(
        UserRegistrationToken::new(entry, clock.now()),
    )))
}

/// Query-string filters for the registration-token list endpoint.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "RegistrationTokenFilter")]
pub struct FilterParams {
    /// Whether the token has been redeemed at least once
    #[serde(rename = "filter[used]")]
    used: Option<bool>,

    /// Whether the token is currently revoked
    #[serde(rename = "filter[revoked]")]
    revoked: Option<bool>,

    /// Whether the token has passed its expiry timestamp
    #[serde(rename = "filter[expired]")]
    expired: Option<bool>,

    /// Whether the token is still usable (not expired, not revoked,
    /// and has not exhausted its usage limit)
    #[serde(rename = "filter[valid]")]
    valid: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delim = '?';

        if let Some(val) = self.used {
            write!(f, "{delim}filter[used]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.revoked {
            write!(f, "{delim}filter[revoked]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.expired {
            write!(f, "{delim}filter[expired]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.valid {
            write!(f, "{delim}filter[valid]={val}")?;
            delim = '&';
        }

        let _ = delim;
        Ok(())
    }
}

/// List registration tokens with optional filtering and cursor-based
/// pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.registration_tokens.list", skip_all)]
pub async fn list_tokens(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base_url = format!("{path}{params}", path = UserRegistrationToken::PATH);
    let base_url = include_count.add_to_base(&base_url);
    let now = clock.now();
    let mut filter = UserRegistrationTokenFilter::new(now);

    if let Some(val) = params.used {
        filter = filter.with_been_used(val);
    }
    if let Some(val) = params.revoked {
        filter = filter.with_revoked(val);
    }
    if let Some(val) = params.expired {
        filter = filter.with_expired(val);
    }
    if let Some(val) = params.valid {
        filter = filter.with_valid(val);
    }

    let result = match include_count {
        IncludeCount::True => {
            let page = repo
                .user_registration_token()
                .list(filter, pagination)
                .await?
                .map(|t| UserRegistrationToken::new(t, now));
            let total = repo.user_registration_token().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .user_registration_token()
                .list(filter, pagination)
                .await?
                .map(|t| UserRegistrationToken::new(t, now));
            PaginatedResponse::for_page(page, pagination, None, &base_url)
        }
        IncludeCount::Only => {
            let total = repo.user_registration_token().count(filter).await?;
            PaginatedResponse::for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

/// Mark a registration token as revoked so it can no longer be used.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.revoke", skip_all)]
pub async fn revoke_token(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let target_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let entry = repo
        .user_registration_token()
        .lookup(target_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Registration token with ID {target_id} not found"))
        })?;

    if entry.revoked_at.is_some() {
        return Err(AppError::bad_request(format!(
            "Registration token with ID {target_id} is already revoked"
        )));
    }

    let revoked = repo.user_registration_token().revoke(&clock, entry).await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::RegistrationTokenRevoked,
        "registration_token",
        Some(target_id),
        serde_json::json!({}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        UserRegistrationToken::new(revoked, clock.now()),
        format!("/api/admin/v1/user-registration-tokens/{target_id}/revoke"),
    )))
}

/// Restore a previously revoked registration token so it becomes usable again.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.unrevoke", skip_all)]
pub async fn unrevoke_token(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let target_id = extract_ulid_param(req)?;

    let entry = repo
        .user_registration_token()
        .lookup(target_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Registration token with ID {target_id} not found"))
        })?;

    if entry.revoked_at.is_none() {
        return Err(AppError::bad_request(format!(
            "Registration token with ID {target_id} is not revoked"
        )));
    }

    let restored = repo.user_registration_token().unrevoke(entry).await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        UserRegistrationToken::new(restored, clock.now()),
        format!("/api/admin/v1/user-registration-tokens/{target_id}/unrevoke"),
    )))
}

/// Treat any value that is present (including explicit `null`) as `Some`.
fn nullable_field<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

/// Payload for `PUT /api/admin/v1/user-registration-tokens/{id}`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "EditUserRegistrationTokenRequest")]
pub struct UpdateRequest {
    /// Updated expiration timestamp, or `null` to clear it
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "nullable_field"
    )]
    #[expect(clippy::option_option)]
    expires_at: Option<Option<DateTime<Utc>>>,

    /// Updated usage cap, or `null` to remove the limit
    #[expect(clippy::option_option)]
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "nullable_field"
    )]
    usage_limit: Option<Option<u32>>,
}

/// Apply partial updates to a registration token's mutable fields.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.update", skip_all)]
pub async fn update_token(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let target_id = extract_ulid_param(req)?;
    let body: UpdateRequest = req.parse_json().await.map_err(AppError::internal)?;

    let mut entry = repo
        .user_registration_token()
        .lookup(target_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Registration token with ID {target_id} not found"))
        })?;

    // Patch expiry when the field was explicitly supplied
    if let Some(new_expiry) = body.expires_at {
        entry = repo
            .user_registration_token()
            .set_expiry(entry, new_expiry)
            .await?;
    }

    // Patch usage limit when the field was explicitly supplied
    if let Some(new_limit) = body.usage_limit {
        entry = repo
            .user_registration_token()
            .set_usage_limit(entry, new_limit)
            .await?;
    }

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        UserRegistrationToken::new(entry, clock.now()),
        format!("/api/admin/v1/user-registration-tokens/{target_id}"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::Clock as _;
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use serde_json::json;
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_create() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "test_token_123",
                "usage_limit": 5,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_create_auto_token() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "usage_limit": 1
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0QMGC989M0XSFVF2X",
            "attributes": {
              "token": "42oTpLoieH5I",
              "valid": true,
              "usage_limit": 1,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_create_conflict() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "test_token_123",
                "usage_limit": 5
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);

        let request = Request::post("/api/admin/v1/user-registration-tokens")
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
        let pool = coauth_data::test_utils::setup_test_pool().await;
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
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_get_nonexistent_token() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let missing_id = Ulid::from_string("00000000000000000000000000").unwrap();
        let request = Request::get(format!(
            "/api/admin/v1/user-registration-tokens/{missing_id}"
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Registration token with ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }

    /// Provision a set of tokens covering all relevant combinations of
    /// used / revoked / expired status so that filter tests can work
    /// against a known data set.
    async fn seed_tokens(ts: &mut TestState) {
        let mut repo = ts.repository().await.unwrap();

        // 1 -- never used, not revoked, not expired
        repo.user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_unused".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();

        // 2 -- used once, not revoked
        let tok = repo
            .user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_used".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();
        repo.user_registration_token()
            .use_token(&ts.clock, tok)
            .await
            .unwrap();

        // 3 -- never used, revoked
        let tok = repo
            .user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_revoked".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();
        repo.user_registration_token()
            .revoke(&ts.clock, tok)
            .await
            .unwrap();

        // 4 -- used once, then revoked
        let tok = repo
            .user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_used_revoked".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();
        let tok = repo
            .user_registration_token()
            .use_token(&ts.clock, tok)
            .await
            .unwrap();
        repo.user_registration_token()
            .revoke(&ts.clock, tok)
            .await
            .unwrap();

        // 5 -- already expired
        let past = ts.clock.now() - Duration::try_days(1).unwrap();
        repo.user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_expired".to_owned(),
                Some(5),
                Some(past),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();
    }

    #[tokio::test]
    async fn test_list_all_tokens() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        seed_tokens(&mut state).await;

        let request = Request::get("/api/admin/v1/user-registration-tokens")
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_used() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        seed_tokens(&mut state).await;

        // used=true
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[used]=true")
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[used]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[used]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[used]=true&page[last]=10"
          }
        }
        "#);

        // used=false
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[used]=false")
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[used]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[used]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[used]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_revoked() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        seed_tokens(&mut state).await;

        // revoked=true
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[revoked]=true")
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&page[last]=10"
          }
        }
        "#);

        // revoked=false
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[revoked]=false")
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[revoked]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[revoked]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[revoked]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_expired() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        seed_tokens(&mut state).await;

        // expired=true
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[expired]=true")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[expired]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[expired]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[expired]=true&page[last]=10"
          }
        }
        "#);

        // expired=false
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[expired]=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 4
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[expired]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[expired]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[expired]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_valid() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        seed_tokens(&mut state).await;

        // valid=true
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[valid]=true")
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[valid]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[valid]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[valid]=true&page[last]=10"
          }
        }
        "#);

        // valid=false
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[valid]=false")
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[valid]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[valid]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[valid]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_combined_filters() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        seed_tokens(&mut state).await;

        // used AND revoked
        let request = Request::get(
            "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true",
        )
        .bearer(&admin_token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_pagination() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        seed_tokens(&mut state).await;

        // First page of 2
        let request = Request::get("/api/admin/v1/user-registration-tokens?page[first]=2")
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[first]=2",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=2",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=2",
            "next": "/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2"
          }
        }
        "#);

        // Second page
        let request = Request::get("/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2")
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
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=2",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=2",
            "next": "/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=2"
          }
        }
        "#);

        // Last item via page[last]=1
        let request = Request::get("/api/admin/v1/user-registration-tokens?page[last]=1")
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
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[last]=1",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=1",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=1",
            "prev": "/api/admin/v1/user-registration-tokens?page[before]=01FSHN9AG0S3ZJD8CXQ7F11KXN&page[last]=1"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_invalid_filter() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[used]=invalid")
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
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        seed_tokens(&mut state).await;

        // count=false -- no meta.count in the response
        let request = Request::get("/api/admin/v1/user-registration-tokens?count=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?count=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?count=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?count=false&page[last]=10"
          }
        }
        "#);

        // count=only -- just the total
        let request = Request::get("/api/admin/v1/user-registration-tokens?count=only")
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
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?count=only"
          }
        }
        "#);

        // count=false combined with a filter
        let request =
            Request::get("/api/admin/v1/user-registration-tokens?count=false&filter[valid]=true")
                .bearer(&admin_token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
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
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[valid]=true&count=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[valid]=true&count=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[valid]=true&count=false&page[last]=10"
          }
        }
        "#);

        // count=only combined with a filter
        let request =
            Request::get("/api/admin/v1/user-registration-tokens?count=only&filter[revoked]=true")
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
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&count=only"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_revoke_token() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
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
            "/api/admin/v1/user-registration-tokens/{}/revoke",
            reg_token.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["revoked_at"],
            serde_json::json!(state.clock.now())
        );
    }

    #[tokio::test]
    async fn test_revoke_already_revoked_token() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
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
            "/api/admin/v1/user-registration-tokens/{}/revoke",
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
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post(
            "/api/admin/v1/user-registration-tokens/01040G2081040G2081040G2081/revoke",
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
    async fn test_unrevoke_token() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
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
            "/api/admin/v1/user-registration-tokens/{}/unrevoke",
            revoked_entry.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_456",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E/unrevoke"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_unrevoke_not_revoked_token() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
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
            "/api/admin/v1/user-registration-tokens/{}/unrevoke",
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
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post(
            "/api/admin/v1/user-registration-tokens/01040G2081040G2081040G2081/unrevoke",
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
        let pool = coauth_data::test_utils::setup_test_pool().await;
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
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": new_expiry
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_expiry",
              "valid": true,
              "usage_limit": null,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": "2022-02-15T14:40:00Z",
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);

        // Clear the expiry
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": null
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_expiry",
              "valid": true,
              "usage_limit": null,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_update_usage_limit() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
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
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({
            "usage_limit": 10
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_limit",
              "valid": true,
              "usage_limit": 10,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);

        // Remove the limit entirely
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({
            "usage_limit": null
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_limit",
              "valid": true,
              "usage_limit": null,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_update_multiple_fields() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
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
            "/api/admin/v1/user-registration-tokens/{}",
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

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_multiple",
              "valid": true,
              "usage_limit": 20,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": "2022-02-15T14:40:00Z",
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_update_no_fields() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
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
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({}));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_none",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": "2022-02-15T14:40:00Z",
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_update_unknown_token() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request =
            Request::put("/api/admin/v1/user-registration-tokens/01040G2081040G2081040G2081")
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
}
