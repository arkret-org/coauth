// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use chrono::{DateTime, Utc};
use coauth_data::RepositoryAccess;
use coauth_data::audit::AdminOperation;
use coauth_data::user::UserRegistrationTokenFilter;
use rand::distributions::{Alphanumeric, DistString};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};

use crate::handlers::admin::CreatedJson;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::model::{Resource, UserRegistrationToken};
use crate::handlers::admin::params::{IncludeCount, extract_pagination, extract_ulid_param};
use crate::handlers::admin::response::{
    PaginatedOutcome, SingleOutcome, paginated_response_for_count_only, paginated_response_for_page,
};
use crate::{AppError, CreatedJsonResult, JsonResult};

/// Payload for `POST /_coauth/admin/user-registration-tokens`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRegistrationTokenRequest")]
pub struct AddRequestBody {
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
) -> CreatedJsonResult<SingleOutcome<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let body: AddRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    // Fall back to a randomly generated token string
    let token_str = body
        .token
        .unwrap_or_else(|| Alphanumeric.sample_string(&mut rand::thread_rng(), 12));

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

    Ok(CreatedJson(SingleOutcome::new_canonical(
        UserRegistrationToken::new(entry, clock.now()),
    )))
}

/// Fetch a single registration token by its ULID.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.get", skip_all)]
pub async fn get_token(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UserRegistrationToken>> {
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

    Ok(Json(SingleOutcome::new_canonical(
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
) -> JsonResult<PaginatedOutcome<UserRegistrationToken>> {
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
            paginated_response_for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .user_registration_token()
                .list(filter, pagination)
                .await?
                .map(|t| UserRegistrationToken::new(t, now));
            paginated_response_for_page(page, pagination, None, &base_url)
        }
        IncludeCount::Only => {
            let total = repo.user_registration_token().count(filter).await?;
            paginated_response_for_count_only(total, &base_url)
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
) -> JsonResult<SingleOutcome<UserRegistrationToken>> {
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

    Ok(Json(SingleOutcome::new(
        UserRegistrationToken::new(revoked, clock.now()),
        format!("/_coauth/admin/user-registration-tokens/{target_id}/revoke"),
    )))
}

/// Restore a previously revoked registration token so it becomes usable again.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.unrevoke", skip_all)]
pub async fn unrevoke_token(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UserRegistrationToken>> {
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

    Ok(Json(SingleOutcome::new(
        UserRegistrationToken::new(restored, clock.now()),
        format!("/_coauth/admin/user-registration-tokens/{target_id}/unrevoke"),
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

/// Payload for `PUT /_coauth/admin/user-registration-tokens/{id}`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "EditUserRegistrationTokenRequest")]
pub struct UpdateRequestBody {
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
) -> JsonResult<SingleOutcome<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let target_id = extract_ulid_param(req)?;
    let body: UpdateRequestBody = req.parse_json().await.map_err(AppError::internal)?;

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

    Ok(Json(SingleOutcome::new(
        UserRegistrationToken::new(entry, clock.now()),
        format!("/_coauth/admin/user-registration-tokens/{target_id}"),
    )))
}

#[cfg(test)]
mod tests;
