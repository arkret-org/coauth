// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr as _;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use coauth_data::TokenType;
use coauth_data::personal::PersonalSessionFilter;
use coauth_data::personal::session::PersonalSessionOwner;
use coauth_data::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};
use coauth_principal::PrincipalServerAdmin;
use oauth_types::scope::{Scope, ScopeToken};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::error;
use ulid::Ulid;

use crate::handlers::admin::call_context::{CallerSession, extract_call_context};
use crate::handlers::admin::model::{PersonalSession, Resource};
use crate::handlers::admin::params::{IncludeCount, extract_pagination, extract_ulid_param};
use crate::handlers::admin::response::{
    PaginatedOutcome, SingleOutcome, paginated_response_for_count_only, paginated_response_for_page,
};
use crate::handlers::common::DepotExt;
use crate::{AppError, CreatedJsonResult, JsonResult};

/// Derives the [`PersonalSessionOwner`] from the caller's active session,
/// so that newly created personal sessions are attributed correctly.
pub(crate) fn personal_session_owner_from_caller(caller: &CallerSession) -> PersonalSessionOwner {
    match caller {
        CallerSession::OAuthSession(entry) => {
            if let Some(uid) = entry.user_id {
                PersonalSessionOwner::User(uid)
            } else {
                PersonalSessionOwner::OAuthClient(entry.client_id)
            }
        }
        CallerSession::PersonalSession(entry) => PersonalSessionOwner::User(entry.actor_user_id),
    }
}

/// Request body accepted by `POST /_coauth/admin/personal-sessions`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "CreatePersonalSessionRequest")]
pub struct AddRequestBody {
    /// The user this session acts on behalf of
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    actor_user_id: Ulid,

    /// A human-friendly label for the session
    human_name: String,

    /// Space-separated OAuth scopes
    scope: String,

    /// How long (in seconds) before the access token expires.
    /// Omit for a non-expiring token.
    expires_in: Option<u32>,
}

/// Create a new personal session and its initial access token.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.add", skip_all)]
pub async fn add_session(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleOutcome<PersonalSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        session: caller_session,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let principal_server = depot.principal_server()?;
    let body: AddRequestBody = req.parse_json().await.map_err(AppError::internal)?;
    let owner = personal_session_owner_from_caller(&caller_session);

    // Look up the target user
    let target_user = repo
        .user()
        .lookup(body.actor_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("Specified user does not exist"))?;

    if !target_user.is_valid_actor() {
        return Err(AppError::gone("Target user account is not active"));
    }

    let parsed_scope: Scope = body
        .scope
        .parse()
        .map_err(|_| AppError::bad_request("Provided scope string is malformed"))?;

    // Persist the personal session
    let new_session = repo
        .personal_session()
        .add(
            &mut rng,
            &clock,
            owner,
            &target_user,
            body.human_name,
            parsed_scope,
        )
        .await?;

    // Issue the initial access token
    let raw_token = TokenType::PersonalAccessToken.generate(&mut rng);
    let token_record = repo
        .personal_access_token()
        .add(
            &mut rng,
            &clock,
            &new_session,
            &raw_token,
            body.expires_in
                .map(|secs| Duration::seconds(i64::from(secs))),
        )
        .await?;

    // Provision any Cokret devices declared through scope entries.
    if new_session.has_device() {
        repo.user().acquire_lock_for_sync(&target_user).await?;

        for scope_token in &*new_session.scope {
            let raw = scope_token.as_str();
            if let Some(device_id) = raw.strip_prefix("urn:cokret:client:device:") {
                principal_server
                    .upsert_device(&target_user.localpart, device_id, None)
                    .await
                    .context("Device provisioning failed")
                    .map_err(|e| AppError::internal(std::io::Error::other(e.to_string())))?;
            }
        }
    }

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleOutcome::new_canonical(
            PersonalSession::try_from((new_session, Some(token_record)))?.with_token(raw_token),
        ),
    ))
}

/// Retrieve a single personal session by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.get", skip_all)]
pub async fn get_session(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<PersonalSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let target_id = extract_ulid_param(req)?;

    let entry = repo
        .personal_session()
        .lookup(target_id)
        .await?
        .ok_or_else(|| AppError::not_found("No personal session matches the given ID"))?;

    let active_token = if entry.is_revoked() {
        None
    } else {
        repo.personal_access_token()
            .find_active_for_session(&entry)
            .await?
    };

    Ok(Json(SingleOutcome::new_canonical(
        PersonalSession::try_from((entry, active_token))?,
    )))
}

/// Whether a personal session is currently active or has been revoked.
#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum PersonalSessionStatus {
    Active,
    Revoked,
}

impl std::fmt::Display for PersonalSessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Revoked => f.write_str("revoked"),
        }
    }
}

/// Query-string parameters that control filtering on the list endpoint.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "PersonalSessionFilter")]
pub struct FilterParams {
    /// Narrow results to sessions owned by this user
    #[serde(rename = "filter[owner_user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    owner_user: Option<Ulid>,

    /// Narrow results to sessions owned by this OAuth client
    #[serde(rename = "filter[owner_client]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    owner_client: Option<Ulid>,

    /// Narrow results to sessions where the acting user matches
    #[serde(rename = "filter[actor_user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    actor_user: Option<Ulid>,

    /// Only return sessions whose scope contains every listed token
    #[serde(default, rename = "filter[scope]")]
    scope: Vec<String>,

    /// Restrict by lifecycle status
    #[serde(rename = "filter[status]")]
    status: Option<PersonalSessionStatus>,

    /// Upper bound on the access-token expiry timestamp
    #[serde(rename = "filter[expires_before]")]
    expires_before: Option<DateTime<Utc>>,

    /// Lower bound on the access-token expiry timestamp
    #[serde(rename = "filter[expires_after]")]
    expires_after: Option<DateTime<Utc>>,

    /// Whether the access token carries an expiry at all
    #[serde(rename = "filter[expires]")]
    expires: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delim = '?';

        if let Some(val) = self.owner_user {
            write!(f, "{delim}filter[owner_user]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.owner_client {
            write!(f, "{delim}filter[owner_client]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.actor_user {
            write!(f, "{delim}filter[actor_user]={val}")?;
            delim = '&';
        }
        for tok in &self.scope {
            write!(f, "{delim}filter[scope]={tok}")?;
            delim = '&';
        }
        if let Some(val) = self.status {
            write!(f, "{delim}filter[status]={val}")?;
            delim = '&';
        }
        if let Some(ts) = self.expires_before {
            write!(
                f,
                "{delim}filter[expires_before]={}",
                ts.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            delim = '&';
        }
        if let Some(ts) = self.expires_after {
            write!(
                f,
                "{delim}filter[expires_after]={}",
                ts.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            delim = '&';
        }
        if let Some(val) = self.expires {
            write!(f, "{delim}filter[expires]={val}")?;
            delim = '&';
        }

        let _ = delim;
        Ok(())
    }
}

/// List personal sessions, with optional filtering and cursor-based pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.list", skip_all)]
pub async fn list_sessions(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedOutcome<PersonalSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base_url = format!("{path}{params}", path = PersonalSession::PATH);
    let base_url = include_count.add_to_base(&base_url);

    let mut filter = PersonalSessionFilter::new();

    // Resolve and apply the owner-user filter
    let resolved_owner = if let Some(uid) = params.owner_user {
        let u = repo
            .user()
            .lookup(uid)
            .await?
            .ok_or_else(|| AppError::not_found(format!("User {uid} does not exist")))?;
        Some(u)
    } else {
        None
    };

    filter = match &resolved_owner {
        Some(u) => filter.for_owner_user(u),
        None => filter,
    };

    // Resolve and apply the owner-client filter
    let resolved_client = if let Some(cid) = params.owner_client {
        let c = repo
            .oauth_client()
            .lookup(cid)
            .await?
            .ok_or_else(|| AppError::not_found(format!("Client {cid} does not exist")))?;
        Some(c)
    } else {
        None
    };

    filter = match &resolved_client {
        Some(c) => filter.for_owner_oauth_client(c),
        None => filter,
    };

    // Resolve and apply the actor-user filter
    let resolved_actor = if let Some(uid) = params.actor_user {
        let u = repo
            .user()
            .lookup(uid)
            .await?
            .ok_or_else(|| AppError::not_found(format!("User {uid} does not exist")))?;
        Some(u)
    } else {
        None
    };

    filter = match &resolved_actor {
        Some(u) => filter.for_actor_user(u),
        None => filter,
    };

    // Parse and apply scope tokens
    let requested_scope: Scope = params
        .scope
        .into_iter()
        .map(|raw| {
            ScopeToken::from_str(&raw)
                .map_err(|_| AppError::bad_request(format!("Scope token {raw:?} is not valid")))
        })
        .collect::<Result<_, _>>()?;

    if !requested_scope.is_empty() {
        filter = filter.with_scope(&requested_scope);
    }

    // Apply status filter
    filter = match params.status {
        Some(PersonalSessionStatus::Active) => filter.active_only(),
        Some(PersonalSessionStatus::Revoked) => filter.finished_only(),
        None => filter,
    };

    // Apply expiry-window filters
    if let Some(after) = params.expires_after {
        filter = filter.with_expires_after(after);
    }
    if let Some(before) = params.expires_before {
        filter = filter.with_expires_before(before);
    }
    if let Some(has_expiry) = params.expires {
        filter = filter.with_expires(has_expiry);
    }

    let result = match include_count {
        IncludeCount::True => {
            let page = repo.personal_session().list(filter, pagination).await?;
            let total = repo.personal_session().count(filter).await?;
            paginated_response_for_page(
                page.try_map(PersonalSession::try_from)?,
                pagination,
                Some(total),
                &base_url,
            )
        }
        IncludeCount::False => {
            let page = repo.personal_session().list(filter, pagination).await?;
            paginated_response_for_page(
                page.try_map(PersonalSession::try_from)?,
                pagination,
                None,
                &base_url,
            )
        }
        IncludeCount::Only => {
            let total = repo.personal_session().count(filter).await?;
            paginated_response_for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

/// Optional payload for the regenerate endpoint.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "RegeneratePersonalSessionRequest")]
pub struct RegenerateRequestBody {
    /// Lifetime of the new token in seconds; omit for a non-expiring token.
    expires_in: Option<u32>,
}

/// Rotate the access token for an existing personal session.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.add", skip_all)]
pub async fn regenerate_session(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleOutcome<PersonalSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        session: caller_session,
        ..
    } = ctx;
    let target_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let body: RegenerateRequestBody = req
        .parse_json()
        .await
        .unwrap_or(RegenerateRequestBody { expires_in: None });

    let entry = repo
        .personal_session()
        .lookup(target_id)
        .await?
        .ok_or_else(|| AppError::not_found("Requested session does not exist"))?;

    if !entry.is_valid() {
        return Err(AppError::unprocessable_entity("Session not valid"));
    }

    // Only the session owner may regenerate the token
    let caller_owner = personal_session_owner_from_caller(&caller_session);
    if entry.owner != caller_owner {
        return Err(AppError::forbidden("Session does not belong to you"));
    }

    // Revoke the currently-active token
    let previous_token = repo
        .personal_access_token()
        .find_active_for_session(&entry)
        .await?;
    let Some(prev) = previous_token else {
        error!("session appears valid but has no active access token");
        return Err(AppError::unprocessable_entity("Session not valid"));
    };

    repo.personal_access_token().revoke(&clock, prev).await?;

    // Mint the replacement token
    let new_token_str = TokenType::PersonalAccessToken.generate(&mut rng);
    let new_token_record = repo
        .personal_access_token()
        .add(
            &mut rng,
            &clock,
            &entry,
            &new_token_str,
            body.expires_in
                .map(|secs| Duration::seconds(i64::from(secs))),
        )
        .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleOutcome::new_canonical(
            PersonalSession::try_from((entry, Some(new_token_record)))?.with_token(new_token_str),
        ),
    ))
}

/// Revoke a personal session, invalidating its access token.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.revoke", skip_all)]
pub async fn revoke_session(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<PersonalSession>> {
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
        .personal_session()
        .lookup(target_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Personal session with ID {target_id} not found"))
        })?;

    if entry.is_revoked() {
        return Err(AppError::conflict(format!(
            "Personal session with ID {target_id} is already revoked"
        )));
    }

    let revoked = repo.personal_session().revoke(&clock, entry).await?;

    // Schedule a device-sync job when the session carried device scopes
    if revoked.has_device() {
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SyncDevicesJob::new_for_id(revoked.actor_user_id),
            )
            .await?;
    }

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        coauth_data::audit::AdminOperation::SessionTerminated,
        "personal_session",
        Some(target_id),
        serde_json::json!({}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleOutcome::new_canonical(
        PersonalSession::try_from((revoked, None))?,
    )))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Duration;
    use coauth_data::Clock;
    use coauth_data::personal::session::PersonalSessionOwner;
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use oauth_types::scope::{OPENID, Scope};
    use serde_json::{Value, json};
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_create_personal_session_with_token() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Provision a user first
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let payload = serde_json::json!({
            "actor_user_id": user.id,
            "human_name": "Test Session",
            "scope": "openid urn:coauth:admin",
            "expires_in": 3600
        });

        let request = Request::post("/_coauth/admin/personal-sessions")
            .bearer(&token)
            .json(&payload);

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "personal-session",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "revoked_at": null,
              "owner_user_id": null,
              "owner_client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
              "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_name": "Test Session",
              "scope": "openid urn:coauth:admin",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": "2022-01-16T15:40:00Z",
              "access_token": "mpt_FM44zJN5qePGMLvvMXC4Ds1A3lCWc6_bJ9Wj1"
            },
            "links": {
              "self": "/_coauth/admin/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/_coauth/admin/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_create_personal_session_invalid_user() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let payload = serde_json::json!({
            "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "scope": "openid",
            "human_name": "Test Session",
            "expires_in": 3600
        });

        let request = Request::post("/_coauth/admin/personal-sessions")
            .bearer(&token)
            .json(&payload);

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_personal_session_invalid_scope() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Provision a user first
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let payload = serde_json::json!({
            "actor_user_id": user.id,
            "human_name": "Test Session",
            "scope": "invalid\nscope",
            "expires_in": 3600
        });

        let request = Request::post("/_coauth/admin/personal-sessions")
            .bearer(&token)
            .json(&payload);

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Create a user and personal session for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let personal_session = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.personal_access_token()
            .add(&mut rng, &state.clock, &personal_session, "mpt_hiss", None)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get(format!(
            "/_coauth/admin/personal-sessions/{}",
            personal_session.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["id"], personal_session.id.to_string());
        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "personal-session",
            "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "revoked_at": null,
              "owner_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "owner_client_id": null,
              "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_name": "Test session",
              "scope": "openid",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": null
            },
            "links": {
              "self": "/_coauth/admin/personal-sessions/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
            }
          },
          "links": {
            "self": "/_coauth/admin/personal-sessions/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_not_found() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let missing_id = Ulid::nil();
        let request = Request::get(format!("/_coauth/admin/personal-sessions/{missing_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();

        // Provision a user and several personal sessions for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let sess_a = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.personal_access_token()
            .add(
                &mut rng,
                &state.clock,
                &sess_a,
                "mpt_hiss",
                Some(Duration::days(42)),
            )
            .await
            .unwrap();

        state.clock.advance(Duration::days(1));

        let sess_b = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Another test session".to_owned(),
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.personal_access_token()
            .add(
                &mut rng,
                &state.clock,
                &sess_b,
                "mpt_scratch",
                Some(Duration::days(21)),
            )
            .await
            .unwrap();
        repo.personal_session()
            .revoke(&state.clock, sess_b)
            .await
            .unwrap();

        state.clock.advance(Duration::days(1));

        let sess_c = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Another test session".to_owned(),
                Scope::from_iter([OPENID, "urn:coauth:admin".parse().unwrap()]),
            )
            .await
            .unwrap();
        repo.personal_access_token()
            .add(
                &mut rng,
                &state.clock,
                &sess_c,
                "mpt_meow",
                Some(Duration::days(14)),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let token = state.token_with_scope("urn:coauth:admin").await;
        let request = Request::get("/_coauth/admin/personal-sessions")
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
              "type": "personal-session",
              "id": "01FSHN9AG0YQYAR04VCYTHJ8SK",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "revoked_at": null,
                "owner_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "owner_client_id": null,
                "actor_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "human_name": "Test session",
                "scope": "openid",
                "last_active_at": null,
                "last_active_ip": null,
                "expires_at": "2022-02-27T14:40:00Z"
              },
              "links": {
                "self": "/_coauth/admin/personal-sessions/01FSHN9AG0YQYAR04VCYTHJ8SK"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0YQYAR04VCYTHJ8SK"
                }
              }
            },
            {
              "type": "personal-session",
              "id": "01FSM7P1G0VBGAMK9D9QMGQ5MY",
              "attributes": {
                "created_at": "2022-01-17T14:40:00Z",
                "revoked_at": "2022-01-17T14:40:00Z",
                "owner_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "owner_client_id": null,
                "actor_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "human_name": "Another test session",
                "scope": "openid",
                "last_active_at": null,
                "last_active_ip": null,
                "expires_at": null
              },
              "links": {
                "self": "/_coauth/admin/personal-sessions/01FSM7P1G0VBGAMK9D9QMGQ5MY"
              },
              "meta": {
                "page": {
                  "cursor": "01FSM7P1G0VBGAMK9D9QMGQ5MY"
                }
              }
            },
            {
              "type": "personal-session",
              "id": "01FSPT2RG08Y11Y5BM4VZ4CN8K",
              "attributes": {
                "created_at": "2022-01-18T14:40:00Z",
                "revoked_at": null,
                "owner_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "owner_client_id": null,
                "actor_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "human_name": "Another test session",
                "scope": "openid urn:coauth:admin",
                "last_active_at": null,
                "last_active_ip": null,
                "expires_at": "2022-02-01T14:40:00Z"
              },
              "links": {
                "self": "/_coauth/admin/personal-sessions/01FSPT2RG08Y11Y5BM4VZ4CN8K"
              },
              "meta": {
                "page": {
                  "cursor": "01FSPT2RG08Y11Y5BM4VZ4CN8K"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/personal-sessions?page[first]=10",
            "first": "/_coauth/admin/personal-sessions?page[first]=10",
            "last": "/_coauth/admin/personal-sessions?page[last]=10"
          }
        }
        "#);

        // Validate individual filters against expected ID sets
        let cases: &[(&str, &[&str])] = &[
            (
                "filter[expires_before]=2022-02-15T00:00:00Z",
                &["01FSPT2RG08Y11Y5BM4VZ4CN8K"],
            ),
            (
                "filter[expires_after]=2022-02-15T00:00:00Z",
                &["01FSHN9AG0YQYAR04VCYTHJ8SK"],
            ),
            (
                "filter[status]=active",
                &["01FSHN9AG0YQYAR04VCYTHJ8SK", "01FSPT2RG08Y11Y5BM4VZ4CN8K"],
            ),
            ("filter[status]=revoked", &["01FSM7P1G0VBGAMK9D9QMGQ5MY"]),
            (
                "filter[expires]=true",
                &["01FSHN9AG0YQYAR04VCYTHJ8SK", "01FSPT2RG08Y11Y5BM4VZ4CN8K"],
            ),
            ("filter[expires]=false", &["01FSM7P1G0VBGAMK9D9QMGQ5MY"]),
            (
                "filter[scope]=urn:coauth:admin",
                &["01FSPT2RG08Y11Y5BM4VZ4CN8K"],
            ),
        ];

        for (qs, want_ids) in cases {
            let request = Request::get(format!("/_coauth/admin/personal-sessions?{qs}"))
                .bearer(&token)
                .empty();
            let response = state.request(request).await;
            response.assert_status(StatusCode::OK);
            let body: serde_json::Value = response.json();
            let got: BTreeSet<&str> = body["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["id"].as_str().unwrap())
                .collect();
            let want: BTreeSet<&str> = want_ids.iter().copied().collect();

            assert_eq!(got, want, "filter {qs} returned unexpected results");
        }
    }

    #[tokio::test]
    async fn test_regenerate_personal_session() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Provision a user first
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/_coauth/admin/personal-sessions")
            .bearer(&token)
            .json(json!({
                "actor_user_id": user.id,
                "human_name": "SuperDuperAdminCLITool Token",
                "scope": "openid urn:coauth:admin",
                "expires_in": 3600
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let created_body: Value = response.json();

        let sess_id = created_body["data"]["id"].as_str().unwrap();

        state.clock.advance(Duration::minutes(3));

        let request = Request::post(format!(
            "/_coauth/admin/personal-sessions/{sess_id}/regenerate"
        ))
        .bearer(&token)
        .json(json!({
            "expires_in": 86400
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "personal-session",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "revoked_at": null,
              "owner_user_id": null,
              "owner_client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
              "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_name": "SuperDuperAdminCLITool Token",
              "scope": "openid urn:coauth:admin",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": "2022-01-17T14:43:00Z",
              "access_token": "mpt_6cq7FqNSYoosbXl3bbpfh9yNy9NzuR_0vOV2O"
            },
            "links": {
              "self": "/_coauth/admin/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/_coauth/admin/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_revoke_session() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Provision a user and a personal session
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let sess = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([]),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post(format!(
            "/_coauth/admin/personal-sessions/{}/revoke",
            sess.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["revoked_at"],
            serde_json::json!(Clock::now(&state.clock))
        );
    }

    #[tokio::test]
    async fn test_revoke_already_revoked_session() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Provision a user and a personal session, then revoke it
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let sess = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([]),
            )
            .await
            .unwrap();

        let revoked_sess = repo
            .personal_session()
            .revoke(&state.clock, sess)
            .await
            .unwrap();

        repo.save().await.unwrap();

        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/_coauth/admin/personal-sessions/{}/revoke",
            revoked_sess.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!(
                "Personal session with ID {} is already revoked",
                revoked_sess.id
            )
        );
    }

    #[tokio::test]
    async fn test_revoke_unknown_session() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request =
            Request::post("/_coauth/admin/personal-sessions/01040G2081040G2081040G2081/revoke")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Personal session with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
