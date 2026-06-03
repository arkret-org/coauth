// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use coauth_data::{
    RepositoryAccess,
    audit::AdminOperation,
    oauth::OAuthSessionFilter,
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
};
use oauth_types::scope::{Scope, ScopeToken};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    AppError, JsonResult,
    handlers::admin::{
        call_context::extract_call_context,
        model::{OAuthSession, Resource},
        params::{IncludeCount, extract_pagination, extract_ulid_param},
        response::{
            PaginatedResponse, SingleResponse, paginated_response_for_count_only,
            paginated_response_for_page,
        },
    },
};

/// Terminate an active OAuth session. If the session is associated with a
/// user, a device-sync job is enqueued so that downstream `PrincipalServers`
/// learn about the revocation promptly.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.oauth_sessions.finish", skip_all)]
pub async fn finish_session(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<OAuthSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let session_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let oauth_session = repo
        .oauth_session()
        .lookup(session_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("OAuth session with ID {session_id} not found"))
        })?;

    if oauth_session.finished_at().is_some() {
        return Err(AppError::bad_request(format!(
            "OAuth session with ID {session_id} is already finished"
        )));
    }

    // When the session belongs to a user, schedule a device list sync so that
    // the PrincipalServer is notified of the change.
    if let Some(uid) = oauth_session.user_id {
        tracing::info!(user.id = %uid, "Scheduling device sync job for user");
        let sync_job = SyncDevicesJob::new_for_id(uid);
        repo.queue_job()
            .schedule_job(&mut rng, &clock, sync_job)
            .await?;
    }

    let ended = repo.oauth_session().finish(&clock, oauth_session).await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::SessionTerminated,
        "oauth_session",
        Some(session_id),
        serde_json::json!({}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        OAuthSession::from(ended),
        format!("/_cokret/local/admin/oauth-sessions/{session_id}/finish"),
    )))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.oauth_session.get", skip_all)]
pub async fn get_session(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<OAuthSession>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let session = repo
        .oauth_session()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("OAuth session ID {id} not found")))?;

    Ok(Json(SingleResponse::new_canonical(OAuthSession::from(
        session,
    ))))
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum OAuthSessionStatus {
    Active,
    Finished,
}

impl std::fmt::Display for OAuthSessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Finished => write!(f, "finished"),
        }
    }
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum OAuthClientKind {
    Dynamic,
    Static,
}

impl std::fmt::Display for OAuthClientKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dynamic => write!(f, "dynamic"),
            Self::Static => write!(f, "static"),
        }
    }
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "OAuthSessionFilter")]
pub struct FilterParams {
    /// Retrieve the items for the given user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Retrieve the items for the given client
    #[serde(rename = "filter[client]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    client: Option<Ulid>,

    /// Retrieve the items only for a specific client kind
    #[serde(rename = "filter[client-kind]")]
    client_kind: Option<OAuthClientKind>,

    /// Retrieve the items started from the given browser session
    #[serde(rename = "filter[user-session]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    user_session: Option<Ulid>,

    /// Retrieve the items with the given scope
    #[serde(default, rename = "filter[scope]")]
    scope: Vec<String>,

    /// Retrieve the items with the given status
    ///
    /// Defaults to retrieve all sessions, including finished ones.
    ///
    /// * `active`: Only retrieve active sessions
    ///
    /// * `finished`: Only retrieve finished sessions
    #[serde(rename = "filter[status]")]
    status: Option<OAuthSessionStatus>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(user) = self.user {
            write!(f, "{sep}filter[user]={user}")?;
            sep = '&';
        }

        if let Some(client) = self.client {
            write!(f, "{sep}filter[client]={client}")?;
            sep = '&';
        }

        if let Some(client_kind) = self.client_kind {
            write!(f, "{sep}filter[client-kind]={client_kind}")?;
            sep = '&';
        }

        if let Some(user_session) = self.user_session {
            write!(f, "{sep}filter[user-session]={user_session}")?;
            sep = '&';
        }

        for scope in &self.scope {
            write!(f, "{sep}filter[scope]={scope}")?;
            sep = '&';
        }

        if let Some(status) = self.status {
            write!(f, "{sep}filter[status]={status}")?;
            sep = '&';
        }

        let _ = sep;
        Ok(())
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.oauth_sessions.list", skip_all)]
pub async fn list_sessions(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<OAuthSession>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base = format!("{path}{params}", path = OAuthSession::PATH);
    let base = include_count.add_to_base(&base);
    let filter = OAuthSessionFilter::default();

    // Load the user from the filter
    let user = if let Some(user_id) = params.user {
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("User ID {user_id} not found")))?;

        Some(user)
    } else {
        None
    };

    let filter = match &user {
        Some(user) => filter.for_user(user),
        None => filter,
    };

    let client = if let Some(client_id) = params.client {
        let client = repo
            .oauth_client()
            .lookup(client_id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("Client ID {client_id} not found")))?;

        Some(client)
    } else {
        None
    };

    let filter = match &client {
        Some(client) => filter.for_client(client),
        None => filter,
    };

    let filter = match params.client_kind {
        Some(OAuthClientKind::Dynamic) => filter.only_dynamic_clients(),
        Some(OAuthClientKind::Static) => filter.only_static_clients(),
        None => filter,
    };

    let user_session = if let Some(user_session_id) = params.user_session {
        let user_session = repo
            .browser_session()
            .lookup(user_session_id)
            .await?
            .ok_or_else(|| {
                AppError::not_found(format!("User session ID {user_session_id} not found"))
            })?;

        Some(user_session)
    } else {
        None
    };

    let filter = match &user_session {
        Some(user_session) => filter.for_browser_session(user_session),
        None => filter,
    };

    let scope: Scope = params
        .scope
        .into_iter()
        .map(|s| {
            ScopeToken::from_str(&s).map_err(|_| {
                AppError::bad_request(format!("Invalid scope {s:?} in filter parameters"))
            })
        })
        .collect::<Result<_, _>>()?;

    let filter = if scope.is_empty() {
        filter
    } else {
        filter.with_scope(&scope)
    };

    let filter = match params.status {
        Some(OAuthSessionStatus::Active) => filter.active_only(),
        Some(OAuthSessionStatus::Finished) => filter.finished_only(),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .oauth_session()
                .list(filter, pagination)
                .await?
                .map(OAuthSession::from);
            let count = repo.oauth_session().count(filter).await?;
            paginated_response_for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .oauth_session()
                .list(filter, pagination)
                .await?
                .map(OAuthSession::from);
            paginated_response_for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.oauth_session().count(filter).await?;
            paginated_response_for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::{AccessToken, Clock as _};
    use hyper::{Request, StatusCode};
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_finish_session() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // Get the session ID from the token we just created
        let mut repo = state.repository().await.unwrap();
        let AccessToken { session_id, .. } = repo
            .oauth_access_token()
            .find_by_token(&token)
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post(format!(
            "/_cokret/local/admin/oauth-sessions/{session_id}/finish"
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The finished_at timestamp should be the same as the current time
        assert_eq!(
            body["data"]["attributes"]["finished_at"],
            serde_json::json!(state.clock.now())
        );
    }

    #[tokio::test]
    async fn test_finish_already_finished_session() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();

        // Create first admin token for the API call
        let admin_token = state.token_with_scope("urn:coauth:admin").await;

        // Create a second admin session that we'll finish
        let second_admin_token = state.token_with_scope("urn:coauth:admin").await;

        // Get the second session and finish it first
        let mut repo = state.repository().await.unwrap();
        let AccessToken { session_id, .. } = repo
            .oauth_access_token()
            .find_by_token(&second_admin_token)
            .await
            .unwrap()
            .unwrap();

        let session = repo
            .oauth_session()
            .lookup(session_id)
            .await
            .unwrap()
            .unwrap();

        // Finish the session first
        let session = repo
            .oauth_session()
            .finish(&state.clock, session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Move the clock forward
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/_cokret/local/admin/oauth-sessions/{}/finish",
            session.id
        ))
        .bearer(&admin_token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!("OAuth session with ID {} is already finished", session.id)
        );
    }

    #[tokio::test]
    async fn test_finish_unknown_session() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request =
            Request::post("/_cokret/local/admin/oauth-sessions/01040G2081040G2081040G2081/finish")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "OAuth session with ID 01040G2081040G2081040G2081 not found"
        );
    }

    #[tokio::test]
    async fn test_get() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // state.token_with_scope did create a session, so we can get it here
        let mut repo = state.repository().await.unwrap();
        let AccessToken { session_id, .. } = repo
            .oauth_access_token()
            .find_by_token(&token)
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get(format!("/_cokret/local/admin/oauth-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "oauth-session");
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "oauth-session",
            "id": "01FSHN9AG0MKGTBNZ16RDR3PVY",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "finished_at": null,
              "user_id": null,
              "user_session_id": null,
              "client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
              "scope": "urn:coauth:admin",
              "user_agent": null,
              "last_active_at": null,
              "last_active_ip": null,
              "human_name": null
            },
            "links": {
              "self": "/_cokret/local/admin/oauth-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
            }
          },
          "links": {
            "self": "/_cokret/local/admin/oauth-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
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

        let session_id = Ulid::nil();
        let request = Request::get(format!("/_cokret/local/admin/oauth-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_oauth_simple_session_list() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        // We already have a session because of the token above
        let request = Request::get("/_cokret/local/admin/oauth-sessions")
            .bearer(&token)
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
              "type": "oauth-session",
              "id": "01FSHN9AG0MKGTBNZ16RDR3PVY",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "finished_at": null,
                "user_id": null,
                "user_session_id": null,
                "client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
                "scope": "urn:coauth:admin",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "human_name": null
              },
              "links": {
                "self": "/_cokret/local/admin/oauth-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MKGTBNZ16RDR3PVY"
                }
              }
            }
          ],
          "links": {
            "self": "/_cokret/local/admin/oauth-sessions?page[first]=10",
            "first": "/_cokret/local/admin/oauth-sessions?page[first]=10",
            "last": "/_cokret/local/admin/oauth-sessions?page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/_cokret/local/admin/oauth-sessions?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "oauth-session",
              "id": "01FSHN9AG0MKGTBNZ16RDR3PVY",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "finished_at": null,
                "user_id": null,
                "user_session_id": null,
                "client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
                "scope": "urn:coauth:admin",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "human_name": null
              },
              "links": {
                "self": "/_cokret/local/admin/oauth-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MKGTBNZ16RDR3PVY"
                }
              }
            }
          ],
          "links": {
            "self": "/_cokret/local/admin/oauth-sessions?count=false&page[first]=10",
            "first": "/_cokret/local/admin/oauth-sessions?count=false&page[first]=10",
            "last": "/_cokret/local/admin/oauth-sessions?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/_cokret/local/admin/oauth-sessions?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/_cokret/local/admin/oauth-sessions?count=only"
          }
        }
        "#);
    }
}
