// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use coauth_data::RepositoryAccess;
use coauth_data::audit::AdminOperation;
use coauth_data::user::BrowserSessionFilter;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::model::{Resource, UserSession, to_user_session};
use crate::handlers::admin::params::{IncludeCount, extract_pagination, extract_ulid_param};
use crate::handlers::admin::response::{
    PaginatedOutcome, SingleOutcome, paginated_response_for_count_only, paginated_response_for_page,
};
use crate::{AppError, JsonResult};

/// End an active browser session. Returns an error when the session does not
/// exist or has already been finished.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_sessions.finish", skip_all)]
pub async fn finish_session(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UserSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let session_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let browser_session = repo
        .browser_session()
        .lookup(session_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("User session with ID {session_id} not found"))
        })?;

    if browser_session.finished_at.is_some() {
        return Err(AppError::bad_request(format!(
            "User session with ID {session_id} is already finished"
        )));
    }

    let ended = repo
        .browser_session()
        .finish(&clock, browser_session)
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::SessionTerminated,
        "user_session",
        Some(session_id),
        serde_json::json!({}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleOutcome::new(
        to_user_session(ended),
        format!("/_coauth/admin/user-sessions/{session_id}/finish"),
    )))
}

/// Look up a single browser session by its ULID.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_sessions.get", skip_all)]
pub async fn get_session(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UserSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let session_id = extract_ulid_param(req)?;

    let browser_session = repo
        .browser_session()
        .lookup(session_id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User session ID {session_id} not found")))?;

    Ok(Json(SingleOutcome::new_canonical(to_user_session(
        browser_session,
    ))))
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum UserSessionStatus {
    Active,
    Finished,
}

impl std::fmt::Display for UserSessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Finished => f.write_str("finished"),
        }
    }
}

/// Query-string filters accepted by the list endpoint.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UserSessionFilter")]
pub struct FilterParams {
    /// Only return sessions belonging to this user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Restrict results by lifecycle state.
    ///
    /// * `active` -- sessions that have not been ended
    /// * `finished` -- sessions that have been ended
    ///
    /// When omitted, both active and finished sessions are returned.
    #[serde(rename = "filter[status]")]
    status: Option<UserSessionStatus>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delimiter = '?';

        if let Some(uid) = self.user {
            write!(f, "{delimiter}filter[user]={uid}")?;
            delimiter = '&';
        }

        if let Some(st) = self.status {
            write!(f, "{delimiter}filter[status]={st}")?;
            delimiter = '&';
        }

        let _ = delimiter;
        Ok(())
    }
}

/// List browser sessions with optional filtering and pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_sessions.list", skip_all)]
pub async fn list_sessions(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedOutcome<UserSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req
        .parse_queries()
        .map_err(|error| AppError::bad_request(format!("Invalid filter parameters: {error}")))?;

    let base_url = format!("{path}{params}", path = UserSession::PATH);
    let base_url = include_count.add_to_base(&base_url);

    let mut filter = BrowserSessionFilter::default();

    // Optionally restrict to a specific user
    let resolved_user = match params.user {
        Some(uid) => {
            let u = repo
                .user()
                .lookup(uid)
                .await?
                .ok_or_else(|| AppError::not_found(format!("User ID {uid} not found")))?;
            Some(u)
        }
        None => None,
    };

    filter = match &resolved_user {
        Some(u) => filter.for_user(u),
        None => filter,
    };

    // Optionally restrict by session status
    filter = match params.status {
        Some(UserSessionStatus::Active) => filter.active_only(),
        Some(UserSessionStatus::Finished) => filter.finished_only(),
        None => filter,
    };

    let result = match include_count {
        IncludeCount::True => {
            let page = repo
                .browser_session()
                .list(filter, pagination)
                .await?
                .map(to_user_session);
            let total = repo.browser_session().count(filter).await?;
            paginated_response_for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .browser_session()
                .list(filter, pagination)
                .await?
                .map(to_user_session);
            paginated_response_for_page(page, pagination, None, &base_url)
        }
        IncludeCount::Only => {
            let total = repo.browser_session().count(filter).await?;
            paginated_response_for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;

    use crate::handlers::test_utils::{
        RequestBuilderExt, ResponseExt, TestState, assert_stamped_since, setup, stable_json,
    };

    #[tokio::test]
    async fn test_finish_session() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision a user and a user session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post(format!(
            "/_coauth/admin/user-sessions/{}/finish",
            session.id
        ))
        .bearer(&token)
        .empty();
        let before = chrono::Utc::now();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // `finished_at` is stamped from the request-time wall clock.
        assert_stamped_since(
            &body["data"]["attributes"]["finished_at"],
            before,
            "finished_at",
        );
    }

    #[tokio::test]
    async fn test_finish_already_finished_session() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision a user and a user session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();

        // Finish the session first
        let session = repo
            .browser_session()
            .finish(&state.clock, session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Move the clock forward
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/_coauth/admin/user-sessions/{}/finish",
            session.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!("User session with ID {} is already finished", session.id)
        );
    }

    #[tokio::test]
    async fn test_finish_unknown_session() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request =
            Request::post("/_coauth/admin/user-sessions/01040G2081040G2081040G2081/finish")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "User session with ID 01040G2081040G2081040G2081 not found"
        );
    }

    #[tokio::test]
    async fn test_get() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision a user and a user session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let session_id = session.id;
        let request = Request::get(format!("/_coauth/admin/user-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(stable_json(&body), @r#"
        {
          "data": {
            "type": "user-session",
            "id": "[id-1]",
            "attributes": {
              "created_at": "[timestamp-1]",
              "finished_at": null,
              "user_id": "[id-2]",
              "user_agent": null,
              "last_active_at": null,
              "last_active_ip": null
            },
            "links": {
              "self": "/_coauth/admin/user-sessions/[id-1]"
            }
          },
          "links": {
            "self": "/_coauth/admin/user-sessions/[id-1]"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_user_session_list() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision two users, one user session for each, and finish one of them
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        state.clock.advance(Duration::minutes(1));

        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();

        repo.browser_session()
            .add(&mut rng, &state.clock, &alice, None)
            .await
            .unwrap();

        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &bob, None)
            .await
            .unwrap();
        state.clock.advance(Duration::minutes(1));
        repo.browser_session()
            .finish(&state.clock, session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get("/_coauth/admin/user-sessions")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(stable_json(&body), @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user-session",
              "id": "[id-1]",
              "attributes": {
                "created_at": "[timestamp-1]",
                "finished_at": "[timestamp-2]",
                "user_id": "[id-2]",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null
              },
              "links": {
                "self": "/_coauth/admin/user-sessions/[id-1]"
              },
              "meta": {
                "page": {
                  "cursor": "[id-1]"
                }
              }
            },
            {
              "type": "user-session",
              "id": "[id-3]",
              "attributes": {
                "created_at": "[timestamp-1]",
                "finished_at": null,
                "user_id": "[id-4]",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null
              },
              "links": {
                "self": "/_coauth/admin/user-sessions/[id-3]"
              },
              "meta": {
                "page": {
                  "cursor": "[id-3]"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-sessions?page[first]=10",
            "first": "/_coauth/admin/user-sessions?page[first]=10",
            "last": "/_coauth/admin/user-sessions?page[last]=10"
          }
        }
        "#);

        // Filter by user
        let request = Request::get(format!(
            "/_coauth/admin/user-sessions?filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(stable_json(&body), @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-session",
              "id": "[id-1]",
              "attributes": {
                "created_at": "[timestamp-1]",
                "finished_at": null,
                "user_id": "[id-2]",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null
              },
              "links": {
                "self": "/_coauth/admin/user-sessions/[id-1]"
              },
              "meta": {
                "page": {
                  "cursor": "[id-1]"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-sessions?filter[user]=[id-2]&page[first]=10",
            "first": "/_coauth/admin/user-sessions?filter[user]=[id-2]&page[first]=10",
            "last": "/_coauth/admin/user-sessions?filter[user]=[id-2]&page[last]=10"
          }
        }
        "#);

        // Filter by status (active)
        let request = Request::get("/_coauth/admin/user-sessions?filter[status]=active")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(stable_json(&body), @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-session",
              "id": "[id-1]",
              "attributes": {
                "created_at": "[timestamp-1]",
                "finished_at": null,
                "user_id": "[id-2]",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null
              },
              "links": {
                "self": "/_coauth/admin/user-sessions/[id-1]"
              },
              "meta": {
                "page": {
                  "cursor": "[id-1]"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-sessions?filter[status]=active&page[first]=10",
            "first": "/_coauth/admin/user-sessions?filter[status]=active&page[first]=10",
            "last": "/_coauth/admin/user-sessions?filter[status]=active&page[last]=10"
          }
        }
        "#);

        // Filter by status (finished)
        let request = Request::get("/_coauth/admin/user-sessions?filter[status]=finished")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(stable_json(&body), @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-session",
              "id": "[id-1]",
              "attributes": {
                "created_at": "[timestamp-1]",
                "finished_at": "[timestamp-2]",
                "user_id": "[id-2]",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null
              },
              "links": {
                "self": "/_coauth/admin/user-sessions/[id-1]"
              },
              "meta": {
                "page": {
                  "cursor": "[id-1]"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-sessions?filter[status]=finished&page[first]=10",
            "first": "/_coauth/admin/user-sessions?filter[status]=finished&page[first]=10",
            "last": "/_coauth/admin/user-sessions?filter[status]=finished&page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/_coauth/admin/user-sessions?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(stable_json(&body), @r#"
        {
          "data": [
            {
              "type": "user-session",
              "id": "[id-1]",
              "attributes": {
                "created_at": "[timestamp-1]",
                "finished_at": "[timestamp-2]",
                "user_id": "[id-2]",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null
              },
              "links": {
                "self": "/_coauth/admin/user-sessions/[id-1]"
              },
              "meta": {
                "page": {
                  "cursor": "[id-1]"
                }
              }
            },
            {
              "type": "user-session",
              "id": "[id-3]",
              "attributes": {
                "created_at": "[timestamp-1]",
                "finished_at": null,
                "user_id": "[id-4]",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null
              },
              "links": {
                "self": "/_coauth/admin/user-sessions/[id-3]"
              },
              "meta": {
                "page": {
                  "cursor": "[id-3]"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-sessions?count=false&page[first]=10",
            "first": "/_coauth/admin/user-sessions?count=false&page[first]=10",
            "last": "/_coauth/admin/user-sessions?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/_coauth/admin/user-sessions?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(stable_json(&body), @r#"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/_coauth/admin/user-sessions?count=only"
          }
        }
        "#);

        // Test count=false with filtering
        let request = Request::get(format!(
            "/_coauth/admin/user-sessions?count=false&filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(stable_json(&body), @r#"
        {
          "data": [
            {
              "type": "user-session",
              "id": "[id-1]",
              "attributes": {
                "created_at": "[timestamp-1]",
                "finished_at": null,
                "user_id": "[id-2]",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null
              },
              "links": {
                "self": "/_coauth/admin/user-sessions/[id-1]"
              },
              "meta": {
                "page": {
                  "cursor": "[id-1]"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-sessions?filter[user]=[id-2]&count=false&page[first]=10",
            "first": "/_coauth/admin/user-sessions?filter[user]=[id-2]&count=false&page[first]=10",
            "last": "/_coauth/admin/user-sessions?filter[user]=[id-2]&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get("/_coauth/admin/user-sessions?count=only&filter[status]=active")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(stable_json(&body), @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/_coauth/admin/user-sessions?filter[status]=active&count=only"
          }
        }
        "#);
    }
}
