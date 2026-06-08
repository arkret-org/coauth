// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr as _;

use coauth_data::{
    RepositoryAccess,
    audit::AdminOperation,
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    user::UserEmailFilter,
};
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    AppError, AppResult, CreatedJsonResult, JsonResult,
    handlers::admin::{
        call_context::extract_call_context,
        model::{Resource, UserEmail},
        params::{IncludeCount, extract_pagination, extract_ulid_param},
        response::{
            PaginatedOutcome, SingleOutcome, paginated_response_for_count_only,
            paginated_response_for_page,
        },
    },
};

/// JSON body accepted by `POST /_coauth/admin/user-emails`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserEmailRequest")]
pub struct AddRequestBody {
    /// Identifier of the user who should own this email.
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    user_id: Ulid,

    /// The email address to attach.
    #[schemars(email)]
    email: String,
}

/// Add a new email address to an existing user account.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_emails.add", skip_all)]
pub async fn add_email(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleOutcome<UserEmail>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let body: AddRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    // Resolve the target user
    let owner = repo
        .user()
        .lookup(body.user_id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {} not found", body.user_id)))?;

    // Ensure the provided address is syntactically valid
    if let Err(source) = lettre::Address::from_str(&body.email) {
        return Err(AppError::with_source(
            StatusCode::BAD_REQUEST,
            format!("Email {:?} is not valid", body.email),
            Box::new(source),
            false,
        ));
    }

    // Reject duplicates
    let existing = repo
        .user_email()
        .count(UserEmailFilter::new().for_email(&body.email))
        .await?;

    if existing > 0 {
        return Err(AppError::conflict(format!(
            "User email {:?} already in use",
            body.email
        )));
    }

    // Persist the new email
    let entry = repo
        .user_email()
        .add(&mut rng, &clock, &owner, body.email)
        .await?;

    // Enqueue a provisioning job so downstream systems pick up the change
    repo.queue_job()
        .schedule_job(&mut rng, &clock, ProvisionUserJob::new_for_id(owner.id))
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UserEmailAdded,
        "user_email",
        Some(entry.id),
        serde_json::json!({ "user_id": owner.id.to_string(), "email": entry.email }),
    )
    .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleOutcome::new_canonical(entry.into()),
    ))
}

/// Remove a user email by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_emails.delete", skip_all)]
pub async fn delete_email(req: &mut Request, depot: &Depot) -> AppResult<StatusCode> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let email_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let entry = repo
        .user_email()
        .lookup(email_id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User email ID {email_id} not found")))?;

    let user_id = entry.user_id;
    let email = entry.email.clone();
    let provision_job = ProvisionUserJob::new_for_id(user_id);
    repo.user_email().remove(entry).await?;

    // Notify downstream systems about the change
    repo.queue_job()
        .schedule_job(&mut rng, &clock, provision_job)
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UserEmailRemoved,
        "user_email",
        Some(email_id),
        serde_json::json!({ "user_id": user_id.to_string(), "email": email }),
    )
    .await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Retrieve a single user email record by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_emails.get", skip_all)]
pub async fn get_email(req: &mut Request, depot: &Depot) -> JsonResult<SingleOutcome<UserEmail>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let email_id = extract_ulid_param(req)?;

    let entry = repo
        .user_email()
        .lookup(email_id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User email ID {email_id} not found")))?;

    Ok(Json(SingleOutcome::new_canonical(UserEmail::from(entry))))
}

/// Query-string parameters for filtering user email results.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UserEmailFilter")]
pub struct FilterParams {
    /// Narrow results to emails belonging to this user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Narrow results to a specific email address
    #[serde(rename = "filter[email]")]
    email: Option<String>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delimiter = '?';

        if let Some(uid) = self.user {
            write!(f, "{delimiter}filter[user]={uid}")?;
            delimiter = '&';
        }

        if let Some(addr) = &self.email {
            write!(f, "{delimiter}filter[email]={addr}")?;
            delimiter = '&';
        }

        let _ = delimiter;
        Ok(())
    }
}

/// List user emails with optional filtering and pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_emails.list", skip_all)]
pub async fn list_emails(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedOutcome<UserEmail>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base_url = format!("{path}{params}", path = UserEmail::PATH);
    let base_url = include_count.add_to_base(&base_url);
    let mut filter = UserEmailFilter::default();

    // Optionally scope to a particular user
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

    // Optionally match by email address
    filter = match &params.email {
        Some(addr) => filter.for_email(addr),
        None => filter,
    };

    let result = match include_count {
        IncludeCount::True => {
            let page = repo
                .user_email()
                .list(filter, pagination)
                .await?
                .map(UserEmail::from);
            let total = repo.user_email().count(filter).await?;
            paginated_response_for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .user_email()
                .list(filter, pagination)
                .await?
                .map(UserEmail::from);
            paginated_response_for_page(page, pagination, None, &base_url)
        }
        IncludeCount::Only => {
            let total = repo.user_email().count(filter).await?;
            paginated_response_for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct UpdateRequestBody {
    email: Option<String>,
    confirmed: Option<bool>,
    is_primary: Option<bool>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_emails.update", skip_all)]
pub async fn update_email(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UserEmail>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let body: UpdateRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let user_email = crate::services::user_admin::patch_user_email(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        id,
        coauth_data::UserEmailPatch {
            email: body.email,
            confirmed: body.confirmed,
            is_primary: body.is_primary,
        },
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleOutcome::new_canonical(UserEmail::from(
        user_email,
    ))))
}

fn map_service_error(error: crate::services::user_admin::UserAdminServiceError) -> AppError {
    match error {
        crate::services::user_admin::UserAdminServiceError::UserEmailNotFound(id) => {
            AppError::not_found(format!("User email ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::InvalidEmail { email, .. } => {
            AppError::bad_request(format!("Email {email:?} is not valid"))
        }
        crate::services::user_admin::UserAdminServiceError::EmailAlreadyInUse(email) => {
            AppError::conflict(format!("User email {email:?} already in use"))
        }
        crate::services::user_admin::UserAdminServiceError::Repository(error) => {
            AppError::internal(error)
        }
        crate::services::user_admin::UserAdminServiceError::UserNotFound(id) => {
            AppError::bad_request(format!("Unexpected user lookup failure for {id}"))
        }
        crate::services::user_admin::UserAdminServiceError::ReferencedUserNotFound(id) => {
            AppError::bad_request(format!("Referenced user ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::UpstreamOAuthLinkNotFound(id) => {
            AppError::bad_request(format!(
                "Unexpected upstream oauth link lookup failure for {id}"
            ))
        }
        crate::services::user_admin::UserAdminServiceError::ProviderNotFound(id) => {
            AppError::bad_request(format!("Provider ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::InvalidDisplayName => {
            AppError::bad_request("Invalid display name")
        }
        crate::services::user_admin::UserAdminServiceError::UpstreamSubjectAlreadyLinked {
            provider_id,
            subject,
        } => AppError::conflict(format!(
            "Provider ID {provider_id} already has subject {subject}"
        )),
        crate::services::user_admin::UserAdminServiceError::PrincipalServer(error) => {
            AppError::internal(std::io::Error::other(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::{
        RepositoryAccess,
        user::{UserEmailRepository, UserRepository},
    };
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ulid::Ulid;

    use crate::handlers::test_utils::{
        RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
    };

    #[tokio::test]
    async fn test_create() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision a user
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/_coauth/admin/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "alice@example.com",
                "user_id": alice.id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "user-email",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "email": "alice@example.com"
            },
            "links": {
              "self": "/_coauth/admin/user-emails/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/_coauth/admin/user-emails/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_user_not_found() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post("/_coauth/admin/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "alice@example.com",
                "user_id": Ulid::nil(),
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "User ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_email_already_exists() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/_coauth/admin/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "alice@example.com",
                "user_id": alice.id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "User email \"alice@example.com\" already in use"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_invalid_email() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/_coauth/admin/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "invalid-email",
                "user_id": alice.id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Email \"invalid-email\" is not valid"
            },
            {
              "title": "Missing domain or user"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_delete() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision a user and an email
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let coauth_data::UserEmail { id, .. } = repo
            .user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::delete(format!("/_coauth/admin/user-emails/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Verify that the email was deleted
        let request = Request::get(format!("/_coauth/admin/user-emails/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let email_id = Ulid::nil();
        let request = Request::delete(format!("/_coauth/admin/user-emails/{email_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision a user and an email
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let coauth_data::UserEmail { id, .. } = repo
            .user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get(format!("/_coauth/admin/user-emails/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "user-email");
        insta::assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "user-email",
            "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "email": "alice@example.com"
            },
            "links": {
              "self": "/_coauth/admin/user-emails/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
            }
          },
          "links": {
            "self": "/_coauth/admin/user-emails/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_get_not_found() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let email_id = Ulid::nil();
        let request = Request::get(format!("/_coauth/admin/user-emails/{email_id}"))
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
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision two users, two emails
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

        repo.user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();
        repo.user_email()
            .add(&mut rng, &state.clock, &bob, "bob@example.com".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get("/_coauth/admin/user-emails")
            .bearer(&token)
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
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/_coauth/admin/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            },
            {
              "type": "user-email",
              "id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "email": "bob@example.com"
              },
              "links": {
                "self": "/_coauth/admin/user-emails/01FSHN9AG0KEPHYQQXW9XPTX6Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0KEPHYQQXW9XPTX6Z"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-emails?page[first]=10",
            "first": "/_coauth/admin/user-emails?page[first]=10",
            "last": "/_coauth/admin/user-emails?page[last]=10"
          }
        }
        "#);

        // Filter by user
        let request = Request::get(format!(
            "/_coauth/admin/user-emails?filter[user]={}",
            alice.id
        ))
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
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/_coauth/admin/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "first": "/_coauth/admin/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "last": "/_coauth/admin/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[last]=10"
          }
        }
        "#);

        // Filter by email
        let request = Request::get("/_coauth/admin/user-emails?filter[email]=alice@example.com")
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
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/_coauth/admin/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-emails?filter[email]=alice@example.com&page[first]=10",
            "first": "/_coauth/admin/user-emails?filter[email]=alice@example.com&page[first]=10",
            "last": "/_coauth/admin/user-emails?filter[email]=alice@example.com&page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/_coauth/admin/user-emails?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/_coauth/admin/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            },
            {
              "type": "user-email",
              "id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "email": "bob@example.com"
              },
              "links": {
                "self": "/_coauth/admin/user-emails/01FSHN9AG0KEPHYQQXW9XPTX6Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0KEPHYQQXW9XPTX6Z"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-emails?count=false&page[first]=10",
            "first": "/_coauth/admin/user-emails?count=false&page[first]=10",
            "last": "/_coauth/admin/user-emails?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/_coauth/admin/user-emails?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/_coauth/admin/user-emails?count=only"
          }
        }
        "###);

        // Test count=false with filtering
        let request = Request::get(format!(
            "/_coauth/admin/user-emails?count=false&filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/_coauth/admin/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "first": "/_coauth/admin/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "last": "/_coauth/admin/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get(format!(
            "/_coauth/admin/user-emails?count=only&filter[user]={}",
            alice.id
        ))
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
            "self": "/_coauth/admin/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=only"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_patch_user_email_updates_address_confirmation_and_primary() {
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
        let username = format!("alice{suffix}");
        let primary_email = format!("alice+{suffix}@example.com");
        let secondary_email = format!("alice+secondary+{suffix}@example.com");
        let updated_email = format!("alice+updated+{suffix}@example.com");

        let user = repo
            .user()
            .add(&mut rng, &state.clock, username)
            .await
            .unwrap();
        let primary = repo
            .user_email()
            .add(&mut rng, &state.clock, &user, primary_email)
            .await
            .unwrap();
        let secondary = repo
            .user_email()
            .add(&mut rng, &state.clock, &user, secondary_email)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::patch(format!("/_coauth/admin/user-emails/{}", secondary.id))
            .bearer(&token)
            .json(serde_json::json!({
                "email": updated_email.clone(),
                "confirmed": false,
                "is_primary": true
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["attributes"]["email"], updated_email);
        assert_eq!(body["data"]["attributes"]["is_primary"], true);
        assert_eq!(
            body["data"]["attributes"]["confirmed_at"],
            serde_json::Value::Null
        );

        let mut repo = state.repository().await.unwrap();
        let updated = repo
            .user_email()
            .lookup(secondary.id)
            .await
            .unwrap()
            .unwrap();
        let old_primary = repo.user_email().lookup(primary.id).await.unwrap().unwrap();

        assert_eq!(updated.email, updated_email);
        assert!(updated.is_primary);
        assert!(updated.confirmed_at.is_none());
        assert!(!old_primary.is_primary);
    }
}
