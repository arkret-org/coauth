// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Update endpoint: `PATCH /users/{id}`.

use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    AppError, JsonResult,
    handlers::{
        admin::{
            audit_helper::AdminAuditSigning, call_context::extract_call_context, model::User,
            params::extract_ulid_param, response::SingleResponse,
        },
        common::DepotExt,
        contrix::service_did_for,
    },
};

#[derive(Deserialize, JsonSchema)]
pub struct UpdateRequest {
    display_name: Option<Option<String>>,
    avatar_url: Option<Option<String>>,
    preferred_locale: Option<Option<String>>,
    admin: Option<bool>,
    locked: Option<bool>,
    deactivated: Option<bool>,
    principal_erase: Option<bool>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.update", skip_all)]
pub async fn update_user(req: &mut Request, depot: &Depot) -> JsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let principal_server = depot.principal_server()?;
    let key_store = depot.key_store()?;
    let contrix_config = depot.contrix_config()?;
    let url_builder = depot.url_builder()?;
    let service_did = service_did_for(&url_builder, &contrix_config);
    let audit_signing = AdminAuditSigning {
        keystore: &key_store,
        service_did: &service_did,
        fail_closed: contrix_config.audit_signature_fail_closed,
    };
    let mut rng = crate::handlers::account::make_rng();
    let body: UpdateRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let patch = coauth_data::AdminUserPatch {
        display_name: body.display_name,
        avatar_url: body.avatar_url,
        preferred_locale: body.preferred_locale,
        can_request_admin: body.admin,
        locked: body.locked,
        deactivated: body.deactivated,
    };

    let user = crate::services::user_admin::patch_user(
        &mut repo,
        &mut rng,
        &*clock,
        principal_server.as_ref(),
        admin_user.as_ref(),
        id,
        patch,
        body.principal_erase.unwrap_or(true),
        Some(audit_signing),
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(User::from(user))))
}

/// Translate a `UserAdminServiceError` returned by the `user_admin`
/// service into a wire-friendly [`AppError`]. Lives in this module rather
/// than `services/user_admin.rs` so it can stay an internal detail of the
/// PATCH endpoint.
fn map_service_error(error: crate::services::user_admin::UserAdminServiceError) -> AppError {
    match error {
        crate::services::user_admin::UserAdminServiceError::UserNotFound(id) => {
            AppError::not_found(format!("User ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::ReferencedUserNotFound(id) => {
            AppError::bad_request(format!("Referenced user ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::UserEmailNotFound(id) => {
            AppError::bad_request(format!("Unexpected user email lookup failure for {id}"))
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
        crate::services::user_admin::UserAdminServiceError::InvalidEmail { email, .. } => {
            AppError::bad_request(format!("Email {email:?} is not valid"))
        }
        crate::services::user_admin::UserAdminServiceError::EmailAlreadyInUse(email) => {
            AppError::conflict(format!("User email {email:?} already in use"))
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
        crate::services::user_admin::UserAdminServiceError::Repository(error) => {
            AppError::internal(error)
        }
    }
}
