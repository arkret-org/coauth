// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Security endpoints: `POST /users/{id}/risk-action` and
//! `POST /users/{id}/set-password`.
//!
//! Both endpoints require admin auth and write to the audit log; they are
//! grouped here to keep the security-sensitive code paths together.

use coauth_data::audit::AdminOperation;
use salvo::{http::StatusCode, oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    AppError, AppResult, JsonResult,
    handlers::{
        admin::{
            audit_helper::record_admin_operation_signed, call_context::extract_call_context,
            model::User, params::extract_ulid_param, response::SingleOutcome,
        },
        cokret::service_did_for,
        common::DepotExt,
    },
};

/// # JSON payload for the `POST /_coauth/admin/users/:id/risk-action` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "RiskActionRequestBody")]
pub struct RiskActionRequestBody {
    /// The risk action to perform: "lock", "`force_password_reset`", or
    /// "`terminate_sessions`"
    action: String,

    /// The reason for the risk action
    reason: Option<String>,
}

/// Response indicating which risk action was taken
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct RiskActionOutcome {
    /// The action that was performed
    action: String,

    /// The reason provided for the action
    reason: Option<String>,

    /// The user the action was performed on
    user: SingleOutcome<User>,

    /// Number of sessions terminated (only for `terminate_sessions` action)
    #[serde(skip_serializing_if = "Option::is_none")]
    sessions_terminated: Option<usize>,
}

fn audit_signing_context(
    depot: &Depot,
) -> Result<(coauth_keystore::Keystore, String, bool), AppError> {
    let key_store = depot.key_store()?;
    let cokret_config = depot.cokret_config()?;
    let url_builder = depot.url_builder()?;
    let service_did = service_did_for(&url_builder, &cokret_config);
    Ok((
        key_store,
        service_did,
        cokret_config.audit_signature_fail_closed,
    ))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.risk_action", skip_all)]
pub async fn risk_action(req: &mut Request, depot: &Depot) -> JsonResult<RiskActionOutcome> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let params: RiskActionRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {id} not found")))?;

    let mut sessions_terminated = None;

    let user = match params.action.as_str() {
        "lock" => repo.user().lock(&clock, user).await?,

        "force_password_reset" => {
            // Lock the user account so they must reset their password

            repo.user().lock(&clock, user).await?
        }

        "terminate_sessions" => {
            use coauth_data::user::BrowserSessionFilter;

            let filter = BrowserSessionFilter::new().for_user(&user).active_only();
            let count = repo.browser_session().finish_bulk(&clock, filter).await?;
            sessions_terminated = Some(count);
            user
        }

        other => {
            return Err(AppError::bad_request(format!(
                "Unknown risk action: {other}"
            )));
        }
    };

    let operation = match params.action.as_str() {
        "lock" | "force_password_reset" => AdminOperation::UserLocked,
        "terminate_sessions" => AdminOperation::Other("terminate_sessions".into()),
        _ => AdminOperation::Other(params.action.clone()),
    };
    let (key_store, service_did, audit_fail_closed) = audit_signing_context(depot)?;
    record_admin_operation_signed(
        &mut repo,
        &mut rng,
        &*clock,
        &key_store,
        &service_did,
        audit_fail_closed,
        admin_user.as_ref(),
        operation,
        "user",
        Some(user.id),
        serde_json::json!({
            "action": params.action,
            "reason": params.reason,
        }),
    )
    .await?;

    repo.save().await?;

    let user_response = SingleOutcome::new(
        User::from(user),
        format!("/_coauth/admin/users/{id}/risk-action"),
    );

    Ok(Json(RiskActionOutcome {
        action: params.action,
        reason: params.reason,
        user: user_response,
        sessions_terminated,
    }))
}

/// # JSON payload for the `POST /_coauth/admin/users/:id/set-password` endpoint
#[derive(Deserialize, JsonSchema)]
#[schemars(rename = "SetUserPasswordRequest")]
pub struct SetPasswordRequestBody {
    /// The password to set for the user
    #[schemars(example = &"hunter2")]
    password: String,

    /// Skip the password complexity check
    skip_password_check: Option<bool>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.set_password", skip_all)]
pub async fn set_password(req: &mut Request, depot: &Depot) -> AppResult<StatusCode> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let password_manager = depot.password_manager()?;
    let params: SetPasswordRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    if !password_manager.is_enabled() {
        return Err(AppError::forbidden("Password auth is disabled"));
    }

    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {id} not found")))?;

    let skip_password_check = params.skip_password_check.unwrap_or(false);
    tracing::info!(skip_password_check, "skip_password_check");
    if !skip_password_check
        && !password_manager
            .is_password_complex_enough(&params.password)
            .unwrap_or(false)
    {
        return Err(AppError::bad_request("Password is too weak"));
    }

    let password = Zeroizing::new(params.password);
    let (version, hashed_password) =
        password_manager
            .hash(&mut rng, password)
            .await
            .map_err(|error| {
                AppError::with_source(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Password hashing failed",
                    Box::new(std::io::Error::other(error.to_string())),
                    true,
                )
            })?;

    repo.user_password()
        .add(&mut rng, &clock, &user, version, hashed_password, None)
        .await?;

    let (key_store, service_did, audit_fail_closed) = audit_signing_context(depot)?;
    record_admin_operation_signed(
        &mut repo,
        &mut rng,
        &*clock,
        &key_store,
        &service_did,
        audit_fail_closed,
        admin_user.as_ref(),
        AdminOperation::UserPasswordSet,
        "user",
        Some(user.id),
        serde_json::json!({}),
    )
    .await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}
