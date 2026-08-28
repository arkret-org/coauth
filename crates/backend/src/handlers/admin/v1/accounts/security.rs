// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Security endpoint: `POST /accounts/{id}/set-password`.
//!
//! Requires admin auth and writes to the audit log. The former immediate
//! `users/{id}/risk-action` endpoint was removed: risk actions (lock /
//! force_password_reset / terminate_sessions / disable / erase /
//! reset_recovery) go through the accountable propose -> approve -> execute
//! workflow in `accounts/risk_action.rs`.

use coauth_data::audit::AdminOperation;
use salvo::http::StatusCode;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::handlers::admin::audit_helper::record_admin_operation_signed;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::params::extract_ulid_param;
use crate::handlers::arkret::issuer_did_for;
use crate::handlers::common::DepotExt;
use crate::{AppError, AppResult};

fn audit_signing_context(
    depot: &Depot,
) -> Result<(coauth_keystore::Keystore, arkret_identifiers::Did, bool), AppError> {
    let key_store = depot.key_store()?;
    let arkret_config = depot.arkret_config()?;
    let service_did = issuer_did_for(&arkret_config);
    Ok((
        key_store,
        service_did,
        arkret_config.audit_signature_fail_closed,
    ))
}

/// # JSON payload for the `POST /_coauth/admin/accounts/:id/set-password` endpoint
#[derive(Deserialize, JsonSchema)]
#[schemars(rename = "SetAccountPasswordRequest")]
pub struct SetPasswordRequestBody {
    /// The password to set for the user
    #[schemars(example = &"hunter2")]
    password: String,

    /// Skip the password complexity check
    skip_password_check: Option<bool>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.set_password", skip_all)]
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
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

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

    let (key_store, service_id, audit_fail_closed) = audit_signing_context(depot)?;
    record_admin_operation_signed(
        &mut repo,
        &mut rng,
        &*clock,
        &key_store,
        &service_id,
        audit_fail_closed,
        admin_user.as_ref(),
        AdminOperation::UserPasswordSet,
        "account",
        Some(user.id),
        serde_json::json!({}),
    )
    .await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}
