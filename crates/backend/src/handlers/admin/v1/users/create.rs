// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Creation endpoints: `POST /users` and `POST /users/batch-invite`.

use chrono::Duration;
use coauth_data::audit::{AdminOperation, NewAdminOperationLog};
use coauth_matrix::ProvisionRequest;
use rand::distr::{Alphanumeric, SampleString};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    AppError, CreatedJsonResult,
    handlers::{
        admin::{
            call_context::extract_call_context,
            model::{User, UserRegistrationToken},
            response::SingleResponse,
        },
        common::DepotExt,
    },
    util::username_valid,
};

/// # JSON payload for the `POST /api/admin/v1/users` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRequest")]
pub struct AddRequest {
    /// The username of the user to add.
    username: String,

    /// Skip checking with the homeserver whether the username is available.
    ///
    /// Use this with caution! The main reason to use this, is when a user used
    /// by an application service needs to exist in Pasion to craft special
    /// tokens (like with admin access) for them
    #[serde(default)]
    skip_homeserver_check: bool,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.add", skip_all)]
pub async fn add_user(req: &mut Request, depot: &Depot) -> CreatedJsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let mut rng = crate::handlers::account::make_rng();
    let homeserver = depot.homeserver()?;
    let params: AddRequest = req.parse_json().await.map_err(AppError::internal)?;

    if repo.user().exists(&params.username).await? {
        return Err(AppError::conflict("User already exists"));
    }

    // Do some basic check on the username
    if !username_valid(&params.username) {
        return Err(AppError::bad_request("Username is not valid"));
    }

    // Ask the homeserver if the username is available
    let homeserver_available = homeserver
        .is_localpart_available(&params.username)
        .await
        .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))?;

    if !homeserver_available {
        if !params.skip_homeserver_check {
            return Err(AppError::conflict("Username is reserved by the homeserver"));
        }

        // If we skipped the check, we still want to shout about it
        warn!("Skipped homeserver check for username {}", params.username);
    }

    let user = repo.user().add(&mut rng, &clock, params.username).await?;

    homeserver
        .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
        .await
        .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UserCreated,
        "user",
        Some(user.id),
        serde_json::json!({ "username": user.username }),
    )
    .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleResponse::new_canonical(User::from(user)),
    ))
}

/// # JSON payload for the `POST /api/admin/v1/users/batch-invite` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "BatchInviteRequest")]
pub struct BatchInviteRequest {
    /// Number of registration tokens to create (1-100)
    count: u32,

    /// Maximum number of times each token can be used. If not provided, each
    /// token can be used an unlimited number of times.
    usage_limit: Option<u32>,

    /// Number of hours until each token expires. If not provided, the tokens
    /// never expire.
    expires_in_hours: Option<u64>,
}

/// Response containing the list of created registration tokens
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct BatchInviteResponse {
    /// The list of created registration tokens
    data: Vec<SingleResponse<UserRegistrationToken>>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.batch_invite", skip_all)]
pub async fn batch_invite(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<BatchInviteResponse> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let mut rng = crate::handlers::account::make_rng();
    let params: BatchInviteRequest = req.parse_json().await.map_err(AppError::internal)?;

    if params.count == 0 || params.count > 100 {
        return Err(AppError::bad_request("Count must be between 1 and 100"));
    }

    let expires_at = params
        .expires_in_hours
        .and_then(|h| Duration::try_hours(h as i64))
        .map(|d| clock.now() + d);

    let mut tokens = Vec::with_capacity(params.count as usize);

    for _ in 0..params.count {
        let token_string = Alphanumeric.sample_string(&mut rand::rng(), 12);

        let registration_token = repo
            .user_registration_token()
            .add(
                &mut rng,
                &clock,
                token_string,
                params.usage_limit,
                expires_at,
            )
            .await?;

        if let Some(admin_user) = &admin_user {
            repo.audit()
                .add_admin_operation(
                    &mut rng,
                    &clock,
                    NewAdminOperationLog::new(
                        admin_user.id,
                        AdminOperation::RegistrationTokenCreated,
                        "registration_token",
                        serde_json::json!({}),
                    )
                    .with_resource_id(registration_token.id),
                )
                .await?;
        }

        let model = UserRegistrationToken::new(registration_token, clock.now());
        tokens.push(SingleResponse::new_canonical(model));
    }

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(BatchInviteResponse {
        data: tokens,
    }))
}
