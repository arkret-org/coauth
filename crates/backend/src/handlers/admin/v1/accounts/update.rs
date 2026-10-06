// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Update endpoint: `PATCH /accounts/{id}` (profile / lifecycle patch).

use arkret_models_collaboration::objects::account_status::AccountStatus;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

use super::AccountRecord;
use crate::handlers::admin::audit_helper::AdminAuditSigning;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::params::extract_ulid_param;
use crate::handlers::admin::response::SingleOutcome;
use crate::handlers::arkret::{owning_station_did_for, owning_station_id_for};
use crate::handlers::common::DepotExt;
use crate::{AppError, JsonResult};

#[derive(Deserialize, JsonSchema)]
pub struct UpdateRequestBody {
    #[serde(default, with = "serde_with::rust::double_option")]
    #[schemars(with = "Option<Option<String>>")]
    display_name: Option<Option<String>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    #[schemars(with = "Option<Option<String>>")]
    avatar_url: Option<Option<String>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    #[schemars(with = "Option<Option<String>>")]
    preferred_locale: Option<Option<String>>,
    admin: Option<bool>,
    #[schemars(with = "Option<coauth_admin_types::AdminAccountStatus>")]
    status: Option<AccountStatus>,
    locked: Option<bool>,
    deactivated: Option<bool>,
    principal_erase: Option<bool>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.update", skip_all)]
pub async fn update_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<AccountRecord>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let station = depot.station()?;
    let keyring = depot.keyring()?;
    let arkret_config = depot.arkret_config()?;
    let service_id = owning_station_id_for(&arkret_config);
    let service_did = owning_station_did_for(&arkret_config);
    let issuer_context =
        crate::services::account_status_publication::AccountStatusIssuerContext::from_depot(depot)?;
    let audit_signing = AdminAuditSigning {
        issuer_context: &issuer_context,
        keyring: &keyring,
        service_id: &service_id,
        service_did: &service_did,
        fail_closed: arkret_config.audit_signature_fail_closed,
    };
    let mut rng = crate::handlers::account::make_rng();
    let body: UpdateRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let preferred_locale = coauth_data::parse_locale_preference_patch(body.preferred_locale)
        .map_err(|tag| {
            AppError::bad_request(format!(
                "unsupported preferred_locale {tag:?}; this deployment ships en and zh"
            ))
        })?;

    let patch = coauth_data::AdminUserPatch {
        display_name: body.display_name,
        avatar_url: body.avatar_url,
        preferred_locale,
        can_request_admin: body.admin,
        status: body.status,
        locked: body.locked,
        deactivated: body.deactivated,
    };

    let user = crate::services::user_admin::patch_user(
        &mut repo,
        &mut rng,
        &*clock,
        station.as_ref(),
        admin_user.as_ref(),
        id,
        patch,
        body.principal_erase.unwrap_or(true),
        Some(audit_signing),
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleOutcome::new_canonical(
        AccountRecord::from_user(user, depot).await?,
    )))
}

/// Translate a `UserAdminServiceError` returned by the `user_admin`
/// service into a wire-friendly [`AppError`]. This is the exhaustive mapper
/// shared by the accounts module (`super::map_service_error` re-uses it for
/// the lifecycle mutation endpoints).
pub(super) fn map_service_error(
    error: crate::services::user_admin::UserAdminServiceError,
) -> AppError {
    match error {
        crate::services::user_admin::UserAdminServiceError::UserNotFound(id) => {
            AppError::not_found(format!("Account ID {id} not found"))
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
        crate::services::user_admin::UserAdminServiceError::InvalidStatusTransition {
            from,
            to,
        } => AppError::bad_request(format!(
            "Account status transition from {} to {} is invalid",
            from.as_str(),
            to.as_str(),
        )),
        crate::services::user_admin::UserAdminServiceError::MissingAccountStatusPublication => {
            AppError::new(
                salvo::http::StatusCode::SERVICE_UNAVAILABLE,
                "account status authority publication is unavailable",
            )
        }
        crate::services::user_admin::UserAdminServiceError::InvalidAccountStatusPublication(
            error,
        ) => AppError::new(
            salvo::http::StatusCode::FAILED_DEPENDENCY,
            format!("account status authority publication rejected: {error}"),
        ),
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
        crate::services::user_admin::UserAdminServiceError::Station(error) => {
            AppError::internal(std::io::Error::other(error.to_string()))
        }
        crate::services::user_admin::UserAdminServiceError::Repository(error) => {
            AppError::internal(error)
        }
    }
}

#[cfg(test)]
mod patch_deserialization_tests {
    use super::*;

    #[test]
    fn admin_profile_patch_distinguishes_omitted_null_and_value() {
        let omitted: UpdateRequestBody = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(omitted.avatar_url, None);

        let cleared: UpdateRequestBody =
            serde_json::from_value(serde_json::json!({"avatar_url": null})).unwrap();
        assert_eq!(cleared.avatar_url, Some(None));

        let assigned: UpdateRequestBody = serde_json::from_value(serde_json::json!({
            "avatar_url": "https://example.test/avatar.png"
        }))
        .unwrap();
        assert_eq!(
            assigned.avatar_url,
            Some(Some("https://example.test/avatar.png".to_owned()))
        );
    }
}
