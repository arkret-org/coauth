//! Self-serve passkey ceremony endpoints for the account auth API.
//!
//! These routes expose the same WebAuthn service used by the admin passkey
//! handlers under `/_cokret/gate/account/auth/passkey/*`, so browser clients
//! can probe and drive the ceremony without depending on the admin account URL
//! shape.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use coauth_data::{BoxRepository, RepositoryAccess, User};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::{
    AppError, JsonResult,
    handlers::common::DepotExt,
    services::{
        onboarding_starid::{OnboardingStaridError, mint_principal_did_for_first_credential},
        starid_adapter::StaridError,
        webauthn::WebauthnError,
    },
};

#[derive(Default, Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AuthPasskeyAccountHint")]
pub struct PasskeyAccountHint {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AuthPasskeyRegisterFinishRequest")]
pub struct PasskeyRegisterFinishRequest {
    #[serde(flatten)]
    pub hint: PasskeyAccountHint,
    #[serde(default)]
    pub label: Option<String>,
    pub attestation: serde_json::Value,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AuthPasskeyAuthFinishRequest")]
pub struct PasskeyAuthFinishRequest {
    #[serde(flatten)]
    pub hint: PasskeyAccountHint,
    pub assertion: serde_json::Value,
}

#[derive(Serialize, ToSchema)]
pub struct PasskeyRegisterStartResponse {
    pub account_id: String,
    pub handle: String,
    pub challenge: serde_json::Value,
}

#[derive(Serialize, ToSchema)]
pub struct PasskeyRegisterFinishResponse {
    pub account_id: String,
    pub id: String,
    pub credential_id_b64: String,
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starid_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starid_version_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PasskeyAuthStartResponse {
    pub account_id: String,
    pub handle: String,
    pub challenge: serde_json::Value,
}

#[derive(Serialize, ToSchema)]
pub struct PasskeyAuthFinishResponse {
    pub account_id: String,
    pub credential_id_b64: String,
}

fn map_starid_error(err: OnboardingStaridError) -> AppError {
    match err {
        OnboardingStaridError::Starid(StaridError::Api {
            status,
            code,
            message,
        }) => AppError::bad_request(format!(
            "starid_mint_failed: status={status} code={code} message={message}"
        )),
        OnboardingStaridError::Starid(other) => {
            AppError::internal(std::io::Error::other(other.to_string()))
        }
        OnboardingStaridError::Repository(error) => AppError::internal(error),
    }
}

fn map_webauthn_error(err: WebauthnError) -> AppError {
    match err {
        WebauthnError::NoChallenge(_) | WebauthnError::NoCredentials(_) => {
            AppError::bad_request(format!("webauthn_state_missing: {err}"))
        }
        WebauthnError::InvalidOrigin(_) => {
            AppError::bad_request(format!("webauthn_rp_misconfigured: {err}"))
        }
        WebauthnError::Core(_) | WebauthnError::Serde(_) | WebauthnError::Storage(_) => {
            AppError::internal(err)
        }
    }
}

fn trimmed(value: Option<&String>) -> Option<&str> {
    value
        .map(String::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn parse_account_id(value: &str) -> Option<Ulid> {
    if let Ok(id) = value.parse::<Ulid>() {
        return Some(id);
    }
    if let Some((prefix, id)) = value.split_once(':')
        && matches!(prefix, "user" | "account")
    {
        return id.parse::<Ulid>().ok();
    }
    value
        .rsplit_once(":users:")
        .and_then(|(_, id)| id.parse::<Ulid>().ok())
}

async fn resolve_user(
    depot: &Depot,
    hint: &PasskeyAccountHint,
) -> Result<(BoxRepository, User), AppError> {
    let mut repo = depot.repo().await.map_err(AppError::from)?;
    if let Some(account_id) = trimmed(hint.account_id.as_ref()) {
        let id = parse_account_id(account_id)
            .ok_or_else(|| AppError::bad_request("invalid account_id"))?;
        let user = repo
            .user()
            .lookup(id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
        return Ok((repo, user));
    }

    let raw_hint = trimmed(hint.handle.as_ref())
        .or_else(|| trimmed(hint.login_hint.as_ref()))
        .or_else(|| trimmed(hint.display_name.as_ref()))
        .ok_or_else(|| AppError::bad_request("account_hint_required"))?;

    if let Some(id) = parse_account_id(raw_hint) {
        let user = repo
            .user()
            .lookup(id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
        return Ok((repo, user));
    }

    let handle = raw_hint
        .strip_prefix("acct:")
        .unwrap_or(raw_hint)
        .split('@')
        .next()
        .unwrap_or(raw_hint)
        .trim();
    let user = repo
        .user()
        .find_by_handle(handle)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account handle {handle} not found")))?;
    Ok((repo, user))
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.register_start", skip_all)]
pub async fn register_start(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PasskeyRegisterStartResponse> {
    let body: PasskeyAccountHint = req.parse_json().await.unwrap_or_default();
    let (repo, user) = resolve_user(depot, &body).await?;
    let display_name = trimmed(body.display_name.as_ref()).unwrap_or(&user.handle);

    let webauthn = depot.webauthn_service().map_err(AppError::from)?;
    let challenge: CreationChallengeResponse = webauthn
        .register_start(user.id, &user.handle, display_name)
        .await
        .map_err(map_webauthn_error)?;
    repo.cancel().await?;

    Ok(Json(PasskeyRegisterStartResponse {
        account_id: user.id.to_string(),
        handle: user.handle,
        challenge: serde_json::to_value(challenge)
            .map_err(|e| AppError::internal(std::io::Error::other(e.to_string())))?,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.register_finish", skip_all)]
pub async fn register_finish(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PasskeyRegisterFinishResponse> {
    let body: PasskeyRegisterFinishRequest = req.parse_json().await.map_err(AppError::internal)?;
    let attestation: RegisterPublicKeyCredential = serde_json::from_value(body.attestation)
        .map_err(|e| AppError::bad_request(format!("invalid attestation: {e}")))?;
    let (mut repo, user) = resolve_user(depot, &body.hint).await?;
    let now = chrono::Utc::now();

    let webauthn = depot.webauthn_service().map_err(AppError::from)?;
    let record = webauthn
        .register_finish(user.id, &attestation, body.label.clone(), now)
        .await
        .map_err(map_webauthn_error)?;
    let credential_id_b64 = Base64UrlUnpadded::encode_string(&record.credential_id);

    let starid_registry = depot.starid_registry();
    let (starid_did, starid_version_id) = if !user.starid_backend {
        match mint_principal_did_for_first_credential(
            &mut repo,
            starid_registry.as_ref(),
            user.clone(),
            &record.public_key,
        )
        .await
        .map_err(map_starid_error)?
        {
            Some(update) => (Some(update.mint.did), Some(update.mint.version_id)),
            None => (None, None),
        }
    } else {
        (None, None)
    };
    repo.save().await?;

    Ok(Json(PasskeyRegisterFinishResponse {
        account_id: user.id.to_string(),
        id: record.id.to_string(),
        credential_id_b64,
        label: record.label,
        starid_did,
        starid_version_id,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.auth_start", skip_all)]
pub async fn auth_start(req: &mut Request, depot: &Depot) -> JsonResult<PasskeyAuthStartResponse> {
    let body: PasskeyAccountHint = req.parse_json().await.unwrap_or_default();
    let (repo, user) = resolve_user(depot, &body).await?;

    let webauthn = depot.webauthn_service().map_err(AppError::from)?;
    let challenge: RequestChallengeResponse = webauthn
        .auth_start(user.id)
        .await
        .map_err(map_webauthn_error)?;
    repo.cancel().await?;

    Ok(Json(PasskeyAuthStartResponse {
        account_id: user.id.to_string(),
        handle: user.handle,
        challenge: serde_json::to_value(challenge)
            .map_err(|e| AppError::internal(std::io::Error::other(e.to_string())))?,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.auth_finish", skip_all)]
pub async fn auth_finish(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PasskeyAuthFinishResponse> {
    let body: PasskeyAuthFinishRequest = req.parse_json().await.map_err(AppError::internal)?;
    let assertion: PublicKeyCredential = serde_json::from_value(body.assertion)
        .map_err(|e| AppError::bad_request(format!("invalid assertion: {e}")))?;
    let (repo, user) = resolve_user(depot, &body.hint).await?;
    let now = chrono::Utc::now();

    let webauthn = depot.webauthn_service().map_err(AppError::from)?;
    let credential_id = webauthn
        .auth_finish(user.id, &assertion, now)
        .await
        .map_err(map_webauthn_error)?;
    repo.cancel().await?;

    Ok(Json(PasskeyAuthFinishResponse {
        account_id: user.id.to_string(),
        credential_id_b64: Base64UrlUnpadded::encode_string(credential_id.as_ref()),
    }))
}
