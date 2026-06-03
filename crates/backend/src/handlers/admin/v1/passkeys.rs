//! Admin passkey / `WebAuthn` endpoints.
//!
//! These endpoints drive the four ceremonies the
//! [`crate::services::webauthn`] service exposes:
//!
//!   * `POST /api/admin/v1/accounts/{id}/passkeys/register/start`
//!   * `POST /api/admin/v1/accounts/{id}/passkeys/register/finish`
//!   * `POST /api/admin/v1/accounts/{id}/passkeys/auth/start`
//!   * `POST /api/admin/v1/accounts/{id}/passkeys/auth/finish`
//!
//! The handlers are intentionally thin — they extract the account
//! ULID, marshal the payload into / out of `webauthn-rs` types, audit
//! the operation, and return the structured challenge or assertion
//! response. Challenge state lives in-memory inside the
//! [`crate::services::webauthn::PgWebauthnService`]; callers MUST follow
//! `*_start` immediately with the matching `*_finish`.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use coauth_data::{RepositoryAccess, audit::AdminOperation};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::{
    AppError, JsonResult,
    handlers::{
        admin::{
            audit_helper::record_admin_operation_signed, call_context::extract_call_context,
            params::extract_ulid_param,
        },
        common::DepotExt,
        cokret::service_did_for,
    },
    services::{
        onboarding_starid::{OnboardingStaridError, mint_principal_did_for_first_credential},
        starid_adapter::StaridError,
        webauthn::WebauthnError,
    },
};

/// Body for `register/start`. The display fields are surfaced verbatim to
/// the platform authenticator UI, so admins can override the default
/// (`account.handle`).
#[derive(Default, Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "PasskeyRegisterStartRequest")]
pub struct PasskeyRegisterStartRequest {
    /// Override the handle string surfaced to the authenticator.
    #[serde(default)]
    pub handle: Option<String>,

    /// Override the human-readable display name shown by the
    /// authenticator. Falls back to `handle` when absent.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Server response for `register/start`.
#[derive(Serialize, ToSchema)]
pub struct PasskeyRegisterStartResponse {
    /// `CreationChallengeResponse` ready for the browser's
    /// `navigator.credentials.create({ publicKey: ... })`.
    pub challenge: serde_json::Value,
}

/// Body for `register/finish` — the attestation produced by the
/// authenticator.
#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "PasskeyRegisterFinishRequest")]
pub struct PasskeyRegisterFinishRequest {
    /// Optional human-readable label persisted alongside the credential.
    #[serde(default)]
    pub label: Option<String>,

    /// The raw attestation. We accept the raw JSON as `serde_json::Value`
    /// because `RegisterPublicKeyCredential` uses non-self-describing
    /// formats internally; we re-deserialise once we have it.
    pub attestation: serde_json::Value,
}

#[derive(Serialize, ToSchema)]
pub struct PasskeyRegisterFinishResponse {
    /// The persisted credential's ULID.
    pub id: String,
    /// The credential id (binary, base64url-encoded by serde-as-bytes).
    pub credential_id_b64: String,
    /// Optional admin-supplied label.
    pub label: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PasskeyAuthStartResponse {
    /// `RequestChallengeResponse` ready for `navigator.credentials.get`.
    pub challenge: serde_json::Value,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "PasskeyAuthFinishRequest")]
pub struct PasskeyAuthFinishRequest {
    /// The assertion produced by `navigator.credentials.get`.
    pub assertion: serde_json::Value,
}

#[derive(Serialize, ToSchema)]
pub struct PasskeyAuthFinishResponse {
    /// The credential id that was used to authenticate, base64url-encoded.
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

fn audit_signing_context(
    depot: &Depot,
) -> Result<(coauth_keystore::Keystore, String, bool), AppError> {
    let key_store = depot.key_store()?;
    let contrix_config = depot.contrix_config()?;
    let url_builder = depot.url_builder()?;
    let service_did = service_did_for(&url_builder, &contrix_config);
    Ok((
        key_store,
        service_did,
        contrix_config.audit_signature_fail_closed,
    ))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.passkeys.register_start", skip_all)]
pub async fn register_start(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PasskeyRegisterStartResponse> {
    let id = extract_ulid_param(req)?;
    let body: PasskeyRegisterStartRequest = req.parse_json().await.unwrap_or_default();
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();

    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    let handle = body.handle.unwrap_or_else(|| account.handle.clone());
    let display_name = body.display_name.unwrap_or_else(|| handle.clone());

    let webauthn = depot.webauthn_service()?;
    let challenge: CreationChallengeResponse = webauthn
        .register_start(id, &handle, &display_name)
        .await
        .map_err(map_webauthn_error)?;

    let (key_store, service_did, audit_fail_closed) = audit_signing_context(depot)?;
    record_admin_operation_signed(
        &mut repo,
        &mut rng,
        &*clock,
        &key_store,
        &service_did,
        audit_fail_closed,
        admin_user.as_ref(),
        AdminOperation::Other("passkey.register.start".to_owned()),
        "webauthn_credential",
        None,
        serde_json::json!({
            "account_id": id.to_string(),
        }),
    )
    .await?;
    repo.save().await?;

    Ok(Json(PasskeyRegisterStartResponse {
        challenge: serde_json::to_value(challenge)
            .map_err(|e| AppError::internal(std::io::Error::other(e.to_string())))?,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.passkeys.register_finish", skip_all)]
pub async fn register_finish(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PasskeyRegisterFinishResponse> {
    let id = extract_ulid_param(req)?;
    let body: PasskeyRegisterFinishRequest = req.parse_json().await.map_err(AppError::internal)?;
    let attestation: RegisterPublicKeyCredential = serde_json::from_value(body.attestation)
        .map_err(|e| AppError::bad_request(format!("invalid attestation: {e}")))?;

    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let now = clock.now();

    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    let webauthn = depot.webauthn_service()?;
    let record = webauthn
        .register_finish(id, &attestation, body.label.clone(), now)
        .await
        .map_err(map_webauthn_error)?;

    let cred_b64 = Base64UrlUnpadded::encode_string(&record.credential_id);

    // Round 37.4: derive a real, device-bound `update_key` from this
    // passkey's COSE public key and hand it to starid. First-passkey
    // path mints the DID; subsequent passkeys would rotate the key
    // via `rotate_principal_did_for_credential` (driven by the
    // device-rotation flow once the binding lookup lands — out of
    // scope here, this handler only owns the *first* enrolment hook
    // since the binding row write happens elsewhere).
    let starid_registry = depot.starid_registry();
    let (starid_did, starid_version) = if !user.starid_backend {
        match mint_principal_did_for_first_credential(
            &mut repo,
            starid_registry.as_ref(),
            user,
            &record.public_key,
        )
        .await
        .map_err(map_starid_error)?
        {
            Some(update) => (Some(update.mint.did), Some(update.mint.version_id)),
            None => (None, None),
        }
    } else {
        // Account already has a starid-minted DID; this enrolment is
        // the rotation case. The rotation requires the prior
        // `version_id` from `account_identity_binding`, which lands in
        // a follow-up round — for now we record the credential without
        // rotating, and the next privileged op will surface the
        // version-id mismatch to the operator.
        (None, None)
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
        AdminOperation::Other("passkey.register.finish".to_owned()),
        "webauthn_credential",
        Some(record.id),
        serde_json::json!({
            "account_id": id.to_string(),
            "credential_id_b64": cred_b64,
            "label": body.label,
            "starid_did": starid_did,
            "starid_version_id": starid_version,
        }),
    )
    .await?;
    repo.save().await?;

    Ok(Json(PasskeyRegisterFinishResponse {
        id: record.id.to_string(),
        credential_id_b64: cred_b64,
        label: record.label,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.passkeys.auth_start", skip_all)]
pub async fn auth_start(req: &mut Request, depot: &Depot) -> JsonResult<PasskeyAuthStartResponse> {
    let id = extract_ulid_param(req)?;
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    repo.user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    repo.cancel().await?;

    let webauthn = depot.webauthn_service()?;
    let challenge: RequestChallengeResponse =
        webauthn.auth_start(id).await.map_err(map_webauthn_error)?;

    Ok(Json(PasskeyAuthStartResponse {
        challenge: serde_json::to_value(challenge)
            .map_err(|e| AppError::internal(std::io::Error::other(e.to_string())))?,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.passkeys.auth_finish", skip_all)]
pub async fn auth_finish(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PasskeyAuthFinishResponse> {
    let id = extract_ulid_param(req)?;
    let body: PasskeyAuthFinishRequest = req.parse_json().await.map_err(AppError::internal)?;
    let assertion: PublicKeyCredential = serde_json::from_value(body.assertion)
        .map_err(|e| AppError::bad_request(format!("invalid assertion: {e}")))?;

    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let now = clock.now();

    repo.user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    let webauthn = depot.webauthn_service()?;
    let cred_id = webauthn
        .auth_finish(id, &assertion, now)
        .await
        .map_err(map_webauthn_error)?;
    let cred_b64 = Base64UrlUnpadded::encode_string(cred_id.as_ref());

    let (key_store, service_did, audit_fail_closed) = audit_signing_context(depot)?;
    record_admin_operation_signed(
        &mut repo,
        &mut rng,
        &*clock,
        &key_store,
        &service_did,
        audit_fail_closed,
        admin_user.as_ref(),
        AdminOperation::Other("passkey.auth.finish".to_owned()),
        "webauthn_credential",
        None,
        serde_json::json!({
            "account_id": id.to_string(),
            "credential_id_b64": cred_b64,
        }),
    )
    .await?;
    repo.save().await?;

    Ok(Json(PasskeyAuthFinishResponse {
        credential_id_b64: cred_b64,
    }))
}
