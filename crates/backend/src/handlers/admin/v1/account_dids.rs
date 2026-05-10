//! Account DID binding administration endpoints.

use coauth_admin_types::{
    AccountDidBindingPreview, AdminAccountDidBinding as AccountDidBinding,
    AdminAccountDidBindingsMeta as AccountDidBindingsMeta,
    AdminAccountDidBindingsResponse as AccountDidBindingsResponse, DidBindingKind,
    DidBindingResolverDescriptor, DidBindingResolverMode, DidBindingState,
    DidBindingVerificationStatus,
};
use coauth_config::ContrixConfig;
use coauth_data::{RepositoryAccess, User};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    AppError, CreatedJsonResult, JsonResult,
    handlers::{
        admin::{call_context::extract_call_context, params::extract_ulid_param},
        common::DepotExt,
    },
    services::{
        did_binding_proof::{DidBindingProofError, validate_control_proof},
        did_resolver::DidResolverService,
    },
};

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AddAccountDidBindingRequest")]
pub struct AddAccountDidBindingRequest {
    /// DID to bind to the account.
    pub did: String,

    /// Binding purpose.
    pub kind: DidBindingKind,

    /// Proof that the account holder controls the DID. The proof MUST be a
    /// detached JWS signed by one of the DID's verification-method keys
    /// over the canonical binding statement (see
    /// [`crate::services::did_binding_proof`]).
    pub control_proof: ControlProofPayload,

    /// Whether the new binding should become the primary DID when accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub make_primary: Option<bool>,

    /// Hint about the proof type, for example `did_controller_key` or `passkey`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,

    /// Optional delegated resolver submission payload or receipt seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)]
    pub resolver_submission: Option<serde_json::Value>,

    /// Optional operator note for audit and admin UI surfaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_note: Option<String>,

    /// Solved CAPTCHA token. Verified when the deployment has a CAPTCHA
    /// provider configured (`site.captcha`) so admin-on-behalf-of-user
    /// or self-service binding flows can be abuse-gated. Optional and
    /// ignored when no provider is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captcha_token: Option<String>,
}

/// Compact-serialised JWS string + the nonce that was embedded in the
/// canonical binding statement. We accept both `{"jws": "...", "nonce":
/// "..."}` and a bare string (legacy admin clients) for ergonomics.
#[derive(Deserialize, JsonSchema, ToSchema)]
pub struct ControlProofPayload {
    /// The detached JWS in compact serialisation.
    pub jws: String,

    /// Nonce that was included in the canonical binding statement signed
    /// by `jws`.
    pub nonce: String,
}

#[derive(Default, Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "RemoveAccountDidBindingRequest")]
#[allow(dead_code)]
pub struct RemoveAccountDidBindingRequest {
    /// Operator-supplied reason for revoking the binding.
    reason: Option<String>,

    /// Optional approval proof for destructive or high-risk removals.
    approval_proof: Option<String>,

    /// Whether active sessions tied to the DID should be revoked as follow-up.
    revoke_related_sessions: Option<bool>,

    /// Solved CAPTCHA token. Verified when the deployment has a CAPTCHA
    /// provider configured (`site.captcha`). Optional and ignored when
    /// no provider is configured.
    #[serde(default)]
    captcha_token: Option<String>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.account_dids.list", skip_all)]
pub async fn list_account_dids(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountDidBindingsResponse> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;
    let contrix_config = depot.contrix_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    Ok(Json(AccountDidBindingsResponse {
        data: binding_records_for_user(&user, &contrix_config, did_resolver.as_ref()).await,
        meta: AccountDidBindingsMeta {
            resolver: resolver_descriptor(&contrix_config, did_resolver.as_ref()),
            supported_verification_methods: vec![
                "did_controller_key".to_owned(),
                "passkey".to_owned(),
                "oidc_subject_link".to_owned(),
            ],
            supports_write_operations: false,
        },
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.account_dids.add", skip_all)]
pub async fn add_account_did(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<AccountDidBindingsResponse> {
    let body: AddAccountDidBindingRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let id = extract_ulid_param(req)?;
    enforce_did_binding_rate_limit(req, depot, id).await?;
    enforce_captcha(req, depot, body.captcha_token.as_deref()).await?;

    let did = body.did.trim();
    if did.is_empty() || !did.starts_with("did:") {
        return Err(AppError::bad_request("did must be a non-empty DID URI"));
    }
    let did = did.to_owned();

    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;

    // Verify the account exists before doing the (expensive) resolver call.
    repo.user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let now = clock.now();

    validate_control_proof(
        &http_client,
        &url_builder,
        &contrix_config,
        &key_store,
        &mut repo,
        did_resolver.as_ref(),
        body.control_proof.jws.as_str(),
        &did,
        id,
        body.control_proof.nonce.as_str(),
        now,
    )
    .await
    .map_err(map_did_binding_proof_error)?;

    // Today there is no `account_dids` table; binding storage is tracked
    // separately. We've validated the proof, so the next layer (write
    // path) can persist with confidence. Surface a 501 with the precise
    // reason so downstream contracts stay clear.
    repo.cancel().await?;
    Err(AppError::not_implemented(
        "account DID binding control_proof validated, but persistence layer (account_dids table) is not landed yet",
    ))
}

fn map_did_binding_proof_error(error: DidBindingProofError) -> AppError {
    match error {
        DidBindingProofError::EmptyProof
        | DidBindingProofError::InvalidJws(_)
        | DidBindingProofError::NoVerificationKey
        | DidBindingProofError::SignatureMismatch
        | DidBindingProofError::StatementKindMismatch
        | DidBindingProofError::AccountDidMismatch
        | DidBindingProofError::CxAccountIdMismatch
        | DidBindingProofError::NonceMismatch
        | DidBindingProofError::IatOutOfRange => {
            AppError::bad_request(format!("control_proof_invalid: {error}"))
        }
        DidBindingProofError::Resolve(inner) => {
            AppError::bad_request(format!("did_resolver_failed: {inner}"))
        }
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.account_dids.remove", skip_all)]
pub async fn remove_account_did(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountDidBindingsResponse> {
    let body: RemoveAccountDidBindingRequest = req.parse_json().await.unwrap_or_default();
    let id = extract_ulid_param(req)?;
    enforce_did_binding_rate_limit(req, depot, id).await?;
    enforce_captcha(req, depot, body.captcha_token.as_deref()).await?;
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): revoke DID binding with audit trail, not hard-delete.
    Err(AppError::not_implemented(
        "account DID binding removal is not implemented yet",
    ))
}

/// Verify the supplied CAPTCHA token, if the deployment has a CAPTCHA
/// provider configured. Returns `400` on failure so the admin / client
/// surface gets a clear signal rather than the generic 501 the
/// downstream stub returns. No-op when no provider is configured (the
/// helper itself short-circuits).
async fn enforce_captcha(
    req: &Request,
    depot: &Depot,
    captcha_token: Option<&str>,
) -> Result<(), AppError> {
    let site_config = depot.site_config().map_err(AppError::internal)?;
    if site_config.captcha.is_none() && captcha_token.is_none() {
        return Ok(());
    }
    let url_builder = depot.url_builder().map_err(AppError::internal)?;
    let http_client = depot.http_client().map_err(AppError::internal)?;
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);

    crate::handlers::captcha::verify_token(
        activity_tracker.ip(),
        &http_client,
        url_builder.public_hostname(),
        site_config.captcha.as_ref(),
        captcha_token,
    )
    .await
    .map_err(|error| {
        tracing::warn!(error = %error, "CAPTCHA verification failed on DID-binding admin write");
        AppError::bad_request(format!("captcha_failed: {error}"))
    })
}

/// Apply the DID-binding rate limit (per source IP and per target
/// account) before any expensive work runs. Surfaces a 429 with the
/// configured limiter's reason, and degrades to "no limiter
/// configured" by allowing the request.
async fn enforce_did_binding_rate_limit(
    req: &Request,
    depot: &Depot,
    account_id: ulid::Ulid,
) -> Result<(), AppError> {
    let limiter = match depot.limiter() {
        Ok(limiter) => limiter,
        Err(_) => return Ok(()),
    };
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(crate::handlers::RequesterFingerprint::new)
        .unwrap_or(crate::handlers::RequesterFingerprint::EMPTY);

    limiter
        .check_did_binding(requester, account_id)
        .await
        .map_err(|error| AppError::too_many_requests(error.to_string()))
}

pub(crate) async fn preview_bindings_for_user(
    user: &User,
    contrix_config: &ContrixConfig,
    did_resolver: &dyn DidResolverService,
) -> Vec<AccountDidBindingPreview> {
    binding_records_for_user(user, contrix_config, did_resolver)
        .await
        .into_iter()
        .map(|binding| AccountDidBindingPreview {
            did: binding.did,
            kind: binding.kind,
            state: binding.state,
            primary: binding.primary,
            active: binding.active,
        })
        .collect()
}

pub(crate) async fn primary_did_for_user(
    user: &User,
    contrix_config: &ContrixConfig,
    did_resolver: &dyn DidResolverService,
) -> String {
    did_resolver
        .primary_did_for_user(contrix_config, user)
        .await
}

async fn binding_records_for_user(
    user: &User,
    contrix_config: &ContrixConfig,
    did_resolver: &dyn DidResolverService,
) -> Vec<AccountDidBinding> {
    let primary_did = primary_did_for_user(user, contrix_config, did_resolver).await;
    let created_at = Some(user.created_at);
    let last_verified_at = Some(user.updated_at);
    let revoked_at = user.deactivated_at;
    let active = revoked_at.is_none();
    let state = if active {
        DidBindingState::Active
    } else {
        DidBindingState::Revoked
    };
    let verification_status = if active {
        DidBindingVerificationStatus::Verified
    } else {
        DidBindingVerificationStatus::Rejected
    };
    let resolver = resolver_descriptor(contrix_config, did_resolver);

    vec![AccountDidBinding {
        id: format!("acctdid-{}", binding_slug(&user.id.to_string())),
        account_id: user.id.to_string(),
        did: primary_did,
        kind: DidBindingKind::Primary,
        state,
        primary: true,
        active,
        verification_status,
        resolver,
        created_at,
        last_verified_at,
        last_resolver_receipt_id: Some(format!(
            "resolver-preview-{}",
            binding_slug(&user.id.to_string())
        )),
        revoked_at,
    }]
}

fn resolver_descriptor(
    contrix_config: &ContrixConfig,
    did_resolver: &dyn DidResolverService,
) -> DidBindingResolverDescriptor {
    match did_resolver.delegated_resolver(contrix_config) {
        Some(resolver) => DidBindingResolverDescriptor {
            mode: DidBindingResolverMode::DelegatedResolver,
            resolver: Some(resolver),
            proof_required_for_pairwise: did_resolver.proof_required_for_pairwise(contrix_config),
        },
        None => DidBindingResolverDescriptor {
            mode: DidBindingResolverMode::LocalBindings,
            resolver: None,
            proof_required_for_pairwise: false,
        },
    }
}

fn binding_slug(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}
