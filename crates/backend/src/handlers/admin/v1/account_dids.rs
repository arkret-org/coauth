//! Account DID binding administration endpoints.

use chrono::{DateTime, Utc};
use coauth_config::ContrixConfig;
use coauth_data::{RepositoryAccess, User};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AppError, CreatedJsonResult, JsonResult,
    handlers::{
        admin::{call_context::extract_call_context, params::extract_ulid_param},
        common::DepotExt,
    },
    services::did_resolver::DidResolverService,
};

#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DidBindingKind {
    Primary,
    Recovery,
    Pairwise,
}

#[derive(Clone, Copy, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DidBindingState {
    PendingProof,
    Active,
    Revoked,
    Rejected,
}

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DidBindingVerificationStatus {
    Pending,
    Verified,
    Rejected,
    NotRequested,
}

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DidBindingResolverMode {
    LocalBindings,
    DelegatedResolver,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct DidBindingResolverDescriptor {
    /// Whether coauth resolves locally or delegates to a public DID service.
    mode: DidBindingResolverMode,

    /// Delegated/public DID resolver endpoint when coauth is not authoritative.
    resolver: Option<String>,

    /// Whether pairwise bindings require resolver-side proof validation.
    proof_required_for_pairwise: bool,
}

#[derive(Clone, Serialize, JsonSchema, ToSchema)]
pub struct AccountDidBindingPreview {
    /// Bound principal DID.
    pub(crate) did: String,

    /// Binding purpose.
    pub(crate) kind: DidBindingKind,

    /// High-level lifecycle state for downstream admin/UI surfaces.
    pub(crate) state: DidBindingState,

    /// Whether this binding is the account's current primary DID.
    pub(crate) primary: bool,

    /// Whether this binding is currently active.
    pub(crate) active: bool,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountDidBinding {
    /// Binding identifier.
    id: String,

    /// Account ULID.
    account_id: String,

    /// Bound principal DID.
    did: String,

    /// Binding purpose.
    kind: DidBindingKind,

    /// High-level lifecycle state.
    state: DidBindingState,

    /// Whether this binding is the account's primary DID.
    primary: bool,

    /// Whether this binding is currently active.
    active: bool,

    /// Verification status of the delegated/public DID control proof.
    verification_status: DidBindingVerificationStatus,

    /// Resolver/delegation metadata for this binding.
    resolver: DidBindingResolverDescriptor,

    /// When the binding was created.
    created_at: DateTime<Utc>,

    /// When the resolver/control proof was last verified, if available.
    last_verified_at: Option<DateTime<Utc>>,

    /// Resolver receipt or operation identifier, when delegated publication exists.
    last_resolver_receipt_id: Option<String>,

    /// When the binding was revoked, if applicable.
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountDidBindingsResponse {
    data: Vec<AccountDidBinding>,

    /// Placeholder contract metadata so downstream consumers can bind before
    /// storage and resolver wiring lands.
    meta: AccountDidBindingsMeta,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountDidBindingsMeta {
    /// Resolver/delegation mode for this deployment.
    resolver: DidBindingResolverDescriptor,

    /// Supported proof shapes that coauth intends to accept for DID binding.
    supported_verification_methods: Vec<String>,

    /// Stable signal that the surface exists but write logic is not complete yet.
    supports_write_operations: bool,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AddAccountDidBindingRequest")]
#[allow(dead_code)]
pub struct AddAccountDidBindingRequest {
    /// DID to bind to the account.
    did: String,

    /// Binding purpose.
    kind: DidBindingKind,

    /// Proof that the account holder controls the DID.
    control_proof: serde_json::Value,

    /// Whether the new binding should become the primary DID when accepted.
    make_primary: Option<bool>,

    /// Hint about the proof type, for example `did_controller_key` or `passkey`.
    verification_method: Option<String>,

    /// Optional delegated resolver submission payload or receipt seed.
    resolver_submission: Option<serde_json::Value>,

    /// Optional operator note for audit and admin UI surfaces.
    operator_note: Option<String>,
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
        data: binding_records_for_user(&user, &contrix_config, did_resolver.as_ref()),
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
    let _body: AddAccountDidBindingRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let id = extract_ulid_param(req)?;
    enforce_did_binding_rate_limit(req, depot, id).await?;
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): validate control_proof with delegated/public DID resolver before persisting.
    Err(AppError::not_implemented(
        "account DID binding creation is not implemented yet",
    ))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.account_dids.remove", skip_all)]
pub async fn remove_account_did(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountDidBindingsResponse> {
    let _body: RemoveAccountDidBindingRequest = req.parse_json().await.unwrap_or_default();
    let id = extract_ulid_param(req)?;
    enforce_did_binding_rate_limit(req, depot, id).await?;
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): revoke DID binding with audit trail, not hard-delete.
    Err(AppError::not_implemented(
        "account DID binding removal is not implemented yet",
    ))
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

pub(crate) fn preview_bindings_for_user(
    user: &User,
    contrix_config: &ContrixConfig,
    did_resolver: &dyn DidResolverService,
) -> Vec<AccountDidBindingPreview> {
    binding_records_for_user(user, contrix_config, did_resolver)
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

pub(crate) fn primary_did_for_user(user: &User, did_resolver: &dyn DidResolverService) -> String {
    did_resolver.primary_did_for_user(user)
}

fn binding_records_for_user(
    user: &User,
    contrix_config: &ContrixConfig,
    did_resolver: &dyn DidResolverService,
) -> Vec<AccountDidBinding> {
    let primary_did = primary_did_for_user(user, did_resolver);
    let created_at = user.created_at;
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
