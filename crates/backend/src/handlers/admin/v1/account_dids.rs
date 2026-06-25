//! Account DID binding administration endpoints.

use std::sync::{Arc, OnceLock};

use coauth_admin_types::{
    AccountDidBindingPreview, AdminAccountDidBinding as AccountDidBinding,
    AdminAccountDidBindingsMeta as AccountDidBindingsMeta,
    AdminAccountDidBindingsOutcome as AccountDidBindingsOutcome, DidBindingKind,
    DidBindingResolverDescriptor, DidBindingResolverMode, DidBindingState,
    DidBindingVerificationStatus,
};
use coauth_config::CokretConfig;
use coauth_data::audit::{
    AdminOperation, AdminOperationFilter, AdminOperationLog, NewAdminOperationLog,
};
use coauth_data::{BoxRepository, RepositoryAccess, User};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::handlers::admin::CreatedJson;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::params::extract_ulid_param;
use crate::handlers::cokret::SessionGrantError;
use crate::handlers::common::DepotExt;
use crate::services::did_binding_proof::{
    DidBindingProofError, normalize_did_for_binding, validate_control_proof,
};
use crate::services::did_resolver::DidResolverService;
use crate::services::third_party_invite::NonceStore;
use crate::{AppError, CreatedJsonResult, JsonResult};

/// Process-global single-use store for DID-binding control-proof nonces.
///
/// Mirrors the 3PID invite chain's `shared_nonce_store`
/// (`handlers::account::invite_accept`). Single-process semantics are
/// acceptable while coauth runs as a single replica; a multi-replica
/// deployment would back this with the shared DB (see the note on
/// [`NonceStore`]). Held behind an `Arc` so verify calls can borrow a
/// `&NonceStore` into it without cloning the underlying map.
fn shared_did_binding_nonce_store() -> &'static Arc<NonceStore> {
    static STORE: OnceLock<Arc<NonceStore>> = OnceLock::new();
    STORE.get_or_init(|| Arc::new(NonceStore::new()))
}

const DID_BINDING_ADDED_OPERATION: &str = "account_did_binding_added";
const DID_BINDING_REVOKED_OPERATION: &str = "account_did_binding_revoked";

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AddAccountDidBindingRequestBody")]
pub struct AddAccountDidBindingRequestBody {
    /// DID to bind to the account.
    pub did: String,

    /// Binding purpose.
    pub kind: DidBindingKind,

    /// Proof that the account holder controls the DID. The proof MUST be a
    /// compact JWS signed by one of the DID's verification-method keys
    /// with the canonical binding statement as its attached payload (see
    /// [`crate::services::did_binding_proof`]).
    pub control_proof: ControlProofPayload,

    /// Optional SDK `ck.schema.did_continuity_proof.v1` payload. Required
    /// when promoting a weak `did:web` primary binding to `did:webvh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = serde_json::Value))]
    pub continuity_proof: Option<serde_json::Value>,

    /// Whether the new binding should become the primary DID when accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub make_primary: Option<bool>,

    /// Hint about the proof type, for example `did_controller_key` or
    /// `passkey`.
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
    /// or self-service binding strands can be abuse-gated. Optional and
    /// ignored when no provider is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captcha_token: Option<String>,
}

/// Compact-serialised JWS string + the nonce that was embedded in the
/// canonical binding statement.
#[derive(Deserialize, JsonSchema, ToSchema)]
pub struct ControlProofPayload {
    /// Compact JWS whose attached payload is the canonical binding statement.
    pub jws: String,

    /// Nonce that was included in the canonical binding statement signed
    /// by `jws`.
    pub nonce: String,
}

#[derive(Default, Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "RemoveAccountDidBindingRequestBody")]
#[allow(dead_code)]
pub struct RemoveAccountDidBindingRequestBody {
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
) -> JsonResult<AccountDidBindingsOutcome> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;
    let cokret_config = depot.cokret_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let events = did_binding_event_logs(&mut repo, id).await?;
    let data = binding_records_for_user(&user, &cokret_config, did_resolver.as_ref()).await?;
    let data = apply_did_binding_events(
        data,
        &events,
        &resolver_descriptor(&cokret_config, did_resolver.as_ref()),
    );
    repo.cancel().await?;

    Ok(Json(AccountDidBindingsOutcome {
        data,
        meta: did_bindings_meta(&cokret_config, did_resolver.as_ref()),
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.account_dids.add", skip_all)]
pub async fn add_account_did(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<AccountDidBindingsOutcome> {
    let body: AddAccountDidBindingRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;
    let id = extract_ulid_param(req)?;
    enforce_did_binding_rate_limit(req, depot, id).await?;
    enforce_captcha(req, depot, body.captcha_token.as_deref()).await?;

    // Phase P2 (B-D): all DID binding writes round-trip through the SDK
    // `Did::new` validator (Round-4 regex `^did:[a-z0-9]+:[^\s]+$`). Reject
    // malformed DIDs BEFORE invoking the resolver chain so network I/O
    // never fires on a non-canonical value.
    let did = normalize_did_for_binding(&body.did)
        .map_err(|error| AppError::bad_request(format!("did_invalid: {error}")))?;

    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let Some(admin_user) = admin_user.as_ref() else {
        repo.cancel().await?;
        return Err(AppError::forbidden(
            "account DID binding addition requires a user-bound admin token",
        ));
    };
    let admin_user_id = admin_user.id;
    let admin_user_handle = admin_user.localpart.clone();

    // Verify the account exists before doing the (expensive) resolver call.
    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let now = clock.now();
    let resolver = resolver_descriptor(&cokret_config, did_resolver.as_ref());
    let events = did_binding_event_logs(&mut repo, id).await?;
    let current_bindings = apply_did_binding_events(
        binding_records_for_user(&account, &cokret_config, did_resolver.as_ref()).await?,
        &events,
        &resolver,
    );
    if current_bindings
        .iter()
        .any(|binding| binding.did == did && binding.active)
    {
        repo.cancel().await?;
        return Err(AppError::conflict("account DID binding is already active"));
    }

    // identity-did §5.1 / §3.6: the control proof MUST bind to this
    // receiver (local coauth service DID) and this deployment
    // (`trust_domain`) so it cannot be relayed cross-receiver or carried
    // cross-deployment. The nonce is consumed single-use on success.
    let expected_audience = crate::handlers::cokret::service_did_for(&url_builder, &cokret_config);
    let expected_trust_domain =
        crate::handlers::cokret::trust_domain_for(&url_builder, &cokret_config);
    enforce_did_continuity_for_primary_upgrade(
        &current_bindings,
        &did,
        body.make_primary.unwrap_or(false),
        body.continuity_proof.as_ref(),
        &expected_audience,
        &expected_trust_domain,
        now,
    )?;
    let nonce_store = shared_did_binding_nonce_store();
    validate_control_proof(
        &http_client,
        &url_builder,
        &cokret_config,
        &key_store,
        &mut repo,
        did_resolver.as_ref(),
        nonce_store.as_ref(),
        body.control_proof.jws.as_str(),
        &did,
        body.control_proof.nonce.as_str(),
        &expected_audience,
        &expected_trust_domain,
        now,
    )
    .await
    .map_err(map_did_binding_proof_error)?;

    let mut rng = crate::handlers::account::make_rng();
    let audit_log = repo
        .audit()
        .add_admin_operation(
            &mut rng,
            &clock,
            NewAdminOperationLog::new(
                admin_user_id,
                AdminOperation::Other(DID_BINDING_ADDED_OPERATION.to_owned()),
                "account",
                serde_json::json!({
                    "transition_kind": "did_binding_added",
                    "binding_id": format!("acctdid-{}", binding_slug(&did)),
                    "did": did,
                    "kind": did_binding_kind_wire(body.kind),
                    "state": "active",
                    "make_primary": body.make_primary.unwrap_or(false),
                    "continuity_proof_present": body.continuity_proof.is_some(),
                    "verification_status": "verified",
                    "verification_method": body.verification_method,
                    "resolver_submission_present": body.resolver_submission.is_some(),
                    "operator_note": body.operator_note,
                    "verified_at": now,
                    "added_by": admin_user_id,
                    "added_by_handle": admin_user_handle,
                }),
            )
            .with_resource_id(account.id),
        )
        .await?;
    repo.save().await?;

    let mut events = events;
    events.push(audit_log);
    let data = apply_did_binding_events(
        binding_records_for_user(&account, &cokret_config, did_resolver.as_ref()).await?,
        &events,
        &resolver,
    );

    Ok(CreatedJson(AccountDidBindingsOutcome {
        data,
        meta: did_bindings_meta(&cokret_config, did_resolver.as_ref()),
    }))
}

fn map_did_binding_proof_error(error: DidBindingProofError) -> AppError {
    match error {
        DidBindingProofError::EmptyProof
        | DidBindingProofError::InvalidJws(_)
        | DidBindingProofError::NoVerificationKey
        | DidBindingProofError::MissingVerificationMethod
        | DidBindingProofError::UnsupportedAlgorithm(_)
        | DidBindingProofError::VerificationMethodMismatch
        | DidBindingProofError::VerificationMethodNotFound
        | DidBindingProofError::SignatureMismatch
        | DidBindingProofError::CanonicalStatement(_)
        | DidBindingProofError::CanonicalStatementMismatch
        | DidBindingProofError::StatementSchemaMismatch
        | DidBindingProofError::AccountDidMismatch
        | DidBindingProofError::NonceMismatch
        | DidBindingProofError::AudienceMismatch
        | DidBindingProofError::TrustDomainMismatch
        | DidBindingProofError::IatOutOfRange
        | DidBindingProofError::FreshnessWindowExceeded
        | DidBindingProofError::ProofExpired
        | DidBindingProofError::NonceReplayed => {
            AppError::bad_request(format!("control_proof_invalid: {error}"))
        }
        DidBindingProofError::ResolverNotFullIdentityFact(rejection) => {
            AppError::bad_request(format!(
                "control_proof_invalid: did_resolver_not_full_identity_fact: {}",
                rejection.as_str()
            ))
        }
        DidBindingProofError::Resolve(inner) => {
            AppError::bad_request(format!("did_resolver_failed: {inner}"))
        }
    }
}

fn enforce_did_continuity_for_primary_upgrade(
    current_bindings: &[AccountDidBinding],
    new_did: &str,
    make_primary: bool,
    continuity_proof: Option<&serde_json::Value>,
    expected_audience: &str,
    expected_trust_domain: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    if !make_primary {
        return Ok(());
    }
    let Some(current_primary) = current_bindings
        .iter()
        .find(|binding| binding.primary && binding.active)
    else {
        return Ok(());
    };
    if !current_primary.did.starts_with("did:web:") || !new_did.starts_with("did:webvh:") {
        return Ok(());
    }
    let proof_value = continuity_proof.ok_or_else(|| {
        AppError::bad_request("did_continuity_proof_required: did:web to did:webvh primary upgrade")
    })?;
    let proof: cokret_core::DidContinuityProof = serde_json::from_value(proof_value.clone())
        .map_err(|error| AppError::bad_request(format!("did_continuity_proof_invalid: {error}")))?;
    proof
        .validate_minimal()
        .map_err(|error| AppError::bad_request(format!("did_continuity_proof_invalid: {error}")))?;
    if proof.purpose != cokret_core::DidContinuityPurpose::PrincipalMethodUpgrade {
        return Err(AppError::bad_request(
            "did_continuity_proof_invalid: purpose must be principal_method_upgrade",
        ));
    }
    if proof.old_did.as_str() != current_primary.did || proof.new_did.as_str() != new_did {
        return Err(AppError::bad_request(
            "did_continuity_proof_invalid: old_did/new_did mismatch",
        ));
    }
    if !proof
        .audience
        .iter()
        .any(|audience| audience == expected_audience)
        || !proof
            .audience
            .iter()
            .any(|audience| audience == expected_trust_domain)
    {
        return Err(AppError::bad_request(
            "did_continuity_proof_invalid: audience/trust_domain binding missing",
        ));
    }
    if let Some(expires_at) = proof.expires_at
        && now >= expires_at
    {
        return Err(AppError::bad_request(
            "did_continuity_proof_invalid: proof expired",
        ));
    }
    if proof.old_did_document_digest.is_none() {
        return Err(AppError::bad_request(
            "did_continuity_proof_invalid: old_did_document_digest required",
        ));
    }
    if proof.new_did_document_digest.is_none() {
        return Err(AppError::bad_request(
            "did_continuity_proof_invalid: new_did_document_digest required",
        ));
    }
    if proof
        .transfer_evidence
        .user_oob_confirmation_id
        .trim()
        .is_empty()
    {
        return Err(AppError::bad_request(
            "did_continuity_proof_invalid: OOB confirmation is required",
        ));
    }
    let fingerprint = proof
        .transfer_evidence
        .inception_public_key_fingerprint
        .as_str();
    if !fingerprint.starts_with("sha256:") {
        return Err(AppError::bad_request(
            "did_continuity_proof_invalid: inception fingerprint must be sha256",
        ));
    }
    Ok(())
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.account_dids.remove", skip_all)]
pub async fn remove_account_did(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountDidBindingsOutcome> {
    let body: RemoveAccountDidBindingRequestBody = req.parse_json().await.unwrap_or_default();
    let id = extract_ulid_param(req)?;
    let did = req
        .param::<String>("did")
        .ok_or_else(|| AppError::bad_request("missing did"))?;
    enforce_did_binding_rate_limit(req, depot, id).await?;
    enforce_captcha(req, depot, body.captcha_token.as_deref()).await?;
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let cokret_config = depot.cokret_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let events = did_binding_event_logs(&mut repo, id).await?;
    let resolver = resolver_descriptor(&cokret_config, did_resolver.as_ref());
    let data = binding_records_for_user(&user, &cokret_config, did_resolver.as_ref()).await?;
    let mut data = apply_did_binding_events(data, &events, &resolver);
    let Some(binding) = data.iter_mut().find(|binding| binding.did == did) else {
        repo.cancel().await?;
        return Err(AppError::not_found("account DID binding not found"));
    };
    if binding.state == DidBindingState::Revoked {
        repo.cancel().await?;
        return Err(AppError::conflict("account DID binding is already revoked"));
    }
    let Some(admin_user) = admin_user.as_ref() else {
        repo.cancel().await?;
        return Err(AppError::forbidden(
            "account DID binding removal requires a user-bound admin token",
        ));
    };
    // High-risk: a supplied approval_proof MUST be a real detached JWS
    // bound to the admin DID over the canonical revocation transcript,
    // rather than recorded as a bare `approval_proof_present` boolean.
    let reason = body.reason.as_deref().unwrap_or_default();
    let approval_verification_method =
        crate::handlers::admin::v1::revocation_approval::verify_revocation_approval_proof(
            depot,
            &mut repo,
            admin_user,
            "account_did_binding.revoke",
            &did,
            Some(&user.id.to_string()),
            reason,
            body.approval_proof.as_deref(),
        )
        .await?;
    let revoked_at = clock.now();
    let mut rng = crate::handlers::account::make_rng();
    repo.audit()
        .add_admin_operation(
            &mut rng,
            &clock,
            NewAdminOperationLog::new(
                admin_user.id,
                AdminOperation::Other(DID_BINDING_REVOKED_OPERATION.to_owned()),
                "account",
                serde_json::json!({
                    "transition_kind": "did_binding_revoked",
                    "did": did,
                    "kind": did_binding_kind_wire(binding.kind),
                    "previous_state": did_binding_state_wire(binding.state),
                    "next_state": "revoked",
                    "reason": body.reason,
                    "approval_proof_present": body.approval_proof.as_ref().is_some_and(|value| !value.trim().is_empty()),
                    "approval_verification_method": approval_verification_method,
                    "revoke_related_sessions": body.revoke_related_sessions.unwrap_or(false),
                    "revoked_by": admin_user.id,
                    "revoked_by_handle": admin_user.localpart,
                }),
            )
            .with_resource_id(user.id),
        )
        .await?;
    repo.save().await?;

    binding.state = DidBindingState::Revoked;
    binding.active = false;
    binding.primary = false;
    binding.verification_status = DidBindingVerificationStatus::Rejected;
    binding.revoked_at = Some(revoked_at);

    Ok(Json(AccountDidBindingsOutcome {
        data,
        meta: did_bindings_meta(&cokret_config, did_resolver.as_ref()),
    }))
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
    let requester = activity_tracker.ip().map_or(
        crate::handlers::RequesterFingerprint::EMPTY,
        crate::handlers::RequesterFingerprint::new,
    );

    limiter
        .check_did_binding(requester, account_id)
        .await
        .map_err(|error| AppError::too_many_requests(error.to_string()))
}

pub(crate) async fn preview_bindings_for_user(
    user: &User,
    cokret_config: &CokretConfig,
    did_resolver: &dyn DidResolverService,
) -> Vec<AccountDidBindingPreview> {
    binding_records_for_user(user, cokret_config, did_resolver)
        .await
        .unwrap_or_default()
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
    cokret_config: &CokretConfig,
    did_resolver: &dyn DidResolverService,
) -> Result<Option<String>, AppError> {
    match did_resolver.primary_did_for_user(cokret_config, user).await {
        Ok(did) => Ok(Some(did)),
        Err(SessionGrantError::DidWebPrincipalNotExplicit) => Ok(None),
        Err(error) => Err(AppError::bad_request(format!(
            "principal_did_policy: {error}"
        ))),
    }
}

async fn binding_records_for_user(
    user: &User,
    cokret_config: &CokretConfig,
    did_resolver: &dyn DidResolverService,
) -> Result<Vec<AccountDidBinding>, AppError> {
    let Some(primary_did) = primary_did_for_user(user, cokret_config, did_resolver).await? else {
        return Ok(Vec::new());
    };
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
    let resolver = resolver_descriptor(cokret_config, did_resolver);

    Ok(vec![AccountDidBinding {
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
    }])
}

async fn did_binding_event_logs(
    repo: &mut BoxRepository,
    account_id: ulid::Ulid,
) -> Result<Vec<AdminOperationLog>, AppError> {
    let logs = repo
        .audit()
        .list_admin_operations(
            AdminOperationFilter::new()
                .for_resource_type("account")
                .for_resource(account_id)
                .with_limit(200),
        )
        .await?;
    Ok(logs
        .into_iter()
        .filter(|log| is_did_binding_event_log(log, account_id))
        .collect())
}

fn is_did_binding_event_log(log: &AdminOperationLog, account_id: ulid::Ulid) -> bool {
    log.resource_type == "account"
        && log.resource_id == Some(account_id)
        && matches!(
            &log.operation,
            AdminOperation::Other(operation)
                if operation == DID_BINDING_ADDED_OPERATION
                    || operation == DID_BINDING_REVOKED_OPERATION
        )
        && did_binding_detail_string(&log.details, "did").is_some()
}

fn apply_did_binding_events(
    mut bindings: Vec<AccountDidBinding>,
    events: &[AdminOperationLog],
    resolver: &DidBindingResolverDescriptor,
) -> Vec<AccountDidBinding> {
    let mut events = events.to_vec();
    events.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));

    for event in events {
        match &event.operation {
            AdminOperation::Other(operation) if operation == DID_BINDING_ADDED_OPERATION => {
                upsert_added_did_binding(&mut bindings, &event, resolver);
            }
            AdminOperation::Other(operation) if operation == DID_BINDING_REVOKED_OPERATION => {
                apply_did_binding_revocation(&mut bindings, &event);
            }
            _ => {}
        }
    }

    bindings
}

fn upsert_added_did_binding(
    bindings: &mut Vec<AccountDidBinding>,
    log: &AdminOperationLog,
    resolver: &DidBindingResolverDescriptor,
) {
    let Some(did) = did_binding_detail_string(&log.details, "did") else {
        return;
    };
    let kind = did_binding_detail_string(&log.details, "kind")
        .and_then(|kind| DidBindingKind::from_wire(&kind))
        .unwrap_or(DidBindingKind::Pairwise);
    let primary = log
        .details
        .get("make_primary")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        || kind == DidBindingKind::Primary;
    if primary {
        for binding in bindings.iter_mut() {
            binding.primary = false;
        }
    }
    let binding = AccountDidBinding {
        id: did_binding_detail_string(&log.details, "binding_id")
            .unwrap_or_else(|| format!("acctdid-{}", binding_slug(&did))),
        account_id: log.resource_id.map(|id| id.to_string()).unwrap_or_default(),
        did: did.clone(),
        kind,
        state: DidBindingState::Active,
        primary,
        active: true,
        verification_status: DidBindingVerificationStatus::Verified,
        resolver: resolver.clone(),
        created_at: Some(log.created_at),
        last_verified_at: Some(log.created_at),
        last_resolver_receipt_id: did_binding_detail_string(
            &log.details,
            "last_resolver_receipt_id",
        )
        .or_else(|| Some(format!("audit-{}", log.id))),
        revoked_at: None,
    };
    match bindings.iter_mut().find(|binding| binding.did == did) {
        Some(existing) => *existing = binding,
        None => bindings.push(binding),
    }
}

fn apply_did_binding_revocation(bindings: &mut [AccountDidBinding], log: &AdminOperationLog) {
    let Some(did) = did_binding_detail_string(&log.details, "did") else {
        return;
    };
    if let Some(binding) = bindings.iter_mut().find(|binding| binding.did == did) {
        binding.state = DidBindingState::Revoked;
        binding.active = false;
        binding.primary = false;
        binding.verification_status = DidBindingVerificationStatus::Rejected;
        binding.revoked_at = Some(log.created_at);
    }
}

fn did_binding_detail_string(details: &serde_json::Value, field: &str) -> Option<String> {
    details
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.trim().is_empty())
}

fn did_binding_kind_wire(kind: DidBindingKind) -> &'static str {
    match kind {
        DidBindingKind::Primary => "primary",
        DidBindingKind::Recovery => "recovery",
        DidBindingKind::Pairwise => "pairwise",
    }
}

fn did_binding_state_wire(state: DidBindingState) -> &'static str {
    match state {
        DidBindingState::PendingProof => "pending_proof",
        DidBindingState::Active => "active",
        DidBindingState::Revoked => "revoked",
        DidBindingState::Rejected => "rejected",
    }
}

fn did_bindings_meta(
    cokret_config: &CokretConfig,
    did_resolver: &dyn DidResolverService,
) -> AccountDidBindingsMeta {
    AccountDidBindingsMeta {
        resolver: resolver_descriptor(cokret_config, did_resolver),
        supported_verification_methods: vec![
            "did_controller_key".to_owned(),
            "passkey".to_owned(),
            "oidc_subject_link".to_owned(),
        ],
        supports_write_operations: true,
    }
}

fn resolver_descriptor(
    cokret_config: &CokretConfig,
    did_resolver: &dyn DidResolverService,
) -> DidBindingResolverDescriptor {
    match did_resolver.delegated_resolver(cokret_config) {
        Some(resolver) => DidBindingResolverDescriptor {
            mode: DidBindingResolverMode::DelegatedResolver,
            resolver: Some(resolver),
            proof_required_for_pairwise: did_resolver.proof_required_for_pairwise(cokret_config),
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
