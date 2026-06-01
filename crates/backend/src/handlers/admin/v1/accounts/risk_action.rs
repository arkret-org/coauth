//! Risk-action proposal/approval/execute workflow for admin account mutations.
//!
//! Split from `admin/v1/accounts.rs`. The execute step applies mutations via
//! `services::user_admin`; durable proposal persistence is tracked in
//! `_todos.md`.

use chrono::{DateTime, Utc};
use coauth_admin_types::{
    AccountRiskActionApprovalRequest, AccountRiskActionApprovalResponse,
    AccountRiskActionCurrentResponse, AccountRiskActionExecuteRequest,
    AccountRiskActionHistoryResponse, AccountRiskActionProposalRequest,
    AccountRiskActionProposalResponse, AccountRiskActionTransitionRecord,
};
use coauth_data::{AdminUserPatch, RepositoryAccess, audit::AdminOperation};
use contrix_core::canonical::canonical_json_bytes;
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::Serialize;
use ulid::Ulid;

use crate::{
    AppError, JsonResult,
    handlers::{
        admin::{
            audit_helper::{AdminAuditSigning, record_admin_operation_signed},
            call_context::extract_call_context,
            params::extract_ulid_param,
            response::SingleResponse,
        },
        common::DepotExt,
        contrix::service_did_for,
    },
    services::{
        did_binding_proof::verify_detached_jws_with_sdk,
        did_resolver::DidResolverService,
        risk_action_proposals::{
            ApprovalProof, CreateProposal, ProposalState, RiskActionProposalRecord,
            RiskActionProposalsError, required_approvals_for,
        },
        risk_action_state::RiskActionStateService,
    },
};

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRiskActionExecuteResponse {
    /// Stable persisted state-record identifier for this risk-action state
    /// machine.
    state_record_id: String,

    /// Proposal identifier being executed.
    proposal_id: String,

    /// Account targeted by the proposal.
    account_id: String,

    /// Executed action.
    action: String,

    /// Optional ticket or incident reference.
    ticket: Option<String>,

    /// Previous lifecycle state before this transition.
    previous_state: String,

    /// Execution state reported by the scaffold contract.
    execution_state: String,

    /// Account mutation kind performed by the controlled executor.
    mutation_kind: String,

    /// Monotonic state-machine revision.
    state_revision: u64,

    /// Explicit transition kind written by this scaffold.
    transition_kind: String,

    /// When the execute step was recorded.
    executed_at: DateTime<Utc>,

    /// How the execute scaffold expects the final mutation to run.
    execution_mode: String,

    /// Human execution note for the scaffold trail.
    execution_note: Option<String>,

    /// Account state after the mutation was applied.
    account: SingleResponse<super::AccountRecord>,

    /// Legacy mutation endpoint equivalent to the controlled execute path.
    mutation_endpoint: String,

    /// Allowed next transitions from this execution state.
    allowed_next_transitions: Vec<String>,

    /// How this scaffold persists the state machine today.
    state_store_kind: String,

    /// Remaining implementation work for this scaffold.
    todo: String,
}

// `impl Resource for AccountRiskActionCurrentResponse` lives next to the
// type in `coauth_admin_types::risk_action` — both moved together to
// satisfy the orphan rule.
//
// The bridge risk-action example structs and example constructor now
// live in `coauth_admin_types::bridge_admin`, keeping the OpenAPI
// example payload and admin bridge discovery response in one shared
// contract.

struct AccountRiskActionMutation {
    patch: AdminUserPatch,
    principal_erase: bool,
    mutation_kind: &'static str,
    mutation_description: &'static str,
}

fn account_risk_action_mutation(action: &str) -> Result<AccountRiskActionMutation, AppError> {
    match action {
        "lock" => Ok(AccountRiskActionMutation {
            patch: AdminUserPatch {
                locked: Some(true),
                ..AdminUserPatch::default()
            },
            principal_erase: false,
            mutation_kind: "account_locked",
            mutation_description: "account locked through services.user_admin",
        }),
        "disable" => Ok(AccountRiskActionMutation {
            patch: AdminUserPatch {
                deactivated: Some(true),
                ..AdminUserPatch::default()
            },
            principal_erase: false,
            mutation_kind: "account_disabled",
            mutation_description: "account disabled through services.user_admin",
        }),
        "erase" => Ok(AccountRiskActionMutation {
            patch: AdminUserPatch {
                deactivated: Some(true),
                ..AdminUserPatch::default()
            },
            principal_erase: true,
            mutation_kind: "account_erasure_scheduled",
            mutation_description: "account disabled and PrincipalServer erasure job scheduled through services.user_admin",
        }),
        "reset_recovery" => Ok(AccountRiskActionMutation {
            patch: AdminUserPatch {
                locked: Some(true),
                ..AdminUserPatch::default()
            },
            principal_erase: false,
            mutation_kind: "account_locked_pending_recovery_reset",
            mutation_description: "account locked pending dedicated recovery reset workflow",
        }),
        other => Err(AppError::bad_request(format!(
            "Unknown account risk action: {other}"
        ))),
    }
}

fn parse_proposal_id(value: &str) -> Result<Ulid, AppError> {
    value
        .parse::<Ulid>()
        .map_err(|_| AppError::bad_request("invalid proposal_id"))
}

fn map_risk_action_proposals_error(error: RiskActionProposalsError) -> AppError {
    match error {
        RiskActionProposalsError::Storage(error) => {
            AppError::internal(std::io::Error::other(error.to_string()))
        }
        RiskActionProposalsError::NotFound => AppError::not_found("risk action proposal not found"),
        RiskActionProposalsError::NotDraft => {
            AppError::bad_request("risk action proposal is not in draft state")
        }
        RiskActionProposalsError::DuplicateApproval(admin_did) => AppError::conflict(format!(
            "risk action proposal already has an approval from {admin_did}"
        )),
        RiskActionProposalsError::NotApproved { got, need } => AppError::bad_request(format!(
            "risk action proposal must be approved before execution (got {got}, need {need})"
        )),
        RiskActionProposalsError::AlreadyExecuted => {
            AppError::conflict("risk action proposal has already been executed")
        }
        RiskActionProposalsError::AlreadyCancelled => {
            AppError::conflict("risk action proposal has already been cancelled")
        }
    }
}

async fn admin_actor_id(
    admin_user: Option<&coauth_data::User>,
    contrix_config: &coauth_config::ContrixConfig,
    did_resolver: &dyn DidResolverService,
) -> Result<String, AppError> {
    let admin_user = admin_user.ok_or_else(|| {
        AppError::forbidden("risk action workflow requires a user-bound admin token")
    })?;
    Ok(did_resolver
        .primary_did_for_user(contrix_config, admin_user)
        .await)
}

fn bind_approval_admin_did(
    caller_admin_did: String,
    request_approved_by: Option<&str>,
) -> Result<String, AppError> {
    let Some(request_approved_by) = request_approved_by
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(caller_admin_did);
    };

    if request_approved_by != caller_admin_did {
        return Err(AppError::bad_request(
            "approved_by must match the authenticated admin DID",
        ));
    }

    Ok(caller_admin_did)
}

fn ensure_proposal_targets(
    proposal: &RiskActionProposalRecord,
    account_id: Ulid,
    action: &str,
    ticket: Option<&str>,
) -> Result<(), AppError> {
    if proposal.account_id != account_id {
        return Err(AppError::not_found("risk action proposal not found"));
    }
    if proposal.action != action {
        return Err(AppError::bad_request(format!(
            "risk action proposal action mismatch: expected {}, got {action}",
            proposal.action
        )));
    }
    if let Some(ticket) = ticket
        && proposal.ticket.as_deref() != Some(ticket)
    {
        return Err(AppError::bad_request(
            "risk action proposal ticket does not match request",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct RiskActionApprovalTranscript {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub proposal_id: String,
    pub account_id: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    pub approval_note: String,
    pub approved_by: String,
}

pub(crate) fn risk_action_approval_transcript(
    proposal_id: &str,
    account_id: Ulid,
    action: &str,
    ticket: Option<&str>,
    approval_note: &str,
    approved_by: &str,
) -> RiskActionApprovalTranscript {
    RiskActionApprovalTranscript {
        kind: "cx.coauth.account_risk_action.approval.v1",
        proposal_id: proposal_id.to_owned(),
        account_id: account_id.to_string(),
        action: action.to_owned(),
        ticket: ticket.map(str::to_owned),
        approval_note: approval_note.to_owned(),
        approved_by: approved_by.to_owned(),
    }
}

pub(crate) fn risk_action_approval_transcript_bytes(
    proposal_id: &str,
    account_id: Ulid,
    action: &str,
    ticket: Option<&str>,
    approval_note: &str,
    approved_by: &str,
) -> Result<Vec<u8>, AppError> {
    canonical_json_bytes(&risk_action_approval_transcript(
        proposal_id,
        account_id,
        action,
        ticket,
        approval_note,
        approved_by,
    ))
    .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))
}

#[allow(clippy::too_many_arguments)]
async fn verify_approval_proof_jws(
    http_client: &reqwest::Client,
    url_builder: &coauth_data::UrlBuilder,
    contrix_config: &coauth_config::ContrixConfig,
    key_store: &coauth_keystore::Keystore,
    repo: &mut coauth_data::BoxRepository,
    did_resolver: &dyn DidResolverService,
    proof_jws: &str,
    proposal_id: &str,
    account_id: Ulid,
    action: &str,
    ticket: Option<&str>,
    approval_note: &str,
    approved_by: &str,
) -> Result<String, AppError> {
    if proof_jws.trim().is_empty() {
        return Err(AppError::bad_request(
            "risk action approvals require approval_proof_jws",
        ));
    }
    let payload = risk_action_approval_transcript_bytes(
        proposal_id,
        account_id,
        action,
        ticket,
        approval_note,
        approved_by,
    )?;
    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            contrix_config,
            key_store,
            repo,
            approved_by,
        )
        .await
        .map_err(|error| AppError::bad_request(format!("admin_did_resolve_failed: {error}")))?;
    if resolution.document.verification_method.is_empty() {
        return Err(AppError::bad_request(
            "approved_by DID document has no verificationMethod entries",
        ));
    }
    verify_detached_jws_with_sdk(
        proof_jws,
        &payload,
        &resolution.document.verification_method,
    )
    .map_err(|error| AppError::bad_request(format!("approval_proof_jws_invalid: {error}")))
}

fn state_revision_for(proposal: &RiskActionProposalRecord) -> u64 {
    1 + proposal.approval_proofs.len() as u64
        + u64::from(proposal.executed_at.is_some())
        + u64::from(proposal.cancelled_at.is_some())
}

fn transition_for_state(state: ProposalState) -> &'static str {
    match state {
        ProposalState::Draft => "proposal_approval_recorded",
        ProposalState::Approved => "proposal_approved",
        ProposalState::Executed => "proposal_executed",
        ProposalState::Cancelled => "proposal_cancelled",
        ProposalState::Rejected => "proposal_rejected",
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.risk_action", skip_all)]
pub async fn propose(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountRiskActionProposalResponse> {
    let params: AccountRiskActionProposalRequest =
        req.parse_json().await.map_err(AppError::internal)?;
    if params.action.trim().is_empty() {
        return Err(AppError::bad_request("risk action is required"));
    }
    if params
        .reason
        .as_deref()
        .is_none_or(|reason| reason.trim().is_empty())
    {
        return Err(AppError::bad_request(
            "risk action proposals require a non-empty reason",
        ));
    }

    let _mutation = account_risk_action_mutation(&params.action)?;
    let risk_action_state = depot.risk_action_state_service()?;
    let risk_action_proposals = depot.risk_action_proposals_service()?;
    let contrix_config = depot.contrix_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let key_store = depot.key_store()?;
    let url_builder = depot.url_builder()?;
    let service_did = service_did_for(&url_builder, &contrix_config);
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = extract_call_context(req, depot).await?;
    let requested_at = clock.now();
    let requested_by = admin_user.as_ref().map(|user| user.id.to_string());
    let requested_by_handle = admin_user.as_ref().map(|user| user.handle.clone());
    let id = extract_ulid_param(req)?;
    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let proposer_did =
        admin_actor_id(admin_user.as_ref(), &contrix_config, did_resolver.as_ref()).await?;
    let proposal = risk_action_proposals
        .create(CreateProposal {
            account_id: account.id,
            action: params.action.clone(),
            proposer_did,
            reason: params.reason.clone().unwrap_or_default(),
            ticket: params.ticket.clone(),
            required_approvals: required_approvals_for(
                &params.action,
                contrix_config.high_risk_threshold,
            ),
            now: requested_at,
        })
        .await
        .map_err(map_risk_action_proposals_error)?;
    let proposal_id = proposal.id.to_string();
    let state_record_id = risk_action_state.record_id(account.id, &proposal_id);
    let execution_endpoint = risk_action_state.execution_endpoint(&params.action, account.id)?;
    let allowed_next_transitions = risk_action_state.allowed_next_transitions("draft");
    let state_store_kind = risk_action_state.state_store_kind();
    let todo = "Durable proposal record persisted; execute requires explicit persisted approval and consumes this proposal before mutation.".to_owned();

    if admin_user.is_some() {
        let mut rng = crate::handlers::account::make_rng();
        record_admin_operation_signed(
            &mut repo,
            &mut rng,
            &*clock,
            &key_store,
            &service_did,
            contrix_config.audit_signature_fail_closed,
            admin_user.as_ref(),
            AdminOperation::Other(format!("account_{}_proposal", params.action)),
            "account",
            Some(account.id),
            serde_json::json!({
                "state_record_id": state_record_id,
                "state_store_kind": state_store_kind,
                "state_revision": 1_u64,
                "proposal_id": proposal_id,
                "action": params.action,
                "transition_kind": "proposal_requested",
                "previous_state": "idle",
                "next_state": "draft",
                "reason": params.reason,
                "ticket": params.ticket,
                "approved_by": params.approved_by,
                "requested_by": requested_by,
                "requested_by_handle": requested_by_handle,
                "execution_endpoint": execution_endpoint,
                "allowed_next_transitions": allowed_next_transitions.clone(),
                "todo": todo,
            }),
        )
        .await?;
        repo.save().await?;
    } else {
        repo.cancel().await?;
    }

    Ok(Json(AccountRiskActionProposalResponse {
        state_record_id,
        proposal_id,
        account_id: account.id.to_string(),
        action: params.action,
        reason: params.reason,
        ticket: params.ticket,
        approved_by: params.approved_by,
        requested_at: Some(requested_at),
        requested_by,
        requested_by_handle,
        previous_state: "idle".to_owned(),
        proposal_state: "draft".to_owned(),
        state_revision: 1,
        transition_kind: "proposal_requested".to_owned(),
        approval_mode: "durable_proposal_required".to_owned(),
        allowed_next_transitions,
        execution_endpoint,
        state_store_kind: state_store_kind.to_owned(),
        todo,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.approve_risk_action", skip_all)]
pub async fn approve(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountRiskActionApprovalResponse> {
    let params: AccountRiskActionApprovalRequest =
        req.parse_json().await.map_err(AppError::internal)?;
    if params.action.trim().is_empty() {
        return Err(AppError::bad_request("risk action is required"));
    }
    if params
        .approval_note
        .as_deref()
        .is_none_or(|note| note.trim().is_empty())
    {
        return Err(AppError::bad_request(
            "risk action approvals require a non-empty approval_note",
        ));
    }
    if params.approval_proof_jws.trim().is_empty() {
        return Err(AppError::bad_request(
            "risk action approvals require approval_proof_jws",
        ));
    }

    let risk_action_state = depot.risk_action_state_service()?;
    let risk_action_proposals = depot.risk_action_proposals_service()?;
    let contrix_config = depot.contrix_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let key_store = depot.key_store()?;
    let url_builder = depot.url_builder()?;
    let http_client = depot.http_client().map_err(AppError::internal)?;
    let service_did = service_did_for(&url_builder, &contrix_config);
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = extract_call_context(req, depot).await?;
    let approved_at = clock.now();
    let id = extract_ulid_param(req)?;
    let proposal_id = req
        .param::<String>("proposal_id")
        .ok_or_else(|| AppError::bad_request("missing proposal_id"))?;
    let proposal_ulid = parse_proposal_id(&proposal_id)?;
    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let existing = risk_action_proposals
        .get(proposal_ulid)
        .await
        .map_err(map_risk_action_proposals_error)?
        .ok_or_else(|| AppError::not_found("risk action proposal not found"))?;
    ensure_proposal_targets(
        &existing,
        account.id,
        &params.action,
        params.ticket.as_deref(),
    )?;
    let caller_admin_did =
        admin_actor_id(admin_user.as_ref(), &contrix_config, did_resolver.as_ref()).await?;
    let approved_by = bind_approval_admin_did(caller_admin_did, params.approved_by.as_deref())?;
    let approval_note = params.approval_note.as_deref().unwrap_or_default();
    let verification_method = verify_approval_proof_jws(
        &http_client,
        &url_builder,
        &contrix_config,
        &key_store,
        &mut repo,
        did_resolver.as_ref(),
        &params.approval_proof_jws,
        &proposal_id,
        account.id,
        &params.action,
        existing.ticket.as_deref(),
        approval_note,
        &approved_by,
    )
    .await?;
    let approved = risk_action_proposals
        .approve(
            proposal_ulid,
            ApprovalProof {
                admin_did: approved_by.clone(),
                signature: params.approval_proof_jws.clone(),
                note: params.approval_note.clone(),
                recorded_at: approved_at,
            },
        )
        .await
        .map_err(map_risk_action_proposals_error)?;
    let state_record_id = risk_action_state.record_id(account.id, &proposal_id);
    let execution_endpoint = risk_action_state.execution_endpoint(&params.action, account.id)?;
    let allowed_next_transitions =
        risk_action_state.allowed_next_transitions(approved.state.as_str());
    let state_store_kind = risk_action_state.state_store_kind();
    let todo = format!(
        "Durable approval recorded ({}/{}); execute is allowed only after state reaches approved.",
        approved.approval_proofs.len(),
        approved.required_approvals
    );
    let state_revision = state_revision_for(&approved);
    let transition_kind = transition_for_state(approved.state).to_owned();

    if admin_user.is_some() {
        let mut rng = crate::handlers::account::make_rng();
        record_admin_operation_signed(
            &mut repo,
            &mut rng,
            &*clock,
            &key_store,
            &service_did,
            contrix_config.audit_signature_fail_closed,
            admin_user.as_ref(),
            AdminOperation::Other(format!("account_{}_proposal_approved", params.action)),
            "account",
            Some(account.id),
            serde_json::json!({
                "state_record_id": state_record_id,
                "state_store_kind": state_store_kind,
                "state_revision": state_revision,
                "proposal_id": proposal_id,
                "action": params.action,
                "transition_kind": transition_kind,
                "previous_state": existing.state.as_str(),
                "next_state": approved.state.as_str(),
                "ticket": params.ticket,
                "approved_by": approved_by,
                "approval_verification_method": verification_method,
                "approved_by_handle": admin_user.as_ref().map(|user| user.handle.as_str()),
                "approval_note": params.approval_note,
                "execution_endpoint": execution_endpoint,
                "allowed_next_transitions": allowed_next_transitions.clone(),
                "todo": todo,
            }),
        )
        .await?;
        repo.save().await?;
    } else {
        repo.cancel().await?;
    }

    Ok(Json(AccountRiskActionApprovalResponse {
        state_record_id,
        proposal_id,
        account_id: account.id.to_string(),
        action: params.action,
        ticket: params.ticket,
        previous_state: existing.state.as_str().to_owned(),
        approval_state: approved.state.as_str().to_owned(),
        state_revision,
        transition_kind,
        approved_at: approved.approved_at.or(Some(approved_at)),
        approved_by: Some(approved_by),
        approved_by_handle: admin_user.as_ref().map(|user| user.handle.clone()),
        approval_note: params.approval_note,
        execution_endpoint,
        allowed_next_transitions,
        state_store_kind: state_store_kind.to_owned(),
        todo,
    }))
}

#[cfg(test)]
mod tests {
    use ulid::Ulid;

    use super::{bind_approval_admin_did, risk_action_approval_transcript};

    #[test]
    fn approval_admin_did_is_bound_to_authenticated_caller() {
        let caller = "did:web:coauth.invalid:accounts:admin";

        assert_eq!(
            bind_approval_admin_did(caller.to_owned(), None).unwrap(),
            caller
        );
        assert_eq!(
            bind_approval_admin_did(caller.to_owned(), Some(caller)).unwrap(),
            caller
        );
        assert_eq!(
            bind_approval_admin_did(
                caller.to_owned(),
                Some("  did:web:coauth.invalid:accounts:admin  ")
            )
            .unwrap(),
            caller
        );
        assert!(bind_approval_admin_did(caller.to_owned(), Some("did:web:forged-admin")).is_err());
    }

    #[test]
    fn approval_transcript_binds_security_fields() {
        let account_id = Ulid::nil();
        let transcript = risk_action_approval_transcript(
            "01H00000000000000000000000",
            account_id,
            "erase",
            Some("INC-9"),
            "approved with incident note",
            "did:web:admin.example",
        );

        assert_eq!(transcript.proposal_id, "01H00000000000000000000000");
        assert_eq!(transcript.account_id, account_id.to_string());
        assert_eq!(transcript.action, "erase");
        assert_eq!(transcript.ticket.as_deref(), Some("INC-9"));
        assert_eq!(transcript.approval_note, "approved with incident note");
        assert_eq!(transcript.approved_by, "did:web:admin.example");
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.execute_risk_action", skip_all)]
pub async fn execute(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountRiskActionExecuteResponse> {
    let params: AccountRiskActionExecuteRequest =
        req.parse_json().await.map_err(AppError::internal)?;
    if params.action.trim().is_empty() {
        return Err(AppError::bad_request("risk action is required"));
    }
    if params
        .execution_note
        .as_deref()
        .is_none_or(|note| note.trim().is_empty())
    {
        return Err(AppError::bad_request(
            "risk action execute requires a non-empty execution_note",
        ));
    }

    let mutation = account_risk_action_mutation(&params.action)?;
    let risk_action_state = depot.risk_action_state_service()?;
    let risk_action_proposals = depot.risk_action_proposals_service()?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = extract_call_context(req, depot).await?;
    let contrix_config = depot.contrix_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let principal_server = depot.principal_server()?;
    let key_store = depot.key_store()?;
    let url_builder = depot.url_builder()?;
    let service_did = service_did_for(&url_builder, &contrix_config);
    let audit_signing = AdminAuditSigning {
        keystore: &key_store,
        service_did: &service_did,
        fail_closed: contrix_config.audit_signature_fail_closed,
    };
    let executed_at = clock.now();
    let id = extract_ulid_param(req)?;
    let proposal_id = req
        .param::<String>("proposal_id")
        .ok_or_else(|| AppError::bad_request("missing proposal_id"))?;
    let proposal_ulid = parse_proposal_id(&proposal_id)?;
    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let existing = risk_action_proposals
        .get(proposal_ulid)
        .await
        .map_err(map_risk_action_proposals_error)?
        .ok_or_else(|| AppError::not_found("risk action proposal not found"))?;
    ensure_proposal_targets(
        &existing,
        account.id,
        &params.action,
        params.ticket.as_deref(),
    )?;
    let executed_proposal = risk_action_proposals
        .mark_executed(proposal_ulid, executed_at)
        .await
        .map_err(map_risk_action_proposals_error)?;
    let state_record_id = risk_action_state.record_id(account.id, &proposal_id);
    let mutation_endpoint = risk_action_state.execution_endpoint(&params.action, account.id)?;
    let allowed_next_transitions = risk_action_state.allowed_next_transitions("mutation_recorded");
    let state_store_kind = risk_action_state.state_store_kind();
    let state_revision = state_revision_for(&executed_proposal);
    let todo = "Durable proposal consumed before controlled account mutation.".to_owned();
    let mut rng = crate::handlers::account::make_rng();
    let updated_account = crate::services::user_admin::patch_user(
        &mut repo,
        &mut rng,
        &*clock,
        principal_server.as_ref(),
        admin_user.as_ref(),
        account.id,
        mutation.patch,
        mutation.principal_erase,
        Some(audit_signing),
    )
    .await
    .map_err(super::map_service_error)?;

    record_admin_operation_signed(
        &mut repo,
        &mut rng,
        &*clock,
        &key_store,
        &service_did,
        contrix_config.audit_signature_fail_closed,
        admin_user.as_ref(),
        AdminOperation::Other(format!("account_{}_proposal_executed", params.action)),
        "account",
        Some(account.id),
        serde_json::json!({
            "state_record_id": state_record_id,
            "state_store_kind": state_store_kind,
            "state_revision": state_revision,
            "proposal_id": proposal_id,
            "action": params.action,
            "transition_kind": "proposal_executed",
            "previous_state": existing.state.as_str(),
            "next_state": "mutation_recorded",
            "mutation_kind": mutation.mutation_kind,
            "mutation_description": mutation.mutation_description,
            "principal_erase": mutation.principal_erase,
            "ticket": params.ticket,
            "executed_by": admin_user.as_ref().map(|user| user.id.to_string()),
            "executed_by_handle": admin_user.as_ref().map(|user| user.handle.as_str()),
            "execution_note": params.execution_note,
            "mutation_endpoint": mutation_endpoint,
            "allowed_next_transitions": allowed_next_transitions.clone(),
            "todo": todo,
        }),
    )
    .await?;
    repo.save().await?;

    let account_response = SingleResponse::new_canonical(
        super::AccountRecord::from_user(updated_account, &contrix_config, did_resolver.as_ref())
            .await,
    );

    Ok(Json(AccountRiskActionExecuteResponse {
        state_record_id,
        proposal_id,
        account_id: account.id.to_string(),
        action: params.action,
        ticket: params.ticket,
        previous_state: existing.state.as_str().to_owned(),
        execution_state: "mutation_recorded".to_owned(),
        mutation_kind: mutation.mutation_kind.to_owned(),
        state_revision,
        transition_kind: "proposal_executed".to_owned(),
        executed_at,
        execution_mode: "services.user_admin.patch_user".to_owned(),
        execution_note: params.execution_note,
        account: account_response,
        mutation_endpoint,
        allowed_next_transitions,
        state_store_kind: state_store_kind.to_owned(),
        todo,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.list_risk_action_history", skip_all)]
pub async fn list_history(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountRiskActionHistoryResponse> {
    let risk_action_state = depot.risk_action_state_service()?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } =
        extract_call_context(req, depot).await?;
    let id = extract_ulid_param(req)?;
    repo.user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    let logs = repo
        .audit()
        .list_admin_operations(
            coauth_data::audit::AdminOperationFilter::new()
                .for_resource_type("account")
                .with_limit(100),
        )
        .await?;

    repo.cancel().await?;

    let data = logs
        .into_iter()
        .filter(|log| is_account_risk_action_log(log, id))
        .map(|log| risk_action_transition_record(id, &log, risk_action_state.as_ref()))
        .collect();

    Ok(Json(AccountRiskActionHistoryResponse { data }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.get_risk_action_current", skip_all)]
pub async fn get_current(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<AccountRiskActionCurrentResponse>> {
    let risk_action_state = depot.risk_action_state_service()?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } =
        extract_call_context(req, depot).await?;
    let id = extract_ulid_param(req)?;
    repo.user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    let logs = repo
        .audit()
        .list_admin_operations(
            coauth_data::audit::AdminOperationFilter::new()
                .for_resource_type("account")
                .with_limit(100),
        )
        .await?;

    repo.cancel().await?;

    let current = logs
        .into_iter()
        .find(|log| is_account_risk_action_log(log, id))
        .map(|log| AccountRiskActionCurrentResponse {
            account_id: id.to_string(),
            state_record_id: risk_action_detail_string(&log.details, "state_record_id"),
            proposal_id: risk_action_detail_string(&log.details, "proposal_id"),
            action: risk_action_detail_string(&log.details, "action"),
            lifecycle_state: risk_action_detail_string(&log.details, "next_state")
                .unwrap_or_else(|| "idle".to_owned()),
            last_operation: risk_action_operation_name(&log.operation),
            transition_kind: risk_action_detail_string(&log.details, "transition_kind"),
            previous_state: risk_action_detail_string(&log.details, "previous_state"),
            state_revision: risk_action_detail_u64(&log.details, "state_revision"),
            allowed_next_transitions: risk_action_detail_vec_string(
                &log.details,
                "allowed_next_transitions",
            ),
            ticket: risk_action_detail_string(&log.details, "ticket"),
            recorded_at: Some(log.created_at),
            recorded_by: risk_action_detail_string(&log.details, "requested_by")
                .or_else(|| risk_action_detail_string(&log.details, "approved_by"))
                .or_else(|| risk_action_detail_string(&log.details, "executed_by")),
            recorded_by_handle: risk_action_detail_string(&log.details, "requested_by_handle")
                .or_else(|| risk_action_detail_string(&log.details, "approved_by_handle"))
                .or_else(|| risk_action_detail_string(&log.details, "executed_by_handle")),
            execution_endpoint: risk_action_detail_string(&log.details, "execution_endpoint"),
            mutation_endpoint: risk_action_detail_string(&log.details, "mutation_endpoint"),
            state_store_kind: risk_action_detail_string(&log.details, "state_store_kind")
                .unwrap_or_else(|| risk_action_state.state_store_kind().to_owned()),
            todo: risk_action_detail_string(&log.details, "todo"),
        })
        .unwrap_or(AccountRiskActionCurrentResponse {
            account_id: id.to_string(),
            state_record_id: None,
            proposal_id: None,
            action: None,
            lifecycle_state: "idle".to_owned(),
            last_operation: None,
            transition_kind: None,
            previous_state: None,
            state_revision: None,
            allowed_next_transitions: risk_action_state.allowed_next_transitions("idle"),
            ticket: None,
            recorded_at: None,
            recorded_by: None,
            recorded_by_handle: None,
            execution_endpoint: None,
            mutation_endpoint: None,
            state_store_kind: risk_action_state.state_store_kind().to_owned(),
            todo: Some(
                "No risk-action state-machine record has been persisted for this account yet."
                    .to_owned(),
            ),
        });

    Ok(Json(SingleResponse::new_canonical(current)))
}

fn is_account_risk_action_log(
    log: &coauth_data::audit::AdminOperationLog,
    account_id: Ulid,
) -> bool {
    if log.resource_type != "account" || log.resource_id != Some(account_id) {
        return false;
    }

    matches!(
        &log.operation,
        coauth_data::audit::AdminOperation::Other(operation)
            if operation.starts_with("account_")
                && (operation.ends_with("_proposal")
                    || operation.ends_with("_proposal_approved")
                    || operation.ends_with("_proposal_executed"))
    )
}

fn risk_action_operation_name(operation: &coauth_data::audit::AdminOperation) -> Option<String> {
    match operation {
        coauth_data::audit::AdminOperation::Other(operation) => Some(operation.clone()),
        _ => None,
    }
}

fn risk_action_transition_record(
    account_id: Ulid,
    log: &coauth_data::audit::AdminOperationLog,
    risk_action_state: &dyn RiskActionStateService,
) -> AccountRiskActionTransitionRecord {
    AccountRiskActionTransitionRecord {
        account_id: account_id.to_string(),
        state_record_id: risk_action_detail_string(&log.details, "state_record_id"),
        proposal_id: risk_action_detail_string(&log.details, "proposal_id"),
        action: risk_action_detail_string(&log.details, "action"),
        transition_kind: risk_action_detail_string(&log.details, "transition_kind")
            .unwrap_or_else(|| "unknown_transition".to_owned()),
        previous_state: risk_action_detail_string(&log.details, "previous_state"),
        next_state: risk_action_detail_string(&log.details, "next_state")
            .unwrap_or_else(|| "idle".to_owned()),
        state_revision: risk_action_detail_u64(&log.details, "state_revision"),
        ticket: risk_action_detail_string(&log.details, "ticket"),
        recorded_at: Some(log.created_at),
        recorded_by: risk_action_detail_string(&log.details, "requested_by")
            .or_else(|| risk_action_detail_string(&log.details, "approved_by"))
            .or_else(|| risk_action_detail_string(&log.details, "executed_by")),
        recorded_by_handle: risk_action_detail_string(&log.details, "requested_by_handle")
            .or_else(|| risk_action_detail_string(&log.details, "approved_by_handle"))
            .or_else(|| risk_action_detail_string(&log.details, "executed_by_handle")),
        execution_endpoint: risk_action_detail_string(&log.details, "execution_endpoint"),
        mutation_endpoint: risk_action_detail_string(&log.details, "mutation_endpoint"),
        approval_note: risk_action_detail_string(&log.details, "approval_note"),
        execution_note: risk_action_detail_string(&log.details, "execution_note"),
        state_store_kind: risk_action_detail_string(&log.details, "state_store_kind")
            .unwrap_or_else(|| risk_action_state.state_store_kind().to_owned()),
        todo: risk_action_detail_string(&log.details, "todo"),
    }
}

fn risk_action_detail_string(details: &serde_json::Value, field: &str) -> Option<String> {
    details
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.trim().is_empty())
}

fn risk_action_detail_u64(details: &serde_json::Value, field: &str) -> Option<u64> {
    details.get(field).and_then(serde_json::Value::as_u64)
}

fn risk_action_detail_vec_string(details: &serde_json::Value, field: &str) -> Vec<String> {
    details
        .get(field)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
