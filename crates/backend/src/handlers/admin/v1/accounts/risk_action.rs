//! Risk-action proposal/approval/execute workflow for admin account mutations.
//!
//! Split from `admin/v1/accounts.rs`. The execute step applies mutations via
//! `services::user_admin`; durable proposal persistence is tracked in
//! `_todos.md`.

use chrono::{DateTime, Utc};
use coauth_admin_types::{
    AccountRiskActionApprovalRequest, AccountRiskActionExecuteRequest,
    AccountRiskActionProposalRequest,
};
use coauth_data::audit::{AdminOperation, NewAdminOperationLog};
use coauth_data::{AdminUserPatch, RepositoryAccess};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::Serialize;
use ulid::Ulid;

use crate::{
    AppError, JsonResult,
    handlers::{
        admin::{
            call_context::extract_call_context, model::Resource, params::extract_ulid_param,
            response::SingleResponse,
        },
        common::DepotExt,
    },
    services::risk_action_state::RiskActionStateService,
};

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRiskActionProposalResponse {
    /// Stable persisted state-record identifier for this risk-action state machine.
    state_record_id: String,

    /// Proposal identifier for tracking and later approval.
    proposal_id: String,

    /// Account targeted by the proposal.
    account_id: String,

    /// Requested action.
    action: String,

    /// Human reason supplied by the caller.
    reason: Option<String>,

    /// Optional ticket or incident reference.
    ticket: Option<String>,

    /// Optional approver identifier.
    approved_by: Option<String>,

    /// When the proposal was requested.
    requested_at: DateTime<Utc>,

    /// Admin identifier that submitted the proposal scaffold, if available.
    requested_by: Option<String>,

    /// Admin username that submitted the proposal scaffold, if available.
    requested_by_username: Option<String>,

    /// Previous lifecycle state before this transition.
    previous_state: String,

    /// Proposal state reported by the scaffold contract.
    proposal_state: String,

    /// Monotonic state-machine revision.
    state_revision: u64,

    /// Explicit transition kind written by this scaffold.
    transition_kind: String,

    /// Approval mode expected before executing the real mutation endpoint.
    approval_mode: String,

    /// Allowed next transitions from this proposal state.
    allowed_next_transitions: Vec<String>,

    /// Final execution endpoint that would perform the mutation after approval.
    execution_endpoint: String,

    /// How this scaffold persists the state machine today.
    state_store_kind: String,

    /// Remaining implementation work for this scaffold.
    todo: String,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRiskActionApprovalResponse {
    /// Stable persisted state-record identifier for this risk-action state machine.
    state_record_id: String,

    /// Proposal identifier being approved.
    proposal_id: String,

    /// Account targeted by the proposal.
    account_id: String,

    /// Approved action.
    action: String,

    /// Optional ticket or incident reference.
    ticket: Option<String>,

    /// Previous lifecycle state before this transition.
    previous_state: String,

    /// Approval state reported by the scaffold contract.
    approval_state: String,

    /// Monotonic state-machine revision.
    state_revision: u64,

    /// Explicit transition kind written by this scaffold.
    transition_kind: String,

    /// When the approval was recorded.
    approved_at: DateTime<Utc>,

    /// Admin identifier that approved the proposal, if available.
    approved_by: Option<String>,

    /// Admin username that approved the proposal, if available.
    approved_by_username: Option<String>,

    /// Human approval note for the scaffold trail.
    approval_note: Option<String>,

    /// Final execution endpoint that would perform the mutation after approval.
    execution_endpoint: String,

    /// Allowed next transitions from this approved state.
    allowed_next_transitions: Vec<String>,

    /// How this scaffold persists the state machine today.
    state_store_kind: String,

    /// Remaining implementation work for this scaffold.
    todo: String,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRiskActionExecuteResponse {
    /// Stable persisted state-record identifier for this risk-action state machine.
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

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRiskActionCurrentResponse {
    /// Account targeted by the current risk-action state machine.
    account_id: String,

    /// Stable persisted state-record identifier, if any.
    state_record_id: Option<String>,

    /// Latest proposal identifier, if any.
    proposal_id: Option<String>,

    /// Latest recorded action, if any.
    action: Option<String>,

    /// Current lifecycle state derived from the latest scaffold record.
    lifecycle_state: String,

    /// Latest recorded operation name, if any.
    last_operation: Option<String>,

    /// Explicit transition kind on the current record, if any.
    transition_kind: Option<String>,

    /// Previous lifecycle state before the current transition, if any.
    previous_state: Option<String>,

    /// Monotonic state-machine revision, if any.
    state_revision: Option<u64>,

    /// Allowed next transitions from the current lifecycle state.
    allowed_next_transitions: Vec<String>,

    /// Optional ticket or incident reference.
    ticket: Option<String>,

    /// When the current state record was written.
    recorded_at: Option<DateTime<Utc>>,

    /// Admin identifier associated with the latest state record.
    recorded_by: Option<String>,

    /// Admin username associated with the latest state record.
    recorded_by_username: Option<String>,

    /// Execution endpoint referenced by the latest proposal/approval state.
    execution_endpoint: Option<String>,

    /// Mutation endpoint referenced by the latest execute state.
    mutation_endpoint: Option<String>,

    /// How this scaffold persists the state machine today.
    state_store_kind: String,

    /// Remaining implementation work for this scaffold state.
    todo: Option<String>,
}

impl Resource for AccountRiskActionCurrentResponse {
    const KIND: &'static str = "account-risk-action-current";
    const PATH: &'static str = "/api/admin/v1/accounts";

    fn id(&self) -> Ulid {
        self.account_id
            .parse()
            .expect("account risk-action current response stores a valid Ulid")
    }

    fn path(&self) -> String {
        format!(
            "/api/admin/v1/accounts/{}/risk-action/current",
            self.account_id
        )
    }
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRiskActionHistoryResponse {
    data: Vec<AccountRiskActionTransitionRecord>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRiskActionTransitionRecord {
    /// Account targeted by the persisted transition record.
    account_id: String,

    /// Stable persisted state-record identifier.
    state_record_id: Option<String>,

    /// Proposal identifier associated with the state machine, if any.
    proposal_id: Option<String>,

    /// Action tracked by the state machine, if any.
    action: Option<String>,

    /// Explicit transition kind recorded for this transition.
    transition_kind: String,

    /// Previous lifecycle state before this transition, if any.
    previous_state: Option<String>,

    /// Lifecycle state after this transition.
    next_state: String,

    /// Monotonic state-machine revision, if any.
    state_revision: Option<u64>,

    /// Optional ticket or incident reference.
    ticket: Option<String>,

    /// When the transition record was written.
    recorded_at: DateTime<Utc>,

    /// Admin identifier associated with the transition.
    recorded_by: Option<String>,

    /// Admin username associated with the transition.
    recorded_by_username: Option<String>,

    /// Execution endpoint referenced by this transition, if any.
    execution_endpoint: Option<String>,

    /// Mutation endpoint referenced by this transition, if any.
    mutation_endpoint: Option<String>,

    /// Approval note captured by this transition, if any.
    approval_note: Option<String>,

    /// Execution note captured by this transition, if any.
    execution_note: Option<String>,

    /// How this scaffold persists the state machine today.
    state_store_kind: String,

    /// Remaining implementation work captured on this transition, if any.
    todo: Option<String>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AdminBridgeRiskActionExamples {
    /// Example payload for POST /risk-action
    proposal_request: AdminBridgeRiskActionProposalExample,

    /// Example payload for POST /risk-action/{proposal_id}/approve
    approve_request: AdminBridgeRiskActionApprovalExample,

    /// Example payload for POST /risk-action/{proposal_id}/execute
    execute_request: AdminBridgeRiskActionExecuteExample,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AdminBridgeRiskActionProposalExample {
    action: &'static str,
    reason: &'static str,
    ticket: &'static str,
    approved_by: Option<&'static str>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AdminBridgeRiskActionApprovalExample {
    action: &'static str,
    ticket: &'static str,
    approved_by: &'static str,
    approval_note: &'static str,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AdminBridgeRiskActionExecuteExample {
    action: &'static str,
    ticket: &'static str,
    execution_note: &'static str,
}

struct AccountRiskActionMutation {
    patch: AdminUserPatch,
    hs_erase: bool,
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
            hs_erase: false,
            mutation_kind: "account_locked",
            mutation_description: "account locked through services.user_admin",
        }),
        "disable" => Ok(AccountRiskActionMutation {
            patch: AdminUserPatch {
                deactivated: Some(true),
                ..AdminUserPatch::default()
            },
            hs_erase: false,
            mutation_kind: "account_disabled",
            mutation_description: "account disabled through services.user_admin",
        }),
        "erase" => Ok(AccountRiskActionMutation {
            patch: AdminUserPatch {
                deactivated: Some(true),
                ..AdminUserPatch::default()
            },
            hs_erase: true,
            mutation_kind: "account_erasure_scheduled",
            mutation_description: "account disabled and homeserver erasure job scheduled through services.user_admin",
        }),
        "reset_recovery" => Ok(AccountRiskActionMutation {
            patch: AdminUserPatch {
                locked: Some(true),
                ..AdminUserPatch::default()
            },
            hs_erase: false,
            mutation_kind: "account_locked_pending_recovery_reset",
            mutation_description: "account locked pending dedicated recovery reset workflow",
        }),
        other => Err(AppError::bad_request(format!(
            "Unknown account risk action: {other}"
        ))),
    }
}

pub(super) fn admin_bridge_risk_action_examples() -> AdminBridgeRiskActionExamples {
    AdminBridgeRiskActionExamples {
        proposal_request: AdminBridgeRiskActionProposalExample {
            action: "lock",
            reason: "suspicious session recovery detected",
            ticket: "INC-2026-0504",
            approved_by: None,
        },
        approve_request: AdminBridgeRiskActionApprovalExample {
            action: "lock",
            ticket: "INC-2026-0504",
            approved_by: "did:web:admin.example",
            approval_note: "approved for controlled execution",
        },
        execute_request: AdminBridgeRiskActionExecuteExample {
            action: "lock",
            ticket: "INC-2026-0504",
            execution_note: "execute via controlled mutation worker",
        },
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

    let risk_action_state = depot.risk_action_state_service()?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = extract_call_context(req, depot).await?;
    let requested_at = clock.now();
    let requested_by = admin_user.as_ref().map(|user| user.id.to_string());
    let requested_by_username = admin_user.as_ref().map(|user| user.username.clone());
    let id = extract_ulid_param(req)?;
    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let proposal_id = Ulid::new().to_string();
    let state_record_id = risk_action_state.record_id(account.id, &proposal_id);
    let execution_endpoint = risk_action_state.execution_endpoint(&params.action, account.id)?;
    let allowed_next_transitions = risk_action_state.allowed_next_transitions("draft");
    let state_store_kind = risk_action_state.state_store_kind();
    let todo = "TODO(contrix): persist proposal records in a dedicated state store, capture requester/approver context, require explicit approval, then route approved proposals into the dedicated /lock, /disable, /erase, or /reset-recovery mutation endpoints.".to_owned();

    if let Some(admin_user) = &admin_user {
        let mut rng = crate::handlers::account::make_rng();
        repo.audit()
            .add_admin_operation(
                &mut rng,
                &clock,
                NewAdminOperationLog::new(
                    admin_user.id,
                    AdminOperation::Other(format!("account_{}_proposal", params.action).into()),
                    "account",
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
                        "requested_by_username": requested_by_username,
                        "execution_endpoint": execution_endpoint,
                        "allowed_next_transitions": allowed_next_transitions.clone(),
                        "todo": todo,
                    }),
                )
                .with_resource_id(account.id),
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
        requested_at,
        requested_by,
        requested_by_username,
        previous_state: "idle".to_owned(),
        proposal_state: "draft".to_owned(),
        state_revision: 1,
        transition_kind: "proposal_requested".to_owned(),
        approval_mode: "proposal_scaffold_required".to_owned(),
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

    let risk_action_state = depot.risk_action_state_service()?;
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
    let account = repo
        .user()
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
    let approved = logs.iter().any(|log| {
        is_account_risk_action_log(log, account.id)
            && risk_action_detail_string(&log.details, "proposal_id").as_deref()
                == Some(proposal_id.as_str())
            && risk_action_detail_string(&log.details, "action").as_deref()
                == Some(params.action.as_str())
            && risk_action_detail_string(&log.details, "next_state").as_deref() == Some("approved")
    });
    if !approved {
        return Err(AppError::bad_request(
            "risk action proposal must be approved before execution",
        ));
    }
    let state_record_id = risk_action_state.record_id(account.id, &proposal_id);
    let execution_endpoint = risk_action_state.execution_endpoint(&params.action, account.id)?;
    let allowed_next_transitions = risk_action_state.allowed_next_transitions("approved");
    let state_store_kind = risk_action_state.state_store_kind();
    let todo = "TODO(contrix): replace approval scaffold with a persisted proposal state store, authorization checks, and a controlled execute step that consumes approved proposals.".to_owned();

    if let Some(admin_user) = &admin_user {
        let mut rng = crate::handlers::account::make_rng();
        repo.audit()
            .add_admin_operation(
                &mut rng,
                &clock,
                NewAdminOperationLog::new(
                    admin_user.id,
                    AdminOperation::Other(
                        format!("account_{}_proposal_approved", params.action).into(),
                    ),
                    "account",
                    serde_json::json!({
                        "state_record_id": state_record_id,
                        "state_store_kind": state_store_kind,
                        "state_revision": 2_u64,
                        "proposal_id": proposal_id,
                        "action": params.action,
                        "transition_kind": "proposal_approved",
                        "previous_state": "draft",
                        "next_state": "approved",
                        "ticket": params.ticket,
                        "approved_by": params.approved_by,
                        "approved_by_username": admin_user.username,
                        "approval_note": params.approval_note,
                        "execution_endpoint": execution_endpoint,
                        "allowed_next_transitions": allowed_next_transitions.clone(),
                        "todo": todo,
                    }),
                )
                .with_resource_id(account.id),
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
        previous_state: "draft".to_owned(),
        approval_state: "approved_scaffold".to_owned(),
        state_revision: 2,
        transition_kind: "proposal_approved".to_owned(),
        approved_at,
        approved_by: params
            .approved_by
            .or_else(|| admin_user.as_ref().map(|user| user.id.to_string())),
        approved_by_username: admin_user.as_ref().map(|user| user.username.clone()),
        approval_note: params.approval_note,
        execution_endpoint,
        allowed_next_transitions,
        state_store_kind: state_store_kind.to_owned(),
        todo,
    }))
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
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = extract_call_context(req, depot).await?;
    let contrix_config = depot.contrix_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let homeserver = depot.homeserver()?;
    let executed_at = clock.now();
    let id = extract_ulid_param(req)?;
    let proposal_id = req
        .param::<String>("proposal_id")
        .ok_or_else(|| AppError::bad_request("missing proposal_id"))?;
    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let state_record_id = risk_action_state.record_id(account.id, &proposal_id);
    let mutation_endpoint = risk_action_state.execution_endpoint(&params.action, account.id)?;
    let allowed_next_transitions = risk_action_state.allowed_next_transitions("mutation_recorded");
    let state_store_kind = risk_action_state.state_store_kind();
    let todo = "TODO(contrix): replace audit-derived approval validation with durable proposal records and enforce proposal_id consumption before mutation.".to_owned();
    let mut rng = crate::handlers::account::make_rng();
    let updated_account = crate::services::user_admin::patch_user(
        &mut repo,
        &mut rng,
        &*clock,
        homeserver.as_ref(),
        admin_user.as_ref(),
        account.id,
        mutation.patch,
        mutation.hs_erase,
    )
    .await
    .map_err(super::map_service_error)?;

    if let Some(admin_user) = &admin_user {
        repo.audit()
            .add_admin_operation(
                &mut rng,
                &clock,
                NewAdminOperationLog::new(
                    admin_user.id,
                    AdminOperation::Other(
                        format!("account_{}_proposal_executed", params.action).into(),
                    ),
                    "account",
                    serde_json::json!({
                        "state_record_id": state_record_id,
                        "state_store_kind": state_store_kind,
                        "state_revision": 3_u64,
                        "proposal_id": proposal_id,
                        "action": params.action,
                        "transition_kind": "proposal_executed",
                        "previous_state": "approved",
                        "next_state": "mutation_recorded",
                        "mutation_kind": mutation.mutation_kind,
                        "mutation_description": mutation.mutation_description,
                        "hs_erase": mutation.hs_erase,
                        "ticket": params.ticket,
                        "executed_by": admin_user.id,
                        "executed_by_username": admin_user.username,
                        "execution_note": params.execution_note,
                        "mutation_endpoint": mutation_endpoint,
                        "allowed_next_transitions": allowed_next_transitions.clone(),
                        "todo": todo,
                    }),
                )
                .with_resource_id(account.id),
            )
            .await?;
    }
    repo.save().await?;

    let account_response = SingleResponse::new_canonical(super::AccountRecord::from_user(
        updated_account,
        &contrix_config,
        did_resolver.as_ref(),
    ));

    Ok(Json(AccountRiskActionExecuteResponse {
        state_record_id,
        proposal_id,
        account_id: account.id.to_string(),
        action: params.action,
        ticket: params.ticket,
        previous_state: "approved".to_owned(),
        execution_state: "mutation_recorded".to_owned(),
        mutation_kind: mutation.mutation_kind.to_owned(),
        state_revision: 3,
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
        .filter(|log| is_account_risk_action_log(log, id))
        .next()
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
            recorded_by_username: risk_action_detail_string(&log.details, "requested_by_username")
                .or_else(|| risk_action_detail_string(&log.details, "approved_by_username"))
                .or_else(|| risk_action_detail_string(&log.details, "executed_by_username")),
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
            recorded_by_username: None,
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
        recorded_at: log.created_at,
        recorded_by: risk_action_detail_string(&log.details, "requested_by")
            .or_else(|| risk_action_detail_string(&log.details, "approved_by"))
            .or_else(|| risk_action_detail_string(&log.details, "executed_by")),
        recorded_by_username: risk_action_detail_string(&log.details, "requested_by_username")
            .or_else(|| risk_action_detail_string(&log.details, "approved_by_username"))
            .or_else(|| risk_action_detail_string(&log.details, "executed_by_username")),
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
