//! Contrix account administration endpoints.

use chrono::{DateTime, Utc};
use coauth_data::audit::{AdminOperation, NewAdminOperationLog};
use coauth_data::{AdminUserPatch, RepositoryAccess, user::UserFilter};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    AppError, JsonResult,
    handlers::admin::v1::account_dids::{
        AccountDidBindingPreview, preview_bindings_for_user, primary_did_for_user,
    },
    handlers::{
        admin::{
            call_context::extract_call_context,
            model::Resource,
            params::{IncludeCount, extract_pagination, extract_ulid_param},
            response::{PaginatedResponse, SingleResponse},
        },
        common::DepotExt,
    },
};

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Active,
    Locked,
    Disabled,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Locked => f.write_str("locked"),
            Self::Disabled => f.write_str("disabled"),
        }
    }
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AccountRiskActionProposalRequest")]
pub struct AccountRiskActionProposalRequest {
    /// Risk action to stage for approval: `lock`, `disable`, `erase`, or
    /// `reset_recovery`.
    action: String,

    /// Human reason for the requested action.
    reason: Option<String>,

    /// Optional ticket or incident reference.
    ticket: Option<String>,

    /// Optional approver identifier. Leave empty while the request is still a
    /// draft proposal.
    approved_by: Option<String>,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AccountRiskActionApprovalRequest")]
pub struct AccountRiskActionApprovalRequest {
    /// Risk action being approved.
    action: String,

    /// Optional ticket or incident reference.
    ticket: Option<String>,

    /// Optional approver identifier override.
    approved_by: Option<String>,

    /// Human approval note for the scaffold audit trail.
    approval_note: Option<String>,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AccountRiskActionExecuteRequest")]
pub struct AccountRiskActionExecuteRequest {
    /// Risk action being executed.
    action: String,

    /// Optional ticket or incident reference.
    ticket: Option<String>,

    /// Human execution note for the scaffold trail.
    execution_note: Option<String>,
}

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

    /// Final mutation endpoint that still has to be called by the controlled execute path.
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

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRiskActionHistoryResponse {
    data: Vec<AccountRiskActionTransitionRecord>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AdminBridgeDescribeResponse {
    /// Scaffold contract identifier for coauth admin integration discovery.
    contract: &'static str,

    /// Scaffold contract version.
    version: &'static str,

    /// Base path for this admin REST surface.
    api_base_path: &'static str,

    /// Collection path for account administration.
    accounts_path: &'static str,

    /// Template path for one account.
    account_detail_path_template: &'static str,

    /// Template path for DID binding inventory.
    account_dids_path_template: &'static str,

    /// Template path for staging a risk action proposal.
    risk_action_path_template: &'static str,

    /// Template path for current risk-action state.
    risk_action_current_path_template: &'static str,

    /// Template path for risk-action transition history.
    risk_action_history_path_template: &'static str,

    /// Template path for approving a proposal.
    risk_action_approve_path_template: &'static str,

    /// Template path for executing an approved proposal.
    risk_action_execute_path_template: &'static str,

    /// How the current scaffold persists risk-action state.
    risk_action_state_store_kind: &'static str,

    /// Approval mode exposed by the current scaffold.
    risk_action_approval_mode: &'static str,

    /// Remaining scaffold tasks.
    todos: Vec<&'static str>,
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
pub struct AccountRecord {
    #[serde(skip)]
    id: Ulid,

    /// Stable account handle/localpart.
    username: String,

    /// Contrix account lifecycle state.
    status: AccountStatus,

    /// When the account was created.
    created_at: DateTime<Utc>,

    /// When the account was last updated.
    updated_at: DateTime<Utc>,

    /// When the account was locked, if applicable.
    locked_at: Option<DateTime<Utc>>,

    /// When the account was disabled, if applicable.
    disabled_at: Option<DateTime<Utc>>,

    /// Whether the account can request coauth admin privileges.
    admin: bool,

    /// Human-facing display name.
    display_name: Option<String>,

    /// Optional avatar URL.
    avatar_url: Option<String>,

    /// Preferred locale for account-facing UX.
    preferred_locale: Option<String>,

    /// Primary principal DID once DID binding storage is available.
    primary_principal_did: Option<String>,

    /// Bound principal DIDs. Empty until the DID binding model lands.
    principal_dids: Vec<String>,

    /// Richer placeholder contract for the primary DID binding.
    primary_principal_binding: Option<AccountDidBindingPreview>,

    /// Richer placeholder contract for downstream admin/OpenAPI integrations.
    principal_did_bindings: Vec<AccountDidBindingPreview>,
}

impl From<coauth_data::User> for AccountRecord {
    fn from(user: coauth_data::User) -> Self {
        Self::from_user(user, &coauth_config::ContrixConfig::default())
    }
}

impl AccountRecord {
    fn from_user(user: coauth_data::User, contrix_config: &coauth_config::ContrixConfig) -> Self {
        let status = if user.deactivated_at.is_some() {
            AccountStatus::Disabled
        } else if user.locked_at.is_some() {
            AccountStatus::Locked
        } else {
            AccountStatus::Active
        };
        let principal_did_bindings = preview_bindings_for_user(&user, contrix_config);
        let primary_principal_binding = principal_did_bindings
            .iter()
            .find(|binding| binding.primary)
            .cloned();
        let principal_dids = principal_did_bindings
            .iter()
            .map(|binding| binding.did.clone())
            .collect();

        Self {
            id: user.id,
            username: user.username,
            status,
            created_at: user.created_at,
            updated_at: user.updated_at,
            locked_at: user.locked_at,
            disabled_at: user.deactivated_at,
            admin: user.can_request_admin,
            display_name: user.display_name,
            avatar_url: user.avatar_url,
            preferred_locale: user.preferred_locale,
            primary_principal_did: Some(primary_did_for_user(&user)),
            principal_dids,
            primary_principal_binding,
            principal_did_bindings,
        }
    }
}

impl Resource for AccountRecord {
    const KIND: &'static str = "account";
    const PATH: &'static str = "/api/admin/v1/accounts";

    fn id(&self) -> Ulid {
        self.id
    }
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum AccountFilterStatus {
    Active,
    Locked,
    Disabled,
}

impl std::fmt::Display for AccountFilterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Locked => f.write_str("locked"),
            Self::Disabled => f.write_str("disabled"),
        }
    }
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "AccountFilter")]
pub struct AccountFilterParams {
    /// Retrieve accounts with or without the admin flag set.
    #[serde(rename = "filter[admin]")]
    admin: Option<bool>,

    /// Retrieve accounts where the username contains the given string.
    #[serde(rename = "filter[search]")]
    search: Option<String>,

    /// Retrieve accounts by lifecycle state.
    #[serde(rename = "filter[status]")]
    status: Option<AccountFilterStatus>,
}

impl std::fmt::Display for AccountFilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(admin) = self.admin {
            write!(f, "{sep}filter[admin]={admin}")?;
            sep = '&';
        }
        if let Some(search) = &self.search {
            write!(f, "{sep}filter[search]={search}")?;
            sep = '&';
        }
        if let Some(status) = self.status {
            write!(f, "{sep}filter[status]={status}")?;
        }

        Ok(())
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.list", skip_all)]
pub async fn list_accounts(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<AccountRecord>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let contrix_config = depot.contrix_config()?;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: AccountFilterParams = req.parse_queries().unwrap_or_default();

    let base = format!("{path}{params}", path = AccountRecord::PATH);
    let base = include_count.add_to_base(&base);
    let mut filter = UserFilter::default();

    filter = match params.admin {
        Some(true) => filter.can_request_admin_only(),
        Some(false) => filter.cannot_request_admin_only(),
        None => filter,
    };
    filter = match params.search.as_deref() {
        Some(search) => filter.matching_search(search),
        None => filter,
    };
    filter = match params.status {
        Some(AccountFilterStatus::Active) => filter.active_only(),
        Some(AccountFilterStatus::Locked) => filter.locked_only(),
        Some(AccountFilterStatus::Disabled) => filter.deactivated_only(),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo.user().list(filter, pagination).await?;
            let count = repo.user().count(filter).await?;
            PaginatedResponse::for_page(
                page.map(|user| AccountRecord::from_user(user, &contrix_config)),
                pagination,
                Some(count),
                &base,
            )
        }
        IncludeCount::False => {
            let page = repo.user().list(filter, pagination).await?;
            PaginatedResponse::for_page(
                page.map(|user| AccountRecord::from_user(user, &contrix_config)),
                pagination,
                None,
                &base,
            )
        }
        IncludeCount::Only => {
            let count = repo.user().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.bridge.describe", skip_all)]
pub async fn admin_bridge_describe() -> JsonResult<AdminBridgeDescribeResponse> {
    Ok(Json(AdminBridgeDescribeResponse {
        contract: "contrix.rest.coauth_admin_bridge.v1",
        version: "2026-05-04-scaffold",
        api_base_path: "/api/admin/v1",
        accounts_path: "/api/admin/v1/accounts",
        account_detail_path_template: "/api/admin/v1/accounts/{account_id}",
        account_dids_path_template: "/api/admin/v1/accounts/{account_id}/dids",
        risk_action_path_template: "/api/admin/v1/accounts/{account_id}/risk-action",
        risk_action_current_path_template: "/api/admin/v1/accounts/{account_id}/risk-action/current",
        risk_action_history_path_template: "/api/admin/v1/accounts/{account_id}/risk-action/history",
        risk_action_approve_path_template:
            "/api/admin/v1/accounts/{account_id}/risk-action/{proposal_id}/approve",
        risk_action_execute_path_template:
            "/api/admin/v1/accounts/{account_id}/risk-action/{proposal_id}/execute",
        risk_action_state_store_kind: RISK_ACTION_STATE_STORE_KIND,
        risk_action_approval_mode: "state_machine_scaffold_required",
        todos: vec![
            "TODO: replace audit-backed scaffold transitions with dedicated persisted proposal records",
            "TODO: add controlled executor workers for lock, disable, erase, and reset-recovery mutations",
            "TODO: publish formal OpenAPI examples for admin bridge discovery and risk-action workflows",
        ],
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.get", skip_all)]
pub async fn get_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<AccountRecord>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let contrix_config = depot.contrix_config()?;
    let id = extract_ulid_param(req)?;

    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    Ok(Json(SingleResponse::new_canonical(AccountRecord::from_user(
        account,
        &contrix_config,
    ))))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.risk_action", skip_all)]
pub async fn risk_action(
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
    let state_record_id = risk_action_record_id(account.id, &proposal_id);
    let execution_endpoint = risk_action_execution_endpoint(&params.action, account.id)?;
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
                        "state_store_kind": RISK_ACTION_STATE_STORE_KIND,
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
                        "allowed_next_transitions": risk_action_allowed_next_transitions("draft"),
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
        allowed_next_transitions: risk_action_allowed_next_transitions("draft"),
        execution_endpoint,
        state_store_kind: RISK_ACTION_STATE_STORE_KIND.to_owned(),
        todo,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.approve_risk_action", skip_all)]
pub async fn approve_risk_action(
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
    let state_record_id = risk_action_record_id(account.id, &proposal_id);
    let execution_endpoint = risk_action_execution_endpoint(&params.action, account.id)?;
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
                        "state_store_kind": RISK_ACTION_STATE_STORE_KIND,
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
                        "allowed_next_transitions": risk_action_allowed_next_transitions("approved"),
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
        allowed_next_transitions: risk_action_allowed_next_transitions("approved"),
        state_store_kind: RISK_ACTION_STATE_STORE_KIND.to_owned(),
        todo,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.execute_risk_action", skip_all)]
pub async fn execute_risk_action(
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
            "risk action execute scaffold requires a non-empty execution_note",
        ));
    }

    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = extract_call_context(req, depot).await?;
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
    let state_record_id = risk_action_record_id(account.id, &proposal_id);
    let mutation_endpoint = risk_action_execution_endpoint(&params.action, account.id)?;
    let todo = "TODO(contrix): replace execute scaffold with a persisted proposal executor that validates approval state, performs the mutation, and records outcome + rollback metadata.".to_owned();

    if let Some(admin_user) = &admin_user {
        let mut rng = crate::handlers::account::make_rng();
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
                        "state_store_kind": RISK_ACTION_STATE_STORE_KIND,
                        "state_revision": 3_u64,
                        "proposal_id": proposal_id,
                        "action": params.action,
                        "transition_kind": "proposal_executed",
                        "previous_state": "approved",
                        "next_state": "executed_pending_mutation",
                        "ticket": params.ticket,
                        "execution_note": params.execution_note,
                        "mutation_endpoint": mutation_endpoint,
                        "allowed_next_transitions": risk_action_allowed_next_transitions("executed_pending_mutation"),
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

    Ok(Json(AccountRiskActionExecuteResponse {
        state_record_id,
        proposal_id,
        account_id: account.id.to_string(),
        action: params.action,
        ticket: params.ticket,
        previous_state: "approved".to_owned(),
        execution_state: "execute_scaffold_recorded".to_owned(),
        state_revision: 3,
        transition_kind: "proposal_executed".to_owned(),
        executed_at,
        execution_mode: "manual_mutation_endpoint_required".to_owned(),
        execution_note: params.execution_note,
        mutation_endpoint,
        allowed_next_transitions: risk_action_allowed_next_transitions("executed_pending_mutation"),
        state_store_kind: RISK_ACTION_STATE_STORE_KIND.to_owned(),
        todo,
    }))
}

#[endpoint]
#[tracing::instrument(
    name = "handler.admin.v1.accounts.list_risk_action_history",
    skip_all
)]
pub async fn list_risk_action_history(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountRiskActionHistoryResponse> {
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
        .map(|log| risk_action_transition_record(id, &log))
        .collect();

    Ok(Json(AccountRiskActionHistoryResponse { data }))
}

#[endpoint]
#[tracing::instrument(
    name = "handler.admin.v1.accounts.get_risk_action_current",
    skip_all
)]
pub async fn get_risk_action_current(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<AccountRiskActionCurrentResponse>> {
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
                .or_else(|| risk_action_detail_string(&log.details, "approved_by")),
            recorded_by_username: risk_action_detail_string(&log.details, "requested_by_username")
                .or_else(|| risk_action_detail_string(&log.details, "approved_by_username")),
            execution_endpoint: risk_action_detail_string(&log.details, "execution_endpoint"),
            mutation_endpoint: risk_action_detail_string(&log.details, "mutation_endpoint"),
            state_store_kind: risk_action_detail_string(&log.details, "state_store_kind")
                .unwrap_or_else(|| RISK_ACTION_STATE_STORE_KIND.to_owned()),
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
            allowed_next_transitions: vec!["proposal_requested".to_owned()],
            ticket: None,
            recorded_at: None,
            recorded_by: None,
            recorded_by_username: None,
            execution_endpoint: None,
            mutation_endpoint: None,
            state_store_kind: RISK_ACTION_STATE_STORE_KIND.to_owned(),
            todo: Some(
                "No risk-action state-machine record has been persisted for this account yet.".to_owned(),
            ),
        });

    Ok(Json(SingleResponse::new_canonical(current)))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.lock", skip_all)]
pub async fn lock_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<AccountRecord>> {
    patch_account(
        req,
        depot,
        AdminUserPatch {
            locked: Some(true),
            ..AdminUserPatch::default()
        },
        false,
    )
    .await
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.disable", skip_all)]
pub async fn disable_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<AccountRecord>> {
    patch_account(
        req,
        depot,
        AdminUserPatch {
            deactivated: Some(true),
            ..AdminUserPatch::default()
        },
        false,
    )
    .await
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.erase", skip_all)]
pub async fn erase_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<AccountRecord>> {
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): implement account erasure semantics that scrub admin,
    // search, and profile views before exposing this mutation.
    Err(AppError::not_implemented(
        "account erasure workflow is not implemented yet",
    ))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.reset_recovery", skip_all)]
pub async fn reset_recovery(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<AccountRecord>> {
    let ctx = extract_call_context(req, depot).await?;
    ctx.repo.cancel().await?;
    // TODO(contrix): create recovery workflow records and approval/audit hooks.
    Err(AppError::not_implemented(
        "account recovery reset workflow is not implemented yet",
    ))
}

async fn patch_account(
    req: &mut Request,
    depot: &Depot,
    patch: AdminUserPatch,
    hs_erase: bool,
) -> JsonResult<SingleResponse<AccountRecord>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let contrix_config = depot.contrix_config()?;
    let id = extract_ulid_param(req)?;
    let homeserver = depot.homeserver()?;
    let mut rng = crate::handlers::account::make_rng();

    // TODO(contrix): require and persist reason/approval proof for high-risk
    // account mutations once the audit schema includes request context.
    let account = crate::services::user_admin::patch_user(
        &mut repo,
        &mut rng,
        &*clock,
        homeserver.as_ref(),
        admin_user.as_ref(),
        id,
        patch,
        hs_erase,
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(AccountRecord::from_user(
        account,
        &contrix_config,
    ))))
}

fn map_service_error(error: crate::services::user_admin::UserAdminServiceError) -> AppError {
    match error {
        crate::services::user_admin::UserAdminServiceError::UserNotFound(id) => {
            AppError::not_found(format!("Account ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::InvalidDisplayName => {
            AppError::bad_request("Invalid display name")
        }
        crate::services::user_admin::UserAdminServiceError::Homeserver(error) => {
            AppError::internal(std::io::Error::other(error.to_string()))
        }
        crate::services::user_admin::UserAdminServiceError::Repository(error) => {
            AppError::internal(error)
        }
        other => AppError::bad_request(other.to_string()),
    }
}

fn risk_action_execution_endpoint(action: &str, id: Ulid) -> Result<String, AppError> {
    let action_path = match action {
        "lock" => "lock",
        "disable" => "disable",
        "erase" => "erase",
        "reset_recovery" => "reset-recovery",
        other => {
            return Err(AppError::bad_request(format!(
                "Unknown account risk action: {other}"
            )));
        }
    };

    Ok(format!("/api/admin/v1/accounts/{id}/{action_path}"))
}

const RISK_ACTION_STATE_STORE_KIND: &str = "admin_audit_persisted_state_machine_scaffold";

fn risk_action_record_id(account_id: Ulid, proposal_id: &str) -> String {
    format!("risk-action:{account_id}:{proposal_id}")
}

fn risk_action_allowed_next_transitions(state: &str) -> Vec<String> {
    match state {
        "draft" => vec![
            "proposal_approved".to_owned(),
            "proposal_replaced".to_owned(),
            "proposal_cancelled".to_owned(),
        ],
        "approved" => vec![
            "proposal_executed".to_owned(),
            "proposal_rejected".to_owned(),
            "proposal_cancelled".to_owned(),
        ],
        "executed_pending_mutation" => vec![
            "mutation_recorded".to_owned(),
            "mutation_failed".to_owned(),
            "rollback_requested".to_owned(),
        ],
        _ => vec!["proposal_requested".to_owned()],
    }
}

fn is_account_risk_action_log(log: &coauth_data::audit::AdminOperationLog, account_id: Ulid) -> bool {
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
            .or_else(|| risk_action_detail_string(&log.details, "approved_by")),
        recorded_by_username: risk_action_detail_string(&log.details, "requested_by_username")
            .or_else(|| risk_action_detail_string(&log.details, "approved_by_username")),
        execution_endpoint: risk_action_detail_string(&log.details, "execution_endpoint"),
        mutation_endpoint: risk_action_detail_string(&log.details, "mutation_endpoint"),
        approval_note: risk_action_detail_string(&log.details, "approval_note"),
        execution_note: risk_action_detail_string(&log.details, "execution_note"),
        state_store_kind: risk_action_detail_string(&log.details, "state_store_kind")
            .unwrap_or_else(|| RISK_ACTION_STATE_STORE_KIND.to_owned()),
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

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};
    use coauth_data::RepositoryAccess;

    #[tokio::test]
    async fn test_list_and_get_accounts() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let response = state
            .request(
                Request::get("/api/admin/v1/accounts")
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 1);
        assert_eq!(body["data"][0]["type"], "account");
        assert_eq!(body["data"][0]["id"], user.id.to_string());
        assert_eq!(body["data"][0]["attributes"]["username"], "alice");
        assert_eq!(body["data"][0]["attributes"]["status"], "active");
        assert_eq!(
            body["data"][0]["attributes"]["primary_principal_did"],
            serde_json::Value::Null
        );
        assert_eq!(
            body["data"][0]["attributes"]["principal_dids"],
            serde_json::json!([])
        );

        let response = state
            .request(
                Request::get(format!("/api/admin/v1/accounts/{}", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "account");
        assert_eq!(body["data"]["id"], user.id.to_string());
        assert_eq!(body["data"]["attributes"]["username"], "alice");
        assert_eq!(body["data"]["attributes"]["status"], "active");
    }

    #[tokio::test]
    async fn test_lock_and_disable_account() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let response = state
            .request(
                Request::post(format!("/api/admin/v1/accounts/{}/lock", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["attributes"]["status"], "locked");
        assert!(body["data"]["attributes"]["locked_at"].is_string());
        assert_eq!(
            body["data"]["attributes"]["disabled_at"],
            serde_json::Value::Null
        );

        let response = state
            .request(
                Request::post(format!("/api/admin/v1/accounts/{}/disable", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["attributes"]["status"], "disabled");
        assert!(body["data"]["attributes"]["locked_at"].is_string());
        assert!(body["data"]["attributes"]["disabled_at"].is_string());
    }

    #[tokio::test]
    async fn test_account_dids_contract_is_stubbed_with_not_implemented() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let response = state
            .request(
                Request::get(format!("/api/admin/v1/accounts/{}/dids", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::NOT_IMPLEMENTED);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "account DID binding list is not implemented yet"
        );
    }
}
