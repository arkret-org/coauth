//! Contrix account administration endpoints.

use chrono::{DateTime, Utc};
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

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRiskActionProposalResponse {
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

    /// Proposal state reported by the scaffold contract.
    proposal_state: String,

    /// Approval mode expected before executing the real mutation endpoint.
    approval_mode: String,

    /// Final execution endpoint that would perform the mutation after approval.
    execution_endpoint: String,

    /// Remaining implementation work for this scaffold.
    todo: String,
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

    let ctx = extract_call_context(req, depot).await?;
    let id = extract_ulid_param(req)?;
    let account = ctx
        .repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    ctx.repo.cancel().await?;

    let execution_endpoint = risk_action_execution_endpoint(&params.action, account.id)?;

    Ok(Json(AccountRiskActionProposalResponse {
        account_id: account.id.to_string(),
        action: params.action,
        reason: params.reason,
        ticket: params.ticket,
        approved_by: params.approved_by,
        proposal_state: "draft".to_owned(),
        approval_mode: "proposal_scaffold_required".to_owned(),
        execution_endpoint,
        todo: "TODO(contrix): persist proposal records, capture requester/approver context, require explicit approval, then route approved proposals into the dedicated /lock, /disable, /erase, or /reset-recovery mutation endpoints.".to_owned(),
    }))
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
