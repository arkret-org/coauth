//! Contrix account administration endpoints.

pub mod risk_action;

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
    handlers::admin::v1::accounts::risk_action::{
        AdminBridgeRiskActionExamples, admin_bridge_risk_action_examples,
    },
    handlers::{
        admin::{
            call_context::extract_call_context,
            model::Resource,
            params::{IncludeCount, extract_pagination, extract_ulid_param},
            response::{
                PaginatedResponse, SingleResponse, paginated_response_for_count_only,
                paginated_response_for_page,
            },
        },
        common::DepotExt,
    },
    services::account_claims::{
        AccountClaimFilter, AccountClaimRecord as StoredAccountClaimRecord,
    },
    services::did_resolver::{DidResolverService, default_did_resolver_service},
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

    /// Template path for claim inventory.
    account_claims_path_template: &'static str,

    /// Template path for session-grant inventory.
    account_session_grants_path_template: &'static str,

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

    /// Machine-readable request examples for the risk-action REST workflow.
    risk_action_examples: AdminBridgeRiskActionExamples,

    /// Remaining scaffold tasks.
    todos: Vec<&'static str>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountClaimsResponse {
    data: Vec<AccountClaimRecord>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountClaimRecord {
    id: String,
    account_id: Option<String>,
    claim_type: String,
    value: Option<String>,
    state: String,
    source: String,
    subject: String,
    issuer: String,
    verifier_did: String,
    represented_org: String,
    payload: serde_json::Value,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_reason: Option<String>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountSessionGrantsResponse {
    data: Vec<AccountSessionGrantRecord>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountSessionGrantRecord {
    grant_id: String,
    subject: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    issued_at: Option<DateTime<Utc>>,
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
        let did_resolver = default_did_resolver_service();
        Self::from_user(
            user,
            &coauth_config::ContrixConfig::default(),
            did_resolver.as_ref(),
        )
    }
}

impl AccountRecord {
    fn from_user(
        user: coauth_data::User,
        contrix_config: &coauth_config::ContrixConfig,
        did_resolver: &dyn DidResolverService,
    ) -> Self {
        let status = if user.deactivated_at.is_some() {
            AccountStatus::Disabled
        } else if user.locked_at.is_some() {
            AccountStatus::Locked
        } else {
            AccountStatus::Active
        };
        let principal_did_bindings = preview_bindings_for_user(&user, contrix_config, did_resolver);
        let primary_principal_binding = principal_did_bindings
            .iter()
            .find(|binding| binding.primary)
            .cloned();
        let principal_dids = principal_did_bindings
            .iter()
            .map(|binding| binding.did.clone())
            .collect();
        let primary_principal_did = Some(primary_did_for_user(&user, did_resolver));

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
            primary_principal_did,
            principal_dids,
            primary_principal_binding,
            principal_did_bindings,
        }
    }
}

impl Resource for AccountRecord {
    const KIND: &'static str = "account";
    const PATH: &'static str = "/api/admin/v1/accounts";

    fn id(&self) -> String {
        self.id.to_string()
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
    let did_resolver = depot.did_resolver_service()?;
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
                page.map(|user| {
                    AccountRecord::from_user(user, &contrix_config, did_resolver.as_ref())
                }),
                pagination,
                Some(count),
                &base,
            )
        }
        IncludeCount::False => {
            let page = repo.user().list(filter, pagination).await?;
            PaginatedResponse::for_page(
                page.map(|user| {
                    AccountRecord::from_user(user, &contrix_config, did_resolver.as_ref())
                }),
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
#[tracing::instrument(name = "handler.admin.v1.accounts.admin_bridge_describe", skip_all)]
pub async fn admin_bridge_describe(depot: &Depot) -> JsonResult<AdminBridgeDescribeResponse> {
    let risk_action_state = depot.risk_action_state_service()?;

    Ok(Json(AdminBridgeDescribeResponse {
        contract: "cx.contract.coauth_admin_bridge.v1",
        version: "0.1.0-scaffold",
        api_base_path: "/api/admin/v1",
        accounts_path: "/api/admin/v1/accounts",
        account_detail_path_template: "/api/admin/v1/accounts/{account_id}",
        account_dids_path_template: "/api/admin/v1/accounts/{account_id}/dids",
        account_claims_path_template: "/api/admin/v1/accounts/{account_id}/claims",
        account_session_grants_path_template: "/api/admin/v1/accounts/{account_id}/session-grants",
        risk_action_path_template: "/api/admin/v1/accounts/{account_id}/risk-action",
        risk_action_current_path_template: "/api/admin/v1/accounts/{account_id}/risk-action/current",
        risk_action_history_path_template: "/api/admin/v1/accounts/{account_id}/risk-action/history",
        risk_action_approve_path_template: "/api/admin/v1/accounts/{account_id}/risk-action/{proposal_id}/approve",
        risk_action_execute_path_template: "/api/admin/v1/accounts/{account_id}/risk-action/{proposal_id}/execute",
        risk_action_state_store_kind: risk_action_state.state_store_kind(),
        risk_action_approval_mode: "state_machine_scaffold_required",
        risk_action_examples: admin_bridge_risk_action_examples(),
        todos: vec![
            "TODO: replace audit-backed scaffold transitions with dedicated persisted proposal records",
            "TODO: enforce persisted approval-state consumption before executing risk-action mutations",
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
    let did_resolver = depot.did_resolver_service()?;
    let id = extract_ulid_param(req)?;

    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    Ok(Json(SingleResponse::new_canonical(
        AccountRecord::from_user(account, &contrix_config, did_resolver.as_ref()),
    )))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.claims", skip_all)]
pub async fn list_account_claims(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountClaimsResponse> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    repo.user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let now = clock.now();
    repo.cancel().await?;

    let claim_service = depot.account_claims_service()?;
    let data = claim_service
        .list(AccountClaimFilter::for_account(id), now)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(AccountClaimRecord::from_service)
        .collect();

    Ok(Json(AccountClaimsResponse { data }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.session_grants", skip_all)]
pub async fn list_account_session_grants(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountSessionGrantsResponse> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let contrix_config = depot.contrix_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let id = extract_ulid_param(req)?;
    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let record = AccountRecord::from_user(account, &contrix_config, did_resolver.as_ref());
    Ok(Json(AccountSessionGrantsResponse {
        data: admin_session_grant_records(&record),
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
    patch_account(
        req,
        depot,
        AdminUserPatch {
            deactivated: Some(true),
            ..AdminUserPatch::default()
        },
        true,
    )
    .await
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.reset_recovery", skip_all)]
pub async fn reset_recovery(
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
    let did_resolver = depot.did_resolver_service()?;
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

    Ok(Json(SingleResponse::new_canonical(
        AccountRecord::from_user(account, &contrix_config, did_resolver.as_ref()),
    )))
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

impl AccountClaimRecord {
    fn from_service(record: StoredAccountClaimRecord) -> Self {
        let value = account_claim_value(&record.payload);
        let state = record.status.as_str().to_owned();

        Self {
            id: record.id.to_string(),
            account_id: record.account_id.map(|id| id.to_string()),
            claim_type: record.claim_type,
            value,
            state,
            source: "coauth_claim_repository".to_owned(),
            subject: record.subject,
            issuer: record.issuer,
            verifier_did: record.verifier_did,
            represented_org: record.represented_org,
            payload: record.payload,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            revoked_at: record.revoked_at,
            revoked_reason: record.revoked_reason,
        }
    }
}

fn account_claim_value(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("value")
        .or_else(|| payload.get("claim_value"))
        .and_then(|value| match value {
            serde_json::Value::String(value) => Some(value.clone()),
            serde_json::Value::Null => None,
            value => Some(value.to_string()),
        })
}

fn admin_session_grant_records(account: &AccountRecord) -> Vec<AccountSessionGrantRecord> {
    vec![AccountSessionGrantRecord {
        grant_id: format!("sg-scaffold-{}", account.id),
        subject: account.primary_principal_did.clone(),
        scope: Some("urn:contrix:principal-server:session.bind".to_owned()),
        state: Some("inventory_scaffold".to_owned()),
        issued_at: Some(account.updated_at),
    }]
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
    async fn test_risk_action_execute_requires_approval_and_locks_account() {
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
                Request::post(format!("/api/admin/v1/accounts/{}/risk-action", user.id))
                    .bearer(&token)
                    .json(serde_json::json!({
                        "action": "lock",
                        "reason": "suspicious recovery activity",
                        "ticket": "INC-2.1",
                    })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let proposal_id = body["proposal_id"].as_str().unwrap().to_owned();

        let response = state
            .request(
                Request::post(format!(
                    "/api/admin/v1/accounts/{}/risk-action/{}/execute",
                    user.id, proposal_id
                ))
                .bearer(&token)
                .json(serde_json::json!({
                    "action": "lock",
                    "ticket": "INC-2.1",
                    "execution_note": "attempt before approval",
                })),
            )
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let response = state
            .request(
                Request::post(format!(
                    "/api/admin/v1/accounts/{}/risk-action/{}/approve",
                    user.id, proposal_id
                ))
                .bearer(&token)
                .json(serde_json::json!({
                    "action": "lock",
                    "ticket": "INC-2.1",
                    "approved_by": "did:web:admin.example",
                    "approval_note": "approved for controlled executor",
                })),
            )
            .await;
        response.assert_status(StatusCode::OK);

        let response = state
            .request(
                Request::post(format!(
                    "/api/admin/v1/accounts/{}/risk-action/{}/execute",
                    user.id, proposal_id
                ))
                .bearer(&token)
                .json(serde_json::json!({
                    "action": "lock",
                    "ticket": "INC-2.1",
                    "execution_note": "execute approved lock",
                })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["execution_state"], "mutation_recorded");
        assert_eq!(body["mutation_kind"], "account_locked");
        assert_eq!(body["account"]["data"]["attributes"]["status"], "locked");
        assert!(body["account"]["data"]["attributes"]["locked_at"].is_string());

        let response = state
            .request(
                Request::get(format!(
                    "/api/admin/v1/accounts/{}/risk-action/current",
                    user.id
                ))
                .bearer(&token)
                .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["data"]["attributes"]["lifecycle_state"],
            "mutation_recorded"
        );

        let mut repo = state.repository().await.unwrap();
        let updated = repo.user().lookup(user.id).await.unwrap().unwrap();
        repo.cancel().await.unwrap();
        assert!(updated.locked_at.is_some());
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
