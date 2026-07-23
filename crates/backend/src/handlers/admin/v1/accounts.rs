//! Arkret account administration endpoints.
//!
//! This is the ONLY admin resource tree over the users table: the former
//! MAS-inherited `/_coauth/admin/users/*` tree was folded in here
//! (create / by-username / batch-invite / profile patch / set-password),
//! and its unaccountable immediate `risk-action` endpoint was replaced by
//! the propose -> approve -> execute workflow in [`risk_action`].

pub mod create;
pub mod risk_action;
pub mod security;
pub mod update;

#[cfg(test)]
mod api_tests;

use chrono::{DateTime, Utc};
use coauth_admin_types::{
    AdminAccountAttributes, AdminAccountClaimRecord as AccountClaimRecord,
    AdminAccountClaimsOutcome as AccountClaimsOutcome, AdminAccountStatus as AccountStatus,
    AdminBridgeDescribe,
};
use coauth_data::user::UserFilter;
use coauth_data::{AdminUserPatch, RepositoryAccess};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::handlers::admin::audit_helper::AdminAuditSigning;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::model::Resource;
use crate::handlers::admin::params::{IncludeCount, extract_pagination, extract_ulid_param};
use crate::handlers::admin::response::{
    PaginatedOutcome, SingleOutcome, paginated_response_for_count_only, paginated_response_for_page,
};
use crate::handlers::admin::v1::account_dids::{preview_bindings_for_user, primary_did_for_user};
use crate::handlers::arkret::service_id_for;
use crate::handlers::common::DepotExt;
use crate::services::account_claims::{
    AccountClaimFilter, AccountClaimRecord as StoredAccountClaimRecord,
};
use crate::{AppError, JsonResult};

// `AdminBridgeDescribeResponse` (and the nested `AdminBridgeRiskAction*Example`
// triple) used to live inline here and in `risk_action.rs`. They moved
// to `coauth_admin_types::bridge_admin` in C34.2 so the sodmin admin SPA
// decodes them through the same typed shape — the prior client-side
// shim collapsed the three example payloads down to opaque
// `serde_json::Value`, silently dropping the structured `action`/
// `reason`/`ticket`/`approved_by`/`approval_note`/`execution_note`
// fields the SPA wants to render. The endpoint below now returns the
// shared `AdminBridgeDescribe` directly.

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountSessionGrantsOutcome {
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

/// Backend wrapper that owns the resource ID + JSON:API attributes. The
/// attributes block is the shared `AdminAccountAttributes` from
/// `coauth-admin-types` so any field rename / reorder shows up as a
/// rustc error in both the backend and `sodmin` client at the same time.
///
/// The `id` is `#[serde(skip)]` because it lives on the JSON:API
/// envelope (`data.id`), not in the `attributes` block. The
/// `#[serde(flatten)]` makes the on-wire shape exactly match what the
/// shared crate documents — `Serialize` of `AccountRecord` produces the
/// same `username` / `status` / `created_at` / ... keys at the top
/// level of the attributes object.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountRecord {
    #[serde(skip)]
    id: Ulid,

    #[serde(flatten)]
    attributes: AdminAccountAttributes,
}

impl AccountRecord {
    /// Build an `AccountRecord` from a freshly-fetched `User` row and its
    /// persisted principal binding.
    pub(crate) async fn from_user(
        user: coauth_data::User,
        depot: &Depot,
    ) -> Result<Self, AppError> {
        let arkret_config = depot.arkret_config()?;
        let did_resolver = depot.did_resolver_service()?;
        let mut repo = depot.repo().await?;
        let status = admin_account_status(user.status);
        let principal_id_bindings =
            preview_bindings_for_user(&mut repo, &user, &arkret_config, did_resolver.as_ref())
                .await;
        let primary_principal_binding = principal_id_bindings
            .iter()
            .find(|binding| binding.primary)
            .cloned();
        let principal_ids = principal_id_bindings
            .iter()
            .map(|binding| binding.did.clone())
            .collect();
        let primary_principal_id =
            primary_did_for_user(&mut repo, &user, &arkret_config, did_resolver.as_ref())
                .await
                .ok()
                .flatten();
        repo.cancel().await?;

        Ok(Self {
            id: user.id,
            attributes: AdminAccountAttributes {
                handle: user.localpart,
                status,
                created_at: Some(user.created_at),
                updated_at: Some(user.updated_at),
                locked_at: user.locked_at,
                deactivated_at: user.deactivated_at,
                admin: user.can_request_admin,
                display_name: user.display_name,
                avatar_url: user.avatar_url,
                preferred_locale: user.preferred_locale,
                primary_principal_id,
                principal_ids,
                primary_principal_binding,
                principal_id_bindings,
            },
        })
    }

    /// Convenience accessor used by mutation paths that need to peek at
    /// the primary DID after rebuilding from a fresh `User`.
    pub(crate) fn primary_principal_id(&self) -> Option<&str> {
        self.attributes.primary_principal_id.as_deref()
    }

    pub(crate) fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.attributes.updated_at
    }
}

impl Resource for AccountRecord {
    const KIND: &'static str = "account";
    const PATH: &'static str = "/_coauth/admin/accounts";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum AccountFilterStatus {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    ErasurePending,
}

impl std::fmt::Display for AccountFilterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::SoftLoggedOut => f.write_str("soft_logged_out"),
            Self::Locked => f.write_str("locked"),
            Self::Suspended => f.write_str("suspended"),
            Self::Deactivated => f.write_str("deactivated"),
            Self::ErasurePending => f.write_str("erasure_pending"),
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
) -> JsonResult<PaginatedOutcome<AccountRecord>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
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
        Some(AccountFilterStatus::SoftLoggedOut) => filter.soft_logged_out_only(),
        Some(AccountFilterStatus::Locked) => filter.locked_only(),
        Some(AccountFilterStatus::Suspended) => filter.suspended_only(),
        Some(AccountFilterStatus::Deactivated) => filter.deactivated_only(),
        Some(AccountFilterStatus::ErasurePending) => filter.erasure_pending_only(),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo.user().list(filter, pagination).await?;
            let count = repo.user().count(filter).await?;
            let page = map_page_async(page, depot).await?;
            paginated_response_for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo.user().list(filter, pagination).await?;
            let page = map_page_async(page, depot).await?;
            paginated_response_for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.user().count(filter).await?;
            paginated_response_for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.admin_bridge_describe", skip_all)]
pub async fn admin_bridge_describe(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AdminBridgeDescribe> {
    // SEC-ADMIN-NOAUTH: this endpoint discloses deployment fingerprint
    // (risk-action state-store kind / bridge capabilities), so it MUST be
    // gated behind the same admin authorization as every other admin
    // handler. `extract_call_context` validates the bearer token, its
    // session, expiry, and the `urn:coauth:admin` / `urn:arkret:admin:*`
    // scope before we read any deployment state. We drop the repository
    // transaction immediately since this handler does no DB work.
    let crate::handlers::admin::call_context::CallContext { repo, .. } =
        extract_call_context(req, depot).await?;
    repo.cancel().await?;
    let risk_action_state = depot.risk_action_state_service()?;

    Ok(Json(coauth_admin_types::admin_bridge_describe(
        risk_action_state.state_store_kind(),
    )))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.by_username", skip_all)]
pub async fn get_account_by_username(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<AccountRecord>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let username: String = req
        .param::<String>("username")
        .ok_or_else(|| AppError::not_found(r#"Account with username "unknown" not found"#))?;

    let self_path = format!("/_coauth/admin/accounts/by-username/{username}");
    let account = repo
        .user()
        .find_by_handle(&username)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Account with username {username:?} not found"))
        })?;

    Ok(Json(SingleOutcome::new(
        AccountRecord::from_user(account, depot).await?,
        self_path,
    )))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.get", skip_all)]
pub async fn get_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<AccountRecord>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;

    Ok(Json(SingleOutcome::new_canonical(
        AccountRecord::from_user(account, depot).await?,
    )))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.claims", skip_all)]
pub async fn list_account_claims(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountClaimsOutcome> {
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
        .map(account_claim_record_from_service)
        .collect();

    Ok(Json(AccountClaimsOutcome { data }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.session_grants", skip_all)]
pub async fn list_account_session_grants(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<AccountSessionGrantsOutcome> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;
    let account = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Account ID {id} not found")))?;
    let record = AccountRecord::from_user(account, depot).await?;
    Ok(Json(AccountSessionGrantsOutcome {
        data: admin_session_grant_records(&record),
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.lock", skip_all)]
pub async fn lock_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<AccountRecord>> {
    patch_account(
        req,
        depot,
        AdminUserPatch {
            status: Some(arkret_core::AccountStatus::Locked),
            locked: Some(true),
            ..AdminUserPatch::default()
        },
        false,
        "lock",
    )
    .await
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.disable", skip_all)]
pub async fn disable_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<AccountRecord>> {
    patch_account(
        req,
        depot,
        AdminUserPatch {
            status: Some(arkret_core::AccountStatus::Deactivated),
            deactivated: Some(true),
            ..AdminUserPatch::default()
        },
        false,
        "disable",
    )
    .await
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.erase", skip_all)]
pub async fn erase_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<AccountRecord>> {
    patch_account(
        req,
        depot,
        AdminUserPatch {
            status: Some(arkret_core::AccountStatus::ErasurePending),
            deactivated: Some(true),
            ..AdminUserPatch::default()
        },
        true,
        "erase",
    )
    .await
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.reset_recovery", skip_all)]
pub async fn reset_recovery(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<AccountRecord>> {
    patch_account(
        req,
        depot,
        AdminUserPatch {
            status: Some(arkret_core::AccountStatus::Locked),
            locked: Some(true),
            ..AdminUserPatch::default()
        },
        false,
        "reset_recovery",
    )
    .await
}

async fn patch_account(
    req: &mut Request,
    depot: &Depot,
    patch: AdminUserPatch,
    principal_erase: bool,
    action_label: &str,
) -> JsonResult<SingleOutcome<AccountRecord>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let arkret_config = depot.arkret_config()?;
    let id = extract_ulid_param(req)?;
    let principal_server = depot.principal_server()?;
    let key_store = depot.key_store()?;
    let service_id = service_id_for(&arkret_config);
    let audit_signing = AdminAuditSigning {
        keystore: &key_store,
        service_id: service_id.as_str(),
        fail_closed: arkret_config.audit_signature_fail_closed,
    };
    let mut rng = crate::handlers::account::make_rng();

    // AKP-0007 P2B.5: high-risk patches (disable / erase / reset_recovery)
    // MUST be preceded by an N-of-M approved RiskActionProposal. The
    // proposal id is bound to the request via the `risk_action_proposal_id`
    // query / header parameter; the propose / approve workflow lives in
    // `admin/v1/accounts/risk_action.rs` and persists each approval as an
    // `ApprovalProof` row inside the proposal's `approval_proofs` JSONB
    // column.
    //
    // REL-03: the proposal MUST be consumed (`mark_executed`) *before* the
    // mutation runs, not after. `mark_executed` transitions the proposal
    // `approved -> executed`; a second concurrent request observes the
    // proposal already `executed` and is rejected with
    // `AlreadyExecuted`, so the high-risk mutation cannot be double-applied
    // off a single approved proposal. (Previously the consume happened
    // after the mutation, leaving a TOCTOU window where two requests both
    // mutated before either marked the proposal executed.)
    let approved_proposal = if crate::services::risk_action_proposals::is_high_risk_action(
        action_label,
    ) {
        let proposal_id_raw = req
            .query::<String>("risk_action_proposal_id")
            .or_else(|| req.header::<String>("x-coauth-risk-action-proposal-id"))
            .ok_or_else(|| {
                AppError::bad_request(format!(
                    "high-risk action '{action_label}' requires an approved \
                     risk_action_proposal_id (query parameter or \
                     x-coauth-risk-action-proposal-id header)"
                ))
            })?;
        let proposal_ulid = Ulid::from_string(proposal_id_raw.trim())
            .map_err(|err| AppError::bad_request(format!("invalid proposal_id: {err}")))?;
        let proposals = depot.risk_action_proposals_service()?;
        let existing = proposals
            .get(proposal_ulid)
            .await
            .map_err(|err| {
                AppError::new(
                    salvo::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("risk_action lookup: {err}"),
                )
            })?
            .ok_or_else(|| AppError::not_found("risk_action proposal not found"))?;
        if existing.account_id != id {
            return Err(AppError::bad_request(
                "risk_action proposal targets a different account",
            ));
        }
        if existing.action != action_label {
            return Err(AppError::bad_request(format!(
                "risk_action proposal action {:?} does not match endpoint action {action_label:?}",
                existing.action
            )));
        }
        if existing.state != crate::services::risk_action_proposals::ProposalState::Approved {
            return Err(AppError::bad_request(format!(
                "risk_action proposal state {:?} is not 'approved'; need at \
                 least {} signed admin approvals before execution",
                existing.state.as_str(),
                existing.required_approvals
            )));
        }
        Some(proposal_ulid)
    } else {
        None
    };

    // REL-03: consume the approved proposal *before* applying the
    // mutation. This claims execution rights (`approved -> executed`); a
    // concurrent request racing on the same proposal sees `AlreadyExecuted`
    // and is rejected, so the mutation runs at most once per proposal.
    if let Some(proposal_ulid) = approved_proposal {
        let proposals = depot.risk_action_proposals_service()?;
        let _ = proposals
            .mark_executed(proposal_ulid, clock.now())
            .await
            .map_err(|err| {
                AppError::new(
                    salvo::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("risk_action mark_executed: {err}"),
                )
            })?;
    }

    let account = crate::services::user_admin::patch_user(
        &mut repo,
        &mut rng,
        &*clock,
        principal_server.as_ref(),
        admin_user.as_ref(),
        id,
        patch,
        principal_erase,
        Some(audit_signing),
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleOutcome::new_canonical(
        AccountRecord::from_user(account, depot).await?,
    )))
}

/// Map a `Page<User>` into a `Page<AccountRecord>` honouring the now-async
/// `AccountRecord::from_user`. The synchronous `Page::map` helper can't
/// drive an async closure, so we walk the edges by hand.
async fn map_page_async(
    page: coauth_data::Page<coauth_data::User>,
    depot: &Depot,
) -> Result<coauth_data::Page<AccountRecord>, AppError> {
    let coauth_data::Page {
        has_next_page,
        has_previous_page,
        edges,
    } = page;
    let mut mapped_edges = Vec::with_capacity(edges.len());
    for edge in edges {
        let cursor = edge.cursor;
        let node = AccountRecord::from_user(edge.node, depot).await?;
        mapped_edges.push(coauth_data::pagination::Edge { cursor, node });
    }
    Ok(coauth_data::Page {
        has_next_page,
        has_previous_page,
        edges: mapped_edges,
    })
}

// The exhaustive `UserAdminServiceError` -> `AppError` mapper lives in
// `update.rs` next to the PATCH endpoint; the lifecycle mutation endpoints
// above share it.
use update::map_service_error;

fn admin_account_status(status: arkret_core::AccountStatus) -> AccountStatus {
    match status {
        arkret_core::AccountStatus::Active => AccountStatus::Active,
        arkret_core::AccountStatus::SoftLoggedOut => AccountStatus::SoftLoggedOut,
        arkret_core::AccountStatus::Locked => AccountStatus::Locked,
        arkret_core::AccountStatus::Suspended => AccountStatus::Suspended,
        arkret_core::AccountStatus::Deactivated => AccountStatus::Deactivated,
        arkret_core::AccountStatus::ErasurePending => AccountStatus::ErasurePending,
    }
}

fn account_claim_record_from_service(record: StoredAccountClaimRecord) -> AccountClaimRecord {
    let value = account_claim_value(&record.payload);
    let state = record.status.as_str().to_owned();

    AccountClaimRecord {
        id: record.id.to_string(),
        account_id: record.account_id.map(|id| id.to_string()),
        claim_kind: record.claim_kind,
        value,
        state,
        source: "coauth_claim_repository".to_owned(),
        subject: record.subject,
        issuer: record.issuer,
        verifier_did: record.verifier_did,
        represented_org: record.represented_org,
        payload: record.payload,
        issued_at: Some(record.issued_at),
        expires_at: record.expires_at,
        revoked_at: record.revoked_at,
        revoked_reason: record.revoked_reason,
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
        subject: account.primary_principal_id().map(str::to_owned),
        scope: Some("urn:arkret:principal-server:session.bind".to_owned()),
        state: Some("inventory_scaffold".to_owned()),
        issued_at: account.updated_at(),
    }]
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use coauth_data::personal::session::PersonalSessionOwner;
    use coauth_data::{Clock, RepositoryAccess};
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::jwt::JsonWebSignatureHeader;
    use hyper::{Request, StatusCode};
    use serde_json::Value;
    use signature::RandomizedSigner as _;
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};
    use crate::services::did_binding_proof::{
        BindingStatementClaims, DID_BINDING_CONTROL_PROOF_SCHEMA,
    };

    #[tokio::test]
    async fn test_list_and_get_accounts() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
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
                Request::get("/_coauth/admin/accounts")
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
            body["data"][0]["attributes"]["primary_principal_id"],
            serde_json::Value::Null
        );
        assert_eq!(
            body["data"][0]["attributes"]["principal_ids"],
            serde_json::json!([])
        );

        let response = state
            .request(
                Request::get(format!("/_coauth/admin/accounts/{}", user.id))
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
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
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
                Request::post(format!("/_coauth/admin/accounts/{}/lock", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["attributes"]["status"], "locked");
        assert!(body["data"]["attributes"]["locked_at"].is_string());
        assert_eq!(
            body["data"]["attributes"]["deactivated_at"],
            serde_json::Value::Null
        );

        let response = state
            .request(
                Request::post(format!("/_coauth/admin/accounts/{}/disable", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["attributes"]["status"], "deactivated");
        assert!(body["data"]["attributes"]["locked_at"].is_string());
        assert!(body["data"]["attributes"]["deactivated_at"].is_string());
    }

    #[tokio::test]
    async fn test_risk_action_execute_requires_approval_and_locks_account() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
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
                Request::post(format!("/_coauth/admin/accounts/{}/risk-action", user.id))
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
        assert_eq!(body["approval_mode"], "durable_proposal_required");
        let admin_did = admin_did_for_token(&state, &token).await;
        let approval_note = "approved for controlled executor";
        let approval_proof_jws = sign_risk_action_approval_proof(
            &state,
            &proposal_id,
            user.id,
            "lock",
            Some("INC-2.1"),
            approval_note,
            &admin_did,
        );

        let proposals =
            crate::services::risk_action_proposals::risk_action_proposals_service(pool.clone());
        let proposal_ulid = proposal_id.parse::<ulid::Ulid>().unwrap();
        let persisted = proposals.get(proposal_ulid).await.unwrap().unwrap();
        assert_eq!(persisted.account_id, user.id);
        assert_eq!(persisted.action, "lock");
        assert_eq!(persisted.state.as_str(), "draft");

        let response = state
            .request(
                Request::post(format!(
                    "/_coauth/admin/accounts/{}/risk-action/{}/execute",
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
                    "/_coauth/admin/accounts/{}/risk-action/{}/approve",
                    user.id, proposal_id
                ))
                .bearer(&token)
                .json(serde_json::json!({
                    "action": "lock",
                    "ticket": "INC-2.1",
                    "approval_note": approval_note,
                    "approval_proof_jws": approval_proof_jws,
                })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["approval_state"], "approved");
        assert_eq!(
            body["state_store_kind"],
            "pg_risk_action_proposals_with_admin_audit_trail"
        );

        let persisted = proposals.get(proposal_ulid).await.unwrap().unwrap();
        assert_eq!(persisted.state.as_str(), "approved");
        assert_eq!(persisted.approval_proofs.len(), 1);

        let response = state
            .request(
                Request::post(format!(
                    "/_coauth/admin/accounts/{}/risk-action/{}/execute",
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

        let persisted = proposals.get(proposal_ulid).await.unwrap().unwrap();
        assert_eq!(persisted.state.as_str(), "executed");
        assert!(persisted.executed_at.is_some());

        let response = state
            .request(
                Request::post(format!(
                    "/_coauth/admin/accounts/{}/risk-action/{}/execute",
                    user.id, proposal_id
                ))
                .bearer(&token)
                .json(serde_json::json!({
                    "action": "lock",
                    "ticket": "INC-2.1",
                    "execution_note": "replay approved lock",
                })),
            )
            .await;
        response.assert_status(StatusCode::CONFLICT);

        let response = state
            .request(
                Request::get(format!(
                    "/_coauth/admin/accounts/{}/risk-action/current",
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
    async fn test_risk_action_approve_rejects_forged_approved_by_threshold_bypass() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
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
                Request::post(format!("/_coauth/admin/accounts/{}/risk-action", user.id))
                    .bearer(&token)
                    .json(serde_json::json!({
                        "action": "disable",
                        "reason": "confirmed account takeover",
                        "ticket": "INC-SEC-COA-1",
                    })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let proposal_id = body["proposal_id"].as_str().unwrap().to_owned();
        let proposal_ulid = proposal_id.parse::<ulid::Ulid>().unwrap();
        let proposals =
            crate::services::risk_action_proposals::risk_action_proposals_service(pool.clone());
        let admin_did = admin_did_for_token(&state, &token).await;
        let approval_note = "first real admin approval";
        let approval_proof_jws = sign_risk_action_approval_proof(
            &state,
            &proposal_id,
            user.id,
            "disable",
            Some("INC-SEC-COA-1"),
            approval_note,
            &admin_did,
        );

        let response = state
            .request(
                Request::post(format!(
                    "/_coauth/admin/accounts/{}/risk-action/{}/approve",
                    user.id, proposal_id
                ))
                .bearer(&token)
                .json(serde_json::json!({
                    "action": "disable",
                    "ticket": "INC-SEC-COA-1",
                    "approval_note": approval_note,
                    "approval_proof_jws": approval_proof_jws,
                })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["approval_state"], "draft");
        let authenticated_admin_did = body["approved_by"].as_str().unwrap().to_owned();

        let persisted = proposals.get(proposal_ulid).await.unwrap().unwrap();
        assert_eq!(persisted.required_approvals, 2);
        assert_eq!(persisted.state.as_str(), "draft");
        assert_eq!(persisted.approval_proofs.len(), 1);
        assert_eq!(
            persisted.approval_proofs[0].admin_did,
            authenticated_admin_did
        );

        for forged_approved_by in [
            "did:web:forged-admin-one.example",
            "did:web:forged-admin-two.example",
        ] {
            let response = state
                .request(
                    Request::post(format!(
                        "/_coauth/admin/accounts/{}/risk-action/{}/approve",
                        user.id, proposal_id
                    ))
                    .bearer(&token)
                    .json(serde_json::json!({
                        "action": "disable",
                        "ticket": "INC-SEC-COA-1",
                        "approved_by": forged_approved_by,
                        "approval_note": "attempt forged threshold bypass",
                        "approval_proof_jws": "protected..signature",
                    })),
                )
                .await;
            response.assert_status(StatusCode::BAD_REQUEST);

            let persisted = proposals.get(proposal_ulid).await.unwrap().unwrap();
            assert_eq!(persisted.state.as_str(), "draft");
            assert_eq!(persisted.approval_proofs.len(), 1);
            assert_eq!(
                persisted.approval_proofs[0].admin_did,
                authenticated_admin_did
            );
        }

        let response = state
            .request(
                Request::post(format!(
                    "/_coauth/admin/accounts/{}/risk-action/{}/execute",
                    user.id, proposal_id
                ))
                .bearer(&token)
                .json(serde_json::json!({
                    "action": "disable",
                    "ticket": "INC-SEC-COA-1",
                    "execution_note": "attempt before real N-of-M approval",
                })),
            )
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_account_dids_add_list_and_revoke_use_audit_trail() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
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
                Request::get(format!("/_coauth/admin/accounts/{}/dids", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let did = body["data"][0]["did"].as_str().unwrap().to_owned();
        assert_eq!(body["data"][0]["state"], "active");
        assert_eq!(body["data"][0]["active"], true);
        assert_eq!(body["meta"]["supports_write_operations"], true);

        let recovery_did = crate::handlers::arkret::service_id_for(&state.arkret_config);
        let nonce = "did-binding-add-nonce";
        let control_proof =
            sign_did_binding_control_proof(&state, recovery_did.as_str(), user.id, nonce);
        let response = state
            .request(
                Request::post(format!("/_coauth/admin/accounts/{}/dids", user.id))
                    .bearer(&token)
                    .json(serde_json::json!({
                        "did": recovery_did,
                        "kind": "recovery",
                        "control_proof": {
                            "jws": control_proof,
                            "nonce": nonce
                        },
                        "verification_method": "did_controller_key",
                        "operator_note": "bind recovery DID"
                    })),
            )
            .await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        let added = binding_for_did(&body, recovery_did.as_str());
        assert_eq!(added["kind"], "recovery");
        assert_eq!(added["state"], "active");
        assert_eq!(added["active"], true);
        assert_eq!(added["verification_status"], "verified");
        assert!(added["last_resolver_receipt_id"].is_string());

        let duplicate_proof = sign_did_binding_control_proof(
            &state,
            recovery_did.as_str(),
            user.id,
            "duplicate-nonce",
        );
        let response = state
            .request(
                Request::post(format!("/_coauth/admin/accounts/{}/dids", user.id))
                    .bearer(&token)
                    .json(serde_json::json!({
                        "did": recovery_did,
                        "kind": "recovery",
                        "control_proof": {
                            "jws": duplicate_proof,
                            "nonce": "duplicate-nonce"
                        }
                    })),
            )
            .await;
        response.assert_status(StatusCode::CONFLICT);

        let response = state
            .request(
                Request::delete(format!(
                    "/_coauth/admin/accounts/{}/dids/{}",
                    user.id, recovery_did
                ))
                .bearer(&token)
                .json(serde_json::json!({
                "reason": "operator requested DID rotation",
                    "revoke_related_sessions": true
                })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let revoked = binding_for_did(&body, recovery_did.as_str());
        assert_eq!(revoked["state"], "revoked");
        assert_eq!(revoked["active"], false);
        assert!(revoked["revoked_at"].is_string());

        let response = state
            .request(
                Request::delete(format!(
                    "/_coauth/admin/accounts/{}/dids/{}",
                    user.id, recovery_did
                ))
                .bearer(&token)
                .json(serde_json::json!({
                "reason": "duplicate revoke"
                })),
            )
            .await;
        response.assert_status(StatusCode::CONFLICT);

        let response = state
            .request(
                Request::get(format!("/_coauth/admin/accounts/{}/dids", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let primary = binding_for_did(&body, &did);
        assert_eq!(primary["state"], "active");
        assert_eq!(primary["active"], true);
        let revoked = binding_for_did(&body, recovery_did.as_str());
        assert_eq!(revoked["state"], "revoked");
        assert_eq!(revoked["active"], false);
    }

    fn binding_for_did<'a>(body: &'a Value, did: &str) -> &'a Value {
        body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["did"] == did)
            .expect("binding should be present")
    }

    fn sign_did_binding_control_proof(
        state: &TestState,
        did: &str,
        _account_id: Ulid,
        nonce: &str,
    ) -> String {
        let alg = [
            JsonWebSignatureAlg::EdDsa,
            JsonWebSignatureAlg::Es512,
            JsonWebSignatureAlg::Es384,
            JsonWebSignatureAlg::Es256,
            JsonWebSignatureAlg::Rs512,
            JsonWebSignatureAlg::Rs384,
            JsonWebSignatureAlg::Rs256,
            JsonWebSignatureAlg::Ps512,
            JsonWebSignatureAlg::Ps384,
            JsonWebSignatureAlg::Ps256,
        ]
        .into_iter()
        .find(|alg| state.key_store.signing_key_for_algorithm(alg).is_some())
        .expect("test keystore should expose a signing key");
        let signer = state.key_store.signer_for_algorithm(&alg).unwrap();
        let verification_method = format!("{did}#key-1");
        let header = JsonWebSignatureHeader::new(alg).with_kid(verification_method.clone());
        // identity-did §5.1 / §3.6: bind the proof to this receiver (local
        // service DID) and this deployment (trust_domain), with a bounded
        // freshness window (exp - iat <= 300s).
        let audience = crate::handlers::arkret::service_id_for(&state.arkret_config);
        let trust_domain =
            crate::handlers::arkret::trust_domain_for(&state.url_builder, &state.arkret_config);
        let iat = state.clock.now();
        let claims = BindingStatementClaims {
            schema: DID_BINDING_CONTROL_PROOF_SCHEMA.to_owned(),
            account_did: did.to_owned(),
            verification_method,
            audience: audience.to_string(),
            trust_domain,
            nonce: nonce.to_owned(),
            iat,
            exp: iat + chrono::Duration::seconds(5 * 60),
        };
        let header_b64 = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap());
        let payload = arkret_canonical::canonical_json_bytes(&claims).unwrap();
        let payload_b64 = Base64UrlUnpadded::encode_string(&payload);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let mut rng = state.rng();
        let raw_sig: coauth_jose::jwa::Signature = signer
            .try_sign_with_rng(&mut rng, signing_input.as_bytes())
            .unwrap();
        let raw_sig: Box<[u8]> = raw_sig.into();
        format!(
            "{signing_input}.{}",
            Base64UrlUnpadded::encode_string(raw_sig.as_ref())
        )
    }

    async fn admin_did_for_token(state: &TestState, token: &str) -> String {
        let mut repo = state.repository().await.unwrap();
        let access = repo
            .personal_access_token()
            .find_by_token(token)
            .await
            .unwrap()
            .expect("test token should resolve");
        let session = repo
            .personal_session()
            .lookup(access.session_id)
            .await
            .unwrap()
            .expect("test token session should resolve");
        let PersonalSessionOwner::User(user_id) = session.owner else {
            panic!("admin test token should be user-owned");
        };
        let user = repo
            .user()
            .lookup(user_id)
            .await
            .unwrap()
            .expect("admin token user should resolve");
        repo.cancel().await.unwrap();
        format!(
            "did:web:coauth.invalid:accounts:{}",
            user.id.to_string().to_ascii_lowercase()
        )
    }

    fn sign_risk_action_approval_proof(
        state: &TestState,
        proposal_id: &str,
        account_id: Ulid,
        action: &str,
        ticket: Option<&str>,
        approval_note: &str,
        approved_by: &str,
    ) -> String {
        let alg = JsonWebSignatureAlg::EdDsa;
        let signer = state
            .key_store
            .signer_for_algorithm(&alg)
            .expect("test keystore should expose an EdDSA signing key");
        let header = JsonWebSignatureHeader::new(alg).with_kid(format!("{approved_by}#key-1"));
        let header_b64 = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap());
        let payload = super::risk_action::risk_action_approval_transcript_bytes(
            proposal_id,
            account_id,
            action,
            ticket,
            approval_note,
            approved_by,
        )
        .unwrap();
        let payload_b64 = Base64UrlUnpadded::encode_string(&payload);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let mut rng = state.rng();
        let raw_sig: coauth_jose::jwa::Signature = signer
            .try_sign_with_rng(&mut rng, signing_input.as_bytes())
            .unwrap();
        let raw_sig: Box<[u8]> = raw_sig.into();
        format!(
            "{header_b64}..{}",
            Base64UrlUnpadded::encode_string(raw_sig.as_ref())
        )
    }
}
