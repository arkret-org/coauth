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

use arkret_identifiers::project_did_to_core_id;
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
use crate::handlers::admin::v1::account_dids::primary_did_for_user;
use crate::handlers::common::DepotExt;
use crate::services::account_claims::{
    AccountClaimFilter, AccountClaimRecord as StoredAccountClaimRecord,
};
use crate::{AppError, JsonResult};

// `AdminBridgeDescribeResponse` and the nested `AdminBridgeRiskAction*Example`
// triple live in `coauth_admin_types::bridge_admin`. The describe endpoint
// below returns the shared `AdminBridgeDescribe` directly so the sodmin admin
// SPA decodes the same typed shape, keeping the structured
// `action` / `reason` / `ticket` / `approved_by` / `approval_note` /
// `execution_note` fields it renders.

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
        let primary_principal_id =
            primary_did_for_user(&mut repo, &user, &arkret_config, did_resolver.as_ref())
                .await?
                .map(|did| {
                    project_did_to_core_id(&did).map_err(|error| {
                        AppError::internal(std::io::Error::other(format!(
                            "stored primary DID cannot project to a principal id: {error}"
                        )))
                    })
                })
                .transpose()?;
        let principal_ids = primary_principal_id.iter().cloned().collect();
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
                preferred_locale: user.preferred_locale.map(|locale| locale.code().to_owned()),
                primary_principal_id,
                principal_ids,
            },
        })
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
    let params: AccountFilterParams = req
        .parse_queries()
        .map_err(|error| AppError::bad_request(format!("Invalid filter parameters: {error}")))?;

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
    // SEC-ADMIN-NOAUTH: this endpoint discloses bridge capabilities, so it
    // MUST be gated behind the same admin authorization as every other
    // admin handler. `extract_call_context` validates the bearer token,
    // its session, expiry, and the `urn:coauth:admin` /
    // `urn:arkret:admin:*` scope. We drop the repository transaction
    // immediately since this handler does no DB work.
    let crate::handlers::admin::call_context::CallContext { repo, .. } =
        extract_call_context(req, depot).await?;
    repo.cancel().await?;

    Ok(Json(coauth_admin_types::admin_bridge_describe()))
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
#[tracing::instrument(name = "handler.admin.v1.accounts.lock", skip_all)]
pub async fn lock_account(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<AccountRecord>> {
    patch_account(
        req,
        depot,
        AdminUserPatch {
            status: Some(
                arkret_models_collaboration::objects::account_status::AccountStatus::Locked,
            ),
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
            status: Some(
                arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated,
            ),
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
            status: Some(
                arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending,
            ),
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
            status: Some(
                arkret_models_collaboration::objects::account_status::AccountStatus::Locked,
            ),
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
    let station = depot.station()?;
    let key_store = depot.key_store()?;
    let service_id = crate::handlers::arkret::owning_station_id_for(&arkret_config);
    let service_did = crate::handlers::arkret::owning_station_did_for(&arkret_config);
    let audit_signing = AdminAuditSigning {
        keystore: &key_store,
        service_id: &service_id,
        service_did: &service_did,
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
        station.as_ref(),
        admin_user.as_ref(),
        id,
        patch,
        principal_erase,
        Some(audit_signing),
        None,
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

fn admin_account_status(
    status: arkret_models_collaboration::objects::account_status::AccountStatus,
) -> AccountStatus {
    match status {
        arkret_models_collaboration::objects::account_status::AccountStatus::Active => {
            AccountStatus::Active
        }
        arkret_models_collaboration::objects::account_status::AccountStatus::SoftLoggedOut => {
            AccountStatus::SoftLoggedOut
        }
        arkret_models_collaboration::objects::account_status::AccountStatus::Locked => {
            AccountStatus::Locked
        }
        arkret_models_collaboration::objects::account_status::AccountStatus::Suspended => {
            AccountStatus::Suspended
        }
        arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated => {
            AccountStatus::Deactivated
        }
        arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending => {
            AccountStatus::ErasurePending
        }
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
        represented_organization: record.represented_organization,
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

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use coauth_data::RepositoryAccess;
    use coauth_data::personal::session::PersonalSessionOwner;
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::constraints::Constrainable as _;
    use coauth_jose::jwt::JsonWebSignatureHeader;
    use hyper::{Request, StatusCode};
    use signature::RandomizedSigner as _;
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

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
        // The admin token owns an account of its own, so the listing carries
        // both it and `alice`.
        assert_eq!(body["meta"]["count"], 2);
        let entry = body["data"]
            .as_array()
            .expect("account listing")
            .iter()
            .find(|entry| entry["id"] == user.id.to_string())
            .expect("the created account is listed")
            .clone();
        let body = serde_json::json!({ "data": [entry] });
        assert_eq!(body["data"][0]["type"], "account");
        assert_eq!(body["data"][0]["id"], user.id.to_string());
        assert_eq!(body["data"][0]["attributes"]["handle"], "alice");
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
        assert_eq!(body["data"]["attributes"]["handle"], "alice");
        assert_eq!(body["data"]["attributes"]["status"], "active");
    }

    #[tokio::test]
    async fn test_lock_account_and_refuse_unapproved_disable() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        // Locking and disabling are account-status transitions, so they need a
        // configured publication destination and an accepted principal binding
        // for the target account.
        let mut state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();
        state.seed_principal_binding(&user, "lockdisable").await;

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

        // `disable` is a high-risk action: unlike `lock` it is only reachable
        // through an approved risk-action proposal, so the direct endpoint
        // refuses a bare call.
        let response = state
            .request(
                Request::post(format!("/_coauth/admin/accounts/{}/disable", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert!(
            body["errors"][0]["title"]
                .as_str()
                .unwrap()
                .contains("requires an approved risk_action_proposal_id"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn test_risk_action_execute_requires_approval_and_locks_account() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        // Executing a risk action resolves the acting admin's principal DID and
        // publishes the resulting account-status transition, so both need a
        // configured Station and an accepted binding.
        let mut state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();
        state.seed_principal_binding(&user, "riskexectarget").await;
        // The proposal endpoint already resolves the acting admin's principal
        // DID, so the admin binding has to exist before the first request.
        let admin_did = admin_did_for_token(&state, &token, "riskexec").await;
        seed_admin_authority_acceptance(&state, &admin_did).await;

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
        // The proposal workflow resolves the acting admin's principal DID
        // through the accepted-binding projection.
        let mut state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();
        state
            .seed_principal_binding(&user, "riskapprovetarget")
            .await;
        let admin_did = admin_did_for_token(&state, &token, "riskapprove").await;
        seed_admin_authority_acceptance(&state, &admin_did).await;

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
        let authenticated_admin_id = body["approved_by"].as_str().unwrap().to_owned();

        let persisted = proposals.get(proposal_ulid).await.unwrap().unwrap();
        assert_eq!(persisted.required_approvals, 2);
        assert_eq!(persisted.state.as_str(), "draft");
        assert_eq!(persisted.approval_proofs.len(), 1);
        assert_eq!(
            persisted.approval_proofs[0].admin_id.as_str(),
            authenticated_admin_id
        );

        for forged_approved_by in [
            "ak:did_core:web:forged-admin-one.example",
            "ak:did_core:web:forged-admin-two.example",
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
                persisted.approval_proofs[0].admin_id.as_str(),
                authenticated_admin_id
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
    async fn test_account_dids_list_uses_accepted_binding_projection() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        // The inventory projects accepted principal bindings only, so the
        // account needs one against a configured Station audience.
        let mut state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();
        let bound_principal_id = state.seed_principal_binding(&user, "didinventory").await;

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
        // `data[].did` is the complete DID; `seed_principal_binding` returns
        // the stable core id it projects to. Comparing the two directly was
        // comparing a DID against a `ak:did_core:` core id.
        assert_eq!(
            arkret_identifiers::project_did_to_core_id(
                &arkret_identifiers::Did::new(did.clone()).unwrap()
            )
            .unwrap()
            .as_str(),
            bound_principal_id
        );
        assert_eq!(body["data"][0]["state"], "active");
        assert_eq!(body["data"][0]["active"], true);
        assert_eq!(body["meta"]["supports_write_operations"], true);
        assert_eq!(body["data"][0]["did"], did);
    }

    /// Bind an accepted principal DID to the admin behind `token` and return
    /// it.
    ///
    /// The risk-action workflow resolves the acting admin through the same
    /// accepted-binding projection as every other principal lookup, so a
    /// fabricated DID is never the admin's actor id.
    async fn admin_did_for_token(state: &TestState, token: &str, label: &str) -> String {
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
        state.seed_principal_binding(&user, label).await
    }

    /// File an `AdminAction` authority acceptance for the admin's accepted
    /// principal binding into the durable verified-DID-binding store.
    ///
    /// The approve step resolves the admin's authority document through the
    /// `verified_did` retained on that binding. Tests configure no
    /// delegated resolver, so the acceptance must already be durable — the §4
    /// "binding hit, zero resolver calls" path — or the high-risk freshness
    /// gate fails closed.
    async fn seed_admin_authority_acceptance(state: &TestState, admin_did: &str) {
        use coauth_data::user::PrincipalDidRepository as _;

        let mut repo = state.repository().await.unwrap();
        let binding = repo
            .principal_did()
            .get_by_principal_id(admin_did)
            .await
            .unwrap()
            .expect("admin principal binding should be seeded");
        let did = binding.verified_did.to_string();

        // The approval proof is signed by the test keystore's Ed25519 key
        // under `kid = {admin core id}#key-1`, so the pinned document must
        // advertise that method with the same public key.
        let public_jwk = state
            .key_store
            .public_jwks()
            .iter()
            .find(|jwk| jwk.kid() == Some(crate::handlers::test_utils::TEST_ED25519_KEY_ID))
            .expect("test keystore should expose its Ed25519 public key")
            .clone();
        let resolution = crate::services::did_resolver::DidResolution {
            document: crate::handlers::arkret::DidDocument {
                id: did.clone(),
                also_known_as: Vec::new(),
                verification_method: vec![crate::handlers::arkret::VerificationMethod {
                    id: format!("{admin_did}#key-1"),
                    kind: "JsonWebKey2020".to_owned(),
                    controller: did.clone(),
                    public_key_jwk: Some(public_jwk),
                    public_key_multibase: None,
                }],
                authentication: Vec::new(),
                assertion_method: Vec::new(),
                service: Vec::new(),
                metadata: None,
            },
            source: crate::services::did_resolver::DidResolutionSource::DelegatedResolver,
            verified_local_binding: false,
            key_log_head: Some(binding.key_log_head.clone()),
            method_evidence: serde_json::json!({
                "method": "did:webvh",
                "history_evidence_kind": "webvh_key_log",
                "controller_proof_verified": true,
            }),
            closed_method_evidence: None,
            identity_fact_rejection: None,
        };
        let now = chrono::Utc::now();
        let accepted = crate::services::did_binding::binding_from_resolution(
            &resolution,
            crate::services::did_binding::trust_domain_id(&state.url_builder, &state.arkret_config)
                .unwrap(),
            arkret_identity::DidBindingPurpose::AdminAction,
            crate::services::did_binding::policy_digest(&state.arkret_config).unwrap(),
            None,
            &crate::services::did_binding::high_risk_freshness(),
            now,
        )
        .expect("fixture resolution should build an authority-grade binding");
        crate::services::did_binding::shared_verified_did_binding_store()
            .persist(&mut repo, &accepted, now)
            .await
            .expect("authority acceptance should persist");
        repo.save().await.unwrap();
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
        let alg = JsonWebSignatureAlg::Ed25519;
        // Select by `kid`, not by algorithm: `seed_admin_authority_acceptance`
        // pins `test-ed25519`'s public JWK in the fixture DID document, and the
        // fixture keystore holds four Ed25519 keys whose order decides what
        // `signer_for_algorithm` returns.
        let signer = crate::handlers::test_utils::test_ed25519_private_key()
            .signing_key_for_alg(&alg)
            .expect("the fixture Ed25519 key signs Ed25519");
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
