//! Contrix claim and attestation administration endpoints.

use chrono::{DateTime, Utc};
use coauth_data::{RepositoryAccess, audit::AdminOperation};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    AppError, CreatedJsonResult, JsonResult,
    handlers::{
        admin::{
            CreatedJson, audit_helper::record_admin_operation, call_context::extract_call_context,
            params::extract_ulid_param,
        },
        common::DepotExt,
    },
    services::account_claims::{
        AccountClaimFilter, AccountClaimRecord as StoredClaimRecord, AccountClaimStatus,
        AccountClaimsError, IssueAccountClaim,
    },
};

#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Active,
    Revoked,
    Expired,
}

impl ClaimStatus {
    fn from_service(status: AccountClaimStatus) -> Self {
        match status {
            AccountClaimStatus::Active => Self::Active,
            AccountClaimStatus::Revoked => Self::Revoked,
            AccountClaimStatus::Expired => Self::Expired,
        }
    }

    fn into_service(self) -> AccountClaimStatus {
        match self {
            Self::Active => AccountClaimStatus::Active,
            Self::Revoked => AccountClaimStatus::Revoked,
            Self::Expired => AccountClaimStatus::Expired,
        }
    }
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct ClaimRecord {
    /// Claim identifier.
    id: String,

    /// Bound local account, when the subject resolves to a coauth account.
    account_id: Option<String>,

    /// Claim type, for example `verified_email_domain` or `org_role`.
    claim_type: String,

    /// Subject account or DID.
    subject: String,

    /// Issuer DID or trusted issuer identifier.
    issuer: String,

    /// DID of the verifier that checked the progressive-disclosure claim.
    verifier_did: String,

    /// Organization represented by the verifier.
    represented_org: String,

    /// Claim payload.
    payload: serde_json::Value,

    /// Current lifecycle state.
    status: ClaimStatus,

    /// When the claim was issued.
    issued_at: DateTime<Utc>,

    /// When the claim expires.
    expires_at: Option<DateTime<Utc>>,

    /// When the claim was revoked.
    revoked_at: Option<DateTime<Utc>>,

    /// Operator-supplied revocation reason.
    revoked_reason: Option<String>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct ClaimListResponse {
    data: Vec<ClaimRecord>,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "IssueClaimRequest")]
pub struct IssueClaimRequest {
    /// Optional local account to bind this claim to.
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    account_id: Option<Ulid>,

    /// Claim type, for example `verified_email_domain` or `org_role`.
    claim_type: String,

    /// Subject account, local DID, username, or external DID.
    subject: String,

    /// Issuer DID or trusted issuer identifier. Defaults to the local issuer DID.
    issuer: Option<String>,

    /// DID of the verifier that checked the progressive-disclosure claim.
    verifier_did: String,

    /// Organization represented by the verifier.
    represented_org: String,

    /// Claim payload.
    payload: serde_json::Value,

    /// Optional expiry.
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "RevokeClaimRequest")]
pub struct RevokeClaimRequest {
    /// Operator-supplied revocation reason for audit.
    reason: String,
}

#[derive(Deserialize, Default)]
pub struct ClaimStatusQuery {
    /// Filter by local account ULID.
    #[serde(rename = "filter[account_id]")]
    account_id: Option<Ulid>,

    /// Filter by exact subject.
    #[serde(rename = "filter[subject]")]
    subject: Option<String>,

    /// Filter by claim type.
    #[serde(rename = "filter[claim_type]")]
    claim_type: Option<String>,

    /// Filter by lifecycle status.
    #[serde(rename = "filter[status]")]
    status: Option<ClaimStatus>,

    /// Maximum rows to return.
    limit: Option<i64>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.claims.issue", skip_all)]
pub async fn issue_claim(req: &mut Request, depot: &Depot) -> CreatedJsonResult<ClaimRecord> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let body: IssueClaimRequest = req.parse_json().await.map_err(AppError::internal)?;

    let now = clock.now();
    let claim_type = require_non_empty(body.claim_type, "claim_type")?;
    let subject = require_non_empty(body.subject, "subject")?;
    let verifier_did = require_did(body.verifier_did, "verifier_did")?;
    let represented_org = require_non_empty(body.represented_org, "represented_org")?;
    let account_id =
        resolve_account_id_for_issue(&mut repo, depot, body.account_id, &subject).await?;

    let issuer = match body.issuer {
        Some(value) => require_non_empty(value, "issuer")?,
        None => {
            let url_builder = depot.url_builder()?;
            let contrix_config = depot.contrix_config()?;
            let did_resolver = depot.did_resolver_service()?;
            did_resolver.issuer_did(&url_builder, &contrix_config)
        }
    };

    let claim_service = depot.account_claims_service()?;
    let record = claim_service
        .issue(IssueAccountClaim {
            account_id,
            claim_type,
            subject,
            issuer,
            verifier_did,
            represented_org,
            payload: body.payload,
            issued_at: now,
            expires_at: body.expires_at,
        })
        .await
        .map_err(map_claim_service_error)?;

    record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::Other("account_claim.issue".to_owned()),
        "account_claim",
        Some(record.id),
        serde_json::json!({
            "account_id": record.account_id.as_ref().map(ToString::to_string),
            "subject": &record.subject,
            "claim_type": &record.claim_type,
            "issuer": &record.issuer,
            "verifier_did": &record.verifier_did,
            "represented_org": &record.represented_org,
            "expires_at": &record.expires_at,
        }),
    )
    .await?;
    repo.save().await?;

    Ok(CreatedJson(claim_record_from_service(record)))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.claims.status", skip_all)]
pub async fn list_claim_status(req: &mut Request, depot: &Depot) -> JsonResult<ClaimListResponse> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { repo, clock, .. } = ctx;
    let query: ClaimStatusQuery = req.parse_queries().unwrap_or_default();
    let claim_service = depot.account_claims_service()?;
    let now = clock.now();
    repo.cancel().await?;

    let data = claim_service
        .list(
            AccountClaimFilter {
                account_id: query.account_id,
                subject: normalize_optional_query(query.subject),
                claim_type: normalize_optional_query(query.claim_type),
                status: query.status.map(ClaimStatus::into_service),
                limit: query.limit,
            },
            now,
        )
        .await
        .map_err(map_claim_service_error)?
        .into_iter()
        .map(claim_record_from_service)
        .collect();

    Ok(Json(ClaimListResponse { data }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.claims.revoke", skip_all)]
pub async fn revoke_claim(req: &mut Request, depot: &Depot) -> JsonResult<ClaimRecord> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let id = extract_ulid_param(req)?;
    let body: RevokeClaimRequest = req.parse_json().await.map_err(AppError::internal)?;
    let reason = require_non_empty(body.reason, "reason")?;
    let claim_service = depot.account_claims_service()?;
    let now = clock.now();

    let record = claim_service
        .revoke(id, reason.clone(), now)
        .await
        .map_err(map_claim_service_error)?
        .ok_or_else(|| AppError::not_found(format!("Claim ID {id} not found")))?;

    record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::Other("account_claim.revoke".to_owned()),
        "account_claim",
        Some(record.id),
        serde_json::json!({
            "account_id": record.account_id.as_ref().map(ToString::to_string),
            "subject": &record.subject,
            "claim_type": &record.claim_type,
            "reason": reason,
        }),
    )
    .await?;
    repo.save().await?;

    Ok(Json(claim_record_from_service(record)))
}

pub(crate) fn claim_record_from_service(record: StoredClaimRecord) -> ClaimRecord {
    ClaimRecord {
        id: record.id.to_string(),
        account_id: record.account_id.map(|id| id.to_string()),
        claim_type: record.claim_type,
        subject: record.subject,
        issuer: record.issuer,
        verifier_did: record.verifier_did,
        represented_org: record.represented_org,
        payload: record.payload,
        status: ClaimStatus::from_service(record.status),
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        revoked_at: record.revoked_at,
        revoked_reason: record.revoked_reason,
    }
}

async fn resolve_account_id_for_issue(
    repo: &mut coauth_data::BoxRepository,
    depot: &Depot,
    explicit_account_id: Option<Ulid>,
    subject: &str,
) -> Result<Option<Ulid>, AppError> {
    let derived_account_id = derive_account_id_from_subject(repo, depot, subject).await?;

    if let Some(account_id) = explicit_account_id {
        let exists = repo.user().lookup(account_id).await?.is_some();
        if !exists {
            return Err(AppError::bad_request(format!(
                "Referenced account ID {account_id} not found"
            )));
        }
        if let Some(derived) = derived_account_id
            && derived != account_id
        {
            return Err(AppError::bad_request(format!(
                "subject resolves to account {derived}, not requested account {account_id}"
            )));
        }
        return Ok(Some(account_id));
    }

    Ok(derived_account_id)
}

async fn derive_account_id_from_subject(
    repo: &mut coauth_data::BoxRepository,
    depot: &Depot,
    subject: &str,
) -> Result<Option<Ulid>, AppError> {
    if let Ok(id) = subject.parse::<Ulid>() {
        return ensure_subject_account_exists(repo, id).await;
    }

    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let did_resolver = depot.did_resolver_service()?;
    if let Some(id) = did_resolver.parse_local_user_did(&url_builder, &contrix_config, subject) {
        return ensure_subject_account_exists(repo, id).await;
    }

    Ok(repo
        .user()
        .find_by_username(subject)
        .await?
        .map(|user| user.id))
}

async fn ensure_subject_account_exists(
    repo: &mut coauth_data::BoxRepository,
    id: Ulid,
) -> Result<Option<Ulid>, AppError> {
    if repo.user().lookup(id).await?.is_some() {
        Ok(Some(id))
    } else {
        Err(AppError::bad_request(format!(
            "Subject account ID {id} not found"
        )))
    }
}

fn require_non_empty(value: String, field: &str) -> Result<String, AppError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        Err(AppError::bad_request(format!("{field} is required")))
    } else {
        Ok(value)
    }
}

fn require_did(value: String, field: &str) -> Result<String, AppError> {
    let value = require_non_empty(value, field)?;
    if value.starts_with("did:") {
        Ok(value)
    } else {
        Err(AppError::bad_request(format!("{field} must be a DID")))
    }
}

fn normalize_optional_query(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn map_claim_service_error(error: AccountClaimsError) -> AppError {
    AppError::internal(error)
}

#[cfg(test)]
mod tests {
    use coauth_data::RepositoryAccess;
    use hyper::{Request, StatusCode};

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_claim_lifecycle_repo_backs_account_claims() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
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

        let response =
            state
                .request(Request::post("/api/admin/v1/claims").bearer(&token).json(
                    serde_json::json!({
                        "account_id": user.id.to_string(),
                        "claim_type": "org_role",
                        "subject": user.id.to_string(),
                        "verifier_did": "did:web:verifier.example",
                        "represented_org": "Example Org",
                        "payload": {
                            "value": "admin",
                            "scope": "progressive_disclosure"
                        }
                    }),
                ))
                .await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_eq!(body["account_id"], user.id.to_string());
        assert_eq!(body["status"], "active");
        assert_eq!(body["verifier_did"], "did:web:verifier.example");
        assert_eq!(body["represented_org"], "Example Org");
        let claim_id = body["id"].as_str().unwrap().to_owned();

        let response = state
            .request(
                Request::get(format!("/api/admin/v1/accounts/{}/claims", user.id))
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"][0]["id"], claim_id);
        assert_eq!(body["data"][0]["state"], "active");
        assert_eq!(body["data"][0]["value"], "admin");
        assert_eq!(body["data"][0]["represented_org"], "Example Org");

        let response = state
            .request(
                Request::post(format!("/api/admin/v1/claims/{claim_id}/revoke"))
                    .bearer(&token)
                    .json(serde_json::json!({
                        "reason": "attestation superseded"
                    })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["status"], "revoked");
        assert_eq!(body["revoked_reason"], "attestation superseded");

        let response = state
            .request(
                Request::get(format!(
                    "/api/admin/v1/claims/status?filter[account_id]={}&filter[status]=revoked",
                    user.id
                ))
                .bearer(&token)
                .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"][0]["id"], claim_id);
        assert_eq!(body["data"][0]["status"], "revoked");
    }
}
