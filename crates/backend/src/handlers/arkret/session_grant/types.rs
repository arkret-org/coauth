use arkret_identifiers::{DidCoreId, SessionGrantId};
use chrono::{DateTime, Utc};
use coauth_data::SessionGrant;
use salvo::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub(crate) struct SessionGrantTarget {
    pub audience_id: DidCoreId,
    pub station_name: Option<String>,
    pub station_endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionGrantRecord {
    id: String,
    grant_id: SessionGrantId,
    browser_session_id: Option<String>,
    issuer_id: DidCoreId,
    subject_id: DidCoreId,
    device_id: Option<String>,
    audience_id: DidCoreId,
    scopes: Vec<String>,
    #[serde(serialize_with = "arkret_canonical::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serialize_optional_canonical_timestamp")]
    revoked_at: Option<DateTime<Utc>>,
}

impl From<SessionGrant> for SessionGrantRecord {
    fn from(value: SessionGrant) -> Self {
        Self {
            id: value.id.to_string(),
            grant_id: value.grant_id,
            browser_session_id: value.browser_session_id.map(|id| id.to_string()),
            issuer_id: value.issuer_id,
            subject_id: value.subject_id,
            device_id: value.device_id,
            audience_id: value.audience_id,
            scopes: value
                .scope
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
            created_at: value.created_at,
            expires_at: value.expires_at,
            revoked_at: value.revoked_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PatchPrimaryHandlePreferenceRequestBody {
    #[serde(
        default,
        deserialize_with = "serde_with::rust::double_option::deserialize"
    )]
    pub primary_handle: Option<Option<String>>,
}

/// HTTP status the Spec registry assigns `code` in a given entry context.
///
/// `error-code-registry.json` carries `http_status_by_context` for the account
/// lifecycle codes: the same code is `401` when an already-issued session
/// touches a protected resource and `403` when new session issuance or refresh
/// is denied by policy. Resolving through the generated table keeps that split
/// where the Spec defines it instead of duplicating it per call site.
pub(crate) fn account_lifecycle_status(
    code: arkret_wire::ErrorCode,
    context: arkret_wire::ErrorStatusContext,
) -> StatusCode {
    StatusCode::from_u16(code.http_status_in(context))
        .expect("registry http statuses are valid HTTP status codes")
}

#[derive(Debug, Serialize)]
pub struct PrimaryHandlePreferenceOutcome {
    pub primary_handle: Option<String>,
    #[serde(serialize_with = "arkret_canonical::serialize_canonical_timestamp")]
    pub effective_at: DateTime<Utc>,
    pub source_claim_id: Option<String>,
}
