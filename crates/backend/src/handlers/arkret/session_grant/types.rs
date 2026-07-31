use arkret_identifiers::GrantId;
use chrono::{DateTime, Utc};
use coauth_data::SessionGrant;
use salvo::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct SessionGrantMaterial {
    pub grant_id: GrantId,
    pub grant_jwt: String,
    pub session_public_key: String,
    pub credential_class: String,
    pub recovery_session_id: Option<String>,
    pub recovery_policy_id: Option<String>,
    pub recovery_policy_version: Option<i64>,
    pub device_authorization_event_id: Option<String>,
    pub model_generation_ref: Option<serde_json::Value>,
    pub expires_at: String,
    pub expires_at_timestamp: DateTime<Utc>,
    pub issuer: String,
    pub subject: String,
    pub device_id: Option<String>,
    pub audience: String,
    pub scopes: Vec<String>,
    /// RFC 7638 JWK SHA-256 thumbprint (base64url) of the DPoP proof the
    /// grant is bound to, when issuance happened on a request that
    /// carried a `DPoP` header. `None` for unbound minting paths such as
    /// internal admin minting or debug seeds without a `dpop_jwk`.
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionGrantTarget {
    pub audience: String,
    pub principal_server_name: Option<String>,
    pub principal_server_endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionGrantRecord {
    id: String,
    grant_id: GrantId,
    browser_session_id: Option<String>,
    issuer: String,
    subject: String,
    device_id: Option<String>,
    audience: String,
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
            issuer: value.issuer,
            subject: value.subject,
            device_id: value.device_id,
            audience: value.audience,
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
    pub source_claim_digest: Option<String>,
}
