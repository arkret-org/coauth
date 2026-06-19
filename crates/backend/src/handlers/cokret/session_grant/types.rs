use chrono::{DateTime, Utc};
use coauth_data::SessionGrant;
use cokret_core::SessionGrantProofKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct SessionGrantMaterial {
    pub grant_jwt: String,
    pub session_public_key: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantPayload {
    #[serde(rename = "type")]
    pub kind: String,
    pub issuer: String,
    pub subject: String,
    pub service_account_id: String,
    pub session_public_key: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revocation_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub session_id: String,
    pub browser_session_id: String,
    /// RFC 9449 §6 confirmation — when the grant was issued bound to a
    /// DPoP proof, `cnf.jkt` carries the RFC 7638 SHA-256 thumbprint
    /// (base64url) of the proof's public key. The refresh path requires
    /// any follow-up proof to recompute the same thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<SessionGrantConfirmation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_kind: Option<SessionGrantProofKind>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub scope_details: Value,
    pub proof: SessionGrantProof,
}

/// RFC 9449 / RFC 7800 confirmation claim, carrying the JWK thumbprint
/// that binds an access token (here a session grant) to the holder's
/// proof-of-possession key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantConfirmation {
    /// `jkt` — base64url SHA-256 JWK thumbprint per RFC 7638.
    pub jkt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantProof {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: String,
    pub key_id: String,
    pub canonicalization: String,
    pub payload_digest_alg: String,
    pub payload_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionGrantPayloadClaims {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) service_account_id: String,
    pub(crate) session_public_key: String,
    pub(crate) audience: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) not_before: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) revocation_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device_id: Option<String>,
    pub(crate) session_id: String,
    pub(crate) browser_session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cnf: Option<SessionGrantConfirmation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) proof_kind: Option<SessionGrantProofKind>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub(crate) scope_details: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionGrantRecord {
    id: String,
    browser_session_id: String,
    issuer: String,
    subject: String,
    device_id: Option<String>,
    audience: String,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionGrantIntrospectionProofClaims {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) grant_id: String,
    pub(crate) grant_jwt_hash: String,
    pub(crate) audience: String,
    pub(crate) challenge: String,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

impl From<SessionGrant> for SessionGrantRecord {
    fn from(value: SessionGrant) -> Self {
        Self {
            id: value.id.to_string(),
            browser_session_id: value.browser_session_id.to_string(),
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

#[derive(Debug, Serialize)]
pub struct PrimaryHandlePreferenceOutcome {
    pub primary_handle: Option<String>,
    pub effective_at: DateTime<Utc>,
    pub source_claim_id: Option<String>,
    pub source_claim_digest: Option<String>,
}
