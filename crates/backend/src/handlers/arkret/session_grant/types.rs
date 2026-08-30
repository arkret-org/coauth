use arkret_identifiers::{DidCoreId, ServiceAccountId, SessionGrantId};
use arkret_models_identity::SessionGrantIssuanceNonce;
use chrono::{DateTime, Utc};
use coauth_data::SessionGrant;
use salvo::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantMaterial {
    pub grant_id: SessionGrantId,
    pub grant_jwt: String,
    pub session_public_key: String,
    pub credential_class: String,
    pub expires_at: String,
    pub expires_at_timestamp: DateTime<Utc>,
    pub not_before_timestamp: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub subject_id: DidCoreId,
    pub service_account_id: ServiceAccountId,
    pub device_id: Option<String>,
    pub audience_id: DidCoreId,
    pub scopes: Vec<String>,
    /// RFC 7638 JWK SHA-256 thumbprint (base64url) of the DPoP proof the
    /// grant is bound to, when issuance happened on a request that
    /// carried a `DPoP` header. `None` for unbound minting paths such as
    /// internal admin minting or debug seeds without a `dpop_jwk`.
    pub dpop_jkt: Option<String>,
    /// Stable refresh-chain id. It is allocated independently from `grant_id`.
    pub session_id: String,
    /// Canonical issuer_id nonce committed by the signed issuance preimage.
    pub issuance_nonce: String,
    /// Exact RFC 8785/JCS bytes from which `grant_id` was derived.
    pub issuance_preimage: Vec<u8>,
    /// SHA-256 of `issuance_preimage`.
    pub issuance_digest: [u8; 32],
    /// Issuer key id used to sign the durable JWT outcome.
    pub signing_key_id: String,
}

/// Issuer-generated values durably fixed by the operation reservation.
///
/// A retry MUST reconstruct this value from the reserved operation instead of
/// drawing new randomness, otherwise the same request identity could produce a
/// different preimage, grant id and JWT after an authorization checkpoint.
#[derive(Debug, Clone)]
pub(crate) struct SessionGrantIssuanceSeed {
    pub issuance_nonce: SessionGrantIssuanceNonce,
    pub session_id: String,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signing_key_id: String,
}

impl SessionGrantIssuanceSeed {
    pub(crate) fn new(
        issuance_nonce: impl Into<String>,
        session_id: impl Into<String>,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        signing_key_id: impl Into<String>,
    ) -> Result<Self, arkret_wire::WireError> {
        let not_before = arkret_canonical::normalize_timestamp_canonical(not_before);
        let expires_at = arkret_canonical::normalize_timestamp_canonical(expires_at);
        let session_id = session_id.into();
        if session_id.trim().is_empty() {
            return Err(arkret_wire::WireError::Protocol(
                "reserved session_id must not be empty".to_owned(),
            ));
        }
        let signing_key_id = signing_key_id.into();
        if expires_at <= not_before || signing_key_id.trim().is_empty() {
            return Err(arkret_wire::WireError::Protocol(
                "reserved issuance window and signing key id are invalid".to_owned(),
            ));
        }
        Ok(Self {
            issuance_nonce: SessionGrantIssuanceNonce::new(issuance_nonce)?,
            session_id,
            not_before,
            expires_at,
            signing_key_id,
        })
    }

    pub(crate) fn from_operation(
        operation: &coauth_data::SessionGrantOperation,
    ) -> Result<Self, arkret_wire::WireError> {
        let issuance_nonce = operation.issuance_nonce.clone().ok_or_else(|| {
            arkret_wire::WireError::Protocol(
                "reserved issue/refresh operation is missing issuance_nonce".to_owned(),
            )
        })?;
        let session_id = operation.session_id.clone().ok_or_else(|| {
            arkret_wire::WireError::Protocol(
                "reserved issue/refresh operation is missing session_id".to_owned(),
            )
        })?;
        let not_before = operation.grant_not_before.ok_or_else(|| {
            arkret_wire::WireError::Protocol(
                "reserved issue/refresh operation is missing grant_not_before".to_owned(),
            )
        })?;
        let expires_at = operation.grant_expires_at.ok_or_else(|| {
            arkret_wire::WireError::Protocol(
                "reserved issue/refresh operation is missing grant_expires_at".to_owned(),
            )
        })?;
        let signing_key_id = operation.signing_key_id.clone().ok_or_else(|| {
            arkret_wire::WireError::Protocol(
                "reserved issue/refresh operation is missing signing_key_id".to_owned(),
            )
        })?;
        Self::new(
            issuance_nonce,
            session_id,
            not_before,
            expires_at,
            signing_key_id,
        )
    }
}

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
    pub source_claim_digest: Option<String>,
}
