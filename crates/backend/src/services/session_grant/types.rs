use arkret_identifiers::{DeviceId, DidCoreId, EventId, SessionGrantId, SessionGrantSecret};
use arkret_models_identity::{
    SessionGrantDeviceBinding, SessionGrantMetadata, SessionGrantProofKind,
};
use arkret_wire::DidUrl;
use chrono::{DateTime, Utc};
use coauth_data::{BrowserSession, LocalAccountId};
use coauth_jose::jwk::PublicJsonWebKey;
use serde::{Deserialize, Serialize};

/// Issuer material. Query projections are checked against the sole metadata record at commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantMaterial {
    pub grant_id: SessionGrantId,
    pub session_grant: SessionGrantSecret,
    pub metadata: SessionGrantMetadata,
    pub session_public_key: String,
    pub credential_class: String,
    pub expires_at: String,
    pub expires_at_timestamp: DateTime<Utc>,
    pub not_before_timestamp: DateTime<Utc>,
    pub issuer_id: DidCoreId,
    pub account_id: arkret_wire::AccountId,
    pub subject_id: DidCoreId,
    pub local_account_id: LocalAccountId,
    pub device_id: Option<String>,
    pub audience_id: DidCoreId,
    pub scopes: Vec<String>,
    pub dpop_jkt: Option<String>,
    pub session_id: String,
}

/// Random values and the immutable window are allocated once in the existing reservation.
/// A pending reservation does not authorize the secret; only the atomic grant commit does.
#[derive(Debug, Clone)]
pub(crate) struct SessionGrantIssuanceSeed {
    pub grant_id: SessionGrantId,
    pub session_grant: SessionGrantSecret,
    pub session_id: String,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl SessionGrantIssuanceSeed {
    #[cfg(test)]
    pub(crate) fn allocate(
        rng: &mut (dyn rand_core::RngCore + Send),
        session_id: impl Into<String>,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, arkret_wire::WireError> {
        let unix_ms = u64::try_from(not_before.timestamp_millis()).map_err(|_| {
            arkret_wire::WireError::Protocol("issuer clock is outside UUIDv7 range".into())
        })?;
        let mut secret = [0_u8; 32];
        rng.fill_bytes(&mut secret);
        Self::new(
            SessionGrantId::new_v7_at(unix_ms),
            SessionGrantSecret::from_bytes(secret),
            session_id,
            not_before,
            expires_at,
        )
    }

    pub(crate) fn new(
        grant_id: SessionGrantId,
        session_grant: SessionGrantSecret,
        session_id: impl Into<String>,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, arkret_wire::WireError> {
        let not_before = arkret_canonical::normalize_timestamp_canonical(not_before);
        let expires_at = arkret_canonical::normalize_timestamp_canonical(expires_at);
        let session_id = session_id.into();
        if session_id.trim().is_empty()
            || session_id.starts_with("ak:")
            || session_id.len() > 255
            || expires_at <= not_before
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid reserved session chain or issuance window".to_owned(),
            ));
        }
        Ok(Self {
            grant_id,
            session_grant,
            session_id,
            not_before,
            expires_at,
        })
    }

    pub(crate) fn from_operation(
        operation: &coauth_data::SessionGrantOperation,
    ) -> Result<Self, arkret_wire::WireError> {
        let missing = || {
            arkret_wire::WireError::Protocol(
                "reserved grant-producing operation has incomplete issuer material".to_owned(),
            )
        };
        Self::new(
            operation.reserved_grant_id.clone().ok_or_else(missing)?,
            operation
                .reserved_session_grant
                .clone()
                .ok_or_else(missing)?,
            operation.session_id.clone().ok_or_else(missing)?,
            operation.grant_not_before.ok_or_else(missing)?,
            operation.grant_expires_at.ok_or_else(missing)?,
        )
    }
}

pub(crate) struct HumanGrantIssuance<'a> {
    pub browser_session: &'a BrowserSession,
    pub session_public_key: PublicJsonWebKey,
    pub audience_id: DidCoreId,
    pub device_id: DeviceId,
    pub scopes: Vec<String>,
    pub subject_override: Option<&'a DidCoreId>,
    pub account_id: &'a arkret_wire::AccountId,
    pub dpop_jkt: String,
    pub device_binding: SessionGrantDeviceBinding,
    pub proof_kind: SessionGrantProofKind,
}

pub(crate) struct RecoveryGrantIssuance<'a> {
    pub session_public_key: PublicJsonWebKey,
    pub audience_id: DidCoreId,
    pub device_id: DeviceId,
    pub scopes: Vec<String>,
    pub subject_id: &'a DidCoreId,
    pub local_account_id: LocalAccountId,
    pub account_id: &'a arkret_wire::AccountId,
    pub dpop_jkt: String,
}

pub(crate) struct AgentGrantIssuance<'a> {
    pub agent_id: &'a DidCoreId,
    pub local_account_id: LocalAccountId,
    pub audience_id: DidCoreId,
    pub scopes: Vec<String>,
    pub dpop_jkt: String,
    pub session_public_key: String,
    pub scope_details: serde_json::Map<String, serde_json::Value>,
    pub agent_key_authorization_ref: EventId,
    pub verification_method: DidUrl,
}

#[cfg(test)]
pub(crate) struct TestGrantIssuance<'a> {
    pub browser_session: &'a BrowserSession,
    pub session_public_key: PublicJsonWebKey,
    pub subject_id: &'a str,
    pub account_id: &'a arkret_wire::AccountId,
    pub device_id: DeviceId,
    pub scopes: Vec<String>,
}
