use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Ulid;
pub use crate::accountability::{
    AccountabilityGrantFanoutState, ParseAccountabilityGrantFanoutStateError,
};
pub use crate::storage::agent_key::*;

/// Durable record of an accepted `ak.agent.key.authorize` (AKP-0008 §4.5).
///
/// coauth delegates runtime pairing verification to the owning Station and
/// retains its authenticated exact result with the encrypted private request.
/// This issuer projection supports the agent-key-proof session branch and
/// retries the unchanged standard key-pair request. The row is
/// usable only after that server durably accepts the supplied
/// `ak.agent.key.authorize` Event. Column order tracks
/// `event-payload.schema.json#/$defs/agent_key_authorize_payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentKeyAuthorization {
    /// Storage row id.
    pub id: Ulid,
    /// Complete suite-tagged content identity of the durable
    /// `ak.agent.key.authorize` Event accepted by the Station. The
    /// session-grant agent branch resolves `agent_key_authorization_ref`
    /// against this id.
    pub authorized_event_id: String,
    /// Agent principal DID the authorized key belongs to.
    pub agent_id: String,
    /// Stable key id (`<verification_method>` fragment scope).
    pub key_id: String,
    /// DID URL of the authorized verification method.
    pub verification_method: String,
    /// Spec `PublicKey` JSON object submitted at pairing.
    pub public_key: serde_json::Value,
    /// Controller DID accountable for the agent.
    pub accountable_principal_id: arkret_identifiers::DidCoreId,
    /// AEAD-encrypted exact authorized key scope in the original text column.
    pub agent_key_scope: String,
    /// Audience values the key proof must match.
    pub audience: Vec<String>,
    /// Authorization issuance timestamp.
    pub issued_at: DateTime<Utc>,
    /// Optional authorization expiry. `None` means the authorization never
    /// expires by time and stays valid until revoked (key-management §3.6.1).
    pub expires_at: Option<DateTime<Utc>>,
    /// Pairing request id consumed to produce this authorization.
    pub pairing_request_id: String,
    /// `sha256:<hex>` digest the pairing proof was bound to.
    pub request_canonical_digest: String,
    /// Timestamp when the authorization was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Reason recorded when the authorization was revoked.
    pub revoked_reason: Option<String>,
    /// Timestamp when full-hash collision evidence quarantined this Event id.
    pub quarantined_at: Option<DateTime<Utc>>,
    /// Internal quarantine discriminator. Protocol responses use
    /// `witness_disagreement`.
    pub quarantine_reason: Option<String>,
    /// `sha256:<hex>` digest of the canonical fan-out payload.
    pub raw_payload_digest: String,
    /// Current coland fan-out state.
    pub coland_fanout_state: AccountabilityGrantFanoutState,
    /// Idempotency key used for coland fan-out and retry jobs.
    pub coland_fanout_idempotency_key: String,
    /// AEAD-encrypted exact request and authenticated Station result.
    pub coland_fanout_payload: serde_json::Value,
    /// Current fan-out attempt count.
    pub coland_fanout_attempt: i32,
    /// Next retry timestamp, if a retry is scheduled.
    pub coland_fanout_next_retry_at: Option<DateTime<Utc>>,
    /// Terminal failure reason, if fan-out entered dead-letter state.
    pub coland_fanout_dead_letter_reason: Option<String>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Row update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Process-only issuer custody of a delegated canonical Station command.
/// This is encrypted inside the existing private ledger; it is not a wire DTO
/// or another verifier's requested-scope presentation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyPairCustody {
    pub request: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
    pub station_id: arkret_identifiers::DidCoreId,
    pub station_name: String,
    pub request_digest: String,
    pub station_outcome: Option<arkret_models_collaboration::agent_operations::AgentKeyPairOutcome>,
}

impl AgentKeyPairCustody {
    /// Seal the whole exact private request and the actual authenticated result.
    pub fn seal(&self, encrypter: &coauth_keyring::Encrypter) -> Result<serde_json::Value, String> {
        let bytes = arkret_canonical::canonical_json_bytes(self)
            .map_err(|_| "Agent pairing custody is not canonical".to_owned())?;
        let encrypted = encrypter
            .encrypt_to_string(&bytes)
            .map_err(|_| "Agent pairing custody encryption failed".to_owned())?;
        Ok(serde_json::Value::String(encrypted))
    }

    /// Plain JSON records are not verifier-private evidence. Do not accept a
    /// legacy plaintext row as a fallback if AEAD authentication fails.
    pub fn open(
        value: &serde_json::Value,
        encrypter: &coauth_keyring::Encrypter,
    ) -> Result<Self, String> {
        let encrypted = value
            .as_str()
            .ok_or_else(|| "Agent pairing custody is not encrypted".to_owned())?;
        let bytes = encrypter
            .decrypt_string(encrypted)
            .map_err(|_| "Agent pairing custody authentication failed".to_owned())?;
        serde_json::from_slice(&bytes).map_err(|_| "Agent pairing custody is invalid".to_owned())
    }

    /// Match AEAD-protected identity to the row and the explicitly configured
    /// authenticated delegate. A ciphertext copied to another row is rejected.
    pub fn validate_for(
        &self,
        authorization: &AgentKeyAuthorization,
        station_id: &arkret_identifiers::DidCoreId,
        station_name: &str,
    ) -> Result<(), String> {
        use arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey;
        let key = AgentAuthorizedSigningKey::from_event(&self.request.authorize_event.event)
            .map_err(|_| "Agent pairing custody authorization is invalid".to_owned())?;
        let disclosure = &self.request.requested_scope_disclosure;
        let payload = arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(&self.request.authorize_event.event)
            .map_err(|_| "Agent pairing custody payload is invalid".to_owned())?;
        let digest = arkret_canonical::canonical_sha256(&self.request)
            .map_err(|_| "Agent pairing custody digest is invalid".to_owned())?;
        disclosure
            .validate()
            .map_err(|_| "Agent pairing custody disclosure is invalid".to_owned())?;
        let controller = self
            .request
            .authorize_event
            .event
            .executed_by
            .as_ref()
            .and_then(arkret_wire::ActorId::as_account_id)
            .ok_or_else(|| "Agent pairing custody controller Account is missing".to_owned())?;
        let expected_request_id = self
            .request
            .pairing_request_id
            .as_str()
            .strip_prefix("agent_pairing_request:")
            .map(|suffix| format!("ak:request:{suffix}"));
        let valid = &self.station_id == station_id
            && &disclosure.verifier_id == station_id
            && disclosure.audience.as_str()
                == arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1
            && disclosure.challenge.as_str() == self.request.pairing_request_id.as_str()
            && expected_request_id.as_deref() == Some(disclosure.request_id.as_str())
            && controller.principal_id == authorization.accountable_principal_id
            && payload.approval_evidence.approved_by.as_ref() == Some(&controller.principal_id)
            && payload.approval_evidence.pairing_request_id.as_ref()
                == Some(&self.request.pairing_request_id)
            && self.station_name == station_name
            && self.request_digest == digest
            && digest == authorization.raw_payload_digest
            && self.request.authorize_event.event.event_id.as_str()
                == authorization.authorized_event_id
            && self.request.pairing_request_id.as_str() == authorization.pairing_request_id
            && self
                .request
                .authorize_event
                .event
                .actor_id
                .as_account_id()
                .is_some_and(|account| {
                    account.principal_id.as_str() == authorization.agent_id
                        && &account.station_id == station_id
                })
            && serde_json::to_value(&payload.public_key).ok().as_ref()
                == Some(&authorization.public_key)
            && payload.key_id.as_str() == authorization.key_id
            && payload.issued_at == authorization.issued_at
            && payload.expires_at == authorization.expires_at
            && payload
                .approval_evidence
                .request_canonical_digest
                .as_ref()
                .is_some_and(|digest| digest.as_str() == authorization.request_canonical_digest)
            && key.agent_id.as_str() == authorization.agent_id
            && key.verification_method.as_str() == authorization.verification_method
            && key.controller_principal_id.as_str()
                == authorization.accountable_principal_id.as_str()
            && disclosure.agent_id.as_str() == authorization.agent_id
            && disclosure.controller_principal_id == authorization.accountable_principal_id
            && payload
                .audience
                .iter()
                .any(|audience| audience == disclosure.verifier_id.as_str())
            && authorization
                .audience
                .iter()
                .any(|audience| audience == disclosure.verifier_id.as_str())
            && self.station_outcome.as_ref().is_none_or(|outcome| {
                outcome.authorize_event_ref.as_str() == authorization.authorized_event_id
            });
        if !valid {
            return Err("Agent pairing custody identity mismatch".to_owned());
        }
        Ok(())
    }

    /// Keep the derived private scope encrypted in its existing text column.
    pub fn sealed_key_scope(
        &self,
        encrypter: &coauth_keyring::Encrypter,
    ) -> Result<String, String> {
        let payload = arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(&self.request.authorize_event.event)
            .map_err(|_| "Agent pairing custody authorization is invalid".to_owned())?;
        let scope = arkret_canonical::canonical_json_bytes(&payload.agent_key_scope)
            .map_err(|_| "Agent key scope is invalid".to_owned())?;
        encrypter
            .encrypt_to_string(&scope)
            .map_err(|_| "Agent key scope encryption failed".to_owned())
    }
}
