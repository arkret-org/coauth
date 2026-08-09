//! Durable state for canonical account handoff and first-principal binding.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Ulid;
pub use crate::storage::account_handoff::AccountHandoffRepository;

/// Closed lifecycle for the durable, authorization-code-backed handoff
/// creation fence. `Reserved` means an external exchange may already have
/// consumed the code, so an uncheckpointed retry must fail indeterminate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountHandoffCreationAttemptState {
    Reserved,
    Authorized,
    Committed,
}

impl AccountHandoffCreationAttemptState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Authorized => "authorized",
            Self::Committed => "committed",
        }
    }
}

impl TryFrom<&str> for AccountHandoffCreationAttemptState {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "reserved" => Ok(Self::Reserved),
            "authorized" => Ok(Self::Authorized),
            "committed" => Ok(Self::Committed),
            other => Err(format!(
                "unknown account handoff creation attempt state: {other}"
            )),
        }
    }
}

/// Durable fence for one account-handoff creation request. Sensitive OIDC
/// material is represented only by digests in `canonical_intent`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountHandoffAuthorizationCheckpoint {
    pub service_account_id: String,
    pub browser_session_id: Option<String>,
    pub audience: String,
    pub account_handle: String,
    pub preferred_locale: Option<String>,
}

/// Durable fence for one account-handoff creation request. Sensitive OIDC
/// material is represented only by digests in `canonical_intent`.
#[derive(Clone, Debug)]
pub struct AccountHandoffCreationAttempt {
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub canonical_intent_digest: arkret_identifiers::Hash,
    pub canonical_intent: Vec<u8>,
    pub holder_jkt: String,
    pub issuer: String,
    pub client_id: String,
    pub authorization_code_digest: arkret_identifiers::Hash,
    pub dpop_jti_digest: arkret_identifiers::Hash,
    pub state: AccountHandoffCreationAttemptState,
    pub authorization_checkpoint: Option<AccountHandoffAuthorizationCheckpoint>,
    pub canonical_outcome: Option<Vec<u8>>,
    pub outcome_digest: Option<arkret_identifiers::Hash>,
    pub retained_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub authorized_at: Option<DateTime<Utc>>,
    pub committed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct NewAccountHandoffCreationAttempt {
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub canonical_intent_digest: arkret_identifiers::Hash,
    pub canonical_intent: Vec<u8>,
    pub holder_jkt: String,
    pub issuer: String,
    pub client_id: String,
    pub authorization_code_digest: arkret_identifiers::Hash,
    pub dpop_jti_digest: arkret_identifiers::Hash,
    pub retained_until: DateTime<Utc>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum AccountHandoffCreationAttemptReserve {
    /// This transaction installed the durable external-call fence.
    Reserved(AccountHandoffCreationAttempt),
    /// The same request is already fenced. `Authorized` may be resumed;
    /// `Reserved` must not repeat the external exchange.
    Pending(AccountHandoffCreationAttempt),
    Replay(AccountHandoffCreationAttempt),
    Conflict(AccountHandoffCreationAttempt),
    Indeterminate(AccountHandoffCreationAttempt),
}

#[derive(Clone, Debug)]
pub enum AccountHandoffCreationAttemptCommit {
    Committed(AccountHandoffCreationAttempt),
    Replay(AccountHandoffCreationAttempt),
    Conflict(AccountHandoffCreationAttempt),
    Indeterminate(AccountHandoffCreationAttempt),
}

#[derive(Clone)]
pub struct AccountHandoffGrant {
    pub id: Ulid,
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub service_account_id: Ulid,
    pub browser_session_id: Option<Ulid>,
    pub audience: String,
    pub cnf_jkt: String,
    pub allowed_operations: [arkret_models_identity::AccountHandoffAllowedOperation; 4],
    pub account_handoff_grant: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for AccountHandoffGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountHandoffGrant")
            .field("id", &self.id)
            .field("request_id", &self.request_id)
            .field("request_digest", &self.request_digest)
            .field("service_account_id", &self.service_account_id)
            .field("browser_session_id", &self.browser_session_id)
            .field("audience", &self.audience)
            .field("cnf_jkt", &self.cnf_jkt)
            .field("allowed_operations", &self.allowed_operations)
            .field("account_handoff_grant", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct AccountHandoffGrantInput {
    pub id: Ulid,
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub service_account_id: Ulid,
    pub browser_session_id: Option<Ulid>,
    pub audience: String,
    pub cnf_jkt: String,
    pub account_handoff_grant: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub lease_id: String,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityCreationSagaState {
    Active,
    Reserved,
    DidPublished,
    PcrAccepted,
    AccountBound,
    Completed,
}

impl IdentityCreationSagaState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::DidPublished => "did_published",
            Self::PcrAccepted => "pcr_accepted",
            Self::AccountBound => "account_bound",
            Self::Completed => "completed",
        }
    }
}

impl TryFrom<&str> for IdentityCreationSagaState {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "active" => Ok(Self::Active),
            "reserved" => Ok(Self::Reserved),
            "did_published" => Ok(Self::DidPublished),
            "pcr_accepted" => Ok(Self::PcrAccepted),
            "account_bound" => Ok(Self::AccountBound),
            "completed" => Ok(Self::Completed),
            other => Err(format!("unknown identity creation saga state: {other}")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct IdentityCreationLeaseRecord {
    pub service_account_id: Ulid,
    pub audience: String,
    pub lease_id: String,
    pub holder_jkt: String,
    pub fence: u64,
    pub expires_at: DateTime<Utc>,
    pub reserved_identity: Option<arkret_models_identity::ReservedIdentityCreation>,
    pub state: IdentityCreationSagaState,
    pub registry_receipt: Option<arkret_models_identity::DidOperationSubmitOutcome>,
    pub head_event_digest: Option<arkret_identifiers::Hash>,
    pub pcr_genesis_request_digest: Option<arkret_identifiers::Hash>,
    pub pcr_genesis_receipt:
        Option<arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome>,
    pub binding_receipt: Option<arkret_models_identity::AccountBindingReceipt>,
    pub register_ledger: Option<IdentityCreationRegisterLedger>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl IdentityCreationLeaseRecord {
    pub fn wire_lease(&self) -> arkret_models_identity::IdentityCreationLease {
        arkret_models_identity::IdentityCreationLease {
            lease_id: self.lease_id.clone(),
            fence: self.fence,
            expires_at: self.expires_at,
            reserved_identity: self.reserved_identity.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct IdentityCreationRegisterLedger {
    pub handoff_grant_id: Ulid,
    pub challenge_id: String,
    pub request_digest: arkret_identifiers::Hash,
    pub outcome: arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome,
}

#[derive(Clone, Debug)]
pub enum IdentityCreationRegisterReplay {
    Pending,
    // Boxed: the outcome is ~1 KiB while every other variant is a unit, so an
    // inline payload would make each `Pending` cost the same as a full replay.
    Replay(Box<arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome>),
    DuplicateConflict,
}

#[derive(Clone, Debug)]
pub enum IdentityCreationBindingCommit {
    Committed,
    // Boxed for the same reason as `IdentityCreationRegisterReplay::Replay`.
    Replay(Box<arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome>),
    DuplicateConflict,
    Stale,
}

#[derive(Clone, Debug)]
pub enum AccountHandoffCreation {
    Active {
        grant: AccountHandoffGrant,
        lease: Box<IdentityCreationLeaseRecord>,
    },
    Busy {
        grant: AccountHandoffGrant,
        retry_after_ms: u64,
        expires_at: DateTime<Utc>,
    },
    Bound {
        grant: AccountHandoffGrant,
        principal_id: arkret_identifiers::Did,
    },
    DuplicateConflict,
    ExpiredReplay,
}

#[derive(Clone, Debug)]
pub struct IdentityBindingChallengeInput {
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub service_account_id: Ulid,
    pub audience: String,
    pub lease_id: String,
    pub lease_fence: u64,
    pub holder_jkt: String,
    pub did_operation: arkret_models_identity::DidOperationSubmitRequestBody,
    pub operation_digest: arkret_identifiers::Hash,
    pub account_subject: arkret_identifiers::Hash,
    pub did_version_id: String,
    pub log_head_digest: arkret_identifiers::Hash,
    pub control_key_digest: arkret_identifiers::Hash,
    pub pcr_realm_id: arkret_identifiers::RealmId,
    pub realm_create_payload_digest: arkret_identifiers::Hash,
    pub founding_authorize_payload_digest: arkret_identifiers::Hash,
    pub initial_session_request_digest: arkret_identifiers::Hash,
    pub challenge_id: String,
    pub challenge: String,
    pub origin: String,
    pub trust_domain: arkret_identifiers::TypedTrustDomainId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct IdentityBindingChallengeRecord {
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub service_account_id: Ulid,
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: arkret_models_identity::IdentityBindingPurpose,
    pub account_subject: arkret_identifiers::Hash,
    pub principal_id: arkret_identifiers::Did,
    pub operation_digest: arkret_identifiers::Hash,
    pub did_version_id: String,
    pub log_head_digest: arkret_identifiers::Hash,
    pub control_key_digest: arkret_identifiers::Hash,
    pub pcr_realm_id: arkret_identifiers::RealmId,
    pub realm_create_payload_digest: arkret_identifiers::Hash,
    pub founding_authorize_payload_digest: arkret_identifiers::Hash,
    pub initial_session_request_digest: arkret_identifiers::Hash,
    pub lease_id: String,
    pub lease_fence: u64,
    pub dpop_jkt: String,
    pub audience: arkret_identifiers::Did,
    pub origin: String,
    pub trust_domain: arkret_identifiers::TypedTrustDomainId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub replaced_at: Option<DateTime<Utc>>,
}

impl IdentityBindingChallengeRecord {
    pub fn wire_outcome(&self) -> arkret_models_identity::IdentityBindingChallengeOutcome {
        arkret_models_identity::IdentityBindingChallengeOutcome {
            request_id: self.request_id.clone(),
            challenge_id: self.challenge_id.clone(),
            challenge: self.challenge.clone(),
            purpose: self.purpose,
            account_subject: self.account_subject.clone(),
            principal_id: self.principal_id.clone(),
            operation_digest: self.operation_digest.clone(),
            did_version_id: self.did_version_id.clone(),
            log_head_digest: self.log_head_digest.clone(),
            control_key_digest: self.control_key_digest.clone(),
            pcr_realm_id: self.pcr_realm_id.clone(),
            realm_create_payload_digest: self.realm_create_payload_digest.clone(),
            founding_authorize_payload_digest: self.founding_authorize_payload_digest.clone(),
            initial_session_request_digest: self.initial_session_request_digest.clone(),
            genesis_unit_kinds: arkret_models_identity::PCR_GENESIS_UNIT_KINDS,
            identity_creation_lease_id: self.lease_id.clone(),
            lease_fence: self.lease_fence,
            dpop_jkt: self.dpop_jkt.clone(),
            audience: self.audience.clone(),
            origin: self.origin.clone(),
            trust_domain: self.trust_domain.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Clone, Debug)]
pub enum IdentityBindingChallengeIssue {
    Issued(IdentityBindingChallengeRecord),
    Replay(IdentityBindingChallengeRecord),
    DuplicateConflict,
    LeaseMismatch,
    ReservationConflict,
    StaleRequest,
}

#[derive(Clone, Debug)]
pub struct IdentityCreationRegistrationContext {
    pub grant: AccountHandoffGrant,
    pub lease: IdentityCreationLeaseRecord,
    pub challenge: IdentityBindingChallengeRecord,
}
