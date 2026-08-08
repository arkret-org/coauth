//! Durable state for canonical account handoff and first-principal binding.

use chrono::{DateTime, Utc};

use crate::Ulid;
pub use crate::storage::account_handoff::AccountHandoffRepository;

#[derive(Clone, Debug, PartialEq)]
pub enum FirstDeviceEnrollmentCommit {
    Committed,
    Replay(serde_json::Value),
    Conflict,
}

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
    pub authorization_checkpoint: Option<serde_json::Value>,
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

/// Closed lifecycle of a device-bootstrap transaction. An enrollment-authority
/// signature does not make the transaction `Accepted`; only the Principal
/// Server's atomic founding batch acceptance may perform that transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceBootstrapTransactionState {
    Pending,
    Accepted,
    Cancelled,
    Expired,
}

impl DeviceBootstrapTransactionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

impl TryFrom<&str> for DeviceBootstrapTransactionState {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            other => Err(format!(
                "unknown device bootstrap transaction state: {other}"
            )),
        }
    }
}

/// Durable issuer ledger for one closed founding bootstrap transaction.
#[derive(Clone, Debug)]
pub struct DeviceBootstrapTransaction {
    pub transaction_id: arkret_wire::ProtocolOpaqueId,
    pub mode: arkret_models_collaboration::contact_operations::BootstrapMode,
    pub account_authority_id: arkret_identifiers::Did,
    pub principal_server_id: arkret_identifiers::Did,
    pub principal_id: arkret_identifiers::Did,
    pub device_id: arkret_identifiers::DeviceId,
    pub device_key_digest: arkret_identifiers::Hash,
    pub holder_jkt: String,
    pub canonical_request_digest: arkret_identifiers::Hash,
    pub canonical_request: Vec<u8>,
    pub founding_batch_digest: arkret_identifiers::Hash,
    pub founding_event_ids: Vec<arkret_identifiers::EventId>,
    pub bootstrap_grant_id: arkret_identifiers::SessionGrantId,
    pub state: DeviceBootstrapTransactionState,
    pub enrollment_request_digest: Option<arkret_identifiers::Hash>,
    pub canonical_enrollment_outcome: Option<Vec<u8>>,
    pub enrollment_outcome_digest: Option<arkret_identifiers::Hash>,
    pub authorized_event_id: Option<arkret_identifiers::EventId>,
    pub authorized_event_digest: Option<arkret_identifiers::Hash>,
    pub standard_grant_id: Option<arkret_identifiers::SessionGrantId>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub enrolled_at: Option<DateTime<Utc>>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub cancelled_at: Option<DateTime<Utc>>,
    pub expired_at: Option<DateTime<Utc>>,
    /// Principal Server notary identity for the immutable terminal decision.
    pub decision_principal_server_id: Option<arkret_identifiers::Did>,
    /// Canonical JCS bytes of the signed Principal Server receipt.
    pub canonical_decision_receipt: Option<Vec<u8>>,
    /// Domain-separated receipt digest retained for v1 audit/replay.
    pub decision_receipt_digest: Option<arkret_identifiers::Hash>,
}

/// Immutable founding material installed in the same issuer transaction as
/// the `device_bootstrap` session grant.
#[derive(Clone, Debug)]
pub struct NewDeviceBootstrapTransaction {
    pub transaction_id: arkret_wire::ProtocolOpaqueId,
    pub mode: arkret_models_collaboration::contact_operations::BootstrapMode,
    pub account_authority_id: arkret_identifiers::Did,
    pub principal_server_id: arkret_identifiers::Did,
    pub principal_id: arkret_identifiers::Did,
    pub device_id: arkret_identifiers::DeviceId,
    pub device_key_digest: arkret_identifiers::Hash,
    pub holder_jkt: String,
    pub canonical_request_digest: arkret_identifiers::Hash,
    pub canonical_request: Vec<u8>,
    pub founding_batch_digest: arkret_identifiers::Hash,
    pub founding_event_ids: Vec<arkret_identifiers::EventId>,
    pub bootstrap_grant_id: arkret_identifiers::SessionGrantId,
    pub expires_at: DateTime<Utc>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum DeviceBootstrapTransactionCreate {
    Created(DeviceBootstrapTransaction),
    Replay(DeviceBootstrapTransaction),
    Conflict(DeviceBootstrapTransaction),
}

#[derive(Clone, Copy, Debug)]
pub struct DeviceBootstrapEnrollmentReservationInput<'a> {
    pub transaction_id: &'a arkret_wire::ProtocolOpaqueId,
    pub principal_id: &'a arkret_identifiers::Did,
    pub device_id: &'a arkret_identifiers::DeviceId,
    pub request_digest: &'a arkret_identifiers::Hash,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum DeviceBootstrapEnrollmentReserve {
    Reserved(DeviceBootstrapTransaction),
    /// The local deadline elapsed but no Principal Server terminal receipt
    /// has been verified. The transaction remains durably pending.
    RequiresDecision(DeviceBootstrapTransaction),
    Replay(DeviceBootstrapTransaction),
    Conflict(DeviceBootstrapTransaction),
    Cancelled(DeviceBootstrapTransaction),
    Expired(DeviceBootstrapTransaction),
    NotFound,
}

/// Exact enrollment-authority outcome commit. This deliberately leaves the
/// transaction pending until the founding Event batch is accepted elsewhere.
#[derive(Clone, Debug)]
pub struct DeviceBootstrapEnrollmentInput<'a> {
    pub transaction_id: &'a arkret_wire::ProtocolOpaqueId,
    pub principal_id: &'a arkret_identifiers::Did,
    pub device_id: &'a arkret_identifiers::DeviceId,
    pub request_digest: &'a arkret_identifiers::Hash,
    pub authorized_event_id: &'a arkret_identifiers::EventId,
    pub authorized_event_digest: &'a arkret_identifiers::Hash,
    pub canonical_outcome: &'a [u8],
    pub outcome_digest: &'a arkret_identifiers::Hash,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum DeviceBootstrapEnrollmentCommit {
    Committed(DeviceBootstrapTransaction),
    /// The local deadline elapsed but no Principal Server terminal receipt
    /// has been verified. The transaction remains durably pending.
    RequiresDecision(DeviceBootstrapTransaction),
    Replay(DeviceBootstrapTransaction),
    Conflict(DeviceBootstrapTransaction),
    Cancelled(DeviceBootstrapTransaction),
    Expired(DeviceBootstrapTransaction),
    NotFound,
}

#[derive(Clone, Debug)]
pub struct DeviceBootstrapCancelOperation {
    pub transaction_id: arkret_wire::ProtocolOpaqueId,
    pub idempotency_key: arkret_wire::IdempotencyKey,
    pub canonical_request_digest: arkret_identifiers::Hash,
    pub canonical_request: Vec<u8>,
    pub authority_request:
        arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRequestBody,
    pub canonical_authority_request: Vec<u8>,
    pub canonical_outcome: Option<Vec<u8>>,
    pub outcome_digest: Option<arkret_identifiers::Hash>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct DeviceBootstrapCancelReserveInput {
    pub request: arkret_models_collaboration::contact_operations::CancelDeviceBootstrapRequestBody,
    pub canonical_request_digest: arkret_identifiers::Hash,
    pub canonical_request: Vec<u8>,
    pub authority_request:
        arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRequestBody,
    pub canonical_authority_request: Vec<u8>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum DeviceBootstrapCancelReserve {
    Reserved(DeviceBootstrapCancelOperation),
    Replay(DeviceBootstrapCancelOperation),
    Conflict,
    Terminal(DeviceBootstrapTransaction),
    NotFound,
}

#[derive(Clone, Debug)]
pub struct DeviceBootstrapCancelInput {
    pub request: arkret_models_collaboration::contact_operations::CancelDeviceBootstrapRequestBody,
    pub canonical_request_digest: arkret_identifiers::Hash,
    pub canonical_request: Vec<u8>,
    pub decision: DeviceBootstrapCancelDecision,
    pub authority: DeviceBootstrapDecisionEvidence,
    pub now: DateTime<Utc>,
}

/// Fully request-bound Principal Server decision evidence. The backend
/// cryptographically verifies the detached proof; storage independently
/// validates every closed request/transaction field before retaining the
/// canonical receipt in the same transaction as the lifecycle transition.
#[derive(Clone, Debug)]
pub struct DeviceBootstrapDecisionEvidence {
    pub request:
        arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionRequestBody,
    pub outcome: arkret_models_collaboration::contact_operations::DeviceBootstrapDecisionOutcome,
    pub canonical_receipt: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub enum DeviceBootstrapCancelDecision {
    /// The Principal Server proved that the founding batch is already
    /// accepted. The client cancel operation commits an exact 409 response.
    Accept,
    Cancel,
    /// The Principal Server's durable decision fence proved that the
    /// founding transaction is expired. This is distinct from a local clock
    /// observation and may therefore be committed even when the Account
    /// Authority clock is marginally behind.
    Expire,
}

#[derive(Clone, Debug)]
pub enum DeviceBootstrapCancelCommit {
    Committed {
        transaction: DeviceBootstrapTransaction,
        operation: DeviceBootstrapCancelOperation,
    },
    Replay(DeviceBootstrapCancelOperation),
    Conflict,
    Accepted(DeviceBootstrapTransaction),
    Cancelled(DeviceBootstrapTransaction),
    Expired(DeviceBootstrapTransaction),
    NotFound,
}

#[derive(Clone, Debug)]
pub enum DeviceBootstrapAcceptanceCommit {
    Accepted(DeviceBootstrapTransaction),
    Replay(DeviceBootstrapTransaction),
    Conflict(DeviceBootstrapTransaction),
    Cancelled(DeviceBootstrapTransaction),
    Expired(DeviceBootstrapTransaction),
    NotFound,
}

/// Borrowed inputs for the founding-device enrollment commit. The slot is
/// keyed by `(service_account_id, audience, principal_id)` and the replay
/// decision compares `(device_id, request_digest)`, so the whole tuple travels
/// together.
#[derive(Clone, Copy, Debug)]
pub struct FirstDeviceEnrollmentInput<'a> {
    pub service_account_id: Ulid,
    pub audience: &'a str,
    pub principal_id: &'a arkret_identifiers::Did,
    pub device_id: &'a arkret_identifiers::DeviceId,
    pub request_digest: &'a arkret_identifiers::Hash,
    pub outcome: &'a serde_json::Value,
    pub now: DateTime<Utc>,
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
    pub allowed_operations: [arkret_models_identity::AccountHandoffAllowedOperation; 3],
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
    Published,
    Bound,
}

impl IdentityCreationSagaState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Published => "published",
            Self::Bound => "bound",
        }
    }
}

impl TryFrom<&str> for IdentityCreationSagaState {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "active" => Ok(Self::Active),
            "reserved" => Ok(Self::Reserved),
            "published" => Ok(Self::Published),
            "bound" => Ok(Self::Bound),
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
    pub registry_receipt: Option<serde_json::Value>,
    pub head_event_digest: Option<arkret_identifiers::Hash>,
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
    pub principal_id: arkret_identifiers::Did,
    pub operation_digest: arkret_identifiers::Hash,
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
            principal_id: self.principal_id.clone(),
            operation_digest: self.operation_digest.clone(),
            lease_id: self.lease_id.clone(),
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
