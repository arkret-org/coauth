//! Durable state for canonical account handoff and first-principal binding.

use arkret_identifiers::WebOrigin;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Ulid;
pub use crate::storage::account_handoff::AccountHandoffRepository;

/// Durable issuance fence for one Account Authority controller gate request.
#[derive(Clone, Debug)]
pub struct ControllerGateAttestationIssuance {
    pub request_id: arkret_identifiers::RequestId,
    pub canonical_intent_digest: arkret_identifiers::Hash,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub agent_authority_id: arkret_identifiers::DidCoreId,
    pub canonical_outcome: Option<Vec<u8>>,
    pub outcome_digest: Option<arkret_identifiers::Hash>,
    pub attestation_expires_at: Option<DateTime<Utc>>,
    pub retained_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub committed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct NewControllerGateAttestationIssuance {
    pub request_id: arkret_identifiers::RequestId,
    pub canonical_intent_digest: arkret_identifiers::Hash,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub agent_authority_id: arkret_identifiers::DidCoreId,
    pub retained_until: DateTime<Utc>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum ControllerGateAttestationReserve {
    Reserved(ControllerGateAttestationIssuance),
    Replay(ControllerGateAttestationIssuance),
    Conflict(ControllerGateAttestationIssuance),
    Indeterminate(ControllerGateAttestationIssuance),
}

#[derive(Clone, Debug)]
pub enum ControllerGateAttestationCommit {
    Committed(ControllerGateAttestationIssuance),
    Replay(ControllerGateAttestationIssuance),
    Conflict(ControllerGateAttestationIssuance),
    Indeterminate(ControllerGateAttestationIssuance),
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountHandoffAuthorizationCheckpoint {
    pub local_account_id: String,
    pub browser_session_id: Option<String>,
    pub audience_id: arkret_identifiers::DidCoreId,
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
    pub local_account_id: Ulid,
    pub browser_session_id: Option<Ulid>,
    pub audience_id: String,
    pub cnf_jkt: String,
    pub allowed_operations: [arkret_models_identity::AccountHandoffAllowedOperation; 7],
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
            .field("local_account_id", &self.local_account_id)
            .field("browser_session_id", &self.browser_session_id)
            .field("audience_id", &self.audience_id)
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
    pub local_account_id: Ulid,
    pub browser_session_id: Option<Ulid>,
    pub audience_id: String,
    /// Stable, non-reversible subject used to serialize and rate-limit lease
    /// acquisition without persisting the raw upstream OIDC subject.
    pub account_subject: arkret_identifiers::Hash,
    /// The fail-closed account-risk conclusion made before entering the
    /// atomic lease transaction.
    pub risk_decision: IdentityCreationLeaseRiskDecision,
    pub cnf_jkt: String,
    pub account_handoff_grant: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub lease_id: String,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityCreationLeaseRiskDecision {
    Allowed,
    Rejected,
}

#[derive(Clone, Debug)]
pub struct IdentityCreationLeaseRecord {
    pub local_account_id: Ulid,
    pub audience_id: String,
    pub lease_id: String,
    pub holder_jkt: String,
    pub fence: u64,
    pub expires_at: DateTime<Utc>,
    pub reserved_identity: Option<arkret_models_identity::ReservedIdentityCreation>,
    pub state: arkret_models_identity::IdentityCreationLeaseState,
    pub registry_receipt: Option<arkret_models_identity::DidOperationSubmitOutcome>,
    pub log_head_digest: Option<arkret_identifiers::Hash>,
    /// Complete historical registration evidence frozen at the registry's
    /// original acceptance time.  Renewed handoffs and replacement devices
    /// must reuse this object instead of combining a new client proof with an
    /// older registry receipt.
    pub registration_did_evidence: Option<arkret_wire::RegistrationDidEvidence>,
    pub pcr_genesis_request_digest: Option<arkret_identifiers::Hash>,
    pub pcr_genesis_receipt:
        Option<arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome>,
    pub binding_receipt: Option<arkret_models_identity::AccountBindingReceipt>,
    pub register_reservation: Option<IdentityCreationRegisterReservation>,
    pub register_ledger: Option<IdentityCreationRegisterLedger>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl IdentityCreationLeaseRecord {
    pub fn wire_lease(&self) -> arkret_models_identity::IdentityCreationLease {
        arkret_models_identity::IdentityCreationLease {
            identity_creation_lease_id: self.lease_id.clone(),
            fence: self.fence,
            state: self.state,
            expires_at: self.expires_at,
            reserved_identity: self.reserved_identity.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCreationRegisterReservation {
    pub handoff_grant_id: Ulid,
    pub challenge_id: String,
    pub request_digest: arkret_identifiers::Hash,
}

#[derive(Clone, Debug)]
pub struct IdentityCreationRegisterLedger {
    pub handoff_grant_id: Ulid,
    pub challenge_id: String,
    pub request_digest: arkret_identifiers::Hash,
    pub outcome: arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityCreationRegisterReserve {
    Reserved,
    Replay,
    DuplicateConflict,
    Stale,
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
        principal_id: arkret_identifiers::DidCoreId,
        did: arkret_identifiers::Did,
    },
    RateLimited {
        grant: AccountHandoffGrant,
        retry_after_ms: u64,
    },
    RiskRejected {
        grant: AccountHandoffGrant,
    },
    DuplicateConflict,
    ExpiredReplay,
}

#[derive(Clone, Debug)]
pub struct IdentityBindingChallengeInput {
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub local_account_id: Ulid,
    pub audience_id: arkret_identifiers::DidCoreId,
    pub lease_id: String,
    pub lease_fence: u64,
    pub holder_jkt: String,
    pub principal_registration_anchor: arkret_models_identity::PrincipalRegistrationAnchor,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub did: arkret_identifiers::Did,
    pub registration_anchor_digest: arkret_identifiers::Hash,
    pub account_subject: arkret_identifiers::Hash,
    pub did_version_id: String,
    pub method_history_head: arkret_identifiers::Hash,
    pub control_key_digest: arkret_identifiers::Hash,
    pub pcr_realm_id: arkret_identifiers::RealmId,
    pub realm_create_payload_digest: arkret_identifiers::Hash,
    pub founding_authorize_payload_digest: arkret_identifiers::Hash,
    pub initial_session_request_digest: arkret_identifiers::Hash,
    pub challenge_id: String,
    pub challenge: String,
    pub origin: WebOrigin,
    pub trust_domain: arkret_identifiers::TrustDomainId,
    pub handoff_grant_id: Ulid,
    pub challenge_ttl: chrono::Duration,
}

#[derive(Clone, Debug)]
pub struct IdentityBindingChallengeRecord {
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub local_account_id: Ulid,
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: arkret_models_identity::IdentityBindingPurpose,
    pub account_subject: arkret_identifiers::Hash,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub did: arkret_identifiers::Did,
    pub registration_anchor_digest: arkret_identifiers::Hash,
    pub did_version_id: String,
    pub method_history_head: arkret_identifiers::Hash,
    pub control_key_digest: arkret_identifiers::Hash,
    pub pcr_realm_id: arkret_identifiers::RealmId,
    pub realm_create_payload_digest: arkret_identifiers::Hash,
    pub founding_authorize_payload_digest: arkret_identifiers::Hash,
    pub initial_session_request_digest: arkret_identifiers::Hash,
    pub lease_id: String,
    pub lease_fence: u64,
    pub dpop_jkt: String,
    pub audience_id: arkret_identifiers::DidCoreId,
    pub origin: WebOrigin,
    pub trust_domain: arkret_identifiers::TrustDomainId,
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
    Expired,
    Consumed,
    RiskRejected,
    RateLimited { retry_after_ms: u64 },
}

/// Durable challenge for proving control of an already-published DID.
#[derive(Clone, Debug)]
pub struct DidBindingChallengeInput {
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub issuing_handoff_grant_id: Ulid,
    pub local_account_id: Ulid,
    pub account_subject: arkret_identifiers::Hash,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub did: arkret_identifiers::Did,
    pub did_version_id: String,
    pub log_head_digest: arkret_identifiers::Hash,
    pub control_key_digest: arkret_identifiers::Hash,
    pub witness_evidence: Option<String>,
    pub challenge_id: String,
    pub challenge: String,
    pub dpop_jkt: String,
    pub audience_id: arkret_identifiers::DidCoreId,
    pub origin: WebOrigin,
    pub trust_domain: arkret_identifiers::TrustDomainId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct DidBindingChallengeRecord {
    pub input: DidBindingChallengeInput,
    pub consumed_at: Option<DateTime<Utc>>,
    pub register_request_digest: Option<arkret_identifiers::Hash>,
    pub register_outcome:
        Option<Box<arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome>>,
}

impl DidBindingChallengeRecord {
    pub fn wire_outcome(&self) -> arkret_models_identity::DidBindingChallengeOutcome {
        let input = &self.input;
        arkret_models_identity::DidBindingChallengeOutcome {
            request_id: input.request_id.clone(),
            challenge_id: input.challenge_id.clone(),
            challenge: input.challenge.clone(),
            purpose: arkret_models_identity::DidBindingPurpose::AccountBindingForPublishedDid,
            account_subject: input.account_subject.clone(),
            principal_id: input.principal_id.clone(),
            did: input.did.clone(),
            did_version_id: input.did_version_id.clone(),
            control_key_digest: input.control_key_digest.clone(),
            witness_evidence: input.witness_evidence.clone(),
            dpop_jkt: input.dpop_jkt.clone(),
            audience_id: input.audience_id.clone(),
            origin: input.origin.clone(),
            trust_domain: input.trust_domain.clone(),
            issued_at: input.issued_at,
            expires_at: input.expires_at,
        }
    }
}

#[derive(Clone, Debug)]
pub enum DidBindingChallengeIssue {
    Issued(DidBindingChallengeRecord),
    Replay(DidBindingChallengeRecord),
    DuplicateConflict,
    StaleRequest,
}

#[derive(Clone, Debug)]
pub enum DidBindingChallengeConsume {
    Consumed(Box<DidBindingChallengeRecord>),
    Mismatch,
    Stale,
}

#[derive(Clone, Debug)]
pub enum PublishedDidRegisterReplay {
    Pending(Box<DidBindingChallengeRecord>),
    Replay(Box<arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome>),
    DuplicateConflict,
    Stale,
}

#[derive(Clone, Debug)]
pub enum PublishedDidRegisterCommit {
    Committed,
    Replay(Box<arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome>),
    DuplicateConflict,
    Stale,
}

#[derive(Clone, Debug)]
pub struct IdentityAbandonmentCommitInput {
    pub request_id: arkret_identifiers::RequestId,
    pub request_digest: arkret_identifiers::Hash,
    pub confirming_handoff_grant_id: Ulid,
    pub local_account_id: Ulid,
    pub audience_id: arkret_identifiers::DidCoreId,
    pub holder_jkt: String,
    pub lease_id: String,
    pub lease_fence: u64,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub did_version_id: String,
    pub account_subject: arkret_identifiers::Hash,
}

#[derive(Clone, Debug)]
pub enum IdentityAbandonmentCommit {
    Abandoned(arkret_models_identity::IdentityAbandonmentOutcome),
    Replay(arkret_models_identity::IdentityAbandonmentOutcome),
    DuplicateConflict,
    AuthenticationRequired,
    DispatchUncertain,
    CheckpointMismatch,
    LeaseFenced,
    AlreadyAccepted,
}

#[derive(Clone, Debug)]
pub struct IdentityCreationRegistrationContext {
    pub grant: AccountHandoffGrant,
    pub lease: IdentityCreationLeaseRecord,
    pub challenge: IdentityBindingChallengeRecord,
}

#[derive(Clone, Debug)]
pub enum IdentityCreationRegistrationAdmission {
    Ready(Box<IdentityCreationRegistrationContext>),
    AccountInactive,
    ExecutionAuthorityInvalid,
    ChallengeMismatch,
    ChallengeReplaced,
    ChallengeExpired,
    ChallengeConsumed,
}
