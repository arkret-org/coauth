//! Durable account-handoff, identity-creation lease, and challenge storage.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::account_handoff::{
    FirstDeviceEnrollmentCommit, FirstDeviceEnrollmentInput, IdentityCreationBindingCommit,
    IdentityCreationRegisterReplay,
};
use coauth_data::{
    AccountHandoffCreation, AccountHandoffCreationAttemptCommit,
    AccountHandoffCreationAttemptReserve, AccountHandoffGrant, AccountHandoffGrantInput,
    DeviceBootstrapAcceptanceCommit, DeviceBootstrapCancelCommit, DeviceBootstrapCancelInput,
    DeviceBootstrapEnrollmentCommit, DeviceBootstrapEnrollmentInput,
    DeviceBootstrapEnrollmentReservationInput, DeviceBootstrapEnrollmentReserve,
    DeviceBootstrapTransaction, DeviceBootstrapTransactionCreate, IdentityBindingChallengeInput,
    IdentityBindingChallengeIssue, IdentityCreationRegistrationContext,
    NewAccountHandoffCreationAttempt, NewDeviceBootstrapTransaction,
};

use crate::repository_impl;

#[async_trait]
/// Stores the durable state machine used by account-first identity creation.
pub trait AccountHandoffRepository: Send + Sync {
    /// Backend-specific failure type.
    type Error;

    /// Install the durable fence before contacting the external OIDC token
    /// endpoint. Same-intent `Pending(Reserved)` must never re-exchange.
    async fn reserve_creation_attempt(
        &mut self,
        input: NewAccountHandoffCreationAttempt,
    ) -> Result<AccountHandoffCreationAttemptReserve, Self::Error>;

    /// Persist the non-sensitive authorization conclusion. Exact Authorized
    /// replay is allowed to resume the local commit without re-exchanging.
    async fn checkpoint_creation_authorization(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
        canonical_intent_digest: &arkret_identifiers::Hash,
        checkpoint: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<AccountHandoffCreationAttemptCommit, Self::Error>;

    /// Commit the exact canonical outcome after the handoff and lease were
    /// created in the caller's same repository transaction.
    async fn commit_creation_attempt(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
        canonical_intent_digest: &arkret_identifiers::Hash,
        canonical_outcome: &[u8],
        outcome_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<AccountHandoffCreationAttemptCommit, Self::Error>;

    /// Install the immutable founding transaction beside its bootstrap grant.
    async fn create_device_bootstrap_transaction(
        &mut self,
        input: NewDeviceBootstrapTransaction,
    ) -> Result<DeviceBootstrapTransactionCreate, Self::Error>;

    /// Resolve a bootstrap transaction by its protocol identifier.
    async fn get_device_bootstrap_transaction(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
    ) -> Result<Option<DeviceBootstrapTransaction>, Self::Error>;

    /// Lock the transaction and elect the sole signer for an enrollment
    /// request. The caller must keep this repository transaction open through
    /// `commit_device_bootstrap_enrollment` and `save`.
    async fn reserve_device_bootstrap_enrollment(
        &mut self,
        input: DeviceBootstrapEnrollmentReservationInput<'_>,
    ) -> Result<DeviceBootstrapEnrollmentReserve, Self::Error>;

    /// Persist the exact authority-signed enrollment outcome while keeping the
    /// transaction pending until the founding Event batch is accepted.
    async fn commit_device_bootstrap_enrollment(
        &mut self,
        input: DeviceBootstrapEnrollmentInput<'_>,
    ) -> Result<DeviceBootstrapEnrollmentCommit, Self::Error>;

    /// Commit a founding cancellation after the caller has obtained the
    /// Principal-side accepted|cancelled|expired decision-fence receipt. A
    /// directory miss is not sufficient authority for this transition. Exact
    /// `(transaction,idempotency_key)` replay returns the first canonical
    /// outcome.
    async fn commit_device_bootstrap_cancel(
        &mut self,
        input: DeviceBootstrapCancelInput,
    ) -> Result<DeviceBootstrapCancelCommit, Self::Error>;

    /// Durably freeze the exact Principal decision request before the caller
    /// crosses the service boundary. Exact retries recover the same prepared
    /// bytes; terminal lifecycle state is not changed by this reservation.
    async fn reserve_device_bootstrap_cancel(
        &mut self,
        input: coauth_data::DeviceBootstrapCancelReserveInput,
    ) -> Result<coauth_data::DeviceBootstrapCancelReserve, Self::Error>;

    /// Resolve an exact cancel operation before any external projection read.
    async fn get_device_bootstrap_cancel_operation(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
        idempotency_key: &arkret_wire::IdempotencyKey,
    ) -> Result<Option<coauth_data::DeviceBootstrapCancelOperation>, Self::Error>;

    /// Persist the authoritative Principal Server acceptance checkpoint.
    async fn mark_device_bootstrap_accepted(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
        authorized_event_id: &arkret_identifiers::EventId,
        device_key_digest: &arkret_identifiers::Hash,
        authority: coauth_data::DeviceBootstrapDecisionEvidence,
    ) -> Result<DeviceBootstrapAcceptanceCommit, Self::Error>;

    /// Look up a handoff by its replay-protection request identifier.
    async fn get_by_request_id(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
    ) -> Result<Option<AccountHandoffGrant>, Self::Error>;

    /// Resolve an unexpired, unconsumed handoff bearer value.
    async fn get_active_by_token(
        &mut self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AccountHandoffGrant>, Self::Error>;

    /// Persist a handoff and acquire or reclaim its identity-creation lease.
    async fn create_with_lease(
        &mut self,
        input: AccountHandoffGrantInput,
    ) -> Result<AccountHandoffCreation, Self::Error>;

    /// Resolve the current lease or binding outcome for an existing handoff.
    async fn resolve_creation(
        &mut self,
        grant: &AccountHandoffGrant,
        now: DateTime<Utc>,
    ) -> Result<AccountHandoffCreation, Self::Error>;

    /// Atomically reserve an inception operation and issue its durable challenge.
    async fn reserve_and_issue_challenge(
        &mut self,
        input: IdentityBindingChallengeInput,
    ) -> Result<IdentityBindingChallengeIssue, Self::Error>;

    /// Load a fail-closed registration context for an active challenge and fence.
    async fn registration_context(
        &mut self,
        grant: &AccountHandoffGrant,
        lease_id: &str,
        lease_fence: u64,
        challenge_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<IdentityCreationRegistrationContext>, Self::Error>;

    /// Resolve a completed register request against its exact durable
    /// handoff/challenge boundary and canonical request digest.
    async fn registration_replay(
        &mut self,
        grant: &AccountHandoffGrant,
        lease_id: &str,
        lease_fence: u64,
        challenge_id: &str,
        request_digest: &arkret_identifiers::Hash,
    ) -> Result<IdentityCreationRegisterReplay, Self::Error>;

    /// Record that the reserved inception operation has been durably published.
    async fn mark_published(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        registry_receipt: &serde_json::Value,
        head_event_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error>;

    /// Record the local account binding and its signed protocol receipt.
    async fn mark_bound(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        binding_receipt: &arkret_models_identity::AccountBindingReceipt,
        request_digest: &arkret_identifiers::Hash,
        outcome: &arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome,
        now: DateTime<Utc>,
    ) -> Result<IdentityCreationBindingCommit, Self::Error>;

    /// Atomically persist the one founding-device enrollment authorized by a
    /// verified identity-creation receipt. An exact request replays the first
    /// byte-stable outcome; a different request cannot consume the slot.
    async fn commit_first_device_enrollment(
        &mut self,
        input: FirstDeviceEnrollmentInput<'_>,
    ) -> Result<FirstDeviceEnrollmentCommit, Self::Error>;

    /// Consume a handoff after the first session grant has been issued.
    async fn consume_grant(
        &mut self,
        grant: &AccountHandoffGrant,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error>;
}

repository_impl!(AccountHandoffRepository:
    async fn reserve_creation_attempt(
        &mut self,
        input: NewAccountHandoffCreationAttempt,
    ) -> Result<AccountHandoffCreationAttemptReserve, Self::Error>;
    async fn checkpoint_creation_authorization(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
        canonical_intent_digest: &arkret_identifiers::Hash,
        checkpoint: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<AccountHandoffCreationAttemptCommit, Self::Error>;
    async fn commit_creation_attempt(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
        canonical_intent_digest: &arkret_identifiers::Hash,
        canonical_outcome: &[u8],
        outcome_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<AccountHandoffCreationAttemptCommit, Self::Error>;
    async fn create_device_bootstrap_transaction(
        &mut self,
        input: NewDeviceBootstrapTransaction,
    ) -> Result<DeviceBootstrapTransactionCreate, Self::Error>;
    async fn get_device_bootstrap_transaction(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
    ) -> Result<Option<DeviceBootstrapTransaction>, Self::Error>;
    async fn reserve_device_bootstrap_enrollment(
        &mut self,
        input: DeviceBootstrapEnrollmentReservationInput<'_>,
    ) -> Result<DeviceBootstrapEnrollmentReserve, Self::Error>;
    async fn commit_device_bootstrap_enrollment(
        &mut self,
        input: DeviceBootstrapEnrollmentInput<'_>,
    ) -> Result<DeviceBootstrapEnrollmentCommit, Self::Error>;
    async fn commit_device_bootstrap_cancel(
        &mut self,
        input: DeviceBootstrapCancelInput,
    ) -> Result<DeviceBootstrapCancelCommit, Self::Error>;
    async fn reserve_device_bootstrap_cancel(
        &mut self,
        input: coauth_data::DeviceBootstrapCancelReserveInput,
    ) -> Result<coauth_data::DeviceBootstrapCancelReserve, Self::Error>;
    async fn get_device_bootstrap_cancel_operation(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
        idempotency_key: &arkret_wire::IdempotencyKey,
    ) -> Result<Option<coauth_data::DeviceBootstrapCancelOperation>, Self::Error>;
    async fn mark_device_bootstrap_accepted(
        &mut self,
        transaction_id: &arkret_wire::ProtocolOpaqueId,
        authorized_event_id: &arkret_identifiers::EventId,
        device_key_digest: &arkret_identifiers::Hash,
        authority: coauth_data::DeviceBootstrapDecisionEvidence,
    ) -> Result<DeviceBootstrapAcceptanceCommit, Self::Error>;
    async fn get_by_request_id(
        &mut self,
        request_id: &arkret_identifiers::RequestId,
    ) -> Result<Option<AccountHandoffGrant>, Self::Error>;
    async fn get_active_by_token(
        &mut self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AccountHandoffGrant>, Self::Error>;
    async fn create_with_lease(
        &mut self,
        input: AccountHandoffGrantInput,
    ) -> Result<AccountHandoffCreation, Self::Error>;
    async fn resolve_creation(
        &mut self,
        grant: &AccountHandoffGrant,
        now: DateTime<Utc>,
    ) -> Result<AccountHandoffCreation, Self::Error>;
    async fn reserve_and_issue_challenge(
        &mut self,
        input: IdentityBindingChallengeInput,
    ) -> Result<IdentityBindingChallengeIssue, Self::Error>;
    async fn registration_context(
        &mut self,
        grant: &AccountHandoffGrant,
        lease_id: &str,
        lease_fence: u64,
        challenge_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<IdentityCreationRegistrationContext>, Self::Error>;
    async fn registration_replay(
        &mut self,
        grant: &AccountHandoffGrant,
        lease_id: &str,
        lease_fence: u64,
        challenge_id: &str,
        request_digest: &arkret_identifiers::Hash,
    ) -> Result<IdentityCreationRegisterReplay, Self::Error>;
    async fn mark_published(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        registry_receipt: &serde_json::Value,
        head_event_digest: &arkret_identifiers::Hash,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error>;
    async fn mark_bound(
        &mut self,
        context: &IdentityCreationRegistrationContext,
        binding_receipt: &arkret_models_identity::AccountBindingReceipt,
        request_digest: &arkret_identifiers::Hash,
        outcome: &arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome,
        now: DateTime<Utc>,
    ) -> Result<IdentityCreationBindingCommit, Self::Error>;
    async fn commit_first_device_enrollment(
        &mut self,
        input: FirstDeviceEnrollmentInput<'_>,
    ) -> Result<FirstDeviceEnrollmentCommit, Self::Error>;
    async fn consume_grant(
        &mut self,
        grant: &AccountHandoffGrant,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error>;
);
