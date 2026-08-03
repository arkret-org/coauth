//! Durable account-handoff, identity-creation lease, and challenge storage.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::account_handoff::{
    FirstDeviceEnrollmentCommit, IdentityCreationBindingCommit, IdentityCreationRegisterReplay,
};
use coauth_data::{
    AccountHandoffCreation, AccountHandoffGrant, AccountHandoffGrantInput,
    IdentityBindingChallengeInput, IdentityBindingChallengeIssue,
    IdentityCreationRegistrationContext,
};

use crate::repository_impl;

#[async_trait]
/// Stores the durable state machine used by account-first identity creation.
pub trait AccountHandoffRepository: Send + Sync {
    /// Backend-specific failure type.
    type Error;

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
        service_account_id: coauth_data::Ulid,
        audience: &str,
        principal_id: &arkret_identifiers::Did,
        device_id: &arkret_identifiers::DeviceId,
        request_digest: &arkret_identifiers::Hash,
        outcome: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<FirstDeviceEnrollmentCommit, Self::Error>;

    /// Consume a handoff after the first session grant has been issued.
    async fn consume_grant(
        &mut self,
        grant: &AccountHandoffGrant,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error>;
}

repository_impl!(AccountHandoffRepository:
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
        service_account_id: coauth_data::Ulid,
        audience: &str,
        principal_id: &arkret_identifiers::Did,
        device_id: &arkret_identifiers::DeviceId,
        request_digest: &arkret_identifiers::Hash,
        outcome: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<FirstDeviceEnrollmentCommit, Self::Error>;
    async fn consume_grant(
        &mut self,
        grant: &AccountHandoffGrant,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error>;
);
