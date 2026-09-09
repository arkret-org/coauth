//! Durable account-handoff, identity-creation lease, and challenge storage.

use chrono::{DateTime, Utc};
use coauth_data::{
    AccountHandoffAuthorizationCheckpoint, AccountHandoffCreation,
    AccountHandoffCreationAttemptCommit, AccountHandoffCreationAttemptReserve, AccountHandoffGrant,
    AccountHandoffGrantInput, ControllerGateAttestationCommit, ControllerGateAttestationReserve,
    DidBindingChallengeConsume, DidBindingChallengeInput, DidBindingChallengeIssue,
    IdentityAbandonmentChallengeInput, IdentityAbandonmentChallengeIssue,
    IdentityAbandonmentChallengeRecord, IdentityAbandonmentCommit, IdentityAbandonmentCommitInput,
    IdentityBindingChallengeInput, IdentityBindingChallengeIssue, IdentityCreationBindingCommit,
    IdentityCreationRegisterReplay, IdentityCreationRegistrationAdmission,
    IdentityCreationRegistrationContext, NewAccountHandoffCreationAttempt,
    NewControllerGateAttestationIssuance, PublishedDidRegisterCommit, PublishedDidRegisterReplay,
    Ulid,
};

use crate::repository_impl;

repository_impl! {
    /// Stores the durable state machine used by account-first identity creation.
    pub trait AccountHandoffRepository {
        /// Backend-specific failure type.
        type Error;

        /// Install the durable external-effect fence for one gate issuance.
        async fn reserve_controller_gate_attestation(
            &mut self,
            input: NewControllerGateAttestationIssuance,
        ) -> Result<ControllerGateAttestationReserve, Self::Error>;

        /// Commit the exact canonical signed outcome. A retry can only replay the
        /// same bytes and can never mint a second attestation.
        async fn commit_controller_gate_attestation(
            &mut self,
            request_id: &arkret_identifiers::RequestId,
            canonical_intent_digest: &arkret_identifiers::Hash,
            canonical_outcome: &[u8],
            outcome_digest: &arkret_identifiers::Hash,
            attestation_expires_at: DateTime<Utc>,
            now: DateTime<Utc>,
        ) -> Result<ControllerGateAttestationCommit, Self::Error>;

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
            checkpoint: &AccountHandoffAuthorizationCheckpoint,
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

        /// Load a handoff by opaque token for exact completed-operation replay,
        /// including a row already consumed by that completed operation.
        async fn get_by_token(
            &mut self,
            token: &str,
            now: DateTime<Utc>,
        ) -> Result<Option<AccountHandoffGrant>, Self::Error>;

        /// Persist a handoff and acquire or reclaim its identity-creation lease.
        async fn create_with_lease(
            &mut self,
            input: AccountHandoffGrantInput,
        ) -> Result<AccountHandoffCreation, Self::Error>;

        /// Resolve the current lease or binding outcome for an existing unexpired,
        /// unrevoked handoff. Read-only reconciliation may present a handoff that
        /// its completed register command already consumed.
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

        /// Persist or exactly replay the high-freshness challenge for an
        /// already-published DID.
        async fn issue_did_binding_challenge(
            &mut self,
            input: DidBindingChallengeInput,
        ) -> Result<DidBindingChallengeIssue, Self::Error>;

        /// Consume an exact challenge for the target service account inside the
        /// caller's account-binding transaction.
        async fn consume_did_binding_challenge(
            &mut self,
            local_account_id: Ulid,
            account_subject: &arkret_identifiers::Hash,
            challenge_id: &str,
            request_digest: &arkret_identifiers::Hash,
            now: DateTime<Utc>,
        ) -> Result<DidBindingChallengeConsume, Self::Error>;

        /// Lock and classify a published-DID registration retry against its
        /// durable challenge and canonical request digest.
        async fn published_did_registration_replay(
            &mut self,
            grant: &AccountHandoffGrant,
            challenge_id: &str,
            request_digest: &arkret_identifiers::Hash,
            now: DateTime<Utc>,
        ) -> Result<PublishedDidRegisterReplay, Self::Error>;

        /// Consume the published-DID challenge and retain the exact registration
        /// outcome in the caller's account-binding transaction.
        async fn commit_published_did_registration(
            &mut self,
            grant: &AccountHandoffGrant,
            challenge_id: &str,
            request_digest: &arkret_identifiers::Hash,
            outcome: &arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome,
            now: DateTime<Utc>,
        ) -> Result<PublishedDidRegisterCommit, Self::Error>;

        /// Issue or replay the durable explicit-abandonment challenge while the
        /// reserved identity has a published DID but no accepted PCR.
        async fn issue_identity_abandonment_challenge(
            &mut self,
            input: IdentityAbandonmentChallengeInput,
        ) -> Result<IdentityAbandonmentChallengeIssue, Self::Error>;

        /// Load the current durable abandonment goal for one identity-creation
        /// lease. Expired and consumed challenges are never projected.
        async fn active_identity_abandonment_challenge(
            &mut self,
            local_account_id: Ulid,
            audience_id: &arkret_identifiers::DidCoreId,
            lease_id: &str,
            now: DateTime<Utc>,
        ) -> Result<Option<IdentityAbandonmentChallengeRecord>, Self::Error>;

        /// Atomically consume the challenge, reserve the orphan anchor, suppress
        /// the holder checkpoint and release the identity-creation lease.
        async fn abandon_identity_creation(
            &mut self,
            input: IdentityAbandonmentCommitInput,
        ) -> Result<IdentityAbandonmentCommit, Self::Error>;

        /// Load a fail-closed registration context for an active challenge and fence.
        async fn registration_context(
            &mut self,
            grant: &AccountHandoffGrant,
            lease_id: &str,
            lease_fence: u64,
            challenge_id: &str,
        ) -> Result<IdentityCreationRegistrationAdmission, Self::Error>;

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
        async fn mark_did_published(
            &mut self,
            context: &IdentityCreationRegistrationContext,
            registry_receipt: &arkret_models_identity::DidOperationSubmitOutcome,
            head_event_digest: &arkret_identifiers::Hash,
            registration_did_evidence: &arkret_wire::RegistrationDidEvidence,
            now: DateTime<Utc>,
        ) -> Result<bool, Self::Error>;

        /// Record the verified remote PCR-genesis acceptance receipt.
        async fn mark_pcr_accepted(
            &mut self,
            context: &IdentityCreationRegistrationContext,
            request_digest: &arkret_identifiers::Hash,
            receipt: &arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome,
            now: DateTime<Utc>,
        ) -> Result<bool, Self::Error>;

        /// Record the durable service-account to principal binding.
        async fn mark_account_bound(
            &mut self,
            context: &IdentityCreationRegistrationContext,
            binding_receipt: &arkret_models_identity::AccountBindingReceipt,
            now: DateTime<Utc>,
        ) -> Result<bool, Self::Error>;

        /// Commit the first Standard SessionGrant and exact register replay outcome.
        async fn mark_completed(
            &mut self,
            context: &IdentityCreationRegistrationContext,
            request_digest: &arkret_identifiers::Hash,
            outcome: &arkret_models_collaboration::account_lifecycle::AccountRegisterOutcome,
            now: DateTime<Utc>,
        ) -> Result<IdentityCreationBindingCommit, Self::Error>;

        /// Consume a handoff after the first session grant has been issued.
        async fn consume_grant(
            &mut self,
            grant: &AccountHandoffGrant,
            now: DateTime<Utc>,
        ) -> Result<bool, Self::Error>;
    }
}
