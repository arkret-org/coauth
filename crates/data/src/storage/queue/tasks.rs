use arkret_core::AgentKeyPairRequestBody;
use chrono::{DateTime, Utc};
use coauth_data::{
    BrowserSession, Session, User, UserEmailAuthentication, UserPhoneAuthentication,
    UserRecoverySession,
};
use serde::{Deserialize, Serialize};
use soland_core::capability_fanout::CapabilityFanoutBody;
use ulid::Ulid;

use super::InsertableJob;
use crate::{Page, Pagination};

/// A job to send an email authentication code to a user.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SendEmailAuthenticationCodeJob {
    user_email_authentication_id: Ulid,
    language: String,
}

impl SendEmailAuthenticationCodeJob {
    /// Create a new job to send an email authentication code to a user.
    #[must_use]
    pub fn new(user_email_authentication: &UserEmailAuthentication, language: String) -> Self {
        Self {
            user_email_authentication_id: user_email_authentication.id,
            language,
        }
    }

    /// The language to use for the email.
    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The ID of the email authentication to send the code for.
    #[must_use]
    pub fn user_email_authentication_id(&self) -> Ulid {
        self.user_email_authentication_id
    }
}

impl InsertableJob for SendEmailAuthenticationCodeJob {
    const QUEUE_NAME: &'static str = "send-email-authentication-code";
}

/// A job to send a phone authentication code via SMS.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SendSmsAuthenticationCodeJob {
    user_phone_authentication_id: Ulid,
    language: String,
}

impl SendSmsAuthenticationCodeJob {
    /// Create a new job to send a phone authentication code via SMS.
    #[must_use]
    pub fn new(user_phone_authentication: &UserPhoneAuthentication, language: String) -> Self {
        Self {
            user_phone_authentication_id: user_phone_authentication.id,
            language,
        }
    }

    /// The language to use for the SMS.
    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The ID of the phone authentication to send the code for.
    #[must_use]
    pub fn user_phone_authentication_id(&self) -> Ulid {
        self.user_phone_authentication_id
    }
}

impl InsertableJob for SendSmsAuthenticationCodeJob {
    const QUEUE_NAME: &'static str = "send-sms-authentication-code";
}

/// A generic job to dispatch user-facing notifications.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DispatchNotificationJob {
    /// Send a verification notification for a contact point.
    ContactVerification {
        /// The verification target.
        target: ContactVerificationTarget,
        /// The language to use for the notification.
        language: String,
    },

    /// Send an email verification code.
    EmailAuthenticationCode {
        /// The email authentication session to send the code for.
        user_email_authentication_id: Ulid,
        /// The language to use for the email.
        language: String,
    },

    /// Send an SMS verification code.
    SmsAuthenticationCode {
        /// The phone authentication session to send the code for.
        user_phone_authentication_id: Ulid,
        /// The language to use for the SMS.
        language: String,
    },

    /// Send account recovery emails for a recovery session.
    AccountRecovery {
        /// The recovery session for which to send recovery emails.
        user_recovery_session_id: Ulid,
    },
}

/// Target for a contact verification notification.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ContactVerificationTarget {
    /// Email-based verification.
    Email {
        /// The email authentication session to send the code for.
        user_email_authentication_id: Ulid,
    },
    /// Phone-based verification.
    Phone {
        /// The phone authentication session to send the code for.
        user_phone_authentication_id: Ulid,
    },
}

impl DispatchNotificationJob {
    /// Create a new notification dispatch job for contact verification.
    #[must_use]
    pub fn contact_verification(target: ContactVerificationTarget, language: String) -> Self {
        Self::ContactVerification { target, language }
    }

    /// Create a new notification dispatch job for email verification.
    #[must_use]
    pub fn email_authentication_code(
        user_email_authentication: &UserEmailAuthentication,
        language: String,
    ) -> Self {
        Self::EmailAuthenticationCode {
            user_email_authentication_id: user_email_authentication.id,
            language,
        }
    }

    /// Create a new notification dispatch job for SMS verification.
    #[must_use]
    pub fn sms_authentication_code(
        user_phone_authentication: &UserPhoneAuthentication,
        language: String,
    ) -> Self {
        Self::SmsAuthenticationCode {
            user_phone_authentication_id: user_phone_authentication.id,
            language,
        }
    }

    /// Create a new notification dispatch job for account recovery.
    #[must_use]
    pub fn account_recovery(user_recovery_session: &UserRecoverySession) -> Self {
        Self::AccountRecovery {
            user_recovery_session_id: user_recovery_session.id,
        }
    }
}

impl InsertableJob for DispatchNotificationJob {
    const QUEUE_NAME: &'static str = "dispatch-notification";
}

/// A job to process reserved notification deliveries from the notification
/// outbox.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessNotificationDeliveriesJob {
    limit: usize,
}

impl ProcessNotificationDeliveriesJob {
    /// Create a new job to process up to `limit` deliveries.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self { limit }
    }

    /// The maximum number of deliveries this job should process.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

impl Default for ProcessNotificationDeliveriesJob {
    fn default() -> Self {
        Self { limit: 10 }
    }
}

impl InsertableJob for ProcessNotificationDeliveriesJob {
    const QUEUE_NAME: &'static str = "process-notification-deliveries";
}

/// Operation carried by a collaboration capability fan-out job.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollaborationCapabilityFanoutOperation {
    /// Materialize a standard `ak.capability.grant` event.
    Grant,
    /// Materialize a standard `ak.capability.revoke` event.
    Revoke,
}

impl CollaborationCapabilityFanoutOperation {
    /// Wire value used in queue payloads and downstream audit metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke => "revoke",
        }
    }
}

/// A job to materialize a coauth collaboration capability grant/revoke on
/// the configured principal server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CollaborationCapabilityFanoutJob {
    operation: CollaborationCapabilityFanoutOperation,
    idempotency_key: String,
    capability_grant_id: String,
    event_id: String,
    raw_payload_digest: String,
    body: CapabilityFanoutBody,
}

impl CollaborationCapabilityFanoutJob {
    /// Create a grant fan-out job.
    #[must_use]
    pub fn grant(
        idempotency_key: String,
        capability_grant_id: String,
        grant_event_id: String,
        raw_payload_digest: String,
        body: CapabilityFanoutBody,
    ) -> Self {
        Self {
            operation: CollaborationCapabilityFanoutOperation::Grant,
            idempotency_key,
            capability_grant_id,
            event_id: grant_event_id,
            raw_payload_digest,
            body,
        }
    }

    /// Create a revoke fan-out job.
    #[must_use]
    pub fn revoke(
        idempotency_key: String,
        capability_grant_id: String,
        revoke_event_id: String,
        raw_payload_digest: String,
        body: CapabilityFanoutBody,
    ) -> Self {
        Self {
            operation: CollaborationCapabilityFanoutOperation::Revoke,
            idempotency_key,
            capability_grant_id,
            event_id: revoke_event_id,
            raw_payload_digest,
            body,
        }
    }

    /// Fan-out operation.
    #[must_use]
    pub const fn operation(&self) -> CollaborationCapabilityFanoutOperation {
        self.operation
    }

    /// Idempotency key used for downstream delivery.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Standard capability grant id.
    #[must_use]
    pub fn capability_grant_id(&self) -> &str {
        &self.capability_grant_id
    }

    /// Standard grant/revoke event id.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Canonical digest of [`Self::body`].
    #[must_use]
    pub fn raw_payload_digest(&self) -> &str {
        &self.raw_payload_digest
    }

    /// Fan-out body to submit.
    #[must_use]
    pub fn body(&self) -> &CapabilityFanoutBody {
        &self.body
    }
}

impl InsertableJob for CollaborationCapabilityFanoutJob {
    const QUEUE_NAME: &'static str = "soland-collaboration-capability-fanout";
}

/// A durable job that delivers one controller-approved Agent key
/// authorization to the configured Principal Server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentKeyPairCommitJob {
    idempotency_key: String,
    authorized_event_id: String,
    request_digest: String,
    principal_server_name: String,
    body: AgentKeyPairRequestBody,
}

impl AgentKeyPairCommitJob {
    /// Create a durable retry of the canonical Agent key-pair operation.
    #[must_use]
    pub fn new(
        idempotency_key: String,
        authorized_event_id: String,
        request_digest: String,
        principal_server_name: String,
        body: AgentKeyPairRequestBody,
    ) -> Self {
        Self {
            idempotency_key,
            authorized_event_id,
            request_digest,
            principal_server_name,
            body,
        }
    }

    /// Stable downstream idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Controller-signed authorization Event id.
    #[must_use]
    pub fn authorized_event_id(&self) -> &str {
        &self.authorized_event_id
    }

    /// Canonical digest of the fan-out body.
    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    #[must_use]
    /// Configured name of the authoritative Principal Server selected during
    /// the pre-commit Agent lookup.
    pub fn principal_server_name(&self) -> &str {
        &self.principal_server_name
    }

    /// Exact standard operation request received from the client.
    #[must_use]
    pub fn body(&self) -> &AgentKeyPairRequestBody {
        &self.body
    }
}

impl InsertableJob for AgentKeyPairCommitJob {
    const QUEUE_NAME: &'static str = "principal-agent-key-pair-commit";
}

/// A job to provision the user on the `PrincipalServer`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProvisionUserJob {
    user_id: Ulid,
    set_display_name: Option<String>,
    #[serde(default)]
    set_avatar_url: Option<String>,
    #[serde(default)]
    admin: bool,
}

impl ProvisionUserJob {
    /// Create a new job to provision the user on the `PrincipalServer`.
    #[must_use]
    pub fn new(user: &User) -> Self {
        Self {
            user_id: user.id,
            set_display_name: None,
            set_avatar_url: None,
            admin: false,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn new_for_id(user_id: Ulid) -> Self {
        Self {
            user_id,
            set_display_name: None,
            set_avatar_url: None,
            admin: false,
        }
    }

    /// Set the display name of the user.
    #[must_use]
    pub fn set_display_name(mut self, display_name: String) -> Self {
        self.set_display_name = Some(display_name);
        self
    }

    /// Set the avatar URL of the user.
    #[must_use]
    pub fn set_avatar_url(mut self, avatar_url: String) -> Self {
        self.set_avatar_url = Some(avatar_url);
        self
    }

    /// Mark the user as an admin on the `PrincipalServer`.
    #[must_use]
    pub fn set_admin(mut self) -> Self {
        self.admin = true;
        self
    }

    /// Get the display name to be set.
    #[must_use]
    pub fn display_name_to_set(&self) -> Option<&str> {
        self.set_display_name.as_deref()
    }

    /// Get the avatar URL to be set.
    #[must_use]
    pub fn avatar_url_to_set(&self) -> Option<&str> {
        self.set_avatar_url.as_deref()
    }

    /// Whether the user should be made admin on the `PrincipalServer`.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.admin
    }

    /// The ID of the user to provision.
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }
}

impl InsertableJob for ProvisionUserJob {
    const QUEUE_NAME: &'static str = "provision-user";
}

/// A job which syncs the list of devices of a user with the `PrincipalServer`
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SyncDevicesJob {
    user_id: Ulid,
}

impl SyncDevicesJob {
    /// Create a new job to sync the list of devices of a user with the
    /// `PrincipalServer`
    #[must_use]
    pub fn new(user: &User) -> Self {
        Self { user_id: user.id }
    }

    /// Create a new job to sync the list of devices of a user with the
    /// `PrincipalServer` for the given user ID
    ///
    /// This is useful to use in cases where the [`User`] object isn't loaded
    #[must_use]
    pub fn new_for_id(user_id: Ulid) -> Self {
        Self { user_id }
    }

    /// The ID of the user to sync the devices for
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }
}

impl InsertableJob for SyncDevicesJob {
    const QUEUE_NAME: &'static str = "sync-devices";
}

/// A job to deactivate and lock a user
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeactivateUserJob {
    user_id: Ulid,
    principal_erase: bool,
}

impl DeactivateUserJob {
    /// Create a new job to deactivate and lock a user
    ///
    /// # Parameters
    ///
    /// * `user` - The user to deactivate
    /// * `principal_erase` - Whether to erase the user from the `PrincipalServer`
    #[must_use]
    pub fn new(user: &User, principal_erase: bool) -> Self {
        Self {
            user_id: user.id,
            principal_erase,
        }
    }

    /// The ID of the user to deactivate
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }

    /// Whether to erase the user from the `PrincipalServer`
    #[must_use]
    pub fn principal_erase(&self) -> bool {
        self.principal_erase
    }
}

impl InsertableJob for DeactivateUserJob {
    const QUEUE_NAME: &'static str = "deactivate-user";
}

/// A job to rewrite account projections after an erasure lifecycle transition.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountProjectionRewriteJob {
    user_id: Ulid,
    erase_private_state: bool,
}

impl AccountProjectionRewriteJob {
    /// Create a new projection rewrite job for a user.
    #[must_use]
    pub fn new(user: &User, erase_private_state: bool) -> Self {
        Self {
            user_id: user.id,
            erase_private_state,
        }
    }

    /// The ID of the user whose projections must be rewritten.
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }

    /// Whether private account state must be minimized rather than only
    /// recomputed from durable lifecycle state.
    #[must_use]
    pub fn erase_private_state(&self) -> bool {
        self.erase_private_state
    }
}

impl InsertableJob for AccountProjectionRewriteJob {
    const QUEUE_NAME: &'static str = "account-projection-rewrite";
}

/// A job to reactivate a user
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReactivateUserJob {
    user_id: Ulid,
}

impl ReactivateUserJob {
    /// Create a new job to reactivate a user
    ///
    /// # Parameters
    ///
    /// * `user` - The user to reactivate
    #[must_use]
    pub fn new(user: &User) -> Self {
        Self { user_id: user.id }
    }

    /// The ID of the user to reactivate
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }
}

impl InsertableJob for ReactivateUserJob {
    const QUEUE_NAME: &'static str = "reactivate-user";
}

/// Send account recovery emails
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SendAccountRecoveryEmailsJob {
    user_recovery_session_id: Ulid,
}

impl SendAccountRecoveryEmailsJob {
    /// Create a new job to send account recovery emails
    ///
    /// # Parameters
    ///
    /// * `user_recovery_session` - The user recovery session to send the email for
    /// * `language` - The locale to send the email in
    #[must_use]
    pub fn new(user_recovery_session: &UserRecoverySession) -> Self {
        Self {
            user_recovery_session_id: user_recovery_session.id,
        }
    }

    /// The ID of the user recovery session to send the email for
    #[must_use]
    pub fn user_recovery_session_id(&self) -> Ulid {
        self.user_recovery_session_id
    }
}

impl InsertableJob for SendAccountRecoveryEmailsJob {
    const QUEUE_NAME: &'static str = "send-account-recovery-email";
}

/// Cleanup revoked OAuth access tokens
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupRevokedOAuthAccessTokensJob;

impl InsertableJob for CleanupRevokedOAuthAccessTokensJob {
    const QUEUE_NAME: &'static str = "cleanup-revoked-oauth-access-tokens";
}

/// Cleanup expired OAuth access tokens
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupExpiredOAuthAccessTokensJob;

impl InsertableJob for CleanupExpiredOAuthAccessTokensJob {
    const QUEUE_NAME: &'static str = "cleanup-expired-oauth-access-tokens";
}

/// Cleanup revoked OAuth refresh tokens
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupRevokedOAuthRefreshTokensJob;

impl InsertableJob for CleanupRevokedOAuthRefreshTokensJob {
    const QUEUE_NAME: &'static str = "cleanup-revoked-oauth-refresh-tokens";
}

/// Cleanup consumed OAuth refresh tokens
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupConsumedOAuthRefreshTokensJob;

impl InsertableJob for CleanupConsumedOAuthRefreshTokensJob {
    const QUEUE_NAME: &'static str = "cleanup-consumed-oauth-refresh-tokens";
}

/// Cleanup old user registrations
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupUserRegistrationsJob;

impl InsertableJob for CleanupUserRegistrationsJob {
    const QUEUE_NAME: &'static str = "cleanup-user-registrations";
}

/// Cleanup finished OAuth sessions
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupFinishedOAuthSessionsJob;

impl InsertableJob for CleanupFinishedOAuthSessionsJob {
    const QUEUE_NAME: &'static str = "cleanup-finished-oauth-sessions";
}

/// Cleanup expired Arkret session grants (`oauth_session_grants`)
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupExpiredSessionGrantsJob;

impl InsertableJob for CleanupExpiredSessionGrantsJob {
    const QUEUE_NAME: &'static str = "cleanup-expired-session-grants";
}

/// Cleanup finished user/browser sessions
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupFinishedUserSessionsJob;

impl InsertableJob for CleanupFinishedUserSessionsJob {
    const QUEUE_NAME: &'static str = "cleanup-finished-user-sessions";
}

/// Cleanup old OAuth authorization grants
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupOAuthAuthorizationGrantsJob;

impl InsertableJob for CleanupOAuthAuthorizationGrantsJob {
    const QUEUE_NAME: &'static str = "cleanup-oauth-authorization-grants";
}

/// Cleanup old OAuth device code grants
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupOAuthDeviceCodeGrantsJob;

impl InsertableJob for CleanupOAuthDeviceCodeGrantsJob {
    const QUEUE_NAME: &'static str = "cleanup-oauth-device-code-grants";
}

/// Cleanup old user recovery sessions
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupUserRecoverySessionsJob;

impl InsertableJob for CleanupUserRecoverySessionsJob {
    const QUEUE_NAME: &'static str = "cleanup-user-recovery-sessions";
}

/// Cleanup old user email authentications
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupUserEmailAuthenticationsJob;

impl InsertableJob for CleanupUserEmailAuthenticationsJob {
    const QUEUE_NAME: &'static str = "cleanup-user-email-authentications";
}

/// Cleanup old pending upstream OAuth authorization sessions
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupUpstreamOAuthSessionsJob;

impl InsertableJob for CleanupUpstreamOAuthSessionsJob {
    const QUEUE_NAME: &'static str = "cleanup-upstream-oauth-sessions";
}

/// Cleanup orphaned upstream OAuth links
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupUpstreamOAuthLinksJob;

impl InsertableJob for CleanupUpstreamOAuthLinksJob {
    const QUEUE_NAME: &'static str = "cleanup-upstream-oauth-links";
}

/// Cleanup old completed and failed queue jobs
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupQueueJobsJob;

impl InsertableJob for CleanupQueueJobsJob {
    const QUEUE_NAME: &'static str = "cleanup-queue-jobs";
}

/// Scheduled job to expire inactive sessions
///
/// This job triggers jobs to expire inactive OAuth and user sessions.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExpireInactiveSessionsJob;

impl InsertableJob for ExpireInactiveSessionsJob {
    const QUEUE_NAME: &'static str = "expire-inactive-sessions";
}

/// Expire inactive OAuth sessions
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExpireInactiveOAuthSessionsJob {
    threshold: DateTime<Utc>,
    after: Option<Ulid>,
}

impl ExpireInactiveOAuthSessionsJob {
    /// Create a new job to expire inactive OAuth sessions
    ///
    /// # Parameters
    ///
    /// * `threshold` - The threshold to expire sessions at
    #[must_use]
    pub fn new(threshold: DateTime<Utc>) -> Self {
        Self {
            threshold,
            after: None,
        }
    }

    /// Get the threshold to expire sessions at
    #[must_use]
    pub fn threshold(&self) -> DateTime<Utc> {
        self.threshold
    }

    /// Get the pagination cursor
    #[must_use]
    pub fn pagination(&self, batch_size: usize) -> Pagination {
        let pagination = Pagination::first(batch_size);
        if let Some(after) = self.after {
            pagination.after(after)
        } else {
            pagination
        }
    }

    /// Get the next job given the page returned by the database
    #[must_use]
    pub fn next(&self, page: &Page<Session>) -> Option<Self> {
        if !page.has_next_page {
            return None;
        }

        let last_edge = page.edges.last()?;
        Some(Self {
            threshold: self.threshold,
            after: Some(last_edge.cursor),
        })
    }
}

impl InsertableJob for ExpireInactiveOAuthSessionsJob {
    const QUEUE_NAME: &'static str = "expire-inactive-oauth-sessions";
}

/// Expire inactive user sessions
#[derive(Debug, Serialize, Deserialize)]
pub struct ExpireInactiveUserSessionsJob {
    threshold: DateTime<Utc>,
    after: Option<Ulid>,
}

impl ExpireInactiveUserSessionsJob {
    /// Create a new job to expire inactive user/browser sessions
    ///
    /// # Parameters
    ///
    /// * `threshold` - The threshold to expire sessions at
    #[must_use]
    pub fn new(threshold: DateTime<Utc>) -> Self {
        Self {
            threshold,
            after: None,
        }
    }

    /// Get the threshold to expire sessions at
    #[must_use]
    pub fn threshold(&self) -> DateTime<Utc> {
        self.threshold
    }

    /// Get the pagination cursor
    #[must_use]
    pub fn pagination(&self, batch_size: usize) -> Pagination {
        let pagination = Pagination::first(batch_size);
        if let Some(after) = self.after {
            pagination.after(after)
        } else {
            pagination
        }
    }

    /// Get the next job given the page returned by the database
    #[must_use]
    pub fn next(&self, page: &Page<BrowserSession>) -> Option<Self> {
        if !page.has_next_page {
            return None;
        }

        let last_edge = page.edges.last()?;
        Some(Self {
            threshold: self.threshold,
            after: Some(last_edge.cursor),
        })
    }
}

impl InsertableJob for ExpireInactiveUserSessionsJob {
    const QUEUE_NAME: &'static str = "expire-inactive-user-sessions";
}

/// Prune stale policy data
#[derive(Debug, Serialize, Deserialize)]
pub struct PruneStalePolicyDataJob;

impl InsertableJob for PruneStalePolicyDataJob {
    const QUEUE_NAME: &'static str = "prune-stale-policy-data";
}

/// Cleanup IP addresses from inactive OAuth sessions
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupInactiveOAuthSessionIpsJob;

impl InsertableJob for CleanupInactiveOAuthSessionIpsJob {
    const QUEUE_NAME: &'static str = "cleanup-inactive-oauth-session-ips";
}

/// Cleanup IP addresses from inactive user/browser sessions
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupInactiveUserSessionIpsJob;

impl InsertableJob for CleanupInactiveUserSessionIpsJob {
    const QUEUE_NAME: &'static str = "cleanup-inactive-user-session-ips";
}
