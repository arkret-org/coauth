//! Storage-neutral domain types and persistence ports for the coauth
//! authentication service.
//!
//! Storage-neutral models shared with API contracts belong in
//! `coauth-data-model`. This crate re-exports those models where existing
//! repository ports use them. Diesel schema, migrations, and PostgreSQL
//! implementations live in `coauth-storage-postgres`.
//!
//! # Main type categories
//!
//! - **Accounts** — [`AccountContactPoint`], [`AccountIdentityBinding`]
//! - **Users** — [`User`], [`BrowserSession`], [`Password`], [`UserEmail`], [`UserRegistration`],
//!   [`UserRecoveryTicket`]
//! - **Strands** — [`StrandDefinition`], [`StrandStageBinding`], [`StageKind`], [`StrandSession`],
//!   [`StageChallenge`], [`StageSubmission`], [`StageOutcome`]
//! - **OAuth** — [`Client`], [`Session`], [`AuthorizationGrant`], [`AccessToken`],
//!   [`RefreshToken`], [`DeviceCodeGrant`]
//! - **Upstream SSO** — [`UpstreamOAuthProvider`], [`UpstreamOAuthLink`],
//!   [`UpstreamOAuthAuthorizationSession`]
//! - **Notifications** — [`NotificationRequest`], [`NotificationDelivery`],
//!   [`NotificationEventLog`]
//! - **Configuration** — [`SiteConfig`], [`PolicyData`], [`AppVersion`]
//! - **Utilities** — [`Clock`], [`BoxClock`], [`BoxRng`]

#![allow(clippy::module_name_repetitions)]

extern crate self as coauth_data;

use thiserror::Error;

/// Unified contact points and external identity bindings for user accounts.
pub mod account;
/// Durable canonical account handoff and identity-creation state.
pub mod account_handoff;
/// Durable accountability grants for Personal Agent capability approval.
pub mod accountability;
/// Durable agent key authorizations + agent-key-proof replay table (AKP-0008).
pub mod agent_key;
/// App session models and repository ports.
pub mod app_session;
/// Admin operation logs and account security event models.
pub mod audit;
/// Durable Circle capability grants.
pub mod circle_capability;
/// Clock abstraction for testability (`SystemClock` in production, mock clock
/// in tests).
pub mod clock;
/// Durable collaboration capability grants.
pub mod collaboration_capability;
/// Durable accepted DID bindings (DID-P2-A).
pub mod did_binding;
/// Durable DPoP proof replay keys.
pub mod dpop_replay;
/// Persisted notification request, delivery, and audit event models.
pub mod notification;
/// OAuth client and session models.
pub mod oauth;
/// Organization principal control state and organization DID delegations.
pub mod organization_control;
/// Personal access token types.
pub mod personal;
pub mod policy_data;
/// Post-authentication action types.
pub mod post_auth_action;
/// Queue models and repository ports.
pub mod queue;
/// Durable recovery-completion grant issuance outcomes.
pub mod recovery_authority;
mod site_config;
/// Storage repository abstractions and pagination helpers.
pub mod storage;
/// Strand engine data model — multi-step user interaction definitions, stage
/// bindings, and runtime session tracking.
pub mod strand;
pub(crate) mod tokens;
pub mod upstream_oauth;
mod url_builder;
/// User domain types and repository ports.
pub mod user;
pub(crate) mod user_agent;
pub(crate) mod users;
mod utils;
mod version;

/// Error when an invalid state transition is attempted.
#[derive(Debug, Error)]
#[error("invalid state transition")]
pub struct InvalidTransitionError;

pub use ulid::Ulid;

pub use self::storage::{
    BoxRepository, BoxRepositoryFactory, MapErr, Page, Pagination, Repository, RepositoryAccess,
    RepositoryError, RepositoryFactory, RepositoryTransaction, pagination,
};

/// Generate a new UUID v7-compatible identifier (RFC 9562).
///
/// Produces a 128-bit value with the UUID v7 bit layout:
/// 48-bit millisecond timestamp | version 0111 | 12-bit random |
/// variant 10 | 62-bit random.
///
/// The result is returned as a [`Ulid`] for type compatibility with the
/// rest of the codebase; the underlying bytes are valid UUID v7.
pub fn new_id(
    ts: chrono::DateTime<chrono::Utc>,
    rng: &mut (impl rand_core::RngCore + ?Sized),
) -> Ulid {
    let millis = ts.timestamp_millis() as u64;
    let mut bytes = [0u8; 16];

    // 48-bit Unix timestamp in milliseconds (big-endian)
    bytes[0..6].copy_from_slice(&millis.to_be_bytes()[2..8]);

    // Fill remaining 10 bytes with random data
    rng.fill_bytes(&mut bytes[6..]);

    // Set UUID version 7 (bits 48-51 = 0111)
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    // Set RFC 4122 variant (bits 64-65 = 10)
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    Ulid::from(uuid::Uuid::from_bytes(bytes))
}

pub use self::account::{
    AccountContactPoint, AccountIdentityBinding, ContactChannel, IdentityProviderType,
};
pub use self::account_handoff::{
    AccountHandoffAuthorizationCheckpoint, AccountHandoffCreation, AccountHandoffCreationAttempt,
    AccountHandoffCreationAttemptCommit, AccountHandoffCreationAttemptReserve,
    AccountHandoffCreationAttemptState, AccountHandoffGrant, AccountHandoffGrantInput,
    AccountHandoffRepository, ControllerGateAttestationCommit, ControllerGateAttestationReserve,
    DidBindingChallengeConsume, DidBindingChallengeInput, DidBindingChallengeIssue,
    DidBindingChallengeRecord, IdentityAbandonmentChallengeInput,
    IdentityAbandonmentChallengeIssue, IdentityAbandonmentChallengeRecord,
    IdentityAbandonmentCommit, IdentityAbandonmentCommitInput, IdentityBindingChallengeInput,
    IdentityBindingChallengeIssue, IdentityBindingChallengeRecord, IdentityCreationBindingCommit,
    IdentityCreationLeaseRecord, IdentityCreationLeaseRiskDecision, IdentityCreationRegisterReplay,
    IdentityCreationRegistrationContext, IdentityCreationSagaState,
    NewAccountHandoffCreationAttempt, NewControllerGateAttestationIssuance,
    PublishedDidRegisterCommit, PublishedDidRegisterReplay,
};
pub use self::accountability::{
    AccountabilityGrant, AccountabilityGrantFanoutState, AccountabilitySubjectKind,
    AccountabilitySubjectRevocation,
};
pub use self::audit::{AccountSecurityEvent, AdminOperation, AdminOperationLog, SecurityEventType};
pub use self::circle_capability::{
    CIRCLE_CAPABILITY_ACTIONS, CapabilityActionId, CapabilityRiskTier, CircleCapabilityGrant,
    CircleCapabilityGrantRepository, NewCircleCapabilityGrant, capability_action_risk_tier,
    circle_action_requires_allowed_circle_ids, is_circle_capability_action,
};
pub use self::clock::{Clock, SystemClock};
pub use self::collaboration_capability::{
    COLLABORATION_CAPABILITY_ACTIONS, CollaborationCapabilityGrant,
    CollaborationCapabilityGrantRepository, CollaborationCapabilityRevokeFanout,
    NewCollaborationCapabilityGrant, collaboration_action_requires_approval,
    is_collaboration_capability_action,
};
pub use self::did_binding::{
    VerifiedDidBindingInvalidation, VerifiedDidBindingKeyColumns, VerifiedDidBindingRepository,
    VerifiedDidBindingRow,
};
pub use self::dpop_replay::{DpopReplayRepository, NewDpopJtiReplay};
pub use self::notification::{
    NotificationChannel, NotificationDelivery, NotificationDeliveryFailure,
    NotificationDeliveryStatus, NotificationDestination, NotificationEventActor,
    NotificationEventKind, NotificationEventLog, NotificationPreference, NotificationRequest,
    NotificationRequestSource, NotificationRequestStatus,
};
pub use self::oauth::{
    AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, Client, DeviceCodeGrant,
    DeviceCodeGrantState, InvalidRedirectUriError, JwksOrJwksUri, LocalizableField,
    LocalizedClientMetadata, NewSessionGrantOperation, Pkce, Session, SessionGrant,
    SessionGrantCommitOutcome, SessionGrantExactOutcome, SessionGrantLifecycleState,
    SessionGrantOperation, SessionGrantOperationDescriptor, SessionGrantOperationKind,
    SessionGrantOperationState, SessionGrantProofAuthorization, SessionGrantRefreshOutcome,
    SessionGrantReserveOutcome, SessionGrantRevokeOutcome, SessionGrantRevokeSelector,
    SessionGrantRevokeTarget, SessionState,
};
pub use self::organization_control::{
    NewOrganizationDelegation, NewOrganizationPrincipalControl, OrganizationBootstrapAuthorization,
    OrganizationControlRepository, OrganizationDelegation, OrganizationDelegationStatus,
    OrganizationPrincipalControl, PRINCIPAL_CONTROL_REALM_BOOTSTRAP_PURPOSE,
};
pub use self::policy_data::{PolicyData, PolicyDataDocument};
pub use self::post_auth_action::{AccountAction, PostAuthAction};
pub use self::recovery_authority::{
    NewRecoveryCompletionGrantIssuance, RecoveryCompletionGrantIssuance,
};
pub use self::site_config::{
    CaptchaConfig, CaptchaService, SessionExpirationConfig, SessionLimitConfig, SiteConfig,
};
pub use self::strand::{
    IdentificationField, PromptField, PromptFieldType, StageChallenge, StageKind, StageOutcome,
    StageSubmission, StageValidationError, StrandDefinition, StrandDesignation, StrandSession,
    StrandSessionStatus, StrandStageBinding,
};
pub use self::tokens::{
    AccessToken, AccessTokenState, RefreshToken, RefreshTokenChainRevokeOutcome, RefreshTokenState,
    TokenFormatError, TokenType,
};
pub use self::upstream_oauth::{
    UpstreamOAuthAuthorizationSession, UpstreamOAuthAuthorizationSessionState, UpstreamOAuthLink,
    UpstreamOAuthLinkPatch, UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
    UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderHandlePreference,
    UpstreamOAuthProviderImportAction, UpstreamOAuthProviderImportPreference,
    UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderOnConflict,
    UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderResponseMode, UpstreamOAuthProviderSource,
    UpstreamOAuthProviderSubjectPreference, UpstreamOAuthProviderTokenAuthMethod,
};
pub use self::url_builder::UrlBuilder;
pub use self::user_agent::{DeviceType, UserAgent};
pub use self::users::{
    AdminUserPatch, Authentication, AuthenticationMethod, BrowserSession,
    NewUserPrimaryHandlePreference, Password, PrincipalDidBinding, PrincipalUser, User, UserEmail,
    UserEmailAuthentication, UserEmailAuthenticationCode, UserEmailPatch, UserPatch, UserPhone,
    UserPhoneAuthentication, UserPhoneAuthenticationCode, UserPrimaryHandlePreference, UserProfile,
    UserProfilePatch, UserRecoverySession, UserRecoveryTicket, UserRegistration,
    UserRegistrationPassword, UserRegistrationToken, VerifiedUserHandleClaim,
    parse_locale_preference_patch,
};
pub use self::utils::{BoxClock, BoxRng};
pub use self::version::AppVersion;
