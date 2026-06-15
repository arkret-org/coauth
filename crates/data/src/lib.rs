//! Core data model types for the coauth authentication service.
//!
//! This crate defines the domain objects that are persisted in the database
//! and shared across the application. Types here are storage-backend agnostic —
//! they describe *what* is stored, not *how*.
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
extern crate self as coauth_data_model;
extern crate self as coauth_storage;
extern crate self as coauth_storage_pg;

use thiserror::Error;

// Define `lower()` as a SQL function for Diesel (Diesel doesn't ship one).
diesel::define_sql_function! {
    /// SQL `lower()` function for case-insensitive text comparisons
    fn lower(x: diesel::sql_types::Text) -> diesel::sql_types::Text;
}

/// Unified contact points and external identity bindings for user accounts.
pub mod account;
/// Durable accountability grants for Personal Agent capability approval.
pub mod accountability;
/// App session repositories and PostgreSQL implementations.
pub mod app_session;
/// Admin operation logs and account security event models.
pub mod audit;
/// Durable Circle capability grants.
pub mod circle_capability;
/// Clock abstraction for testability (`SystemClock` in production, mock clock
/// in tests).
pub mod clock;
/// Persisted notification request, delivery, and audit event models.
pub mod notification;
/// OAuth client and session models.
pub mod oauth;
/// Personal access token types.
pub mod personal;
/// PostgreSQL storage backend implementation details.
pub mod pg;
pub mod policy_data;
/// Post-authentication action types.
pub mod post_auth_action;
/// Queue repositories and PostgreSQL implementations.
pub mod queue;
mod site_config;
/// Storage repository abstractions and pagination helpers.
pub mod storage;
/// Strand engine data model — multi-step user interaction definitions, stage
/// bindings, and runtime session tracking.
pub mod strand;
pub(crate) mod tokens;
pub mod upstream_oauth;
mod url_builder;
/// User domain types, repositories, and PostgreSQL implementations.
pub mod user;
pub(crate) mod user_agent;
pub(crate) mod users;
mod utils;
mod version;
/// Persisted workflow instance, step, deadline, event, and audit models.
pub mod workflow;

/// Error when an invalid state transition is attempted.
#[derive(Debug, Error)]
#[error("invalid state transition")]
pub struct InvalidTransitionError;

pub use ulid::Ulid;

pub use self::pg::{
    DatabaseError, MIGRATIONS, PgRepository, PgRepositoryFactory, has_pending_migrations, migrate,
    schema, test_utils,
};
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
pub use self::accountability::{
    AccountabilityGrant, AccountabilityGrantFanoutState, AccountabilitySubjectKind,
    AccountabilitySubjectRevocation,
};
pub use self::audit::{AccountSecurityEvent, AdminOperation, AdminOperationLog, SecurityEventType};
pub use self::circle_capability::{
    CircleCapabilityAction, CircleCapabilityGrant, CircleCapabilityGrantRepository,
    NewCircleCapabilityGrant, ParseCircleCapabilityActionError, RiskTier,
};
pub use self::clock::{Clock, SystemClock};
pub use self::notification::{
    NotificationChannel, NotificationDelivery, NotificationDeliveryFailure,
    NotificationDeliveryStatus, NotificationDestination, NotificationEventActor,
    NotificationEventKind, NotificationEventLog, NotificationPreference, NotificationRequest,
    NotificationRequestSource, NotificationRequestStatus,
};
pub use self::oauth::{
    AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, Client, DeviceCodeGrant,
    DeviceCodeGrantState, InvalidRedirectUriError, JwksOrJwksUri, LocalizableField,
    LocalizedClientMetadata, Pkce, Session, SessionGrant, SessionState,
};
pub(crate) use self::pg::DatabaseInconsistencyError;
pub use self::policy_data::PolicyData;
pub use self::post_auth_action::{AccountAction, PostAuthAction};
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
    NewUserPrimaryHandlePreference, Password, PrincipalDidUpdateKey, PrincipalUser, User,
    UserEmail, UserEmailAuthentication, UserEmailAuthenticationCode, UserEmailPatch, UserPatch,
    UserPhone, UserPhoneAuthentication, UserPhoneAuthenticationCode, UserPrimaryHandlePreference,
    UserProfile, UserProfilePatch, UserRecoverySession, UserRecoveryTicket, UserRegistration,
    UserRegistrationPassword, UserRegistrationToken, UserTotpConfig, VerifiedUserHandleClaim,
};
pub use self::utils::{BoxClock, BoxRng};
pub use self::version::AppVersion;
pub use self::workflow::{
    WorkflowActor, WorkflowAssignee, WorkflowAuditAction, WorkflowAuditLog, WorkflowDeadline,
    WorkflowDeadlineStatus, WorkflowEvent, WorkflowEventKind, WorkflowInstance,
    WorkflowInstanceStatus, WorkflowStep, WorkflowStepStatus, WorkflowSubject,
};
