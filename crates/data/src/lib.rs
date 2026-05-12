//! Core data model types for the coauth authentication service.
//!
//! This crate defines the domain objects that are persisted in the database
//! and shared across the application. Types here are storage-backend agnostic —
//! they describe *what* is stored, not *how*.
//!
//! # Main type categories
//!
//! - **Accounts** — [`AccountContactPoint`], [`AccountIdentityBinding`]
//! - **Users** — [`User`], [`BrowserSession`], [`Password`], [`UserEmail`],
//!   [`UserRegistration`], [`UserRecoveryTicket`]
//! - **Flows** — [`FlowDefinition`], [`FlowStageBinding`], [`StageKind`],
//!   [`FlowSession`], [`StageChallenge`], [`StageResponse`], [`StageOutcome`]
//! - **OAuth 2.0** — [`Client`], [`Session`], [`AuthorizationGrant`],
//!   [`AccessToken`], [`RefreshToken`], [`DeviceCodeGrant`]
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
/// App session repositories and PostgreSQL implementations.
pub mod app_session;
/// Admin operation logs and account security event models.
pub mod audit;
/// Clock abstraction for testability (`SystemClock` in production, mock clock
/// in tests).
pub mod clock;
/// Flow engine data model — multi-step user interaction definitions, stage
/// bindings, and runtime session tracking.
pub mod flow;
/// Persisted notification request, delivery, and audit event models.
pub mod notification;
/// OAuth 2.0 client and session models.
pub mod oauth2;
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
pub(crate) mod tokens;
pub mod upstream_oauth2;
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

pub use self::{
    pg::{
        DatabaseError, MIGRATIONS, PgRepository, PgRepositoryFactory, has_pending_migrations,
        migrate, schema, test_utils,
    },
    storage::{
        BoxRepository, BoxRepositoryFactory, MapErr, Page, Pagination, Repository,
        RepositoryAccess, RepositoryError, RepositoryFactory, RepositoryTransaction, pagination,
    },
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

pub(crate) use self::pg::DatabaseInconsistencyError;
pub use self::{
    account::{AccountContactPoint, AccountIdentityBinding, ContactChannel, IdentityProviderType},
    audit::{AccountSecurityEvent, AdminOperation, AdminOperationLog, SecurityEventType},
    clock::{Clock, SystemClock},
    flow::{
        FlowDefinition, FlowDesignation, FlowSession, FlowSessionStatus, FlowStageBinding,
        IdentificationField, PromptField, PromptFieldType, StageChallenge, StageKind, StageOutcome,
        StageResponse, StageValidationError,
    },
    notification::{
        NotificationChannel, NotificationDelivery, NotificationDeliveryFailure,
        NotificationDeliveryStatus, NotificationDestination, NotificationEventActor,
        NotificationEventKind, NotificationEventLog, NotificationPreference, NotificationRequest,
        NotificationRequestSource, NotificationRequestStatus,
    },
    oauth2::{
        AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, Client, DeviceCodeGrant,
        DeviceCodeGrantState, InvalidRedirectUriError, JwksOrJwksUri, LocalizableField,
        LocalizedClientMetadata, Pkce, Session, SessionGrant, SessionState,
    },
    policy_data::PolicyData,
    post_auth_action::{AccountAction, PostAuthAction},
    site_config::{
        CaptchaConfig, CaptchaService, SessionExpirationConfig, SessionLimitConfig, SiteConfig,
    },
    tokens::{
        AccessToken, AccessTokenState, RefreshToken, RefreshTokenState, TokenFormatError, TokenType,
    },
    upstream_oauth2::{
        UpstreamOAuthAuthorizationSession, UpstreamOAuthAuthorizationSessionState,
        UpstreamOAuthLink, UpstreamOAuthLinkPatch, UpstreamOAuthProvider,
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderImportAction, UpstreamOAuthProviderImportPreference,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderOnConflict,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderResponseMode,
        UpstreamOAuthProviderSource, UpstreamOAuthProviderSubjectPreference,
        UpstreamOAuthProviderTokenAuthMethod, UpstreamOAuthProviderUsernamePreference,
    },
    url_builder::UrlBuilder,
    user_agent::{DeviceType, UserAgent},
    users::{
        AdminUserPatch, Authentication, AuthenticationMethod, BrowserSession, Password,
        PrincipalUser, User, UserEmail, UserEmailAuthentication, UserEmailAuthenticationCode,
        UserEmailPatch, UserPatch, UserPhone, UserPhoneAuthentication, UserPhoneAuthenticationCode,
        UserProfile, UserProfilePatch, UserRecoverySession, UserRecoveryTicket, UserRegistration,
        UserRegistrationPassword, UserRegistrationToken, UserTotpConfig,
    },
    utils::{BoxClock, BoxRng},
    version::AppVersion,
    workflow::{
        WorkflowActor, WorkflowAssignee, WorkflowAuditAction, WorkflowAuditLog, WorkflowDeadline,
        WorkflowDeadlineStatus, WorkflowEvent, WorkflowEventKind, WorkflowInstance,
        WorkflowInstanceStatus, WorkflowStep, WorkflowStepStatus, WorkflowSubject,
    },
};
