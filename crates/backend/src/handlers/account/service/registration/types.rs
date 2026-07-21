use std::net::IpAddr;

use anyhow::Error as AnyhowError;
use chrono::{DateTime, Utc};
use coauth_data::{
    BrowserSession, RepositoryError, UpstreamOAuthAuthorizationSession, UpstreamOAuthLink,
    UserEmailAuthentication, UserPhoneAuthentication, UserRegistration, UserRegistrationToken,
};
use serde_json::Value;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::handlers::RequesterFingerprint;

pub struct StartPasswordRegistrationRequestBody {
    pub handle: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: Zeroizing<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub post_auth_action: Option<Value>,
    pub terms_url: Option<Url>,
    pub notification_language: String,
}

pub struct BeginPasswordRegistrationRequestBody {
    pub handle: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: String,
    pub password_confirm: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub requester: RequesterFingerprint,
    pub notification_language: String,
    pub post_auth_action: Option<Value>,
    pub password_registration_enabled: bool,
    pub password_registration_contact_required: bool,
    pub terms_url: Option<Url>,
    pub email_availability: EmailAvailabilityCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailAvailabilityCheck {
    Precheck,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginPasswordRegistrationIssue {
    RegistrationDisabled,
    HandleRequired,
    HandleExists,
    /// The candidate localpart cannot be prepared with the shared RFC 8265
    /// human-identifier input profile.
    HandleInvalid,
    EmailOrPhoneRequired,
    EmailInvalid,
    EmailInUse,
    PhoneInUse,
    PasswordRequired,
    PasswordConfirmRequired,
    PasswordMismatch,
    PasswordTooWeak,
    RateLimited,
    Policy {
        field: Option<String>,
        code: Option<&'static str>,
        message: String,
    },
}

impl BeginPasswordRegistrationIssue {
    #[must_use]
    pub fn as_api_error(&self) -> String {
        match self {
            Self::RegistrationDisabled => "registration_disabled".into(),
            Self::HandleRequired => "handle_required".into(),
            Self::HandleExists => "handle_exists".into(),
            Self::HandleInvalid => "handle_invalid".into(),
            Self::EmailOrPhoneRequired => "email_or_phone_required".into(),
            Self::EmailInvalid => "email_invalid".into(),
            Self::EmailInUse => "email_in_use".into(),
            Self::PhoneInUse => "phone_in_use".into(),
            Self::PasswordRequired => "password_required".into(),
            Self::PasswordConfirmRequired => "password_confirm_required".into(),
            Self::PasswordMismatch => "password_mismatch".into(),
            Self::PasswordTooWeak => "password_too_weak".into(),
            Self::RateLimited => "rate_limited".into(),
            Self::Policy { field, message, .. } => {
                let field = field.as_deref().unwrap_or("form");
                format!("policy_{field}:{message}")
            }
        }
    }
}

pub struct StartedPasswordRegistration {
    pub registration: UserRegistration,
    pub email_verified: bool,
    pub phone_verified: bool,
}

#[allow(clippy::large_enum_variant)]
pub enum BeginPasswordRegistrationResult {
    Started(StartedPasswordRegistration),
    Rejected {
        issues: Vec<BeginPasswordRegistrationIssue>,
    },
}

pub struct RegistrationProgress {
    pub registration: UserRegistration,
    pub email_authentication: Option<UserEmailAuthentication>,
    pub phone_authentication: Option<UserPhoneAuthentication>,
}

pub struct RegistrationStatusSummary {
    pub registration: UserRegistration,
    pub email_pending: bool,
    pub pending_email: Option<String>,
    pub phone_pending: bool,
    pub steps_completed: Vec<&'static str>,
    pub next_step: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationWorkflowState {
    PendingEmailVerification,
    PendingPhoneVerification,
    PendingDisplayName,
    ReadyToFinish,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationWorkflowEventKind {
    Started,
    EmailVerificationRequested,
    EmailVerified,
    PhoneVerificationRequested,
    PhoneVerified,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationWorkflowEvent {
    pub kind: RegistrationWorkflowEventKind,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationWorkflowDeadlineKind {
    RegistrationExpiresAt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationWorkflowDeadline {
    pub kind: RegistrationWorkflowDeadlineKind,
    pub due_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationWorkflowSnapshot {
    pub state: RegistrationWorkflowState,
    pub next_step: Option<&'static str>,
    pub completed_steps: Vec<&'static str>,
    pub events: Vec<RegistrationWorkflowEvent>,
    pub deadlines: Vec<RegistrationWorkflowDeadline>,
}

pub struct CompleteRegistrationRequestBody {
    pub registration: UserRegistration,
    pub registration_token: Option<UserRegistrationToken>,
    pub email_authentication: Option<UserEmailAuthentication>,
    pub phone_authentication: Option<UserPhoneAuthentication>,
    pub user_agent: Option<String>,
    pub upstream_oauth: Option<(UpstreamOAuthAuthorizationSession, UpstreamOAuthLink)>,
}

#[derive(Debug)]
pub struct CompletedRegistration {
    pub registration: UserRegistration,
    pub user_session: BrowserSession,
}

pub struct PreparedRegistrationCompletion {
    pub registration: UserRegistration,
    pub registration_token: Option<UserRegistrationToken>,
    pub email_authentication: Option<UserEmailAuthentication>,
    pub phone_authentication: Option<UserPhoneAuthentication>,
    pub upstream_oauth: Option<(UpstreamOAuthAuthorizationSession, UpstreamOAuthLink)>,
}

impl PreparedRegistrationCompletion {
    #[must_use]
    pub fn into_request(self, user_agent: Option<String>) -> CompleteRegistrationRequestBody {
        CompleteRegistrationRequestBody {
            registration: self.registration,
            registration_token: self.registration_token,
            email_authentication: self.email_authentication,
            phone_authentication: self.phone_authentication,
            user_agent,
            upstream_oauth: self.upstream_oauth,
        }
    }
}

#[derive(Debug, Error)]
pub enum StartPasswordRegistrationError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Password(#[from] AnyhowError),
}

#[derive(Debug, Error)]
pub enum BeginPasswordRegistrationError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(#[from] AnyhowError),
}

#[derive(Debug, Error)]
pub enum LoadRegistrationProgressError {
    #[error("registration not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResendRegistrationVerificationStatus {
    RegistrationCompleted,
    Resent,
    AlreadyVerified,
}

#[derive(Debug, Error)]
pub enum ResendRegistrationVerificationError {
    #[error("registration not found")]
    NotFound,

    #[error("registration verification is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum VerifyRegistrationEmailCodeError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted,

    #[error("registration has no email authentication")]
    NoEmailAuthentication,

    #[error("registration email authentication not found")]
    EmailAuthenticationMissing,

    #[error("email authentication already completed")]
    EmailAlreadyVerified,

    #[error("registration verification is rate limited")]
    RateLimited,

    #[error("invalid email authentication code")]
    InvalidCode,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum VerifyRegistrationPhoneCodeError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted,

    #[error("registration has no phone authentication")]
    NoPhoneAuthentication,

    #[error("registration phone authentication not found")]
    PhoneAuthenticationMissing,

    #[error("phone authentication already completed")]
    PhoneAlreadyVerified,

    #[error("registration verification is rate limited")]
    RateLimited,

    #[error("invalid phone authentication code")]
    InvalidCode,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum SetRegistrationDisplayNameError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted,

    #[error("invalid display name")]
    InvalidDisplayName,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationVerificationOutcome {
    Advanced { next_step: &'static str },
    RegistrationCompleted,
    AlreadyVerified,
    InvalidCode,
    RateLimited,
}

#[derive(Debug, Error)]
pub enum RegistrationVerificationError {
    #[error("registration not found")]
    NotFound,

    #[error("registration verification is not available")]
    NotAvailable,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationResendOutcome {
    Resent,
    AlreadyVerified,
    RegistrationCompleted,
    RateLimited,
}

#[derive(Debug, Error)]
pub enum RegistrationResendError {
    #[error("registration not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationEmailChangeOutcome {
    Updated,
    AlreadyVerified,
    RegistrationCompleted,
    InvalidEmail,
    EmailInUse,
    RateLimited,
}

#[derive(Debug, Error)]
pub enum RegistrationEmailChangeError {
    #[error("registration not found")]
    NotFound,

    #[error("registration verification is not available")]
    NotAvailable,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationDisplayNameOutcome {
    Advanced { next_step: &'static str },
    RegistrationCompleted,
    InvalidDisplayName,
}

#[derive(Debug, Error)]
pub enum RegistrationDisplayNameWorkflowError {
    #[error("registration not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RegistrationFinishOutcome {
    Completed(CompletedRegistration),
    Rejected { error: &'static str },
}

#[derive(Debug, Error)]
pub enum RegistrationFinishError {
    #[error("registration not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(#[from] AnyhowError),
}

#[derive(Debug, Error)]
pub enum CheckRegistrationFinishEligibilityError {
    #[error("registration session has expired")]
    RegistrationExpired,

    #[error("registration does not belong to this browser")]
    BrowserSessionMissing,

    #[error("handle is already taken")]
    HandleTaken,

    #[error("handle is not available")]
    HandleNotAvailable,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum LoadRegistrationFinishPreparationError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    AlreadyCompleted(UserRegistration),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error("registration finish eligibility check failed")]
    Eligibility {
        registration: UserRegistration,
        #[source]
        source: CheckRegistrationFinishEligibilityError,
    },

    #[error("registration finish preparation failed")]
    Prepare {
        registration: UserRegistration,
        #[source]
        source: PrepareRegistrationCompletionError,
    },
}

#[derive(Debug, Error)]
pub enum PrepareRegistrationCompletionError {
    #[error("registration token is required")]
    RegistrationTokenRequired,

    #[error("registration token not found")]
    RegistrationTokenMissing,

    #[error("registration token is invalid")]
    RegistrationTokenInvalid,

    #[error("registration email authentication not found")]
    EmailAuthenticationMissing,

    #[error("registration email is not verified")]
    EmailNotVerified,

    #[error("registration email is already in use")]
    EmailInUse(String),

    #[error("registration phone authentication not found")]
    PhoneAuthenticationMissing,

    #[error("registration phone is not verified")]
    PhoneNotVerified,

    #[error("registration phone is already in use")]
    PhoneInUse,

    #[error("upstream OAuth authorization session not found")]
    UpstreamOAuthSessionMissing,

    #[error("upstream OAuth link not found")]
    UpstreamOAuthLinkMissing,

    #[error("upstream OAuth link already belongs to a user")]
    UpstreamOAuthLinkAlreadyUsed,

    #[error("registration display name is required")]
    DisplayNameRequired,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}
