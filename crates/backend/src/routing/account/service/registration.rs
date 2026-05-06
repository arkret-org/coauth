//! # Migration path
//!
//! The registration workflow currently uses `UserRegistrationRepository` for
//! state tracking. It will be progressively migrated to use
//! `WorkflowRepository` for unified workflow state management. The flow engine
//! (`crate::routing::flow`) can already orchestrate registration as a
//! `default-registration` flow.

use std::{net::IpAddr, str::FromStr};

use anyhow::Error as AnyhowError;
use chrono::{DateTime, Duration, Utc};
use coauth_data::{
    BoxRepository, BrowserSession, Clock, RepositoryAccess, RepositoryError,
    UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, User, UserEmailAuthentication,
    UserPhoneAuthentication, UserRegistration, UserRegistrationToken,
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthSessionRepository},
    user::{
        BrowserSessionRepository, UserEmailFilter, UserEmailRepository, UserFilter,
        UserPasswordRepository, UserPhoneRepository, UserRegistrationTokenRepository,
        UserRepository, UserTermsRepository,
    },
};
use coauth_matrix::HomeserverAdmin;
use coauth_policy::PolicyFactory;
use lettre::Address;
use rand_chacha::rand_core::CryptoRngCore;
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;
use url::Url;
use zeroize::Zeroizing;

use crate::routing::{
    Limiter, RequesterFingerprint,
    notification_dispatch::{NotificationIntent, schedule_notification},
    passwords::PasswordManager,
};

pub struct StartPasswordRegistrationRequest {
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: Zeroizing<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub post_auth_action: Option<Value>,
    pub terms_url: Option<Url>,
    pub notification_language: String,
}

pub struct BeginPasswordRegistrationRequest {
    pub username: String,
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
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginPasswordRegistrationIssue {
    RegistrationDisabled,
    UsernameRequired,
    UsernameExists,
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
            Self::UsernameRequired => "username_required".into(),
            Self::UsernameExists => "username_exists".into(),
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
    pub workflow: RegistrationWorkflowSnapshot,
}

pub struct RegistrationEmailStepContext {
    pub registration: UserRegistration,
    pub email_authentication: UserEmailAuthentication,
}

pub struct RegistrationDisplayNameStepContext {
    pub registration: UserRegistration,
}

pub struct RegistrationTokenStepContext {
    pub registration: UserRegistration,
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

pub struct CompleteRegistrationRequest {
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
    pub user: User,
    pub user_session: BrowserSession,
    pub password_authenticated: bool,
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
    pub fn into_request(self, user_agent: Option<String>) -> CompleteRegistrationRequest {
        CompleteRegistrationRequest {
            registration: self.registration,
            registration_token: self.registration_token,
            email_authentication: self.email_authentication,
            phone_authentication: self.phone_authentication,
            user_agent,
            upstream_oauth: self.upstream_oauth,
        }
    }
}

impl RegistrationProgress {
    #[must_use]
    pub fn workflow_state(&self) -> RegistrationWorkflowState {
        if self.registration.completed_at.is_some() {
            return RegistrationWorkflowState::Completed;
        }

        if self.registration.email_authentication_id.is_some() && !self.email_verified() {
            return RegistrationWorkflowState::PendingEmailVerification;
        }

        if self.registration.phone_authentication_id.is_some() && !self.phone_verified() {
            return RegistrationWorkflowState::PendingPhoneVerification;
        }

        if self.registration.display_name.is_none() {
            return RegistrationWorkflowState::PendingDisplayName;
        }

        RegistrationWorkflowState::ReadyToFinish
    }

    #[must_use]
    pub fn email_verified(&self) -> bool {
        self.email_authentication.as_ref().map_or(
            self.registration.email_authentication_id.is_none(),
            |auth| auth.completed_at.is_some(),
        )
    }

    #[must_use]
    pub fn phone_verified(&self) -> bool {
        self.phone_authentication.as_ref().map_or(
            self.registration.phone_authentication_id.is_none(),
            |auth| auth.completed_at.is_some(),
        )
    }

    #[must_use]
    pub fn next_step(&self) -> &'static str {
        next_registration_step(
            &self.registration,
            self.email_verified(),
            self.phone_verified(),
        )
    }

    #[must_use]
    pub fn completed_steps(&self) -> Vec<&'static str> {
        completed_registration_steps(
            &self.registration,
            self.email_verified(),
            self.phone_verified(),
        )
    }

    #[must_use]
    pub fn workflow_events(&self) -> Vec<RegistrationWorkflowEvent> {
        let mut events = vec![RegistrationWorkflowEvent {
            kind: RegistrationWorkflowEventKind::Started,
            occurred_at: self.registration.created_at,
        }];

        if let Some(email_authentication) = &self.email_authentication {
            events.push(RegistrationWorkflowEvent {
                kind: RegistrationWorkflowEventKind::EmailVerificationRequested,
                occurred_at: email_authentication.created_at,
            });

            if let Some(completed_at) = email_authentication.completed_at {
                events.push(RegistrationWorkflowEvent {
                    kind: RegistrationWorkflowEventKind::EmailVerified,
                    occurred_at: completed_at,
                });
            }
        }

        if let Some(phone_authentication) = &self.phone_authentication {
            events.push(RegistrationWorkflowEvent {
                kind: RegistrationWorkflowEventKind::PhoneVerificationRequested,
                occurred_at: phone_authentication.created_at,
            });

            if let Some(completed_at) = phone_authentication.completed_at {
                events.push(RegistrationWorkflowEvent {
                    kind: RegistrationWorkflowEventKind::PhoneVerified,
                    occurred_at: completed_at,
                });
            }
        }

        if let Some(completed_at) = self.registration.completed_at {
            events.push(RegistrationWorkflowEvent {
                kind: RegistrationWorkflowEventKind::Completed,
                occurred_at: completed_at,
            });
        }

        events.sort_by_key(|event| event.occurred_at);
        events
    }

    #[must_use]
    pub fn workflow_deadlines(&self) -> Vec<RegistrationWorkflowDeadline> {
        if self.registration.completed_at.is_some() {
            return Vec::new();
        }

        vec![RegistrationWorkflowDeadline {
            kind: RegistrationWorkflowDeadlineKind::RegistrationExpiresAt,
            due_at: self.registration.created_at + Duration::hours(1),
        }]
    }

    #[must_use]
    pub fn workflow_snapshot(&self) -> RegistrationWorkflowSnapshot {
        let state = self.workflow_state();
        let next_step = match state {
            RegistrationWorkflowState::Completed => None,
            _ => Some(self.next_step()),
        };

        RegistrationWorkflowSnapshot {
            state,
            next_step,
            completed_steps: self.completed_steps(),
            events: self.workflow_events(),
            deadlines: self.workflow_deadlines(),
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

#[derive(Debug, Error)]
pub enum LoadRegistrationEmailStepError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted(UserRegistration),

    #[error("registration has no email authentication")]
    NoEmailAuthentication,

    #[error("registration email authentication not found")]
    EmailAuthenticationMissing,

    #[error("email authentication already completed")]
    EmailAlreadyVerified,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum LoadRegistrationDisplayNameStepError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted(UserRegistration),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum LoadRegistrationTokenStepError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted(UserRegistration),

    #[error("registration token already attached")]
    TokenAlreadyAttached(UserRegistration),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum AttachRegistrationTokenError {
    #[error("registration not found")]
    NotFound,

    #[error("registration already completed")]
    RegistrationCompleted(UserRegistration),

    #[error("registration token already attached")]
    TokenAlreadyAttached(UserRegistration),

    #[error("registration token invalid")]
    InvalidToken,

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeserverCheckMode {
    Strict,
    BestEffort,
}

#[derive(Debug, Error)]
pub enum CheckRegistrationFinishEligibilityError {
    #[error("registration session has expired")]
    RegistrationExpired,

    #[error("registration does not belong to this browser")]
    BrowserSessionMissing,

    #[error("username is already taken")]
    UsernameTaken,

    #[error("username is not available")]
    UsernameNotAvailable,

    #[error("failed to verify username availability")]
    HomeserverUnavailable(#[source] AnyhowError),

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

#[derive(Debug, Error)]
enum PrepareAdminBootstrapError {
    #[error("bootstrap admin token is invalid")]
    InvalidToken,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[must_use]
pub fn next_registration_step(
    registration: &UserRegistration,
    email_verified: bool,
    phone_verified: bool,
) -> &'static str {
    if registration.email_authentication_id.is_some() && !email_verified {
        return "verify_email";
    }

    if registration.phone_authentication_id.is_some() && !phone_verified {
        return "verify_phone";
    }

    if registration.display_name.is_none() {
        return "display_name";
    }

    "finish"
}

#[must_use]
pub fn completed_registration_steps(
    registration: &UserRegistration,
    email_verified: bool,
    phone_verified: bool,
) -> Vec<&'static str> {
    let mut steps = Vec::new();
    steps.push("register");

    if registration.email_authentication_id.is_some() && email_verified {
        steps.push("verify_email");
    }

    if registration.phone_authentication_id.is_some() && phone_verified {
        steps.push("verify_phone");
    }

    if registration.display_name.is_some() {
        steps.push("display_name");
    }

    if registration.completed_at.is_some() {
        steps.push("finish");
    }

    steps
}

pub async fn load_registration_progress(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationProgress, LoadRegistrationProgressError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(LoadRegistrationProgressError::NotFound)?;

    let email_authentication =
        if let Some(email_authentication_id) = registration.email_authentication_id {
            repo.user_email()
                .lookup_authentication(email_authentication_id)
                .await?
        } else {
            None
        };

    let phone_authentication =
        if let Some(phone_authentication_id) = registration.phone_authentication_id {
            repo.user_phone()
                .lookup_authentication(phone_authentication_id)
                .await?
        } else {
            None
        };

    Ok(RegistrationProgress {
        registration,
        email_authentication,
        phone_authentication,
    })
}

pub async fn load_registration_status(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationStatusSummary, LoadRegistrationProgressError> {
    let progress = load_registration_progress(repo, registration_id).await?;
    let workflow = progress.workflow_snapshot();

    let email_pending =
        progress.registration.email_authentication_id.is_some() && !progress.email_verified();
    let pending_email = progress
        .email_authentication
        .as_ref()
        .filter(|auth| auth.completed_at.is_none())
        .map(|auth| auth.email.clone());
    let phone_pending =
        progress.registration.phone_authentication_id.is_some() && !progress.phone_verified();
    let steps_completed = workflow.completed_steps.clone();
    let next_step = workflow.next_step.unwrap_or_else(|| progress.next_step());

    Ok(RegistrationStatusSummary {
        registration: progress.registration,
        email_pending,
        pending_email,
        phone_pending,
        steps_completed,
        next_step,
        workflow,
    })
}

pub async fn load_registration_email_step(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationEmailStepContext, LoadRegistrationEmailStepError> {
    let progress = load_registration_progress(repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => LoadRegistrationEmailStepError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                LoadRegistrationEmailStepError::Repository(error)
            }
        })?;

    let registration = progress.registration;

    if registration.completed_at.is_some() {
        return Err(LoadRegistrationEmailStepError::RegistrationCompleted(
            registration,
        ));
    }

    if registration.email_authentication_id.is_none() {
        return Err(LoadRegistrationEmailStepError::NoEmailAuthentication);
    }

    let email_authentication = progress
        .email_authentication
        .ok_or(LoadRegistrationEmailStepError::EmailAuthenticationMissing)?;

    if email_authentication.completed_at.is_some() {
        return Err(LoadRegistrationEmailStepError::EmailAlreadyVerified);
    }

    Ok(RegistrationEmailStepContext {
        registration,
        email_authentication,
    })
}

pub async fn load_registration_display_name_step(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationDisplayNameStepContext, LoadRegistrationDisplayNameStepError> {
    let progress = load_registration_progress(repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => {
                LoadRegistrationDisplayNameStepError::NotFound
            }
            LoadRegistrationProgressError::Repository(error) => {
                LoadRegistrationDisplayNameStepError::Repository(error)
            }
        })?;

    let registration = progress.registration;

    if registration.completed_at.is_some() {
        return Err(LoadRegistrationDisplayNameStepError::RegistrationCompleted(
            registration,
        ));
    }

    Ok(RegistrationDisplayNameStepContext { registration })
}

pub async fn load_registration_token_step(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationTokenStepContext, LoadRegistrationTokenStepError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(LoadRegistrationTokenStepError::NotFound)?;

    if registration.completed_at.is_some() {
        return Err(LoadRegistrationTokenStepError::RegistrationCompleted(
            registration,
        ));
    }

    if registration.user_registration_token_id.is_some() {
        return Err(LoadRegistrationTokenStepError::TokenAlreadyAttached(
            registration,
        ));
    }

    Ok(RegistrationTokenStepContext { registration })
}

pub async fn attach_registration_token(
    mut repo: BoxRepository,
    clock: &dyn Clock,
    registration_id: Ulid,
    token: &str,
) -> Result<UserRegistration, AttachRegistrationTokenError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(AttachRegistrationTokenError::NotFound)?;

    if registration.completed_at.is_some() {
        return Err(AttachRegistrationTokenError::RegistrationCompleted(
            registration,
        ));
    }

    if registration.user_registration_token_id.is_some() {
        return Err(AttachRegistrationTokenError::TokenAlreadyAttached(
            registration,
        ));
    }

    let Some(registration_token) = repo.user_registration_token().find_by_token(token).await?
    else {
        return Err(AttachRegistrationTokenError::InvalidToken);
    };

    if !registration_token.is_valid(clock.now()) {
        return Err(AttachRegistrationTokenError::InvalidToken);
    }

    let registration = repo
        .user_registration()
        .set_registration_token(registration, &registration_token)
        .await?;

    repo.save().await?;

    Ok(registration)
}

pub async fn start_password_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    request: StartPasswordRegistrationRequest,
) -> Result<StartedPasswordRegistration, StartPasswordRegistrationError> {
    let mut registration = repo
        .user_registration()
        .add(
            rng,
            clock,
            request.username,
            request.ip_address,
            request.user_agent,
            request.post_auth_action,
        )
        .await?;

    if let Some(terms_url) = request.terms_url {
        registration = repo
            .user_registration()
            .set_terms_url(registration, terms_url)
            .await?;
    }

    let email_verified = if let Some(email) = request.email {
        let user_email_authentication = repo
            .user_email()
            .add_authentication_for_registration(rng, clock, email, &registration)
            .await?;

        schedule_notification(
            &mut repo,
            rng,
            clock,
            NotificationIntent::verify_email(
                &user_email_authentication,
                request.notification_language.clone(),
            ),
        )
        .await?;

        registration = repo
            .user_registration()
            .set_email_authentication(registration, &user_email_authentication)
            .await?;

        false
    } else {
        true
    };

    let phone_verified = if let Some(phone) = request.phone {
        let user_phone_authentication = repo
            .user_phone()
            .add_authentication_for_registration(rng, clock, phone, &registration)
            .await?;

        schedule_notification(
            &mut repo,
            rng,
            clock,
            NotificationIntent::verify_phone(
                &user_phone_authentication,
                request.notification_language,
            ),
        )
        .await?;

        registration = repo
            .user_registration()
            .set_phone_authentication(registration, &user_phone_authentication)
            .await?;

        false
    } else {
        true
    };

    let (version, hashed_password) = password_manager.hash(rng, request.password).await?;

    registration = repo
        .user_registration()
        .set_password(registration, hashed_password, version)
        .await?;

    repo.save().await?;

    Ok(StartedPasswordRegistration {
        registration,
        email_verified,
        phone_verified,
    })
}

pub async fn begin_password_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    homeserver: &dyn HomeserverAdmin,
    policy_factory: &PolicyFactory,
    limiter: &Limiter,
    request: BeginPasswordRegistrationRequest,
) -> Result<BeginPasswordRegistrationResult, BeginPasswordRegistrationError> {
    if !request.password_registration_enabled {
        return Ok(BeginPasswordRegistrationResult::Rejected {
            issues: vec![BeginPasswordRegistrationIssue::RegistrationDisabled],
        });
    }

    let mut issues: Vec<BeginPasswordRegistrationIssue> = Vec::new();

    if request.username.is_empty() {
        issues.push(BeginPasswordRegistrationIssue::UsernameRequired);
    } else if repo.user().exists(&request.username).await? {
        issues.push(BeginPasswordRegistrationIssue::UsernameExists);
    } else {
        match homeserver.is_localpart_available(&request.username).await {
            Ok(false) => issues.push(BeginPasswordRegistrationIssue::UsernameExists),
            Ok(true) => {}
            Err(error) => {
                tracing::warn!(
                    error = &*error as &dyn std::error::Error,
                    "Failed to check localpart availability, skipping homeserver check"
                );
            }
        }
    }

    let email_str = request.email.unwrap_or_default();
    let phone_str = request.phone.unwrap_or_default();

    if request.password_registration_contact_required
        && email_str.is_empty()
        && phone_str.is_empty()
    {
        issues.push(BeginPasswordRegistrationIssue::EmailOrPhoneRequired);
    }

    let email = if !email_str.is_empty() {
        if Address::from_str(&email_str).is_err() {
            issues.push(BeginPasswordRegistrationIssue::EmailInvalid);
            None
        } else if matches!(request.email_availability, EmailAvailabilityCheck::Precheck)
            && repo
                .user_email()
                .count(UserEmailFilter::new().for_email(&email_str))
                .await?
                > 0
        {
            issues.push(BeginPasswordRegistrationIssue::EmailInUse);
            None
        } else {
            Some(email_str)
        }
    } else {
        None
    };

    let phone = if !phone_str.is_empty() {
        if repo.user_phone().find_by_phone(&phone_str).await?.is_some() {
            issues.push(BeginPasswordRegistrationIssue::PhoneInUse);
            None
        } else {
            Some(phone_str)
        }
    } else {
        None
    };

    if request.password.is_empty() {
        issues.push(BeginPasswordRegistrationIssue::PasswordRequired);
    }

    if request.password_confirm.is_empty() {
        issues.push(BeginPasswordRegistrationIssue::PasswordConfirmRequired);
    }

    if request.password != request.password_confirm {
        issues.push(BeginPasswordRegistrationIssue::PasswordMismatch);
    }

    if issues.is_empty()
        && !password_manager
            .is_password_complex_enough(&request.password)
            .map_err(AnyhowError::from)?
    {
        issues.push(BeginPasswordRegistrationIssue::PasswordTooWeak);
    }

    if issues.is_empty() {
        let mut policy = policy_factory
            .instantiate()
            .await
            .map_err(AnyhowError::from)?;
        let result = policy
            .evaluate_register(coauth_policy::RegisterInput {
                registration_method: coauth_policy::RegistrationMethod::Password,
                username: &request.username,
                email: email.as_deref(),
                requester: coauth_policy::Requester {
                    ip_address: request.ip_address,
                    user_agent: request.user_agent.clone(),
                    ..Default::default()
                },
            })
            .await
            .map_err(AnyhowError::from)?;

        for violation in result.violations {
            issues.push(BeginPasswordRegistrationIssue::Policy {
                field: violation.field,
                code: violation.code.map(|code| code.as_str()),
                message: violation.msg,
            });
        }
    }

    if issues.is_empty() {
        let mut rate_limited = false;

        if let Err(error) = limiter.check_registration(request.requester).await {
            tracing::warn!(error = &error as &dyn std::error::Error);
            rate_limited = true;
        }

        if let Some(email) = &email
            && let Err(error) = limiter
                .check_email_authentication_email(request.requester, email)
                .await
        {
            tracing::warn!(error = &error as &dyn std::error::Error);
            rate_limited = true;
        }

        if let Some(phone) = &phone
            && let Err(error) = limiter
                .check_phone_authentication_phone(request.requester, phone)
                .await
        {
            tracing::warn!(error = &error as &dyn std::error::Error);
            rate_limited = true;
        }

        if rate_limited {
            issues.push(BeginPasswordRegistrationIssue::RateLimited);
        }
    }

    if !issues.is_empty() {
        return Ok(BeginPasswordRegistrationResult::Rejected { issues });
    }

    let started = start_password_registration(
        repo,
        rng,
        clock,
        password_manager,
        StartPasswordRegistrationRequest {
            username: request.username,
            email,
            phone,
            password: Zeroizing::new(request.password),
            user_agent: request.user_agent,
            ip_address: request.ip_address,
            post_auth_action: request.post_auth_action,
            terms_url: request.terms_url,
            notification_language: request.notification_language,
        },
    )
    .await
    .map_err(|error| match error {
        StartPasswordRegistrationError::Repository(error) => {
            BeginPasswordRegistrationError::Repository(error)
        }
        StartPasswordRegistrationError::Password(error) => {
            BeginPasswordRegistrationError::Internal(error)
        }
    })?;

    Ok(BeginPasswordRegistrationResult::Started(started))
}

pub async fn resend_pending_registration_verification(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    registration_id: Ulid,
    notification_language: String,
) -> Result<ResendRegistrationVerificationStatus, ResendRegistrationVerificationError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(ResendRegistrationVerificationError::NotFound)?;

    if registration.completed_at.is_some() {
        return Ok(ResendRegistrationVerificationStatus::RegistrationCompleted);
    }

    if let Some(email_authentication_id) = registration.email_authentication_id {
        let auth = repo
            .user_email()
            .lookup_authentication(email_authentication_id)
            .await?
            .ok_or(ResendRegistrationVerificationError::NotFound)?;

        if auth.completed_at.is_none() {
            if let Err(error) = limiter
                .check_email_authentication_send_code(requester, &auth)
                .await
            {
                tracing::warn!(error = &error as &dyn std::error::Error);
                return Err(ResendRegistrationVerificationError::RateLimited);
            }

            schedule_notification(
                &mut repo,
                rng,
                clock,
                NotificationIntent::verify_email(&auth, notification_language),
            )
            .await?;
            repo.save().await?;

            return Ok(ResendRegistrationVerificationStatus::Resent);
        }
    }

    if let Some(phone_authentication_id) = registration.phone_authentication_id {
        let auth = repo
            .user_phone()
            .lookup_authentication(phone_authentication_id)
            .await?
            .ok_or(ResendRegistrationVerificationError::NotFound)?;

        if auth.completed_at.is_none() {
            if let Err(error) = limiter
                .check_phone_authentication_send_code(requester, &auth)
                .await
            {
                tracing::warn!(error = &error as &dyn std::error::Error);
                return Err(ResendRegistrationVerificationError::RateLimited);
            }

            schedule_notification(
                &mut repo,
                rng,
                clock,
                NotificationIntent::verify_phone(&auth, notification_language),
            )
            .await?;
            repo.save().await?;

            return Ok(ResendRegistrationVerificationStatus::Resent);
        }
    }

    Ok(ResendRegistrationVerificationStatus::AlreadyVerified)
}

pub async fn verify_registration_email_code(
    mut repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationProgress, VerifyRegistrationEmailCodeError> {
    let progress = load_registration_progress(&mut repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => VerifyRegistrationEmailCodeError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                VerifyRegistrationEmailCodeError::Repository(error)
            }
        })?;

    if progress.registration.completed_at.is_some() {
        return Err(VerifyRegistrationEmailCodeError::RegistrationCompleted);
    }

    let email_authentication = if progress.registration.email_authentication_id.is_none() {
        return Err(VerifyRegistrationEmailCodeError::NoEmailAuthentication);
    } else {
        progress
            .email_authentication
            .ok_or(VerifyRegistrationEmailCodeError::EmailAuthenticationMissing)?
    };

    if email_authentication.completed_at.is_some() {
        return Err(VerifyRegistrationEmailCodeError::EmailAlreadyVerified);
    }

    if let Err(error) = limiter
        .check_email_authentication_attempt(&email_authentication)
        .await
    {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(VerifyRegistrationEmailCodeError::RateLimited);
    }

    let code = repo
        .user_email()
        .find_authentication_code(&email_authentication, code)
        .await?
        .ok_or(VerifyRegistrationEmailCodeError::InvalidCode)?;

    let email_authentication = repo
        .user_email()
        .complete_authentication_with_code(clock, email_authentication, &code)
        .await?;

    repo.save().await?;

    Ok(RegistrationProgress {
        registration: progress.registration,
        email_authentication: Some(email_authentication),
        phone_authentication: progress.phone_authentication,
    })
}

pub async fn verify_registration_phone_code(
    mut repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationProgress, VerifyRegistrationPhoneCodeError> {
    let progress = load_registration_progress(&mut repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => VerifyRegistrationPhoneCodeError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                VerifyRegistrationPhoneCodeError::Repository(error)
            }
        })?;

    if progress.registration.completed_at.is_some() {
        return Err(VerifyRegistrationPhoneCodeError::RegistrationCompleted);
    }

    let phone_authentication = if progress.registration.phone_authentication_id.is_none() {
        return Err(VerifyRegistrationPhoneCodeError::NoPhoneAuthentication);
    } else {
        progress
            .phone_authentication
            .ok_or(VerifyRegistrationPhoneCodeError::PhoneAuthenticationMissing)?
    };

    if phone_authentication.completed_at.is_some() {
        return Err(VerifyRegistrationPhoneCodeError::PhoneAlreadyVerified);
    }

    if let Err(error) = limiter
        .check_phone_authentication_attempt(&phone_authentication)
        .await
    {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(VerifyRegistrationPhoneCodeError::RateLimited);
    }

    let code = repo
        .user_phone()
        .find_authentication_code(&phone_authentication, code)
        .await?
        .ok_or(VerifyRegistrationPhoneCodeError::InvalidCode)?;

    let phone_authentication = repo
        .user_phone()
        .complete_authentication_with_code(clock, phone_authentication, &code)
        .await?;

    repo.save().await?;

    Ok(RegistrationProgress {
        registration: progress.registration,
        email_authentication: progress.email_authentication,
        phone_authentication: Some(phone_authentication),
    })
}

pub async fn set_registration_display_name(
    mut repo: BoxRepository,
    registration_id: Ulid,
    display_name: Option<String>,
    skip: bool,
) -> Result<UserRegistration, SetRegistrationDisplayNameError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(SetRegistrationDisplayNameError::NotFound)?;

    if registration.completed_at.is_some() {
        return Err(SetRegistrationDisplayNameError::RegistrationCompleted);
    }

    let display_name = if skip {
        registration.username.clone()
    } else {
        let display_name = display_name.as_deref().unwrap_or("").trim().to_owned();

        if display_name.is_empty() || display_name.len() > 255 {
            return Err(SetRegistrationDisplayNameError::InvalidDisplayName);
        }

        display_name
    };

    let registration = repo
        .user_registration()
        .set_display_name(registration, display_name)
        .await?;

    repo.save().await?;

    Ok(registration)
}

pub async fn resend_registration_verification(
    repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    registration_id: Ulid,
    notification_language: String,
) -> Result<RegistrationResendOutcome, RegistrationResendError> {
    match resend_pending_registration_verification(
        repo,
        limiter,
        rng,
        clock,
        requester,
        registration_id,
        notification_language,
    )
    .await
    {
        Ok(ResendRegistrationVerificationStatus::Resent) => Ok(RegistrationResendOutcome::Resent),
        Ok(ResendRegistrationVerificationStatus::AlreadyVerified) => {
            Ok(RegistrationResendOutcome::AlreadyVerified)
        }
        Ok(ResendRegistrationVerificationStatus::RegistrationCompleted) => {
            Ok(RegistrationResendOutcome::RegistrationCompleted)
        }
        Err(ResendRegistrationVerificationError::NotFound) => {
            Err(RegistrationResendError::NotFound)
        }
        Err(ResendRegistrationVerificationError::RateLimited) => {
            Ok(RegistrationResendOutcome::RateLimited)
        }
        Err(ResendRegistrationVerificationError::Repository(error)) => {
            Err(RegistrationResendError::Repository(error))
        }
    }
}

pub async fn change_registration_email(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    registration_id: Ulid,
    email: &str,
    notification_language: String,
) -> Result<RegistrationEmailChangeOutcome, RegistrationEmailChangeError> {
    let progress = load_registration_progress(&mut repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => RegistrationEmailChangeError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                RegistrationEmailChangeError::Repository(error)
            }
        })?;

    if progress.registration.completed_at.is_some() {
        return Ok(RegistrationEmailChangeOutcome::RegistrationCompleted);
    }

    if progress.registration.email_authentication_id.is_none() {
        return Err(RegistrationEmailChangeError::NotAvailable);
    }

    let current_auth = progress
        .email_authentication
        .ok_or(RegistrationEmailChangeError::NotFound)?;

    if current_auth.completed_at.is_some() {
        return Ok(RegistrationEmailChangeOutcome::AlreadyVerified);
    }

    let email = email.trim();
    if Address::from_str(email).is_err() {
        return Ok(RegistrationEmailChangeOutcome::InvalidEmail);
    }

    if repo.user_email().find_by_email(email).await?.is_some() {
        return Ok(RegistrationEmailChangeOutcome::EmailInUse);
    }

    if let Err(error) = limiter
        .check_email_authentication_email(requester, email)
        .await
    {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Ok(RegistrationEmailChangeOutcome::RateLimited);
    }

    let updated_auth = repo
        .user_email()
        .add_authentication_for_registration(rng, clock, email.to_owned(), &progress.registration)
        .await?;

    schedule_notification(
        &mut repo,
        rng,
        clock,
        NotificationIntent::verify_email(&updated_auth, notification_language),
    )
    .await?;

    let _ = repo
        .user_registration()
        .set_email_authentication(progress.registration, &updated_auth)
        .await?;

    repo.save().await?;

    Ok(RegistrationEmailChangeOutcome::Updated)
}

pub async fn submit_registration_email_code(
    repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationVerificationOutcome, RegistrationVerificationError> {
    match verify_registration_email_code(repo, limiter, clock, registration_id, code).await {
        Ok(progress) => Ok(RegistrationVerificationOutcome::Advanced {
            next_step: progress.next_step(),
        }),
        Err(VerifyRegistrationEmailCodeError::NotFound)
        | Err(VerifyRegistrationEmailCodeError::EmailAuthenticationMissing) => {
            Err(RegistrationVerificationError::NotFound)
        }
        Err(VerifyRegistrationEmailCodeError::NoEmailAuthentication) => {
            Err(RegistrationVerificationError::NotAvailable)
        }
        Err(VerifyRegistrationEmailCodeError::RegistrationCompleted) => {
            Ok(RegistrationVerificationOutcome::RegistrationCompleted)
        }
        Err(VerifyRegistrationEmailCodeError::EmailAlreadyVerified) => {
            Ok(RegistrationVerificationOutcome::AlreadyVerified)
        }
        Err(VerifyRegistrationEmailCodeError::RateLimited) => {
            Ok(RegistrationVerificationOutcome::RateLimited)
        }
        Err(VerifyRegistrationEmailCodeError::InvalidCode) => {
            Ok(RegistrationVerificationOutcome::InvalidCode)
        }
        Err(VerifyRegistrationEmailCodeError::Repository(error)) => {
            Err(RegistrationVerificationError::Repository(error))
        }
    }
}

pub async fn submit_registration_phone_code(
    repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationVerificationOutcome, RegistrationVerificationError> {
    match verify_registration_phone_code(repo, limiter, clock, registration_id, code).await {
        Ok(progress) => Ok(RegistrationVerificationOutcome::Advanced {
            next_step: progress.next_step(),
        }),
        Err(VerifyRegistrationPhoneCodeError::NotFound)
        | Err(VerifyRegistrationPhoneCodeError::PhoneAuthenticationMissing) => {
            Err(RegistrationVerificationError::NotFound)
        }
        Err(VerifyRegistrationPhoneCodeError::NoPhoneAuthentication) => {
            Err(RegistrationVerificationError::NotAvailable)
        }
        Err(VerifyRegistrationPhoneCodeError::RegistrationCompleted) => {
            Ok(RegistrationVerificationOutcome::RegistrationCompleted)
        }
        Err(VerifyRegistrationPhoneCodeError::PhoneAlreadyVerified) => {
            Ok(RegistrationVerificationOutcome::AlreadyVerified)
        }
        Err(VerifyRegistrationPhoneCodeError::RateLimited) => {
            Ok(RegistrationVerificationOutcome::RateLimited)
        }
        Err(VerifyRegistrationPhoneCodeError::InvalidCode) => {
            Ok(RegistrationVerificationOutcome::InvalidCode)
        }
        Err(VerifyRegistrationPhoneCodeError::Repository(error)) => {
            Err(RegistrationVerificationError::Repository(error))
        }
    }
}

pub async fn submit_registration_display_name(
    repo: BoxRepository,
    registration_id: Ulid,
    display_name: Option<String>,
    skip: bool,
) -> Result<RegistrationDisplayNameOutcome, RegistrationDisplayNameWorkflowError> {
    match set_registration_display_name(repo, registration_id, display_name, skip).await {
        Ok(_) => Ok(RegistrationDisplayNameOutcome::Advanced {
            next_step: "finish",
        }),
        Err(SetRegistrationDisplayNameError::NotFound) => {
            Err(RegistrationDisplayNameWorkflowError::NotFound)
        }
        Err(SetRegistrationDisplayNameError::RegistrationCompleted) => {
            Ok(RegistrationDisplayNameOutcome::RegistrationCompleted)
        }
        Err(SetRegistrationDisplayNameError::InvalidDisplayName) => {
            Ok(RegistrationDisplayNameOutcome::InvalidDisplayName)
        }
        Err(SetRegistrationDisplayNameError::Repository(error)) => {
            Err(RegistrationDisplayNameWorkflowError::Repository(error))
        }
    }
}

pub async fn check_registration_finish_eligibility(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    homeserver: &dyn HomeserverAdmin,
    registration: &UserRegistration,
    browser_session_present: Option<bool>,
    homeserver_check_mode: HomeserverCheckMode,
) -> Result<(), CheckRegistrationFinishEligibilityError> {
    if clock.now() - registration.created_at > Duration::hours(1) {
        return Err(CheckRegistrationFinishEligibilityError::RegistrationExpired);
    }

    if let Some(false) = browser_session_present {
        return Err(CheckRegistrationFinishEligibilityError::BrowserSessionMissing);
    }

    if repo.user().exists(&registration.username).await? {
        return Err(CheckRegistrationFinishEligibilityError::UsernameTaken);
    }

    match homeserver
        .is_localpart_available(&registration.username)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(CheckRegistrationFinishEligibilityError::UsernameNotAvailable),
        Err(error) => match homeserver_check_mode {
            HomeserverCheckMode::Strict => {
                Err(CheckRegistrationFinishEligibilityError::HomeserverUnavailable(error))
            }
            HomeserverCheckMode::BestEffort => {
                tracing::warn!(
                    error = %error,
                    "Failed to check localpart availability during finish, skipping homeserver check"
                );
                Ok(())
            }
        },
    }
}

pub async fn load_registration_finish_preparation(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    homeserver: &dyn HomeserverAdmin,
    registration_id: Ulid,
    browser_session_present: Option<bool>,
    homeserver_check_mode: HomeserverCheckMode,
    registration_token_required: bool,
) -> Result<PreparedRegistrationCompletion, LoadRegistrationFinishPreparationError> {
    let progress = load_registration_progress(repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => {
                LoadRegistrationFinishPreparationError::NotFound
            }
            LoadRegistrationProgressError::Repository(error) => {
                LoadRegistrationFinishPreparationError::Repository(error)
            }
        })?;

    let registration = progress.registration.clone();

    if registration.completed_at.is_some() {
        return Err(LoadRegistrationFinishPreparationError::AlreadyCompleted(
            registration,
        ));
    }

    check_registration_finish_eligibility(
        repo,
        clock,
        homeserver,
        &registration,
        browser_session_present,
        homeserver_check_mode,
    )
    .await
    .map_err(
        |source| LoadRegistrationFinishPreparationError::Eligibility {
            registration: registration.clone(),
            source,
        },
    )?;

    prepare_registration_completion(repo, clock, progress, registration_token_required)
        .await
        .map_err(|source| LoadRegistrationFinishPreparationError::Prepare {
            registration,
            source,
        })
}

pub async fn prepare_registration_completion(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    progress: RegistrationProgress,
    registration_token_required: bool,
) -> Result<PreparedRegistrationCompletion, PrepareRegistrationCompletionError> {
    let registration = progress.registration;

    let registration_token = if registration_token_required {
        if let Some(registration_token_id) = registration.user_registration_token_id {
            let registration_token = repo
                .user_registration_token()
                .lookup(registration_token_id)
                .await?
                .ok_or(PrepareRegistrationCompletionError::RegistrationTokenMissing)?;

            if !registration_token.is_valid(clock.now()) {
                return Err(PrepareRegistrationCompletionError::RegistrationTokenInvalid);
            }

            Some(registration_token)
        } else {
            return Err(PrepareRegistrationCompletionError::RegistrationTokenRequired);
        }
    } else {
        None
    };

    let email_authentication = if registration.email_authentication_id.is_some() {
        let email_authentication = progress
            .email_authentication
            .ok_or(PrepareRegistrationCompletionError::EmailAuthenticationMissing)?;

        if email_authentication.completed_at.is_none() {
            return Err(PrepareRegistrationCompletionError::EmailNotVerified);
        }

        if repo
            .user_email()
            .count(UserEmailFilter::new().for_email(&email_authentication.email))
            .await?
            > 0
        {
            return Err(PrepareRegistrationCompletionError::EmailInUse(
                email_authentication.email.clone(),
            ));
        }

        Some(email_authentication)
    } else {
        None
    };

    let phone_authentication = if registration.phone_authentication_id.is_some() {
        let phone_authentication = progress
            .phone_authentication
            .ok_or(PrepareRegistrationCompletionError::PhoneAuthenticationMissing)?;

        if phone_authentication.completed_at.is_none() {
            return Err(PrepareRegistrationCompletionError::PhoneNotVerified);
        }

        if repo
            .user_phone()
            .find_by_phone(&phone_authentication.phone)
            .await?
            .is_some()
        {
            return Err(PrepareRegistrationCompletionError::PhoneInUse);
        }

        Some(phone_authentication)
    } else {
        None
    };

    let upstream_oauth = if let Some(upstream_oauth_authorization_session_id) =
        registration.upstream_oauth_authorization_session_id
    {
        let upstream_oauth_authorization_session = repo
            .upstream_oauth_session()
            .lookup(upstream_oauth_authorization_session_id)
            .await?
            .ok_or(PrepareRegistrationCompletionError::UpstreamOAuthSessionMissing)?;

        let link_id = upstream_oauth_authorization_session
            .link_id()
            .ok_or(PrepareRegistrationCompletionError::UpstreamOAuthLinkMissing)?;

        let upstream_oauth_link = repo
            .upstream_oauth_link()
            .lookup(link_id)
            .await?
            .ok_or(PrepareRegistrationCompletionError::UpstreamOAuthLinkMissing)?;

        if upstream_oauth_link.user_id.is_some() {
            return Err(PrepareRegistrationCompletionError::UpstreamOAuthLinkAlreadyUsed);
        }

        Some((upstream_oauth_authorization_session, upstream_oauth_link))
    } else {
        None
    };

    if registration.display_name.is_none() {
        return Err(PrepareRegistrationCompletionError::DisplayNameRequired);
    }

    Ok(PreparedRegistrationCompletion {
        registration,
        registration_token,
        email_authentication,
        phone_authentication,
        upstream_oauth,
    })
}

fn normalize_optional_token(token: Option<&str>) -> Option<&str> {
    token.map(str::trim).filter(|token| !token.is_empty())
}

async fn prepare_admin_bootstrap(
    repo: &mut BoxRepository,
    configured_bootstrap_admin_token: Option<&str>,
    requested_bootstrap_admin_token: Option<&str>,
) -> Result<bool, PrepareAdminBootstrapError> {
    repo.user().acquire_bootstrap_admin_lock().await?;

    let admin_count = repo
        .user()
        .count(UserFilter::new().can_request_admin_only())
        .await?;

    if admin_count > 0 {
        return Ok(false);
    }

    let Some(configured_bootstrap_admin_token) =
        normalize_optional_token(configured_bootstrap_admin_token)
    else {
        return Ok(false);
    };

    match normalize_optional_token(requested_bootstrap_admin_token) {
        Some(requested_bootstrap_admin_token)
            if requested_bootstrap_admin_token == configured_bootstrap_admin_token =>
        {
            Ok(true)
        }
        Some(_) => Err(PrepareAdminBootstrapError::InvalidToken),
        None => Ok(false),
    }
}

pub async fn complete_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    request: CompleteRegistrationRequest,
    grant_admin: bool,
) -> Result<CompletedRegistration, RepositoryError> {
    let registration = repo
        .user_registration()
        .complete(clock, request.registration)
        .await?;

    if let Some(registration_token) = request.registration_token {
        repo.user_registration_token()
            .use_token(clock, registration_token)
            .await?;
    }

    let mut user = repo
        .user()
        .add(rng, clock, registration.username.clone())
        .await?;

    if grant_admin {
        user = repo.user().set_can_request_admin(user, true).await?;
    }

    // Mirror the registration's display_name / avatar_url onto coauth's
    // local user record so the account UI ("Edit profile") shows them
    // immediately, before the async homeserver-provision job runs.
    if registration.display_name.is_some() || registration.avatar_url.is_some() {
        let profile_patch = coauth_data::UserProfilePatch {
            display_name: registration.display_name.clone().map(Some),
            avatar_url: registration.avatar_url.clone().map(Some),
            preferred_locale: None,
        };
        user = repo
            .user()
            .update_profile(clock, user, profile_patch)
            .await?;
    }

    let user_session = repo
        .browser_session()
        .add(rng, clock, &user, request.user_agent)
        .await?;

    if let Some(email_authentication) = request.email_authentication {
        repo.user_email()
            .add(rng, clock, &user, email_authentication.email)
            .await?;
    }

    if let Some(phone_authentication) = request.phone_authentication {
        repo.user_phone()
            .add(rng, clock, &user, phone_authentication.phone)
            .await?;
    }

    let mut password_authenticated = false;
    if let Some(password) = registration.password.clone() {
        let user_password = repo
            .user_password()
            .add(
                rng,
                clock,
                &user,
                password.version,
                password.hashed_password,
                None,
            )
            .await?;

        repo.browser_session()
            .authenticate_with_password(rng, clock, &user_session, &user_password)
            .await?;

        password_authenticated = true;
    }

    if let Some((upstream_session, upstream_link)) = request.upstream_oauth {
        let upstream_session = repo
            .upstream_oauth_session()
            .consume(clock, upstream_session, &user_session)
            .await?;

        repo.upstream_oauth_link()
            .associate_to_user(&upstream_link, &user)
            .await?;

        repo.browser_session()
            .authenticate_with_upstream(rng, clock, &user_session, &upstream_session)
            .await?;
    }

    if let Some(terms_url) = registration.terms_url.clone() {
        repo.user_terms()
            .accept_terms(rng, clock, &user, terms_url)
            .await?;
    }

    let mut job = ProvisionUserJob::new(&user);
    if let Some(display_name) = registration.display_name.clone() {
        job = job.set_display_name(display_name);
    }
    if let Some(avatar_url) = registration.avatar_url.clone() {
        job = job.set_avatar_url(avatar_url);
    }
    if user.can_request_admin {
        job = job.set_admin();
    }
    repo.queue_job().schedule_job(rng, clock, job).await?;

    repo.save().await?;

    Ok(CompletedRegistration {
        registration,
        user,
        user_session,
        password_authenticated,
    })
}

pub async fn finish_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    homeserver: &dyn HomeserverAdmin,
    registration_id: Ulid,
    browser_session_present: Option<bool>,
    homeserver_check_mode: HomeserverCheckMode,
    registration_token_required: bool,
    configured_bootstrap_admin_token: Option<&str>,
    requested_bootstrap_admin_token: Option<String>,
    user_agent: Option<String>,
) -> Result<RegistrationFinishOutcome, RegistrationFinishError> {
    let prepared = match load_registration_finish_preparation(
        &mut repo,
        clock,
        homeserver,
        registration_id,
        browser_session_present,
        homeserver_check_mode,
        registration_token_required,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(LoadRegistrationFinishPreparationError::NotFound) => {
            return Err(RegistrationFinishError::NotFound);
        }
        Err(LoadRegistrationFinishPreparationError::AlreadyCompleted(_)) => {
            return Ok(RegistrationFinishOutcome::Rejected {
                error: "registration_already_completed",
            });
        }
        Err(LoadRegistrationFinishPreparationError::Eligibility { source, .. }) => match source {
            CheckRegistrationFinishEligibilityError::RegistrationExpired => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "registration_expired",
                });
            }
            CheckRegistrationFinishEligibilityError::UsernameTaken => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "username_taken",
                });
            }
            CheckRegistrationFinishEligibilityError::UsernameNotAvailable => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "username_not_available",
                });
            }
            CheckRegistrationFinishEligibilityError::BrowserSessionMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Registration browser session is required",
                )));
            }
            CheckRegistrationFinishEligibilityError::HomeserverUnavailable(_) => unreachable!(),
            CheckRegistrationFinishEligibilityError::Repository(error) => {
                return Err(RegistrationFinishError::Repository(error));
            }
        },
        Err(LoadRegistrationFinishPreparationError::Prepare { source, .. }) => match source {
            PrepareRegistrationCompletionError::RegistrationTokenRequired => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "registration_token_required",
                });
            }
            PrepareRegistrationCompletionError::RegistrationTokenInvalid => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "registration_token_invalid",
                });
            }
            PrepareRegistrationCompletionError::EmailNotVerified => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "email_not_verified",
                });
            }
            PrepareRegistrationCompletionError::EmailInUse(_) => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "email_in_use",
                });
            }
            PrepareRegistrationCompletionError::PhoneNotVerified => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "phone_not_verified",
                });
            }
            PrepareRegistrationCompletionError::PhoneInUse => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "phone_in_use",
                });
            }
            PrepareRegistrationCompletionError::DisplayNameRequired => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "display_name_required",
                });
            }
            PrepareRegistrationCompletionError::RegistrationTokenMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the registration token",
                )));
            }
            PrepareRegistrationCompletionError::EmailAuthenticationMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the email authentication",
                )));
            }
            PrepareRegistrationCompletionError::PhoneAuthenticationMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the phone authentication",
                )));
            }
            PrepareRegistrationCompletionError::UpstreamOAuthSessionMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the upstream OAuth authorization session",
                )));
            }
            PrepareRegistrationCompletionError::UpstreamOAuthLinkMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the upstream OAuth link",
                )));
            }
            PrepareRegistrationCompletionError::UpstreamOAuthLinkAlreadyUsed => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "The upstream identity was already linked to a user",
                )));
            }
            PrepareRegistrationCompletionError::Repository(error) => {
                return Err(RegistrationFinishError::Repository(error));
            }
        },
        Err(LoadRegistrationFinishPreparationError::Repository(error)) => {
            return Err(RegistrationFinishError::Repository(error));
        }
    };

    let grant_admin = match prepare_admin_bootstrap(
        &mut repo,
        configured_bootstrap_admin_token,
        requested_bootstrap_admin_token.as_deref(),
    )
    .await
    {
        Ok(grant_admin) => grant_admin,
        Err(PrepareAdminBootstrapError::InvalidToken) => {
            return Ok(RegistrationFinishOutcome::Rejected {
                error: "bootstrap_admin_token_invalid",
            });
        }
        Err(PrepareAdminBootstrapError::Repository(error)) => {
            return Err(RegistrationFinishError::Repository(error));
        }
    };

    let completed = complete_registration(
        repo,
        rng,
        clock,
        prepared.into_request(user_agent),
        grant_admin,
    )
    .await
    .map_err(RegistrationFinishError::Repository)?;

    Ok(RegistrationFinishOutcome::Completed(completed))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use coauth_data::{
        RepositoryAccess as _, RepositoryFactory as _, clock::MockClock, user::UserRepository as _,
    };
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;
    fn sample_registration(created_at: DateTime<Utc>) -> UserRegistration {
        UserRegistration {
            id: Ulid::new(),
            username: "alice".into(),
            display_name: None,
            avatar_url: None,
            terms_url: None,
            email_authentication_id: None,
            phone_authentication_id: None,
            user_registration_token_id: None,
            password: None,
            upstream_oauth_authorization_session_id: None,
            post_auth_action: None,
            ip_address: None,
            user_agent: None,
            created_at,
            completed_at: None,
        }
    }

    async fn test_repo() -> BoxRepository {
        let pool = coauth_data::test_utils::setup_test_pool().await;
        coauth_data::PgRepositoryFactory::new(pool)
            .create()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn prepare_admin_bootstrap_requires_exact_token_to_grant_admin() {
        let mut repo = test_repo().await;

        assert!(
            !prepare_admin_bootstrap(&mut repo, Some("bootstrap-secret"), None)
                .await
                .unwrap()
        );
        assert!(
            prepare_admin_bootstrap(
                &mut repo,
                Some("bootstrap-secret"),
                Some("bootstrap-secret")
            )
            .await
            .unwrap()
        );

        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn prepare_admin_bootstrap_rejects_invalid_token_while_no_admin_exists() {
        let mut repo = test_repo().await;

        let error = prepare_admin_bootstrap(&mut repo, Some("bootstrap-secret"), Some("wrong"))
            .await
            .unwrap_err();

        assert!(matches!(error, PrepareAdminBootstrapError::InvalidToken));

        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn prepare_admin_bootstrap_stops_granting_after_first_admin_exists() {
        let mut repo = test_repo().await;
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let user = repo
            .user()
            .add(&mut rng, &clock, "admin".to_owned())
            .await
            .unwrap();
        repo.user().set_can_request_admin(user, true).await.unwrap();

        assert!(
            !prepare_admin_bootstrap(
                &mut repo,
                Some("bootstrap-secret"),
                Some("bootstrap-secret")
            )
            .await
            .unwrap()
        );

        repo.cancel().await.unwrap();
    }

    #[test]
    fn workflow_snapshot_tracks_pending_email_verification() {
        let created_at = Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap();
        let email_authentication = UserEmailAuthentication {
            id: Ulid::new(),
            user_session_id: None,
            user_registration_id: Some(Ulid::new()),
            email: "alice@example.com".into(),
            created_at: created_at + Duration::minutes(1),
            completed_at: None,
        };

        let mut registration = sample_registration(created_at);
        registration.email_authentication_id = Some(email_authentication.id);

        let progress = RegistrationProgress {
            registration,
            email_authentication: Some(email_authentication),
            phone_authentication: None,
        };

        let snapshot = progress.workflow_snapshot();

        assert_eq!(
            snapshot.state,
            RegistrationWorkflowState::PendingEmailVerification
        );
        assert_eq!(snapshot.next_step, Some("verify_email"));
        assert_eq!(snapshot.deadlines.len(), 1);
        assert_eq!(
            snapshot.deadlines[0].due_at,
            created_at + Duration::hours(1)
        );
        assert_eq!(snapshot.events.len(), 2);
        assert_eq!(
            snapshot.events[0].kind,
            RegistrationWorkflowEventKind::Started
        );
        assert_eq!(
            snapshot.events[1].kind,
            RegistrationWorkflowEventKind::EmailVerificationRequested
        );
    }

    #[test]
    fn workflow_snapshot_tracks_completed_registration() {
        let created_at = Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap();
        let completed_at = created_at + Duration::minutes(10);
        let email_verified_at = created_at + Duration::minutes(2);

        let email_authentication = UserEmailAuthentication {
            id: Ulid::new(),
            user_session_id: None,
            user_registration_id: Some(Ulid::new()),
            email: "alice@example.com".into(),
            created_at: created_at + Duration::minutes(1),
            completed_at: Some(email_verified_at),
        };

        let mut registration = sample_registration(created_at);
        registration.display_name = Some("Alice".into());
        registration.email_authentication_id = Some(email_authentication.id);
        registration.completed_at = Some(completed_at);

        let progress = RegistrationProgress {
            registration,
            email_authentication: Some(email_authentication),
            phone_authentication: None,
        };

        let snapshot = progress.workflow_snapshot();

        assert_eq!(snapshot.state, RegistrationWorkflowState::Completed);
        assert_eq!(snapshot.next_step, None);
        assert!(snapshot.deadlines.is_empty());
        assert!(snapshot.completed_steps.contains(&"finish"));
        assert_eq!(
            snapshot.events.last().map(|event| event.kind),
            Some(RegistrationWorkflowEventKind::Completed)
        );
    }
}
