//! Concrete stage side-effect implementations.
//!
//! Each stage module provides an `execute` function that performs the
//! actual work (DB writes, email sending, etc.) after the executor
//! validates the response shape.

pub mod authenticator_validate;
pub mod captcha;
pub mod consent;
pub mod email_verification;
pub mod enrollment_token;
pub mod identification;
pub mod password_write;
pub mod prompt;
pub mod user_write;

use coauth_data::strand::{StageKind, StageOutcome, StageSubmission};
use coauth_data::{BoxRepository, Clock};
use rand_core::RngCore;
use thiserror::Error;

use crate::handlers::Limiter;

/// Errors that can occur during stage side-effect execution.
#[derive(Debug, Error)]
pub enum StageExecutionError {
    /// The referenced user was not found in the database.
    #[error("user not found")]
    UserNotFound,

    /// The provided credentials were invalid.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Email verification failed (e.g., missing authentication record).
    #[error("email verification failed")]
    VerificationFailed,

    /// The user has been rate-limited.
    #[error("rate limited")]
    RateLimited,

    /// A repository error occurred.
    #[error(transparent)]
    Repository(#[from] coauth_data::RepositoryError),

    /// An internal/unexpected error occurred.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Execute the side effects for a stage after validation passes.
///
/// This is the main dispatch function — it routes to the appropriate
/// stage module based on the stage kind.
pub async fn execute_stage(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    stage: &StageKind,
    response: &StageSubmission,
    context: &mut serde_json::Value,
    limiter: Option<&Limiter>,
) -> Result<StageOutcome, StageExecutionError> {
    match (stage, response) {
        (
            StageKind::Identification { .. },
            StageSubmission::Identification {
                uid_field,
                password,
            },
        ) => identification::execute(repo, clock, uid_field, password.as_deref(), context).await,

        (
            StageKind::EmailVerification { max_attempts, .. },
            StageSubmission::EmailVerification { code },
        ) => email_verification::execute(repo, clock, code, *max_attempts, context).await,

        (
            StageKind::PasswordWrite { require_current },
            StageSubmission::PasswordWrite {
                current_password,
                new_password,
            },
        ) => {
            password_write::execute(
                repo,
                rng,
                clock,
                *require_current,
                current_password.as_deref(),
                new_password,
                context,
            )
            .await
        }

        (
            StageKind::UserWrite {
                create_users_as_inactive,
            },
            StageSubmission::UserWrite {
                handle,
                display_name,
            },
        ) => {
            user_write::execute(
                repo,
                rng,
                clock,
                *create_users_as_inactive,
                handle,
                display_name.as_deref(),
                context,
            )
            .await
        }

        (StageKind::Captcha, StageSubmission::Captcha { token }) => {
            captcha::execute(token, context).await
        }

        (StageKind::Prompt { fields }, StageSubmission::Prompt { data }) => {
            prompt::execute(data, fields, context).await
        }

        (
            StageKind::AuthenticatorValidate { .. },
            StageSubmission::AuthenticatorValidate { code, .. },
        ) => authenticator_validate::execute(repo, code, context, limiter).await,

        (StageKind::Consent, StageSubmission::Consent { granted }) => {
            consent::execute(*granted, context).await
        }

        (StageKind::EnrollmentToken { required }, StageSubmission::EnrollmentToken { token }) => {
            enrollment_token::execute(repo, *required, token, context).await
        }

        // Fallback for mismatched stage/response pairs
        _ => Ok(StageOutcome::Continue),
    }
}
