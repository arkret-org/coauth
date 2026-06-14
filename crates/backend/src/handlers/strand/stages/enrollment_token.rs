//! Enrollment token stage side effects.
//!
//! Validates an enrollment/invitation token against the
//! [`UserRegistrationTokenRepository`].  When the token is valid the
//! `enrollment_token_id` is stored in the strand context so downstream
//! stages can reference it (e.g. to associate the new user with the
//! invitation).

use chrono::Utc;
use coauth_data::strand::{StageOutcome, StageValidationError};
use coauth_data::{BoxRepository, RepositoryAccess};

use super::StageExecutionError;

/// Execute the enrollment token stage.
///
/// Looks up the provided `token` string via
/// [`UserRegistrationTokenRepository::find_by_token`].  If the token
/// exists and passes validity checks (not expired, not revoked, usage
/// limit not exceeded) the token's ID is stored in the context under
/// `enrollment_token_id` and the strand continues.
///
/// When `required` is `true` and the token is empty, the stage returns
/// a validation error.  When `required` is `false` and the token is
/// empty, the stage is silently skipped.
pub async fn execute(
    repo: &mut BoxRepository,
    required: bool,
    token: &str,
    context: &mut serde_json::Value,
) -> Result<StageOutcome, StageExecutionError> {
    // If the token is empty and not required, skip silently.
    if token.is_empty() {
        if required {
            return Ok(StageOutcome::Retry {
                errors: vec![StageValidationError {
                    field: Some("token".into()),
                    message: "Enrollment token is required".into(),
                    code: "required".into(),
                }],
            });
        }
        return Ok(StageOutcome::Continue);
    }

    // Look up the token in the repository.
    let registration_token = repo.user_registration_token().find_by_token(token).await?;

    let registration_token = match registration_token {
        Some(t) => t,
        None => {
            return Ok(StageOutcome::Retry {
                errors: vec![StageValidationError {
                    field: Some("token".into()),
                    message: "Invalid enrollment token".into(),
                    code: "invalid_token".into(),
                }],
            });
        }
    };

    // Validate the token (not expired, not revoked, usage limit not exceeded).
    let now = Utc::now();
    if !registration_token.is_valid(now) {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("token".into()),
                message: "Enrollment token is no longer valid".into(),
                code: "token_invalid".into(),
            }],
        });
    }

    // Store the token ID in context for downstream stages.
    if let Some(ctx) = context.as_object_mut() {
        ctx.insert(
            "enrollment_token_id".into(),
            serde_json::json!(registration_token.id.to_string()),
        );
    }

    Ok(StageOutcome::Continue)
}
