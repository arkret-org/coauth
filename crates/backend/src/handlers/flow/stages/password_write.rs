//! Password write stage side effects.
//!
//! Validates and records a new password for the user identified in the
//! flow context.  Full password hashing integration (via
//! `PasswordManager`) is deferred to a later integration step — this
//! module validates the inputs and records that a password was set.

use coauth_data::{
    BoxRepository, Clock, RepositoryAccess,
    flow::{StageOutcome, StageValidationError},
};
use rand_core::RngCore;

use super::StageExecutionError;

/// Execute the password write stage.
///
/// Reads `user_id` from the flow context (set by the identification
/// stage) and validates the password inputs.  Actual hashing and
/// storage via `UserPasswordRepository` will be wired in when the
/// `PasswordManager` is integrated into the flow engine.
pub async fn execute(
    repo: &mut BoxRepository,
    _rng: &mut (dyn RngCore + Send),
    _clock: &dyn Clock,
    require_current: bool,
    current_password: Option<&str>,
    new_password: &str,
    context: &mut serde_json::Value,
) -> Result<StageOutcome, StageExecutionError> {
    // Get user_id from context (set by identification stage)
    let user_id_str = context
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StageExecutionError::Internal(anyhow::anyhow!("missing user_id in flow context"))
        })?;

    let user_id: ulid::Ulid = user_id_str
        .parse()
        .map_err(|e| StageExecutionError::Internal(anyhow::anyhow!("invalid user id: {e}")))?;

    // Verify the user exists
    let _user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(StageExecutionError::UserNotFound)?;

    if require_current && current_password.is_none() {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("current_password".into()),
                message: "Current password is required".into(),
                code: "required".into(),
            }],
        });
    }

    if new_password.is_empty() {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("new_password".into()),
                message: "Password is required".into(),
                code: "required".into(),
            }],
        });
    }

    // Store that password was set in context (actual hashing deferred to
    // integration)
    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("password_set".into(), serde_json::json!(true));
    }

    Ok(StageOutcome::Continue)
}
