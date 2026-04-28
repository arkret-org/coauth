//! Email verification stage side effects.
//!
//! Verifies a one-time code against a stored [`UserEmailAuthentication`]
//! record.  On success the authentication is marked as completed and
//! `email_verified` is set in the flow context.

use coauth_data::{
    BoxRepository, Clock, RepositoryAccess,
    flow::{StageOutcome, StageValidationError},
};

use super::StageExecutionError;

/// Execute the email verification stage.
///
/// Expects `email_authentication_id` to already be present in the flow
/// context (set by an earlier stage that initiated the verification).
pub async fn execute(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    code: &str,
    _max_attempts: u32,
    context: &mut serde_json::Value,
) -> Result<StageOutcome, StageExecutionError> {
    // Get the email_authentication_id from context
    let auth_id_str = context
        .get("email_authentication_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StageExecutionError::Internal(anyhow::anyhow!(
                "missing email_authentication_id in flow context"
            ))
        })?;

    let auth_id: ulid::Ulid = auth_id_str
        .parse()
        .map_err(|e| StageExecutionError::Internal(anyhow::anyhow!("invalid auth id: {e}")))?;

    let auth = repo
        .user_email()
        .lookup_authentication(auth_id)
        .await?
        .ok_or(StageExecutionError::VerificationFailed)?;

    // Already verified — nothing to do
    if auth.completed_at.is_some() {
        return Ok(StageOutcome::Continue);
    }

    let found_code = repo
        .user_email()
        .find_authentication_code(&auth, code)
        .await?;

    let Some(found_code) = found_code else {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("code".into()),
                message: "Invalid verification code".into(),
                code: "invalid_code".into(),
            }],
        });
    };

    if found_code.expires_at < clock.now() {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("code".into()),
                message: "Verification code has expired".into(),
                code: "code_expired".into(),
            }],
        });
    }

    // Complete the authentication
    repo.user_email()
        .complete_authentication_with_code(clock, auth, &found_code)
        .await?;

    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("email_verified".into(), serde_json::json!(true));
    }

    Ok(StageOutcome::Continue)
}
