//! Identification stage side effects.
//!
//! Looks up a user by handle or email address and stores the resolved
//! `user_id` in the flow context for subsequent stages.

use coauth_data::{
    BoxRepository, Clock, RepositoryAccess,
    flow::{StageOutcome, StageValidationError},
};

use super::StageExecutionError;

/// Execute the identification stage.
///
/// Tries to find the user by handle first, then by email if the
/// identifier contains an `@` sign.  On success the user's `id` and
/// `handle` are written into the flow context.
pub async fn execute(
    repo: &mut BoxRepository,
    _clock: &dyn Clock,
    uid_field: &str,
    _password: Option<&str>, // Password validation handled by a separate stage
    context: &mut serde_json::Value,
) -> Result<StageOutcome, StageExecutionError> {
    // Try to find user by handle first
    let user = repo.user().find_by_handle(uid_field).await?;

    let user = if let Some(user) = user {
        user
    } else if uid_field.contains('@') {
        // Try by email — find_by_email returns a UserEmail, then we look up the
        // owning User.
        let maybe_email = repo.user_email().find_by_email(uid_field).await?;

        if let Some(user_email) = maybe_email {
            let user = repo.user().lookup(user_email.user_id).await?;

            match user {
                Some(u) => u,
                None => {
                    return Ok(StageOutcome::Retry {
                        errors: vec![StageValidationError {
                            field: Some("uid_field".into()),
                            message: "User not found".into(),
                            code: "user_not_found".into(),
                        }],
                    });
                }
            }
        } else {
            return Ok(StageOutcome::Retry {
                errors: vec![StageValidationError {
                    field: Some("uid_field".into()),
                    message: "User not found".into(),
                    code: "user_not_found".into(),
                }],
            });
        }
    } else {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("uid_field".into()),
                message: "User not found".into(),
                code: "user_not_found".into(),
            }],
        });
    };

    if !user.is_valid() {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: None,
                message: "Account is locked or deactivated".into(),
                code: "account_inactive".into(),
            }],
        });
    }

    // Store user_id in context for subsequent stages
    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("user_id".into(), serde_json::json!(user.id.to_string()));
        ctx.insert("handle".into(), serde_json::json!(user.handle));
    }

    Ok(StageOutcome::Continue)
}
