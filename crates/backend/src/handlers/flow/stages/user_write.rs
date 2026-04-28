//! User write stage side effects.
//!
//! Creates a new user account or validates that the chosen username is
//! available.  Stores the new user's `id` and `username` in the flow
//! context so subsequent stages can reference them.

use coauth_data::{
    BoxRepository, Clock, RepositoryAccess,
    flow::{StageOutcome, StageValidationError},
};
use rand_core::RngCore;

use super::StageExecutionError;

/// Execute the user write stage.
///
/// Creates a new [`User`](coauth_data::User) record with the
/// given username.  If `create_users_as_inactive` is `true` the
/// caller/admin is expected to activate the user later (the `User`
/// model doesn't have a dedicated "inactive" flag — the admin would
/// lock the account).
pub async fn execute(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    _create_users_as_inactive: bool,
    username: &str,
    _display_name: Option<&str>,
    context: &mut serde_json::Value,
) -> Result<StageOutcome, StageExecutionError> {
    if username.is_empty() {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("username".into()),
                message: "Username is required".into(),
                code: "required".into(),
            }],
        });
    }

    // Check if username already exists
    if repo.user().exists(username).await? {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("username".into()),
                message: "Username is already taken".into(),
                code: "username_taken".into(),
            }],
        });
    }

    // Create the user
    let user = repo.user().add(rng, clock, username.to_owned()).await?;

    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("user_id".into(), serde_json::json!(user.id.to_string()));
        ctx.insert("username".into(), serde_json::json!(user.username));
        ctx.insert("user_created".into(), serde_json::json!(true));
    }

    Ok(StageOutcome::Continue)
}
