//! User write stage side effects.
//!
//! Creates a new user account or validates that the chosen handle is
//! available.  Stores the new user's `id` and `handle` in the strand
//! context so subsequent stages can reference them.
//!
//! Principal identity onboarding is a separate client-signed flow. This stage
//! creates only the service account and never creates DID key material.

use coauth_data::strand::{StageOutcome, StageValidationError};
use coauth_data::{BoxRepository, Clock, RepositoryAccess};
use rand_core::RngCore;

use super::StageExecutionError;

/// Execute the user write stage.
///
/// Creates a new [`User`](coauth_data::User) record with the
/// given handle.  If `create_users_as_inactive` is `true` the
/// caller/admin is expected to activate the user later (the `User`
/// model doesn't have a dedicated "inactive" flag — the admin would
/// lock the account).
pub async fn execute(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    _create_users_as_inactive: bool,
    handle: &str,
    _display_name: Option<&str>,
    context: &mut serde_json::Value,
) -> Result<StageOutcome, StageExecutionError> {
    if handle.is_empty() {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("handle".into()),
                message: "Handle is required".into(),
                code: "required".into(),
            }],
        });
    }

    // Check if handle already exists
    if repo.user().exists(handle).await? {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("handle".into()),
                message: "Handle is already taken".into(),
                code: "handle_taken".into(),
            }],
        });
    }

    let user = repo.user().add(rng, clock, handle.to_owned()).await?;

    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("user_id".into(), serde_json::json!(user.id.to_string()));
        ctx.insert("handle".into(), serde_json::json!(user.localpart));
        ctx.insert("user_created".into(), serde_json::json!(true));
    }

    Ok(StageOutcome::Continue)
}
