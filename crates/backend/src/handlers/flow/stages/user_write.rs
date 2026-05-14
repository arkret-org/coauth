//! User write stage side effects.
//!
//! Creates a new user account or validates that the chosen handle is
//! available.  Stores the new user's `id` and `handle` in the flow
//! context so subsequent stages can reference them.
//!
//! Round 37.4 (rip-and-replace of C35.0): the user-creation flow no
//! longer mints a `did:webvh` at this stage. The starid wire-in is
//! deferred to the first passkey enrolment
//! (`services::onboarding_starid::mint_principal_did_for_first_credential`,
//! invoked from the admin `passkeys::register_finish` handler) so the
//! initial `update_key` is the device-bound key derived from the
//! passkey's COSE public key — never the placeholder this stage used
//! to forward.
//!
//! Accounts that never enrol a passkey simply stay on the local
//! `did:web:coauth.invalid:…` derivation.

use coauth_data::{
    BoxRepository, Clock, RepositoryAccess,
    flow::{StageOutcome, StageValidationError},
};
use rand_core::RngCore;

use super::StageExecutionError;
use crate::services::starid_adapter::StaridRegistryHandle;

/// Execute the user write stage.
///
/// Creates a new [`User`](coauth_data::User) record with the
/// given handle.  If `create_users_as_inactive` is `true` the
/// caller/admin is expected to activate the user later (the `User`
/// model doesn't have a dedicated "inactive" flag — the admin would
/// lock the account).
///
/// `_starid_registry` is accepted (and ignored at this stage) so the
/// dispatcher in `stages::execute_stage` can keep its uniform call
/// shape across stages. The actual starid call lives in
/// `passkeys::register_finish` — see the round 37.4 module-level note
/// above.
pub async fn execute(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    _create_users_as_inactive: bool,
    handle: &str,
    _display_name: Option<&str>,
    _starid_registry: Option<&StaridRegistryHandle>,
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

    // Create the user. starid_backend stays false until the first
    // passkey enrolment lands and `mint_principal_did_for_first_credential`
    // flips it.
    let user = repo.user().add(rng, clock, handle.to_owned()).await?;

    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("user_id".into(), serde_json::json!(user.id.to_string()));
        ctx.insert("handle".into(), serde_json::json!(user.handle));
        ctx.insert("user_created".into(), serde_json::json!(true));
        ctx.insert(
            "starid_backend".into(),
            serde_json::json!(user.starid_backend),
        );
    }

    Ok(StageOutcome::Continue)
}
