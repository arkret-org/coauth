//! Consent stage side effects.
//!
//! Records the user's consent decision.  When consent is granted the
//! `consent_granted` flag is set in the strand context so downstream stages
//! (e.g. token issuance) can observe it.  When rejected the strand is
//! terminated immediately.

use coauth_data::strand::StageOutcome;

use super::StageExecutionError;

/// Execute the consent stage.
///
/// * `granted` – `true` if the user accepted the consent prompt.
/// * `context` – mutable reference to the strand session context.
///
/// When the user grants consent, `consent_granted: true` is stored in the
/// context and the strand continues.  When rejected, the strand ends with no
/// redirect (the client may display its own rejection UI).
pub async fn execute(
    granted: bool,
    context: &mut serde_json::Value,
) -> Result<StageOutcome, StageExecutionError> {
    if granted {
        if let Some(ctx) = context.as_object_mut() {
            ctx.insert("consent_granted".into(), serde_json::json!(true));
        }
        Ok(StageOutcome::Continue)
    } else {
        Ok(StageOutcome::Done { redirect_to: None })
    }
}
