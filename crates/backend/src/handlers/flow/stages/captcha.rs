//! CAPTCHA stage side effects.
//!
//! Validates a CAPTCHA solution token.  The current MVP checks that the
//! token is non-empty; full server-side verification against hCaptcha or
//! reCAPTCHA is deferred to a later integration.

use coauth_data::flow::{StageOutcome, StageValidationError};

use super::StageExecutionError;

/// Execute the CAPTCHA validation stage.
///
/// For the MVP this only checks that the token is non-empty and marks
/// `captcha_verified` in the flow context.  Actual server-side
/// verification against a CAPTCHA provider API will be added later.
pub async fn execute(
    token: &str,
    context: &mut serde_json::Value,
) -> Result<StageOutcome, StageExecutionError> {
    if token.is_empty() {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("token".into()),
                message: "CAPTCHA token is required".into(),
                code: "captcha_required".into(),
            }],
        });
    }

    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("captcha_verified".into(), serde_json::json!(true));
    }

    Ok(StageOutcome::Continue)
}
