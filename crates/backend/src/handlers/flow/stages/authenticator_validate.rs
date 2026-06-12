//! Authenticator validation stage side effects.
//!
//! Validates a TOTP second-factor code by looking up the user's TOTP secret
//! from the repository and verifying the HMAC (RFC 6238).

use coauth_data::BoxRepository;
use coauth_data::flow::{StageOutcome, StageValidationError};
use tracing::warn;
use ulid::Ulid;

use super::StageExecutionError;
use crate::handlers::Limiter;
use crate::totp;

/// Execute the authenticator validation stage.
///
/// Looks up the user's TOTP configuration from the database, then verifies
/// the submitted code against the stored secret using HMAC-SHA1.
///
/// When `limiter` is provided, applies the per-account TOTP rate limit
/// (default: 5 attempts per 15 minutes). The limiter check happens
/// *before* the TOTP code is verified — failed attempts and successful
/// attempts both consume one quota unit, which is what RFC 6238 §5.2
/// recommends for OTP throttling.
pub async fn execute(
    repo: &mut BoxRepository,
    code: &str,
    context: &mut serde_json::Value,
    limiter: Option<&Limiter>,
) -> Result<StageOutcome, StageExecutionError> {
    // The identification stage must have run first and stored the user_id.
    let user_id_str = context
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            StageExecutionError::Internal(anyhow::anyhow!(
                "missing user_id in flow context — identification stage must run first"
            ))
        })?;

    let user_id: Ulid = user_id_str.parse().map_err(|e| {
        StageExecutionError::Internal(anyhow::anyhow!("invalid user_id in flow context: {e}"))
    })?;

    // Validate code format: exactly 6 ASCII digits.
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("code".into()),
                message: "Code must be exactly 6 digits".into(),
                code: "invalid_totp_code".into(),
            }],
        });
    }

    // Apply per-account rate limit before any DB lookup. A locked-out
    // account returns `RateLimited` rather than a Retry so the handler
    // can surface the standard 429 response.
    if let Some(limiter) = limiter
        && limiter.check_mfa_totp(user_id).await.is_err()
    {
        warn!(user.id = %user_id, "TOTP attempt rate-limited");
        return Err(StageExecutionError::RateLimited);
    }

    // Look up the user to pass to the repository.
    let user = repo
        .user()
        .lookup(user_id)
        .await
        .map_err(StageExecutionError::Repository)?
        .ok_or(StageExecutionError::UserNotFound)?;

    // Look up the user's confirmed TOTP configuration.
    let totp_config = repo
        .user_totp()
        .get_for_user(&user)
        .await
        .map_err(StageExecutionError::Repository)?;

    let Some(config) = totp_config else {
        // No TOTP configured for this user — treat as an error.
        warn!(user.id = %user_id, "TOTP validation requested but user has no TOTP configured");
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("code".into()),
                message: "No authenticator configured for this account".into(),
                code: "totp_not_configured".into(),
            }],
        });
    };

    // Only accept confirmed TOTP configurations.
    if config.confirmed_at.is_none() {
        warn!(user.id = %user_id, "TOTP config exists but is not yet confirmed");
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("code".into()),
                message: "Authenticator setup is not complete".into(),
                code: "totp_not_confirmed".into(),
            }],
        });
    }

    // Verify the code against the stored secret.
    let period = u64::try_from(config.period).unwrap_or(30);
    let digits = u32::try_from(config.digits).unwrap_or(6);

    if !totp::verify(&config.secret, code, period, digits) {
        return Ok(StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("code".into()),
                message: "Invalid verification code".into(),
                code: "totp_invalid".into(),
            }],
        });
    }

    // Mark MFA as validated in the flow context.
    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("mfa_validated".into(), serde_json::json!(true));
    }

    Ok(StageOutcome::Continue)
}
