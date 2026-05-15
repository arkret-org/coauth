use std::net::IpAddr;

use coauth_data::{CaptchaConfig, CaptchaService, flow::{FlowDefinition, FlowStageBinding, FlowSession, StageChallenge, StageResponse, StageOutcome, StageKind, StageValidationError}};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use tracing::warn;

use crate::outbound_http::RequestBuilderExt as _;

#[derive(Debug, Error)]
pub enum FlowPlannerError {
    #[error("flow not found: {0}")]
    FlowNotFound(String),

    #[error("flow session expired")]
    SessionExpired,

    #[error("flow session already completed")]
    AlreadyCompleted,

    #[error("no more stages in flow")]
    NoMoreStages,

    #[error(transparent)]
    Repository(#[from] coauth_data::RepositoryError),
}

/// A planned flow — the ordered list of stage bindings to execute.
pub struct FlowPlan {
    pub flow: FlowDefinition,
    pub stages: Vec<FlowStageBinding>,
}

/// The flow executor manages progression through a flow's stages.
pub struct FlowExecutor;

impl FlowExecutor {
    /// Plan a flow: determine which stages should run based on context.
    /// For now, all stages in the flow are included (no policy evaluation).
    #[must_use] 
    pub fn plan(flow: FlowDefinition, bindings: Vec<FlowStageBinding>) -> FlowPlan {
        let mut stages = bindings;
        stages.sort_by_key(|b| b.order);
        FlowPlan { flow, stages }
    }

    /// Get the challenge for the current stage of a flow session.
    ///
    /// Before returning the challenge, this advances past any stages whose
    /// requirements are already satisfied by the session context (auto-skip).
    pub fn current_challenge(
        plan: &FlowPlan,
        session: &mut FlowSession,
    ) -> Result<StageChallenge, FlowPlannerError> {
        if session.status.is_terminal() {
            return Err(FlowPlannerError::AlreadyCompleted);
        }

        // Auto-skip stages that are already satisfied by the context.
        while session.current_stage_index < plan.stages.len() {
            let binding = &plan.stages[session.current_stage_index];
            if is_stage_satisfied(&binding.stage, &session.context) {
                session.current_stage_index += 1;
                continue;
            }
            break;
        }

        let binding = plan
            .stages
            .get(session.current_stage_index)
            .ok_or(FlowPlannerError::NoMoreStages)?;

        Ok(challenge_for_stage(&binding.stage, &session.context))
    }

    /// Process a response for the current stage and determine the outcome.
    /// Returns the outcome and the updated context.
    pub async fn process_response(
        plan: &FlowPlan,
        session: &FlowSession,
        response: StageResponse,
        captcha_ctx: Option<&CaptchaVerifyContext<'_>>,
    ) -> Result<(StageOutcome, Value), FlowPlannerError> {
        if session.status.is_terminal() {
            return Err(FlowPlannerError::AlreadyCompleted);
        }

        let binding = plan
            .stages
            .get(session.current_stage_index)
            .ok_or(FlowPlannerError::NoMoreStages)?;

        let mut context = session.context.clone();
        let outcome = validate_response(&binding.stage, &response, &mut context, captcha_ctx).await;

        Ok((outcome, context))
    }

    /// Check if the flow has more stages after the current one.
    #[must_use] 
    pub fn has_next_stage(plan: &FlowPlan, session: &FlowSession) -> bool {
        session.current_stage_index + 1 < plan.stages.len()
    }
}

/// Generate a challenge from a stage kind and current context.
fn challenge_for_stage(stage: &StageKind, context: &Value) -> StageChallenge {
    match stage {
        StageKind::Identification {
            user_fields,
            password_stage,
        } => StageChallenge::Identification {
            user_fields: user_fields.clone(),
            password_stage: *password_stage,
        },
        StageKind::EmailVerification { purpose, .. } => {
            let email = context
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            StageChallenge::EmailVerification {
                email,
                purpose: purpose.clone(),
            }
        }
        StageKind::PasswordWrite { require_current } => StageChallenge::PasswordWrite {
            require_current: *require_current,
        },
        StageKind::UserWrite { .. } => {
            let suggested = context
                .get("handle")
                .and_then(|v| v.as_str())
                .map(std::borrow::ToOwned::to_owned);
            StageChallenge::UserWrite {
                suggested_handle: suggested,
            }
        }
        StageKind::Captcha => StageChallenge::Captcha {
            site_key: context
                .get("captcha_site_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
        },
        StageKind::Consent => StageChallenge::Consent {
            scope: context
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            client_name: context
                .get("client_name")
                .and_then(|v| v.as_str())
                .map(std::borrow::ToOwned::to_owned),
        },
        StageKind::Prompt { fields } => StageChallenge::Prompt {
            fields: fields.clone(),
        },
        StageKind::AuthenticatorValidate { allowed_types } => {
            StageChallenge::AuthenticatorValidate {
                allowed_types: allowed_types.clone(),
            }
        }
        StageKind::EnrollmentToken { required } => StageChallenge::EnrollmentToken {
            required: *required,
        },
    }
}

/// Context needed for server-side CAPTCHA verification.
pub struct CaptchaVerifyContext<'a> {
    pub http_client: &'a reqwest::Client,
    pub captcha_config: Option<&'a CaptchaConfig>,
    pub site_hostname: &'a str,
    pub remote_ip: Option<IpAddr>,
}

const RECAPTCHA_VERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";
const HCAPTCHA_VERIFY_URL: &str = "https://api.hcaptcha.com/siteverify";
const CF_TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

#[derive(Serialize)]
struct CaptchaApiRequest<'a> {
    secret: &'a str,
    response: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remoteip: Option<IpAddr>,
}

#[derive(serde::Deserialize)]
struct CaptchaApiResponse {
    success: bool,
    hostname: Option<String>,
}

/// Validate a stage response and produce an outcome.
async fn validate_response(
    stage: &StageKind,
    response: &StageResponse,
    context: &mut Value,
    captcha_ctx: Option<&CaptchaVerifyContext<'_>>,
) -> StageOutcome {
    match (stage, response) {
        (
            StageKind::Identification { .. },
            StageResponse::Identification {
                uid_field,
                password,
            },
        ) => {
            // Store identified user in context
            if let Some(ctx) = context.as_object_mut() {
                ctx.insert("uid_field".into(), Value::String(uid_field.clone()));
                if let Some(pw) = password {
                    ctx.insert("password_provided".into(), Value::Bool(true));
                    // Don't store password in context for security
                    let _ = pw;
                }
            }
            StageOutcome::Continue
        }
        (StageKind::EmailVerification { .. }, StageResponse::EmailVerification { code }) => {
            // Actual verification happens in the stage implementation (side effect).
            // The executor just validates the response shape.
            if code.is_empty() {
                StageOutcome::Retry {
                    errors: vec![StageValidationError {
                        field: Some("code".into()),
                        message: "Verification code is required".into(),
                        code: "required".into(),
                    }],
                }
            } else {
                StageOutcome::Continue
            }
        }
        (
            StageKind::PasswordWrite { require_current },
            StageResponse::PasswordWrite {
                current_password,
                new_password,
            },
        ) => {
            let mut errors = vec![];
            if *require_current && current_password.is_none() {
                errors.push(StageValidationError {
                    field: Some("current_password".into()),
                    message: "Current password is required".into(),
                    code: "required".into(),
                });
            }
            if new_password.is_empty() {
                errors.push(StageValidationError {
                    field: Some("new_password".into()),
                    message: "New password is required".into(),
                    code: "required".into(),
                });
            }
            if errors.is_empty() {
                StageOutcome::Continue
            } else {
                StageOutcome::Retry { errors }
            }
        }
        (
            StageKind::UserWrite { .. },
            StageResponse::UserWrite {
                handle,
                display_name,
            },
        ) => {
            if let Some(ctx) = context.as_object_mut() {
                ctx.insert("handle".into(), Value::String(handle.clone()));
                if let Some(dn) = display_name {
                    ctx.insert("display_name".into(), Value::String(dn.clone()));
                }
            }
            StageOutcome::Continue
        }
        (StageKind::Consent, StageResponse::Consent { granted }) => {
            if *granted {
                StageOutcome::Continue
            } else {
                StageOutcome::Done { redirect_to: None }
            }
        }
        (StageKind::Captcha, StageResponse::Captcha { token }) => {
            if token.is_empty() {
                return StageOutcome::Retry {
                    errors: vec![StageValidationError {
                        field: Some("token".into()),
                        message: "CAPTCHA token is required".into(),
                        code: "required".into(),
                    }],
                };
            }

            // Server-side verification against the CAPTCHA provider API
            if let Some(ctx) = captcha_ctx
                && let Some(config) = ctx.captcha_config {
                    let verify_url = match config.service {
                        CaptchaService::RecaptchaV2 => RECAPTCHA_VERIFY_URL,
                        CaptchaService::HCaptcha => HCAPTCHA_VERIFY_URL,
                        CaptchaService::CloudflareTurnstile => CF_TURNSTILE_VERIFY_URL,
                    };

                    let api_req = CaptchaApiRequest {
                        secret: &config.secret_key,
                        response: token,
                        remoteip: ctx.remote_ip,
                    };

                    match ctx
                        .http_client
                        .post(verify_url)
                        .form(&api_req)
                        .send_traced()
                        .await
                    {
                        Ok(resp) => match resp.json::<CaptchaApiResponse>().await {
                            Ok(body) if body.success => {
                                // Optionally verify hostname
                                if let Some(hostname) = &body.hostname
                                    && hostname != ctx.site_hostname {
                                        warn!(
                                            expected = ctx.site_hostname,
                                            got = hostname.as_str(),
                                            "CAPTCHA hostname mismatch"
                                        );
                                    }
                                // Verification passed — fall through to
                                // Continue
                            }
                            Ok(_) => {
                                return StageOutcome::Retry {
                                    errors: vec![StageValidationError {
                                        field: Some("token".into()),
                                        message: "CAPTCHA verification failed".into(),
                                        code: "captcha_failed".into(),
                                    }],
                                };
                            }
                            Err(e) => {
                                warn!(error = %e, "CAPTCHA provider returned invalid response");
                                return StageOutcome::Retry {
                                    errors: vec![StageValidationError {
                                        field: Some("token".into()),
                                        message: "CAPTCHA verification error".into(),
                                        code: "captcha_error".into(),
                                    }],
                                };
                            }
                        },
                        Err(e) => {
                            warn!(error = %e, "Failed to contact CAPTCHA provider");
                            return StageOutcome::Retry {
                                errors: vec![StageValidationError {
                                    field: Some("token".into()),
                                    message: "CAPTCHA verification error".into(),
                                    code: "captcha_error".into(),
                                }],
                            };
                        }
                    }
                }

            StageOutcome::Continue
        }
        (StageKind::Prompt { fields }, StageResponse::Prompt { data }) => {
            let mut errors = vec![];
            for field in fields {
                if field.required {
                    let value = data.get(&field.field_key);
                    let is_missing = match value {
                        None | Some(Value::Null) => true,
                        Some(Value::String(s)) if s.is_empty() => true,
                        _ => false,
                    };
                    if is_missing {
                        errors.push(StageValidationError {
                            field: Some(field.field_key.clone()),
                            message: format!("{} is required", field.label),
                            code: "required".into(),
                        });
                    }
                }
            }
            if errors.is_empty() {
                if let Some(ctx) = context.as_object_mut() {
                    ctx.insert("prompt_data".into(), data.clone());
                }
                StageOutcome::Continue
            } else {
                StageOutcome::Retry { errors }
            }
        }
        (
            StageKind::AuthenticatorValidate { .. },
            StageResponse::AuthenticatorValidate { code, .. },
        ) => {
            if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
                StageOutcome::Retry {
                    errors: vec![StageValidationError {
                        field: Some("code".into()),
                        message: "Code must be exactly 6 digits".into(),
                        code: "invalid_totp_code".into(),
                    }],
                }
            } else {
                if let Some(ctx) = context.as_object_mut() {
                    ctx.insert("mfa_validated".into(), Value::Bool(true));
                }
                StageOutcome::Continue
            }
        }
        (StageKind::EnrollmentToken { required }, StageResponse::EnrollmentToken { token }) => {
            if token.is_empty() && *required {
                StageOutcome::Retry {
                    errors: vec![StageValidationError {
                        field: Some("token".into()),
                        message: "Enrollment token is required".into(),
                        code: "required".into(),
                    }],
                }
            } else {
                // Actual token validation happens in the stage side-effect.
                StageOutcome::Continue
            }
        }
        _ => {
            // Mismatched stage/response types
            StageOutcome::Retry {
                errors: vec![StageValidationError {
                    field: None,
                    message: "Invalid response for this stage".into(),
                    code: "invalid_response".into(),
                }],
            }
        }
    }
}

/// Check whether a stage's requirements are already satisfied by the
/// current session context, allowing the executor to auto-skip it.
fn is_stage_satisfied(stage: &StageKind, context: &Value) -> bool {
    match stage {
        StageKind::Identification { .. } => context.get("user_id").is_some(),
        StageKind::EmailVerification { .. } => {
            context.get("email_verified") == Some(&Value::Bool(true))
        }
        StageKind::PasswordWrite { .. } => context.get("password_set") == Some(&Value::Bool(true)),
        StageKind::UserWrite { .. } => context.get("user_created") == Some(&Value::Bool(true)),
        StageKind::AuthenticatorValidate { .. } => {
            context.get("mfa_validated") == Some(&Value::Bool(true))
        }
        StageKind::Captcha => context.get("captcha_verified") == Some(&Value::Bool(true)),
        StageKind::EnrollmentToken { .. } => context.get("enrollment_token_id").is_some(),
        _ => false,
    }
}
