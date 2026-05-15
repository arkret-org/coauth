//! REST API endpoints for the flow engine.
//!
//! These endpoints expose the flow engine over HTTP, allowing clients to start
//! flows, query the current challenge, and submit stage responses.
//!
//! Session state is stored in-memory for now; a proper repository-backed store
//! will replace this once `FlowSession` has a database repository.

use chrono::Utc;
use coauth_data::{
    flow::{
        AuthenticatorType as DomainAuthenticatorType, FlowSession, FlowSessionStatus,
        IdentificationField as DomainIdentificationField, PromptField as DomainPromptField,
        PromptFieldType as DomainPromptFieldType, StageChallenge as DomainStageChallenge,
        StageOutcome, StageResponse as DomainStageResponse,
        StageValidationError as DomainStageValidationError,
    },
    new_id,
};
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use super::{RouteError, make_rng};
use crate::{
    app_state::DepotExt as _,
    handlers::flow::{CaptchaVerifyContext, FlowExecutor, FlowPlan, flow_session_store_write},
};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Envelope returned for every flow endpoint.
///
/// This is intentionally separate from the data-model flow types. The flow
/// engine continues using domain enums from `coauth_data`, while the REST
/// API exposes a stable schema DTO that can be documented via `OpenAPI`.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentificationField {
    Username,
    Email,
    Phone,
}

impl From<DomainIdentificationField> for IdentificationField {
    fn from(value: DomainIdentificationField) -> Self {
        match value {
            DomainIdentificationField::Username => Self::Username,
            DomainIdentificationField::Email => Self::Email,
            DomainIdentificationField::Phone => Self::Phone,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatorType {
    Totp,
    WebAuthn,
}

impl From<DomainAuthenticatorType> for AuthenticatorType {
    fn from(value: DomainAuthenticatorType) -> Self {
        match value {
            DomainAuthenticatorType::Totp => Self::Totp,
            DomainAuthenticatorType::WebAuthn => Self::WebAuthn,
        }
    }
}

impl From<AuthenticatorType> for DomainAuthenticatorType {
    fn from(value: AuthenticatorType) -> Self {
        match value {
            AuthenticatorType::Totp => Self::Totp,
            AuthenticatorType::WebAuthn => Self::WebAuthn,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PromptFieldType {
    Text,
    Email,
    Password,
    Checkbox,
    Hidden,
    Select,
}

impl From<DomainPromptFieldType> for PromptFieldType {
    fn from(value: DomainPromptFieldType) -> Self {
        match value {
            DomainPromptFieldType::Text => Self::Text,
            DomainPromptFieldType::Email => Self::Email,
            DomainPromptFieldType::Password => Self::Password,
            DomainPromptFieldType::Checkbox => Self::Checkbox,
            DomainPromptFieldType::Hidden => Self::Hidden,
            DomainPromptFieldType::Select => Self::Select,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PromptField {
    pub field_key: String,
    pub label: String,
    pub field_type: PromptFieldType,
    pub required: bool,
    pub placeholder: Option<String>,
    pub order: i32,
}

impl From<DomainPromptField> for PromptField {
    fn from(value: DomainPromptField) -> Self {
        Self {
            field_key: value.field_key,
            label: value.label,
            field_type: value.field_type.into(),
            required: value.required,
            placeholder: value.placeholder,
            order: value.order,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FlowChallenge {
    Identification {
        user_fields: Vec<IdentificationField>,
        password_stage: bool,
    },
    EmailVerification {
        email: String,
        purpose: String,
    },
    PasswordWrite {
        require_current: bool,
    },
    UserWrite {
        suggested_handle: Option<String>,
    },
    Captcha {
        site_key: String,
    },
    Consent {
        scope: String,
        client_name: Option<String>,
    },
    Prompt {
        fields: Vec<PromptField>,
    },
    AuthenticatorValidate {
        allowed_types: Vec<AuthenticatorType>,
    },
    EnrollmentToken {
        required: bool,
    },
    FlowDone {
        redirect_to: Option<String>,
    },
}

impl From<DomainStageChallenge> for FlowChallenge {
    fn from(value: DomainStageChallenge) -> Self {
        match value {
            DomainStageChallenge::Identification {
                user_fields,
                password_stage,
            } => Self::Identification {
                user_fields: user_fields.into_iter().map(Into::into).collect(),
                password_stage,
            },
            DomainStageChallenge::EmailVerification { email, purpose } => {
                Self::EmailVerification { email, purpose }
            }
            DomainStageChallenge::PasswordWrite { require_current } => {
                Self::PasswordWrite { require_current }
            }
            DomainStageChallenge::UserWrite { suggested_handle } => {
                Self::UserWrite { suggested_handle }
            }
            DomainStageChallenge::Captcha { site_key } => Self::Captcha { site_key },
            DomainStageChallenge::Consent { scope, client_name } => {
                Self::Consent { scope, client_name }
            }
            DomainStageChallenge::Prompt { fields } => Self::Prompt {
                fields: fields.into_iter().map(Into::into).collect(),
            },
            DomainStageChallenge::AuthenticatorValidate { allowed_types } => {
                Self::AuthenticatorValidate {
                    allowed_types: allowed_types.into_iter().map(Into::into).collect(),
                }
            }
            DomainStageChallenge::EnrollmentToken { required } => {
                Self::EnrollmentToken { required }
            }
            DomainStageChallenge::FlowDone { redirect_to } => Self::FlowDone { redirect_to },
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FlowValidationError {
    pub field: Option<String>,
    pub message: String,
    pub code: String,
}

impl From<DomainStageValidationError> for FlowValidationError {
    fn from(value: DomainStageValidationError) -> Self {
        Self {
            field: value.field,
            message: value.message,
            code: value.code,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FlowResponse {
    /// The session identifier (ULID).
    pub session_id: String,
    /// The slug of the flow being executed.
    pub flow_slug: String,
    /// The current stage challenge to present to the user.
    pub challenge: FlowChallenge,
    /// Zero-based index of the current stage.
    pub stage_index: usize,
    /// Total number of stages in the flow.
    pub total_stages: usize,
    /// Validation errors, if the last response was rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<FlowValidationError>>,
}

/// Request body for `POST /api/v1/flow/session/:id/respond`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FlowStageResponse {
    Identification {
        uid_field: String,
        password: Option<String>,
    },
    EmailVerification {
        code: String,
    },
    PasswordWrite {
        current_password: Option<String>,
        new_password: String,
    },
    UserWrite {
        handle: String,
        display_name: Option<String>,
    },
    Captcha {
        token: String,
    },
    Consent {
        granted: bool,
    },
    Prompt {
        #[salvo(schema(value_type = Object))]
        data: Value,
    },
    AuthenticatorValidate {
        authenticator_type: AuthenticatorType,
        code: String,
    },
    EnrollmentToken {
        token: String,
    },
}

impl From<FlowStageResponse> for DomainStageResponse {
    fn from(value: FlowStageResponse) -> Self {
        match value {
            FlowStageResponse::Identification {
                uid_field,
                password,
            } => Self::Identification {
                uid_field,
                password,
            },
            FlowStageResponse::EmailVerification { code } => Self::EmailVerification { code },
            FlowStageResponse::PasswordWrite {
                current_password,
                new_password,
            } => Self::PasswordWrite {
                current_password,
                new_password,
            },
            FlowStageResponse::UserWrite {
                handle,
                display_name,
            } => Self::UserWrite {
                handle,
                display_name,
            },
            FlowStageResponse::Captcha { token } => Self::Captcha { token },
            FlowStageResponse::Consent { granted } => Self::Consent { granted },
            FlowStageResponse::Prompt { data } => Self::Prompt { data },
            FlowStageResponse::AuthenticatorValidate {
                authenticator_type,
                code,
            } => Self::AuthenticatorValidate {
                authenticator_type: authenticator_type.into(),
                code,
            },
            FlowStageResponse::EnrollmentToken { token } => Self::EnrollmentToken { token },
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RespondInput {
    /// The stage response submitted by the client.
    pub response: FlowStageResponse,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a flow definition + bindings from a slug using the built-in
/// defaults.  Returns `None` if the slug does not match any known default
/// flow.
fn resolve_flow_by_slug(
    slug: &str,
    rng: &mut (dyn rand_core::RngCore + Send),
) -> Option<(
    coauth_data::flow::FlowDefinition,
    Vec<coauth_data::flow::FlowStageBinding>,
)> {
    match slug {
        "default-registration" => Some(crate::handlers::flow::defaults::default_registration_flow(
            rng,
        )),
        "default-recovery" => Some(crate::handlers::flow::defaults::default_recovery_flow(rng)),
        "default-password-change" => {
            Some(crate::handlers::flow::defaults::default_password_change_flow(rng))
        }
        "default-authentication" => {
            Some(crate::handlers::flow::defaults::default_authentication_flow(rng))
        }
        "default-authorization" => Some(
            crate::handlers::flow::defaults::default_authorization_flow(rng),
        ),
        "default-enrollment" => Some(crate::handlers::flow::defaults::default_enrollment_flow(
            rng,
        )),
        _ => None,
    }
}

/// Build a [`FlowResponse`] from a plan, session, and challenge.
fn build_response(
    plan: &FlowPlan,
    session: &FlowSession,
    challenge: DomainStageChallenge,
    errors: Option<Vec<DomainStageValidationError>>,
) -> FlowResponse {
    FlowResponse {
        session_id: session.id.to_string(),
        flow_slug: plan.flow.slug.clone(),
        challenge: challenge.into(),
        stage_index: session.current_stage_index,
        total_stages: plan.stages.len(),
        errors: errors.map(|items| items.into_iter().map(Into::into).collect()),
    }
}

fn parse_flow_session_id(req: &Request) -> Result<Ulid, RouteError> {
    req.param::<String>("id")
        .ok_or_else(|| RouteError::BadRequest("missing session id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid session id".into()))
}

// ---------------------------------------------------------------------------
// POST /api/v1/flow/:slug/start
// ---------------------------------------------------------------------------

/// Start a new flow session for the given flow slug.
///
/// Creates a `FlowSession`, plans the flow, and returns the first stage
/// challenge.
#[endpoint]
pub async fn start_flow(req: &mut Request) -> Result<Json<FlowResponse>, RouteError> {
    let slug: String = req
        .param::<String>("slug")
        .ok_or_else(|| RouteError::BadRequest("missing flow slug".into()))?;

    let mut rng = make_rng();

    let (flow_def, bindings) =
        resolve_flow_by_slug(&slug, &mut *rng).ok_or_else(|| RouteError::NotFound)?;

    let plan = FlowExecutor::plan(flow_def, bindings);

    let now = Utc::now();
    let session_id = new_id(now, &mut *rng);

    let session = FlowSession {
        id: session_id,
        flow_id: plan.flow.id,
        current_stage_index: 0,
        status: FlowSessionStatus::InProgress,
        context: Value::Object(serde_json::Map::new()),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
        expires_at: now + chrono::Duration::hours(1),
        completed_at: None,
    };

    let mut session = session;
    let challenge = FlowExecutor::current_challenge(&plan, &mut session)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let response = build_response(&plan, &session, challenge, None);

    // Store in memory
    {
        let mut store = flow_session_store_write().await;
        store.insert(session_id, (plan, session));
    }

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// GET /api/v1/flow/session/:id
// ---------------------------------------------------------------------------

/// Get the current challenge for an existing flow session.
#[endpoint]
pub async fn get_flow_session(req: &mut Request) -> Result<Json<FlowResponse>, RouteError> {
    let id = parse_flow_session_id(req)?;

    let mut store = flow_session_store_write().await;
    let (plan, session) = store.get_mut(&id).ok_or(RouteError::NotFound)?;

    if session.status.is_terminal() {
        // Return a FlowDone challenge for completed sessions
        let challenge = DomainStageChallenge::FlowDone {
            redirect_to: Some("/account".into()),
        };
        let response = build_response(plan, session, challenge, None);
        return Ok(Json(response));
    }

    let challenge = FlowExecutor::current_challenge(plan, session)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let response = build_response(plan, session, challenge, None);

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// POST /api/v1/flow/session/:id/respond
// ---------------------------------------------------------------------------

/// Submit a response to the current stage challenge.
///
/// On success, advances to the next stage (or completes the flow) and
/// returns the new challenge.  On validation failure, returns the current
/// challenge again with error details.
#[endpoint]
pub async fn respond_flow(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<FlowResponse>, RouteError> {
    let id = parse_flow_session_id(req)?;

    let input: RespondInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let mut store = flow_session_store_write().await;
    let (plan, session) = store.get_mut(&id).ok_or(RouteError::NotFound)?;

    if session.status.is_terminal() {
        return Err(RouteError::BadRequest(
            "flow session is no longer active".into(),
        ));
    }

    // Build CAPTCHA verification context from depot if available. The
    // verifier needs the actual deployment hostname (so reCAPTCHA /
    // Turnstile / hCaptcha hostname checks succeed) and the requester IP
    // (for the optional `remoteip` parameter).
    let http_client = depot.get::<reqwest::Client>("http_client").ok();
    let site_config = depot.get_site_config();
    let url_builder = depot.get_url_builder();
    let activity_tracker = super::extract_bound_activity_tracker(req, depot);
    let captcha_verify = http_client.map(|client| {
        let captcha_config = site_config.and_then(|sc| sc.captcha.as_ref());
        let site_hostname = url_builder
            .map_or("localhost", coauth_data::UrlBuilder::public_hostname);
        CaptchaVerifyContext {
            http_client: client,
            captcha_config,
            site_hostname,
            remote_ip: activity_tracker.ip(),
        }
    });

    // Process the response through the executor
    let (outcome, updated_context) = FlowExecutor::process_response(
        plan,
        session,
        input.response.into(),
        captcha_verify.as_ref(),
    )
    .await
    .map_err(|e| RouteError::Internal(Box::new(e)))?;

    // Update the session context
    session.context = updated_context;
    session.updated_at = Utc::now();

    match outcome {
        StageOutcome::Continue => {
            // Advance to the next stage
            if FlowExecutor::has_next_stage(plan, session) {
                session.current_stage_index += 1;

                let challenge = FlowExecutor::current_challenge(plan, session)
                    .map_err(|e| RouteError::Internal(Box::new(e)))?;

                let response = build_response(plan, session, challenge, None);
                Ok(Json(response))
            } else {
                // Flow is done
                session.status = FlowSessionStatus::Completed;
                session.completed_at = Some(Utc::now());

                let challenge = DomainStageChallenge::FlowDone {
                    redirect_to: Some("/account".into()),
                };
                // Stage index points past the last stage to indicate completion
                session.current_stage_index = plan.stages.len();
                let response = build_response(plan, session, challenge, None);
                Ok(Json(response))
            }
        }
        StageOutcome::Retry { errors } => {
            // Re-display the current challenge with validation errors
            let challenge = FlowExecutor::current_challenge(plan, session)
                .map_err(|e| RouteError::Internal(Box::new(e)))?;

            let response = build_response(plan, session, challenge, Some(errors));
            Ok(Json(response))
        }
        StageOutcome::Done { redirect_to } => {
            // The stage itself decided the flow is done (e.g. consent denied)
            session.status = FlowSessionStatus::Completed;
            session.completed_at = Some(Utc::now());

            let challenge = DomainStageChallenge::FlowDone { redirect_to };
            session.current_stage_index = plan.stages.len();
            let response = build_response(plan, session, challenge, None);
            Ok(Json(response))
        }
    }
}
