//! REST API endpoints for the journey engine.
//!
//! These endpoints expose the journey engine over HTTP, allowing clients to start
//! journeys, query the current challenge, and submit stage responses.
//!
//! Session state is stored in-memory for now; a proper repository-backed store
//! will replace this once `JourneySession` has a database repository.

use chrono::Utc;
use coauth_data::journey::{
    IdentificationField as DomainIdentificationField, JourneySession, JourneySessionStatus,
    PromptField as DomainPromptField, PromptFieldType as DomainPromptFieldType,
    StageChallenge as DomainStageChallenge, StageOutcome, StageSubmission as DomainStageSubmission,
    StageValidationError as DomainStageValidationError,
};
use coauth_data::new_id;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use super::{RouteError, make_rng};
use crate::app_state::DepotExt as _;
use crate::handlers::journey::{
    CaptchaVerifyContext, JourneyExecutor, JourneyPlan, evict_journey_sessions,
    journey_session_store_write,
};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Envelope returned for every journey endpoint.
///
/// This is intentionally separate from the data-model journey types. The journey
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
pub enum JourneyChallenge {
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
    EnrollmentToken {
        required: bool,
    },
    JourneyDone {
        redirect_to: Option<String>,
    },
}

impl From<DomainStageChallenge> for JourneyChallenge {
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
            DomainStageChallenge::EnrollmentToken { required } => {
                Self::EnrollmentToken { required }
            }
            DomainStageChallenge::JourneyDone { redirect_to } => Self::JourneyDone { redirect_to },
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct JourneyValidationError {
    pub field: Option<String>,
    pub message: String,
    pub code: String,
}

impl From<DomainStageValidationError> for JourneyValidationError {
    fn from(value: DomainStageValidationError) -> Self {
        Self {
            field: value.field,
            message: value.message,
            code: value.code,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct JourneyOutcome {
    /// The session identifier (ULID).
    pub session_id: String,
    /// The slug of the journey being executed.
    pub journey_slug: String,
    /// The current stage challenge to present to the user.
    pub challenge: JourneyChallenge,
    /// Zero-based index of the current stage.
    pub stage_index: usize,
    /// Total number of stages in the journey.
    pub total_stages: usize,
    /// Validation errors, if the last response was rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<JourneyValidationError>>,
}

/// Request body for `POST /_coauth/self/journey/session/:id/respond`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JourneyStageRequestBody {
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
    EnrollmentToken {
        token: String,
    },
}

impl From<JourneyStageRequestBody> for DomainStageSubmission {
    fn from(value: JourneyStageRequestBody) -> Self {
        match value {
            JourneyStageRequestBody::Identification {
                uid_field,
                password,
            } => Self::Identification {
                uid_field,
                password,
            },
            JourneyStageRequestBody::EmailVerification { code } => Self::EmailVerification { code },
            JourneyStageRequestBody::PasswordWrite {
                current_password,
                new_password,
            } => Self::PasswordWrite {
                current_password,
                new_password,
            },
            JourneyStageRequestBody::UserWrite {
                handle,
                display_name,
            } => Self::UserWrite {
                handle,
                display_name,
            },
            JourneyStageRequestBody::Captcha { token } => Self::Captcha { token },
            JourneyStageRequestBody::Consent { granted } => Self::Consent { granted },
            JourneyStageRequestBody::Prompt { data } => Self::Prompt { data },
            JourneyStageRequestBody::EnrollmentToken { token } => Self::EnrollmentToken { token },
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RespondInput {
    /// The stage response submitted by the client.
    pub response: JourneyStageRequestBody,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a journey definition + bindings from a slug using the built-in
/// defaults.  Returns `None` if the slug does not match any known default
/// journey.
fn resolve_journey_by_slug(
    slug: &str,
    rng: &mut (dyn rand_core::RngCore + Send),
) -> Option<(
    coauth_data::journey::JourneyDefinition,
    Vec<coauth_data::journey::JourneyStageBinding>,
)> {
    match slug {
        "default-registration" => {
            Some(crate::handlers::journey::defaults::default_registration_journey(rng))
        }
        "default-recovery" => {
            Some(crate::handlers::journey::defaults::default_recovery_journey(rng))
        }
        "default-password-change" => {
            Some(crate::handlers::journey::defaults::default_password_change_journey(rng))
        }
        "default-authentication" => {
            Some(crate::handlers::journey::defaults::default_authentication_journey(rng))
        }
        "default-authorization" => {
            Some(crate::handlers::journey::defaults::default_authorization_journey(rng))
        }
        "default-enrollment" => {
            Some(crate::handlers::journey::defaults::default_enrollment_journey(rng))
        }
        _ => None,
    }
}

/// Build a [`JourneyOutcome`] from a plan, session, and challenge.
fn build_response(
    plan: &JourneyPlan,
    session: &JourneySession,
    challenge: DomainStageChallenge,
    errors: Option<Vec<DomainStageValidationError>>,
) -> JourneyOutcome {
    JourneyOutcome {
        session_id: session.id.to_string(),
        journey_slug: plan.journey.slug.clone(),
        challenge: challenge.into(),
        stage_index: session.current_stage_index,
        total_stages: plan.stages.len(),
        errors: errors.map(|items| items.into_iter().map(Into::into).collect()),
    }
}

fn parse_journey_session_id(req: &Request) -> Result<Ulid, RouteError> {
    req.param::<String>("id")
        .ok_or_else(|| RouteError::BadRequest("missing session id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid session id".into()))
}

// ---------------------------------------------------------------------------
// POST /_coauth/self/journey/:slug/start
// ---------------------------------------------------------------------------

/// Start a new journey session for the given journey slug.
///
/// Creates a `JourneySession`, plans the journey, and returns the first stage
/// challenge.
#[endpoint]
pub async fn start_journey(req: &mut Request) -> Result<Json<JourneyOutcome>, RouteError> {
    let slug: String = req
        .param::<String>("slug")
        .ok_or_else(|| RouteError::BadRequest("missing journey slug".into()))?;

    let mut rng = make_rng();

    let (journey_def, bindings) =
        resolve_journey_by_slug(&slug, &mut *rng).ok_or_else(|| RouteError::NotFound)?;

    let plan = JourneyExecutor::plan(journey_def, bindings);

    let now = Utc::now();
    let session_id = new_id(now, &mut *rng);

    let session = JourneySession {
        id: session_id,
        journey_id: plan.journey.id,
        current_stage_index: 0,
        status: JourneySessionStatus::InProgress,
        context: Value::Object(serde_json::Map::new()),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
        expires_at: now + chrono::Duration::hours(1),
        completed_at: None,
    };

    let mut session = session;
    let challenge = JourneyExecutor::current_challenge(&plan, &mut session)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let response = build_response(&plan, &session, challenge, None);

    // Store in memory. Evict expired (and, if at capacity, oldest) sessions
    // first so this unauthenticated endpoint cannot grow the map without bound.
    {
        let mut store = journey_session_store_write().await;
        evict_journey_sessions(&mut store);
        store.insert(session_id, (plan, session));
    }

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// GET /_coauth/self/journey/session/:id
// ---------------------------------------------------------------------------

/// Get the current challenge for an existing journey session.
#[endpoint]
pub async fn get_journey_session(req: &mut Request) -> Result<Json<JourneyOutcome>, RouteError> {
    let id = parse_journey_session_id(req)?;

    let mut store = journey_session_store_write().await;

    // Enforce the session TTL: an expired non-terminal session is treated as
    // gone — remove it and report NotFound rather than continuing to serve it.
    if let Some((_, session)) = store.get(&id)
        && !session.status.is_terminal()
        && session.expires_at <= Utc::now()
    {
        store.remove(&id);
        return Err(RouteError::NotFound);
    }

    let (plan, session) = store.get_mut(&id).ok_or(RouteError::NotFound)?;

    if session.status.is_terminal() {
        // Return a JourneyDone challenge for completed sessions
        let challenge = DomainStageChallenge::JourneyDone {
            redirect_to: Some("/account".into()),
        };
        let response = build_response(plan, session, challenge, None);
        return Ok(Json(response));
    }

    let challenge = JourneyExecutor::current_challenge(plan, session)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let response = build_response(plan, session, challenge, None);

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// POST /_coauth/self/journey/session/:id/respond
// ---------------------------------------------------------------------------

/// Submit a response to the current stage challenge.
///
/// On success, advances to the next stage (or completes the journey) and
/// returns the new challenge.  On validation failure, returns the current
/// challenge again with error details.
#[endpoint]
pub async fn respond_journey(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<JourneyOutcome>, RouteError> {
    let id = parse_journey_session_id(req)?;

    let input: RespondInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let mut store = journey_session_store_write().await;

    // Enforce the session TTL before accepting a response: an expired
    // non-terminal session is treated as gone and may not be advanced.
    if let Some((_, session)) = store.get(&id)
        && !session.status.is_terminal()
        && session.expires_at <= Utc::now()
    {
        store.remove(&id);
        return Err(RouteError::NotFound);
    }

    let (plan, session) = store.get_mut(&id).ok_or(RouteError::NotFound)?;

    if session.status.is_terminal() {
        return Err(RouteError::BadRequest(
            "journey session is no longer active".into(),
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
        let site_hostname =
            url_builder.map_or("localhost", coauth_data::UrlBuilder::public_hostname);
        CaptchaVerifyContext {
            http_client: client,
            captcha_config,
            site_hostname,
            remote_ip: activity_tracker.ip(),
        }
    });

    // Process the response through the executor
    let (outcome, updated_context) = JourneyExecutor::process_response(
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
            if JourneyExecutor::has_next_stage(plan, session) {
                session.current_stage_index += 1;

                let challenge = JourneyExecutor::current_challenge(plan, session)
                    .map_err(|e| RouteError::Internal(Box::new(e)))?;

                let response = build_response(plan, session, challenge, None);
                Ok(Json(response))
            } else {
                // Journey is done
                session.status = JourneySessionStatus::Completed;
                session.completed_at = Some(Utc::now());

                let challenge = DomainStageChallenge::JourneyDone {
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
            let challenge = JourneyExecutor::current_challenge(plan, session)
                .map_err(|e| RouteError::Internal(Box::new(e)))?;

            let response = build_response(plan, session, challenge, Some(errors));
            Ok(Json(response))
        }
        StageOutcome::Done { redirect_to } => {
            // The stage itself decided the journey is done (e.g. consent denied)
            session.status = JourneySessionStatus::Completed;
            session.completed_at = Some(Utc::now());

            let challenge = DomainStageChallenge::JourneyDone { redirect_to };
            session.current_stage_index = plan.stages.len();
            let response = build_response(plan, session, challenge, None);
            Ok(Json(response))
        }
    }
}
