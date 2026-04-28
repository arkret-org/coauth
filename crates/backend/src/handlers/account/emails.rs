use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, NodeType, RouteError, extract_bound_activity_tracker, extract_session_info,
    get_requester, make_clock, make_rng,
};
use crate::handlers::account::service::contacts::{
    CompleteEmailVerificationError, LoadEmailVerificationStatusError, RemoveUserEmailError,
    ResendEmailVerificationError, StartEmailVerificationError, complete_email_verification,
    load_email_verification_status, remove_user_email, resend_email_verification_code,
    start_email_verification,
};

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct StartEmailAuthResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<EmailAuthData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violations: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
pub struct EmailAuthData {
    pub id: String,
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct CompleteEmailAuthResponse {
    pub status: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct ResendEmailAuthCodeResponse {
    pub status: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct RemoveEmailResponse {
    pub status: &'static str,
}

// ── GET /api/v1/email-auth/:id ─────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct EmailAuthStatusResponse {
    pub id: String,
    pub email: String,
    pub completed_at: Option<String>,
}

#[endpoint]
pub async fn get_email_auth(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EmailAuthStatusResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmailAuthentication.extract_ulid(&id)?;

    let repo_factory = depot.repo_factory()?;
    let mut repo = repo_factory.create().await?;

    let auth = load_email_verification_status(&mut repo, ulid)
        .await
        .map_err(|error| match error {
            LoadEmailVerificationStatusError::NotFound => RouteError::NotFound,
            LoadEmailVerificationStatusError::Repository(error) => error.into(),
        })?;

    repo.cancel().await?;

    Ok(Json(EmailAuthStatusResponse {
        id: NodeType::UserEmailAuthentication.serialize(auth.id),
        email: auth.email,
        completed_at: auth.completed_at.map(|t| t.to_rfc3339()),
    }))
}

// ── POST /api/v1/email-auth/start ──────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct StartEmailAuthInput {
    pub email: String,
    pub password: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

#[endpoint]
pub async fn start_email_auth(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<StartEmailAuthResponse>, RouteError> {
    let input: StartEmailAuthInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let notification_language =
        crate::handlers::notification_language(req, depot, input.language.as_deref());

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    match start_email_verification(
        repo,
        &mut rng,
        &clock,
        &limiter,
        &password_manager,
        config.email_change_allowed,
        config.password_login_enabled,
        requester.is_admin(),
        requester.fingerprint(),
        requester.browser_session(),
        input.email,
        input.password,
        notification_language,
    )
    .await
    {
        Err(StartEmailVerificationError::Unauthorized) => Err(RouteError::Unauthorized),
        Err(StartEmailVerificationError::Disabled) => Ok(Json(StartEmailAuthResponse {
            status: "DENIED",
            authentication: None,
            violations: Some(vec!["Email changes are not allowed".into()]),
        })),
        Err(StartEmailVerificationError::InvalidEmail) => Ok(Json(StartEmailAuthResponse {
            status: "INVALID_EMAIL_ADDRESS",
            authentication: None,
            violations: None,
        })),
        Err(StartEmailVerificationError::IncorrectPassword) => Ok(Json(StartEmailAuthResponse {
            status: "INCORRECT_PASSWORD",
            authentication: None,
            violations: None,
        })),
        Ok(started) => Ok(Json(StartEmailAuthResponse {
            status: "STARTED",
            authentication: Some(EmailAuthData {
                id: NodeType::UserEmailAuthentication.serialize(started.authentication.id),
                email: started.authentication.email,
            }),
            violations: None,
        })),
        Err(StartEmailVerificationError::RateLimited) => Ok(Json(StartEmailAuthResponse {
            status: "RATE_LIMITED",
            authentication: None,
            violations: None,
        })),
        Err(StartEmailVerificationError::Password(error)) => {
            Err(RouteError::Internal(error.into()))
        }
        Err(StartEmailVerificationError::Repository(error)) => Err(error.into()),
    }
}

// ── POST /api/v1/email-auth/:id/complete ───────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CompleteEmailAuthInput {
    pub code: String,
}

#[endpoint]
pub async fn complete_email_auth(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<CompleteEmailAuthResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmailAuthentication.extract_ulid(&id)?;

    let input: CompleteEmailAuthInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    match complete_email_verification(
        repo,
        &limiter,
        &mut rng,
        &clock,
        ulid,
        requester.browser_session(),
        &input.code,
    )
    .await
    {
        Err(CompleteEmailVerificationError::Unauthorized) => Err(RouteError::Unauthorized),
        Ok(()) => Ok(Json(CompleteEmailAuthResponse {
            status: "COMPLETED",
        })),
        Err(CompleteEmailVerificationError::NotFound) => Err(RouteError::NotFound),
        Err(CompleteEmailVerificationError::NotOwned) => Err(RouteError::Unauthorized),
        Err(CompleteEmailVerificationError::AlreadyCompleted) => {
            Ok(Json(CompleteEmailAuthResponse {
                status: "COMPLETED",
            }))
        }
        Err(CompleteEmailVerificationError::RateLimited) => Ok(Json(CompleteEmailAuthResponse {
            status: "RATE_LIMITED",
        })),
        Err(CompleteEmailVerificationError::InvalidCode) => Ok(Json(CompleteEmailAuthResponse {
            status: "INVALID_CODE",
        })),
        Err(CompleteEmailVerificationError::CodeExpired) => Ok(Json(CompleteEmailAuthResponse {
            status: "CODE_EXPIRED",
        })),
        Err(CompleteEmailVerificationError::Repository(error)) => Err(error.into()),
    }
}

// ── POST /api/v1/email-auth/:id/resend ─────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct ResendEmailAuthInput {
    #[serde(default)]
    pub language: Option<String>,
}

#[endpoint]
pub async fn resend_email_auth_code(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendEmailAuthCodeResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmailAuthentication.extract_ulid(&id)?;

    let input: ResendEmailAuthInput = req
        .parse_json()
        .await
        .unwrap_or(ResendEmailAuthInput { language: None });

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let notification_language =
        crate::handlers::notification_language(req, depot, input.language.as_deref());

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    match resend_email_verification_code(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester.fingerprint(),
        ulid,
        requester.browser_session(),
        notification_language,
    )
    .await
    {
        Err(ResendEmailVerificationError::Unauthorized) => Err(RouteError::Unauthorized),
        Ok(()) => Ok(Json(ResendEmailAuthCodeResponse { status: "RESENT" })),
        Err(ResendEmailVerificationError::NotFound) => Err(RouteError::NotFound),
        Err(ResendEmailVerificationError::NotOwned) => Err(RouteError::Unauthorized),
        Err(ResendEmailVerificationError::AlreadyCompleted) => {
            Ok(Json(ResendEmailAuthCodeResponse {
                status: "COMPLETED",
            }))
        }
        Err(ResendEmailVerificationError::RateLimited) => Ok(Json(ResendEmailAuthCodeResponse {
            status: "RATE_LIMITED",
        })),
        Err(ResendEmailVerificationError::Repository(error)) => Err(error.into()),
    }
}

// ── DELETE /api/v1/user-emails/:id ─────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct RemoveEmailInput {
    pub password: Option<String>,
}

#[endpoint]
pub async fn remove_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RemoveEmailResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmail.extract_ulid(&id)?;

    // Body is optional for DELETE
    let input: RemoveEmailInput = req
        .parse_json()
        .await
        .unwrap_or(RemoveEmailInput { password: None });

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    match remove_user_email(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        requester.user().map(|user| user.id),
        requester.is_admin(),
        config.password_login_enabled,
        input.password,
        ulid,
    )
    .await
    {
        Ok(()) => Ok(Json(RemoveEmailResponse { status: "REMOVED" })),
        Err(RemoveUserEmailError::Unauthorized) => Err(RouteError::Unauthorized),
        Err(RemoveUserEmailError::NotFound) => Err(RouteError::NotFound),
        Err(RemoveUserEmailError::UserNotFound) => Err(RouteError::LoadFailed),
        Err(RemoveUserEmailError::IncorrectPassword) => Ok(Json(RemoveEmailResponse {
            status: "INCORRECT_PASSWORD",
        })),
        Err(RemoveUserEmailError::Password(error)) => Err(RouteError::Internal(error.into())),
        Err(RemoveUserEmailError::Repository(error)) => Err(error.into()),
    }
}
