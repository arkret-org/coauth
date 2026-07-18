use coauth_account_types::RecoveryTicketStatusOutcome;
use coauth_data::user::UserRecoveryRepository;
use coauth_data::{Clock, RepositoryAccess};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    DepotExt, NodeType, RouteError, extract_bound_activity_tracker, extract_session_info,
    get_requester, make_clock, make_rng,
};
use crate::handlers::RequesterFingerprint;
use crate::handlers::account::service::password::{ChangePasswordError, change_password};
use crate::handlers::account::service::recovery::{
    AccountRecoveryCompletion, AccountRecoveryTrustBoundary, CompleteAccountRecoveryError,
    ResendAccountRecoveryByTicketError, complete_account_recovery,
    resend_account_recovery_by_ticket,
};

// ── POST /_coauth/self/viewer/password ───────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct SetPasswordInput {
    pub user_id: String,
    pub current_password: Option<String>,
    pub new_password: String,
}

#[derive(Serialize, ToSchema)]
pub struct SetPasswordOutcome {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_boundary: Option<PasswordRecoveryTrustBoundaryOutcome>,
}

impl SetPasswordOutcome {
    fn status(status: &'static str) -> Self {
        Self {
            status,
            trust_boundary: None,
        }
    }

    fn recovered(completion: AccountRecoveryCompletion) -> Self {
        Self {
            status: "ALLOWED",
            trust_boundary: Some(completion.trust_boundary.into()),
        }
    }

    fn device_trust_recovery_required() -> Self {
        Self {
            status: "DEVICE_TRUST_RECOVERY_REQUIRED",
            trust_boundary: Some(AccountRecoveryTrustBoundary::password_only().into()),
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct PasswordRecoveryTrustBoundaryOutcome {
    pub recovery_credential_kind: &'static str,
    pub account_password_reset: bool,
    pub device_trust_reset: bool,
    pub cross_signing_reset: bool,
    pub trusted_recovery_service_used: bool,
    pub device_trust_recovery_required: bool,
}

impl From<AccountRecoveryTrustBoundary> for PasswordRecoveryTrustBoundaryOutcome {
    fn from(value: AccountRecoveryTrustBoundary) -> Self {
        Self {
            recovery_credential_kind: value.recovery_credential_kind,
            account_password_reset: value.account_password_reset,
            device_trust_reset: value.device_trust_reset,
            cross_signing_reset: value.cross_signing_reset,
            trusted_recovery_service_used: value.trusted_recovery_service_used,
            device_trust_recovery_required: value.device_trust_recovery_required,
        }
    }
}

#[endpoint]
pub async fn set_password(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetPasswordOutcome>, RouteError> {
    let input: SetPasswordInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user_id = NodeType::User.extract_ulid(&input.user_id)?;

    if !requester.is_owner_or_admin(Some(user_id)) {
        return Err(RouteError::Unauthorized);
    }

    // Preserve the session that is performing this change so the caller is not
    // logged out of their own device when the other sessions are revoked.
    let keep_browser_session_id = requester.browser_session().map(|session| session.id);
    let keep_oauth_session_id = requester.oauth_session().map(|session| session.id);
    let requester_fingerprint = requester.fingerprint();

    match change_password(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        &limiter,
        requester_fingerprint,
        user_id,
        input.current_password.map(Zeroizing::new),
        Zeroizing::new(input.new_password),
        requester.is_admin(),
        config.password_change_allowed,
        keep_browser_session_id,
        keep_oauth_session_id,
    )
    .await
    {
        Ok(()) => Ok(Json(SetPasswordOutcome::status("ALLOWED"))),
        Err(ChangePasswordError::PasswordDisabled) => Ok(Json(SetPasswordOutcome::status(
            "PASSWORD_CHANGES_DISABLED",
        ))),
        Err(ChangePasswordError::PasswordTooWeak) => {
            Ok(Json(SetPasswordOutcome::status("INVALID_NEW_PASSWORD")))
        }
        Err(ChangePasswordError::UserNotFound) => Ok(Json(SetPasswordOutcome::status("NOT_FOUND"))),
        Err(ChangePasswordError::PasswordChangesDisabled) => Ok(Json(SetPasswordOutcome::status(
            "PASSWORD_CHANGES_DISABLED",
        ))),
        Err(ChangePasswordError::NoCurrentPassword) => {
            Ok(Json(SetPasswordOutcome::status("NO_CURRENT_PASSWORD")))
        }
        Err(ChangePasswordError::CurrentPasswordRequired) => Err(RouteError::BadRequest(
            "current_password required for non-admins".into(),
        )),
        Err(ChangePasswordError::WrongPassword) => {
            Ok(Json(SetPasswordOutcome::status("WRONG_PASSWORD")))
        }
        Err(ChangePasswordError::RateLimited) => {
            Ok(Json(SetPasswordOutcome::status("RATE_LIMITED")))
        }
        Err(ChangePasswordError::Password(error)) => Err(RouteError::Internal(error.into())),
        Err(ChangePasswordError::Repository(error)) => Err(error.into()),
    }
}

// ── GET /_coauth/account/password-recovery/:ticket ─────────────────────

#[endpoint]
pub async fn get_recovery_ticket_status(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RecoveryTicketStatusOutcome>, RouteError> {
    let ticket = req
        .param::<String>("ticket")
        .ok_or(RouteError::BadRequest("missing ticket".into()))?;

    let config = depot.site_config()?;
    if !config.account_recovery_allowed {
        return Ok(Json(RecoveryTicketStatusOutcome {
            status: "disabled".to_owned(),
            email: None,
        }));
    }

    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();
    let mut repo = repo_factory.create().await?;

    let Some(recovery_ticket) = repo.user_recovery().find_ticket(&ticket).await? else {
        repo.cancel().await?;
        return Ok(Json(RecoveryTicketStatusOutcome {
            status: "not_found".to_owned(),
            email: None,
        }));
    };

    let Some(recovery_session) = repo
        .user_recovery()
        .lookup_session(recovery_ticket.user_recovery_session_id)
        .await?
    else {
        return Err(RouteError::Internal(Box::new(std::io::Error::other(
            "Could not load recovery session",
        ))));
    };

    let status = if recovery_session.consumed_at.is_some() {
        "consumed"
    } else if !recovery_ticket.active(clock.now()) {
        "expired"
    } else {
        "valid"
    };

    // This endpoint is unauthenticated (anyone holding the ticket string can
    // call it), so only return a masked form of the email.
    let email = Some(super::mask_email(&recovery_session.email));
    repo.cancel().await?;

    Ok(Json(RecoveryTicketStatusOutcome {
        status: status.to_owned(),
        email,
    }))
}

// ── POST /_coauth/account/password-recovery/set ─────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct SetPasswordByRecoveryInput {
    pub ticket: String,
    pub new_password: String,
    #[serde(default)]
    pub requested_trust_boundary: PasswordRecoveryTrustBoundaryRequest,
}

#[derive(Default, Deserialize, ToSchema)]
pub struct PasswordRecoveryTrustBoundaryRequest {
    #[serde(default)]
    pub device_trust_reset: bool,
    #[serde(default)]
    pub cross_signing_reset: bool,
    #[serde(default)]
    pub trusted_recovery_service: bool,
}

impl PasswordRecoveryTrustBoundaryRequest {
    fn requires_identity_recovery(&self) -> bool {
        self.device_trust_reset || self.cross_signing_reset || self.trusted_recovery_service
    }
}

#[endpoint]
pub async fn set_password_by_recovery(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetPasswordOutcome>, RouteError> {
    let input: SetPasswordByRecoveryInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    if input.requested_trust_boundary.requires_identity_recovery() {
        return Ok(Json(SetPasswordOutcome::device_trust_recovery_required()));
    }

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();

    // COA-SEC-05: per-IP gate so a held ticket cannot drive repeated
    // password-hash computation. Mirrors the start/resend recovery paths, which
    // already rate-limit; the completion endpoint previously had none.
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);
    if let Err(error) = limiter.check_account_recovery_completion(requester).await {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Ok(Json(SetPasswordOutcome::status("RATE_LIMITED")));
    }

    let repo = repo_factory.create().await?;

    match complete_account_recovery(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        &input.ticket,
        Zeroizing::new(input.new_password),
        config.account_recovery_allowed,
    )
    .await
    {
        Ok(completion) => Ok(Json(SetPasswordOutcome::recovered(completion))),
        Err(CompleteAccountRecoveryError::PasswordDisabled) => Ok(Json(
            SetPasswordOutcome::status("PASSWORD_CHANGES_DISABLED"),
        )),
        Err(CompleteAccountRecoveryError::PasswordTooWeak) => {
            Ok(Json(SetPasswordOutcome::status("INVALID_NEW_PASSWORD")))
        }
        Err(CompleteAccountRecoveryError::TicketNotFound) => {
            Ok(Json(SetPasswordOutcome::status("NO_SUCH_RECOVERY_TICKET")))
        }
        Err(CompleteAccountRecoveryError::SessionNotFound) => Err(RouteError::Internal(Box::new(
            std::io::Error::other("Could not load recovery session"),
        ))),
        Err(CompleteAccountRecoveryError::AlreadyConsumed) => Ok(Json(SetPasswordOutcome::status(
            "RECOVERY_TICKET_ALREADY_USED",
        ))),
        Err(CompleteAccountRecoveryError::TicketExpired) => {
            Ok(Json(SetPasswordOutcome::status("EXPIRED_RECOVERY_TICKET")))
        }
        Err(CompleteAccountRecoveryError::EmailNotFound) => Err(RouteError::Internal(Box::new(
            std::io::Error::other("Unknown email for recovery ticket"),
        ))),
        Err(CompleteAccountRecoveryError::UserNotFound) => Err(RouteError::Internal(Box::new(
            std::io::Error::other("Invalid user for recovery ticket"),
        ))),
        Err(CompleteAccountRecoveryError::AccountLocked) => {
            Ok(Json(SetPasswordOutcome::status("ACCOUNT_LOCKED")))
        }
        Err(CompleteAccountRecoveryError::Password(error)) => {
            Err(RouteError::Internal(error.into()))
        }
        Err(CompleteAccountRecoveryError::Repository(error)) => Err(error.into()),
    }
}

// ── POST /_coauth/account/password-recovery/resend ──────────────────────

#[derive(Deserialize, ToSchema)]
pub struct ResendRecoveryInput {
    pub ticket: String,
}

#[derive(Serialize, ToSchema)]
pub struct ResendRecoveryOutcome {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_url: Option<String>,
}

#[endpoint]
pub async fn resend_recovery_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendRecoveryOutcome>, RouteError> {
    let input: ResendRecoveryInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);
    let url_builder = depot.url_builder()?;

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    match resend_account_recovery_by_ticket(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester.fingerprint(),
        &input.ticket,
    )
    .await
    {
        Ok(session) => Ok(Json(ResendRecoveryOutcome {
            status: "SENT",
            progress_url: Some(
                url_builder.relative_url(&format!("/recover/progress/{}", session.id)),
            ),
        })),
        Err(ResendAccountRecoveryByTicketError::TicketNotFound) => {
            Ok(Json(ResendRecoveryOutcome {
                status: "NO_SUCH_RECOVERY_TICKET",
                progress_url: None,
            }))
        }
        Err(ResendAccountRecoveryByTicketError::SessionNotFound) => Err(RouteError::Internal(
            Box::new(std::io::Error::other("Could not load recovery session")),
        )),
        Err(ResendAccountRecoveryByTicketError::AlreadyConsumed) => {
            Ok(Json(ResendRecoveryOutcome {
                status: "RECOVERY_TICKET_ALREADY_USED",
                progress_url: None,
            }))
        }
        Err(ResendAccountRecoveryByTicketError::RateLimited) => Ok(Json(ResendRecoveryOutcome {
            status: "RATE_LIMITED",
            progress_url: None,
        })),
        Err(ResendAccountRecoveryByTicketError::Repository(error)) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use coauth_data::RepositoryAccess;
    use coauth_data::user::{UserEmailRepository, UserRecoveryRepository, UserRepository};
    use hyper::{Request, StatusCode};
    use ulid::Ulid;

    use super::*;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn create_recovery_ticket(
        state: &TestState,
        email: String,
    ) -> (coauth_data::UserRecoverySession, String) {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let username = format!("recover-{}", Ulid::new().to_string().to_lowercase());

        let user = repo
            .user()
            .add(&mut rng, &state.clock, username)
            .await
            .unwrap();
        let user_email = repo
            .user_email()
            .add(&mut rng, &state.clock, &user, email)
            .await
            .unwrap();
        let session = repo
            .user_recovery()
            .add_session(
                &mut rng,
                &state.clock,
                user_email.email.clone(),
                "test-agent".to_owned(),
                None,
                "en".to_owned(),
            )
            .await
            .unwrap();
        let ticket = repo
            .user_recovery()
            .add_ticket(
                &mut rng,
                &state.clock,
                &session,
                &user_email,
                format!("ticket-{}", Ulid::new().to_string().to_lowercase()),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        (session, ticket.ticket)
    }

    fn has_database_url() -> bool {
        std::env::var_os("DATABASE_URL").is_some()
    }

    #[test]
    fn recovery_success_outcome_serializes_password_only_trust_boundary() {
        let outcome = SetPasswordOutcome::recovered(AccountRecoveryCompletion::password_only());
        let body = serde_json::to_value(outcome).unwrap();
        let boundary = &body["trust_boundary"];

        assert_eq!(body["status"], "ALLOWED");
        assert_eq!(
            boundary["recovery_credential_kind"],
            "email_recovery_ticket"
        );
        assert_eq!(boundary["account_password_reset"], true);
        assert_eq!(boundary["device_trust_reset"], false);
        assert_eq!(boundary["cross_signing_reset"], false);
        assert_eq!(boundary["trusted_recovery_service_used"], false);
        assert_eq!(boundary["device_trust_recovery_required"], true);
    }

    #[test]
    fn requested_trust_boundary_flags_require_identity_recovery() {
        assert!(
            !PasswordRecoveryTrustBoundaryRequest::default().requires_identity_recovery(),
            "plain password recovery stays account-password scoped"
        );

        assert!(
            PasswordRecoveryTrustBoundaryRequest {
                device_trust_reset: true,
                ..Default::default()
            }
            .requires_identity_recovery()
        );
        assert!(
            PasswordRecoveryTrustBoundaryRequest {
                cross_signing_reset: true,
                ..Default::default()
            }
            .requires_identity_recovery()
        );
        assert!(
            PasswordRecoveryTrustBoundaryRequest {
                trusted_recovery_service: true,
                ..Default::default()
            }
            .requires_identity_recovery()
        );
    }

    #[tokio::test]
    async fn get_recovery_ticket_status_reports_valid_ticket() {
        if !has_database_url() {
            return;
        }

        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool(pool).await.unwrap();

        let (_session, ticket) =
            create_recovery_ticket(&state, "alice@example.com".to_owned()).await;

        let response = state
            .request(Request::get(format!("/_coauth/account/password-recovery/{ticket}")).empty())
            .await;

        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["status"], "valid");
        assert_eq!(body["email"], "a***@example.com");
    }

    #[tokio::test]
    async fn resend_recovery_email_returns_progress_url() {
        if !has_database_url() {
            return;
        }

        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool(pool).await.unwrap();

        let (session, ticket) = create_recovery_ticket(&state, "bob@example.com".to_owned()).await;

        let response = state
            .request(
                Request::post("/_coauth/account/password-recovery/resend")
                    .json(serde_json::json!({ "ticket": ticket })),
            )
            .await;

        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["status"], "SENT");
        assert_eq!(
            body["progress_url"],
            format!("/recover/progress/{}", session.id)
        );
    }

    #[tokio::test]
    async fn set_password_by_recovery_rejects_device_trust_scope_without_consuming_ticket() {
        if !has_database_url() {
            return;
        }

        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool(pool).await.unwrap();

        let (session, ticket) =
            create_recovery_ticket(&state, "carol@example.com".to_owned()).await;

        let response = state
            .request(
                Request::post("/_coauth/account/password-recovery/set").json(serde_json::json!({
                    "ticket": ticket,
                    "new_password": "Correct Horse Battery Staple 42!",
                    "requested_trust_boundary": {
                        "device_trust_reset": true
                    }
                })),
            )
            .await;

        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["status"], "DEVICE_TRUST_RECOVERY_REQUIRED");
        assert_eq!(body["trust_boundary"]["device_trust_reset"], false);
        assert_eq!(body["trust_boundary"]["cross_signing_reset"], false);
        assert_eq!(
            body["trust_boundary"]["trusted_recovery_service_used"],
            false
        );

        let mut repo = state.repository().await.unwrap();
        let stored = repo
            .user_recovery()
            .lookup_session(session.id)
            .await
            .unwrap()
            .expect("recovery session still present");
        assert!(
            stored.consumed_at.is_none(),
            "blocked device-trust request must not consume the recovery ticket"
        );
        repo.cancel().await.unwrap();
    }
}
