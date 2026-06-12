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
use crate::handlers::account::service::password::{ChangePasswordError, change_password};
use crate::handlers::account::service::recovery::{
    CompleteAccountRecoveryError, ResendAccountRecoveryByTicketError, complete_account_recovery,
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

    match change_password(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        user_id,
        input.current_password.map(Zeroizing::new),
        Zeroizing::new(input.new_password),
        requester.is_admin(),
        config.password_change_allowed,
    )
    .await
    {
        Ok(()) => Ok(Json(SetPasswordOutcome { status: "ALLOWED" })),
        Err(ChangePasswordError::PasswordDisabled) => Ok(Json(SetPasswordOutcome {
            status: "PASSWORD_CHANGES_DISABLED",
        })),
        Err(ChangePasswordError::PasswordTooWeak) => Ok(Json(SetPasswordOutcome {
            status: "INVALID_NEW_PASSWORD",
        })),
        Err(ChangePasswordError::UserNotFound) => Ok(Json(SetPasswordOutcome {
            status: "NOT_FOUND",
        })),
        Err(ChangePasswordError::PasswordChangesDisabled) => Ok(Json(SetPasswordOutcome {
            status: "PASSWORD_CHANGES_DISABLED",
        })),
        Err(ChangePasswordError::NoCurrentPassword) => Ok(Json(SetPasswordOutcome {
            status: "NO_CURRENT_PASSWORD",
        })),
        Err(ChangePasswordError::CurrentPasswordRequired) => Err(RouteError::BadRequest(
            "current_password required for non-admins".into(),
        )),
        Err(ChangePasswordError::WrongPassword) => Ok(Json(SetPasswordOutcome {
            status: "WRONG_PASSWORD",
        })),
        Err(ChangePasswordError::Password(error)) => Err(RouteError::Internal(error.into())),
        Err(ChangePasswordError::Repository(error)) => Err(error.into()),
    }
}

// ── GET /_coauth/gate/account/password-recovery/:ticket ─────────────────────

#[derive(Serialize, ToSchema)]
pub struct RecoveryTicketStatusOutcome {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

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
            status: "disabled",
            email: None,
        }));
    }

    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();
    let mut repo = repo_factory.create().await?;

    let Some(recovery_ticket) = repo.user_recovery().find_ticket(&ticket).await? else {
        repo.cancel().await?;
        return Ok(Json(RecoveryTicketStatusOutcome {
            status: "not_found",
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

    let email = Some(recovery_session.email.clone());
    repo.cancel().await?;

    Ok(Json(RecoveryTicketStatusOutcome { status, email }))
}

// ── POST /_coauth/gate/account/password-recovery/set ─────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct SetPasswordByRecoveryInput {
    pub ticket: String,
    pub new_password: String,
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

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let clock = make_clock();
    let mut rng = make_rng();

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
        Ok(()) => Ok(Json(SetPasswordOutcome { status: "ALLOWED" })),
        Err(CompleteAccountRecoveryError::PasswordDisabled) => Ok(Json(SetPasswordOutcome {
            status: "PASSWORD_CHANGES_DISABLED",
        })),
        Err(CompleteAccountRecoveryError::PasswordTooWeak) => Ok(Json(SetPasswordOutcome {
            status: "INVALID_NEW_PASSWORD",
        })),
        Err(CompleteAccountRecoveryError::TicketNotFound) => Ok(Json(SetPasswordOutcome {
            status: "NO_SUCH_RECOVERY_TICKET",
        })),
        Err(CompleteAccountRecoveryError::SessionNotFound) => Err(RouteError::Internal(Box::new(
            std::io::Error::other("Could not load recovery session"),
        ))),
        Err(CompleteAccountRecoveryError::AlreadyConsumed) => Ok(Json(SetPasswordOutcome {
            status: "RECOVERY_TICKET_ALREADY_USED",
        })),
        Err(CompleteAccountRecoveryError::TicketExpired) => Ok(Json(SetPasswordOutcome {
            status: "EXPIRED_RECOVERY_TICKET",
        })),
        Err(CompleteAccountRecoveryError::EmailNotFound) => Err(RouteError::Internal(Box::new(
            std::io::Error::other("Unknown email for recovery ticket"),
        ))),
        Err(CompleteAccountRecoveryError::UserNotFound) => Err(RouteError::Internal(Box::new(
            std::io::Error::other("Invalid user for recovery ticket"),
        ))),
        Err(CompleteAccountRecoveryError::AccountLocked) => Ok(Json(SetPasswordOutcome {
            status: "ACCOUNT_LOCKED",
        })),
        Err(CompleteAccountRecoveryError::Password(error)) => {
            Err(RouteError::Internal(error.into()))
        }
        Err(CompleteAccountRecoveryError::Repository(error)) => Err(error.into()),
    }
}

// ── POST /_coauth/gate/account/password-recovery/resend ──────────────────────

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
            .request(
                Request::get(format!("/_coauth/gate/account/password-recovery/{ticket}")).empty(),
            )
            .await;

        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["status"], "valid");
        assert_eq!(body["email"], "alice@example.com");
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
                Request::post("/_coauth/gate/account/password-recovery/resend")
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
}
