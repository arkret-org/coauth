use arkret_models_collaboration::session_grant_bodies::{
    AuthSessionLogoutOutcome, AuthSessionLogoutRequestBody,
};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;
use sha2::Digest as _;

use super::*;
use crate::handlers::arkret::*;

/// `POST /_arkret/gate/account/auth-sessions/logout` — Auth-side S2S logout
/// sub-operation used by the Account Authority after it has validated the
/// client-visible `ak.gate.account.command.logout` request.
#[handler]
pub async fn logout_auth_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AuthSessionLogoutOutcome>, ArkretRouteError> {
    require_auth_session_logout_service_caller(req, depot)?;

    let body: AuthSessionLogoutRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    if body.grant_jwt.trim().is_empty() {
        return Err(ArkretRouteError::BadRequest("missing grant_jwt".to_owned()));
    }

    // Reject malformed bodies, but do not require the row to still exist. The
    // operation is idempotent once a valid grant-shaped identifier is presented
    // by an authenticated service caller.
    let _jwt: Jwt<'_, SignedSessionGrantClaims> = Jwt::try_from(body.grant_jwt.as_str())
        .map_err(|_| ArkretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;

    Ok(Json(
        terminate_auth_side_session_by_grant_jwt(depot, &body.grant_jwt).await?,
    ))
}

fn require_auth_session_logout_service_caller(
    req: &Request,
    depot: &Depot,
) -> Result<(), ArkretRouteError> {
    let header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| ArkretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let value = header
        .to_str()
        .map_err(|_| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(|| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))?
        .trim();
    if token.is_empty() {
        return Err(ArkretRouteError::Unauthorized(
            "empty service bearer".to_owned(),
        ));
    }

    let arkret_config = depot.arkret_config()?;
    if super::super::principal_server_static_session_grant_bearer_matches(&arkret_config, token) {
        return Ok(());
    }

    Err(ArkretRouteError::Unauthorized(
        "invalid service bearer".to_owned(),
    ))
}

async fn terminate_auth_side_session_by_grant_jwt(
    depot: &Depot,
    grant_jwt: &str,
) -> Result<AuthSessionLogoutOutcome, ArkretRouteError> {
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();
    let mut repo = depot.repo().await?;

    let Some(grant) = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(grant_jwt)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    else {
        repo.cancel()
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        return Ok(success_outcome());
    };
    let issuer = grant.issuer.clone();

    let canonical_intent = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "operation": "auth_session_logout",
        "grant_jwt_digest": format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(grant_jwt.as_bytes()))
        ),
    }))
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let canonical_intent_digest: [u8; 32] = sha2::Sha256::digest(&canonical_intent).into();
    let request_identity = format!(
        "auth-session-logout:{}",
        hex::encode(sha2::Sha256::digest(grant_jwt.as_bytes()))
    );
    let now = clock.now();
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &*clock,
            coauth_data::NewSessionGrantOperation {
                issuer,
                operation: coauth_data::SessionGrantOperationDescriptor::Revoke {
                    selector: coauth_data::SessionGrantRevokeTarget::Grant {
                        grant_id: grant.grant_id.clone(),
                    },
                },
                proof_kind: None,
                request_identity: &request_identity,
                canonical_intent_digest,
                canonical_intent: &canonical_intent,
                target_session_grant_id: None,
                issuance_nonce: None,
                session_id: None,
                grant_not_before: None,
                grant_expires_at: None,
                signing_key_id: None,
                retained_until: now + chrono::Duration::days(7),
            },
        )
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let operation = match reserved {
        coauth_data::SessionGrantReserveOutcome::Reserved(operation) => Some(operation),
        coauth_data::SessionGrantReserveOutcome::Pending(operation)
            if operation.state == coauth_data::SessionGrantOperationState::Reserved =>
        {
            Some(operation)
        }
        coauth_data::SessionGrantReserveOutcome::Replay(_) => None,
        coauth_data::SessionGrantReserveOutcome::Conflict(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "auth-session logout identity conflicts with a different intent",
            ));
        }
        coauth_data::SessionGrantReserveOutcome::Indeterminate(_) => {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "auth-session logout replay is indeterminate",
            ));
        }
        coauth_data::SessionGrantReserveOutcome::Pending(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "auth-session logout authorization is incomplete",
            ));
        }
    };
    if let Some(operation) = operation {
        let checkpoint = serde_json::json!({"kind":"principal_server_logout"});
        let committed = repo
            .oauth_session_grant()
            .commit_revoke(
                &*clock,
                operation.id,
                coauth_data::SessionGrantProofAuthorization {
                    authorization_ref: &request_identity,
                    checkpoint: &checkpoint,
                    proof_expires_at: now + chrono::Duration::days(7),
                },
                coauth_data::SessionGrantRevokeSelector::Grant(&grant.grant_id),
            )
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        if matches!(
            committed,
            coauth_data::SessionGrantRevokeOutcome::Indeterminate(_)
        ) {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "auth-session logout commit is indeterminate",
            ));
        }
    }

    if let Some(browser_session_id) = grant.browser_session_id {
        let unfinished_session = {
            repo.browser_session()
                .lookup(browser_session_id)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .filter(|session| session.finished_at.is_none())
        };
        if let Some(session) = unfinished_session {
            repo.browser_session()
                .finish(&*clock, session)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        }
    }

    repo.save()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    Ok(success_outcome())
}

fn success_outcome() -> AuthSessionLogoutOutcome {
    AuthSessionLogoutOutcome {
        grant_chain_terminated: true,
        auth_session_logged_out: true,
    }
}
