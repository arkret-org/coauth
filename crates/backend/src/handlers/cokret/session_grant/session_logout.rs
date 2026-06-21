use coauth_jose::jwt::Jwt;
use cokret_core::error::{
    ERROR_CODE_DID_PROOF_REQUIRED, ERROR_CODE_INVALID_SIGNATURE, ERROR_CODE_SESSION_GRANT_NOT_FOUND,
};
use cokret_core::{SessionGrantLogoutOutcome, SessionGrantLogoutRequestBody};
use salvo::prelude::*;

use super::*;
use crate::handlers::cokret::*;

/// `POST /_cokret/gate/account/session-grants/revoke` — hard-logout / explicit
/// revocation of a DPoP-bound session grant (account-lifecycle §4.1).
///
/// The caller proves possession of the key bound into the grant's `cnf.jkt`
/// (same holder proof as rotation), then we:
/// 1. revoke the presented grant (single-use; its rotation chain cannot continue because each
///    rotation already revokes its predecessor), and
/// 2. **finish the underlying browser session**, so no future holder proof — even with the correct
///    device key — can rotate a fresh grant under it (`session_logged_out` on `refresh`).
///    Re-authentication is then required.
#[handler]
pub async fn revoke_session_grant_via_holder_proof(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantLogoutOutcome>, CokretRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let clock = crate::handlers::make_clock();

    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        // Holder proof (the device's DPoP) is the authorization for this
        // operation; its absence is an auth failure, not a malformed body.
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_DID_PROOF_REQUIRED,
            "session-grant holder proof (DPoP) required",
        )
    })?;
    let body: SessionGrantLogoutRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;
    if body.grant_jwt.trim().is_empty() {
        return Err(CokretRouteError::BadRequest("missing grant_jwt".to_owned()));
    }

    let jwt: Jwt<'_, SessionGrantPayload> = Jwt::try_from(body.grant_jwt.as_str())
        .map_err(|_| CokretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let expected_jkt = jwt
        .payload()
        .cnf
        .as_ref()
        .map(|cnf| cnf.jkt.clone())
        .ok_or_else(|| {
            CokretRouteError::BadRequest("grant_jwt is not DPoP-bound (cnf.jkt missing)".to_owned())
        })?;

    let mut repo = depot.repo().await?;
    let prior_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&body.grant_jwt)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            CokretRouteError::coded(
                StatusCode::NOT_FOUND,
                ERROR_CODE_SESSION_GRANT_NOT_FOUND,
                "no session grant matches the presented grant_jwt",
            )
        })?;

    // Proof-of-possession: the caller MUST hold the key the grant is bound to.
    let verifier = DpopVerifier::shared();
    let now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let verification = verifier
        .verify(&dpop_header, &htm, &htu, now, Some(&body.grant_jwt))
        .await
        .map_err(|error| {
            CokretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                ERROR_CODE_INVALID_SIGNATURE,
                error.to_string(),
            )
        })?;
    DpopVerifier::require_matching_jkt(&verification.jkt, &expected_jkt).map_err(|error| {
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_INVALID_SIGNATURE,
            error.to_string(),
        )
    })?;

    let revoked = if prior_grant.revoked_at.is_none() {
        repo.oauth_session_grant()
            .revoke(&*clock, prior_grant.clone())
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        true
    } else {
        false
    };

    // Terminate the authentication context so the rotation chain cannot be
    // resumed by any holder proof (account-lifecycle §4.1). Bind the looked-up
    // session to an owned value first so the sub-repo borrow is released before
    // the follow-up `finish` re-borrows `repo`.
    let active_session = repo
        .browser_session()
        .lookup(prior_grant.browser_session_id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .filter(|session| session.finished_at.is_none());
    let browser_session_finished = if let Some(session) = active_session {
        repo.browser_session()
            .finish(&*clock, session)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        true
    } else {
        false
    };

    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantLogoutOutcome {
        revoked,
        browser_session_finished,
    }))
}

// ── Single client hard-logout (account-lifecycle §4.1) ─────────────
//
// `POST /_cokret/gate/account/logout` — the client-visible hard-logout entry
// point. The client presents `Authorization: Bearer <ck.session.grant>` plus
// a DPoP holder proof; this terminates the Auth-side grant rotation chain +
// browser session (the same machinery as
// `session-grants/logout`). When coauth is also the Account Authority host it
// internally drives this Auth-side termination; the Principal-side
// (local account/device session + to-device drop) is performed by the
// Principal Server (soland) either via its own `/logout` handling or by the
// Account Authority front forwarding here. Either way the grant-chain +
// browser-session termination is reachable through this single endpoint.

/// `POST /_cokret/gate/account/logout` — single hard-logout. Internally
/// performs the Auth-side grant-chain + browser-session termination and
/// returns the SDK `AccountLogoutOutcome`.
#[handler]
pub async fn logout(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<cokret_core::AccountLogoutOutcome>, CokretRouteError> {
    let outcome = terminate_auth_side_session(req, depot).await?;
    Ok(Json(cokret_core::AccountLogoutOutcome {
        ok: true,
        // `revoked` reflects whether the presented grant was still active when
        // the logout arrived; the browser-session termination is the
        // durability-critical step (account-lifecycle §4.1 step 2).
        revoked: outcome.revoked || outcome.browser_session_finished,
    }))
}

/// Auth-side hard-logout primitive: revoke the presented grant and finish the
/// underlying browser session so its rotation chain cannot be resumed. Shared
/// by the single `/logout` entry point and the lower-level
/// `session-grants/logout` op. Authorization is the DPoP holder proof bound to
/// the grant's `cnf.jkt` — the same proof-of-possession the rotation chain
/// uses.
async fn terminate_auth_side_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<SessionGrantLogoutOutcome, CokretRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let clock = crate::handlers::make_clock();

    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_DID_PROOF_REQUIRED,
            "session-grant holder proof (DPoP) required for logout",
        )
    })?;

    // The grant JWT is presented as the Authorization Bearer (account-lifecycle
    // §4.1) so the same request both authenticates and identifies the grant
    // chain to terminate.
    let grant_jwt = bearer_session_grant(req)?;

    let jwt: Jwt<'_, SessionGrantPayload> = Jwt::try_from(grant_jwt.as_str()).map_err(|_| {
        CokretRouteError::BadRequest("bearer grant_jwt is not parseable".to_owned())
    })?;
    let expected_jkt = jwt
        .payload()
        .cnf
        .as_ref()
        .map(|cnf| cnf.jkt.clone())
        .ok_or_else(|| {
            CokretRouteError::BadRequest(
                "bearer grant_jwt is not DPoP-bound (cnf.jkt missing)".to_owned(),
            )
        })?;

    let mut repo = depot.repo().await?;
    let prior_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&grant_jwt)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    let Some(prior_grant) = prior_grant else {
        // Idempotent: a hard logout for a grant the Auth Server never minted
        // (or already pruned) is not an error — the chain is already gone.
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Ok(SessionGrantLogoutOutcome {
            revoked: false,
            browser_session_finished: false,
        });
    };

    // Proof-of-possession: the caller MUST hold the key the grant is bound to.
    let verifier = DpopVerifier::shared();
    let now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let verification = verifier
        .verify(&dpop_header, &htm, &htu, now, Some(&grant_jwt))
        .await
        .map_err(|error| {
            CokretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                ERROR_CODE_INVALID_SIGNATURE,
                error.to_string(),
            )
        })?;
    DpopVerifier::require_matching_jkt(&verification.jkt, &expected_jkt).map_err(|error| {
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_INVALID_SIGNATURE,
            error.to_string(),
        )
    })?;

    let revoked = if prior_grant.revoked_at.is_none() {
        repo.oauth_session_grant()
            .revoke(&*clock, prior_grant.clone())
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        true
    } else {
        false
    };

    // Terminate the authentication context so the rotation chain cannot be
    // resumed by any holder proof (account-lifecycle §4.1 step 2).
    let active_session = repo
        .browser_session()
        .lookup(prior_grant.browser_session_id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .filter(|session| session.finished_at.is_none());
    let browser_session_finished = if let Some(session) = active_session {
        repo.browser_session()
            .finish(&*clock, session)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        true
    } else {
        false
    };

    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(SessionGrantLogoutOutcome {
        revoked,
        browser_session_finished,
    })
}

/// Extract the `ck.session.grant` JWT from the `Authorization: Bearer` header.
fn bearer_session_grant(req: &Request) -> Result<String, CokretRouteError> {
    let header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| CokretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let value = header
        .to_str()
        .map_err(|_| CokretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(|| {
            CokretRouteError::Unauthorized(
                "authorization header must carry the ck.session.grant as a Bearer token".to_owned(),
            )
        })?
        .trim();
    if token.is_empty() {
        return Err(CokretRouteError::Unauthorized(
            "empty bearer session grant".to_owned(),
        ));
    }
    Ok(token.to_owned())
}
