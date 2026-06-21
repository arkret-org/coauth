use coauth_jose::jwt::Jwt;
use cokret_core::error::{
    ERROR_CODE_AUDIENCE_MISMATCH, ERROR_CODE_DID_PROOF_REQUIRED, ERROR_CODE_GRANT_ALREADY_CONSUMED,
    ERROR_CODE_INVALID_SIGNATURE, ERROR_CODE_SESSION_GRANT_NOT_FOUND,
    ERROR_CODE_SESSION_LOGGED_OUT,
};
use cokret_core::{SessionGrantRefreshOutcome, SessionGrantRefreshRequestBody};
use salvo::prelude::*;

use super::*;
use crate::handlers::cokret::*;

// ── DPoP-bound session-grant refresh + debug seed ──────────────
//
// These two handlers were added in G3.C1 to complete the device-bound
// session-grant story: `refresh_session_grant` rotates an existing
// DPoP-bound grant onto a new access token (keeping `cnf.jkt` constant),
// and `debug_issue_dpop_grant` is the cotest harness seam that mints a
// fully signed grant without going through OIDC.

/// `POST /_cokret/gate/account/session-grants/refresh` — exchange a near-expiry
/// DPoP-bound session grant for a fresh one. The caller MUST present:
///
/// * A `DPoP` header that proves possession of the same key the existing grant is bound to
///   (`cnf.jkt` on the old grant must match the new proof's `jkt`).
/// * A request body carrying the prior grant JWT.
///
/// On success the old grant is revoked (single-use semantics — its
/// `revoked_at` is persisted) and a new grant is issued with the same
/// `cnf.jkt`, a rotated id, and a fresh expiry.
#[handler]
pub async fn refresh_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantRefreshOutcome>, CokretRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    // 1. DPoP proof must be present — the refresh endpoint is the canonical proof-of-possession
    //    check.
    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        // Holder proof (the device's DPoP) is the authorization for this
        // operation; its absence is an auth failure, not a malformed body.
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_DID_PROOF_REQUIRED,
            "session-grant holder proof (DPoP) required",
        )
    })?;

    let body: SessionGrantRefreshRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;

    if body.grant_jwt.trim().is_empty() {
        return Err(CokretRouteError::BadRequest("missing grant_jwt".to_owned()));
    }

    // 2. Parse + load the existing grant. We never verify the JWT signature here — the persisted
    //    row IS the source of truth — but we DO read the `cnf.jkt` claim out of the JWT payload to
    //    bind the proof.
    let jwt: Jwt<'_, SessionGrantPayload> = Jwt::try_from(body.grant_jwt.as_str())
        .map_err(|_| CokretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let prior_payload = jwt.payload().clone();
    let expected_jkt = prior_payload
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

    // Single-use enforcement: a previously consumed grant can never be rotated
    // again. Re-use of a consumed grant is a credential-compromise signal (the
    // wire code is `grant_already_consumed`; this protocol rotates DPoP-bound
    // session grants, not OAuth refresh tokens — see account-lifecycle §4.1).
    if prior_grant.revoked_at.is_some() {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_GRANT_ALREADY_CONSUMED,
            "session grant already consumed; its rotation chain cannot continue",
        ));
    }

    // 3. Verify the DPoP proof against this exact endpoint, with the prior grant_jwt as the bound
    //    access token (so `ath` MUST match).
    let verifier = depot
        .dpop_verifier()
        .unwrap_or_else(|_| DpopVerifier::shared());
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

    // 4. Resolve the underlying browser session so the new grant lives under the same
    //    authentication context.
    let browser_session = repo
        .browser_session()
        .lookup(prior_grant.browser_session_id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                "session grant references missing browser session",
            ))
        })?;

    // The browser session is the authentication context the grant chain hangs
    // off. Logout finishes it (sets `finished_at`) but does NOT eagerly revoke
    // outstanding grants — so without this check a logged-out device that still
    // holds the DPoP key could keep rotating its grant and stay signed in
    // forever, defeating logout. Refuse rotation once the session is finished:
    // re-authentication (a fresh browser session) is then required.
    if browser_session.finished_at.is_some() {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_SESSION_LOGGED_OUT,
            "underlying browser session is logged out; rotation chain cannot be resumed",
        ));
    }

    // 5. Mint a new grant with the same subject + scope + audience. The
    // audience MUST NOT change across rotation: a client holding a grant for
    // one Principal Server must not be able to rotate it into a grant for a
    // different audience (which it could then exchange there). Ignore any
    // client-supplied audience; reject an explicit mismatch defensively.
    if let Some(requested) = body.audience.as_deref()
        && requested != prior_grant.audience
    {
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_AUDIENCE_MISMATCH,
            "session-grant rotation MUST NOT change the bound audience",
        ));
    }

    // 5. Single-use rotation gate (CAS). Atomically consume the prior grant
    // BEFORE minting its successor: `revoke_if_active` sets `revoked_at` only
    // if it is still NULL and reports whether THIS call won. Two concurrent
    // rotations of the same parent contend on the row lock, so exactly one
    // wins and the loser is rejected with `grant_already_consumed` — without
    // this, both could read the parent active and each insert an active child,
    // violating single-use rotation (account-lifecycle §4.1). Doing the consume
    // first (rather than after the insert) means the loser never mints a grant
    // it would have to throw away, and the consume + insert commit atomically
    // in this one transaction.
    let consumed = repo
        .oauth_session_grant()
        .revoke_if_active(&*clock, prior_grant.id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
    if !consumed {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_GRANT_ALREADY_CONSUMED,
            "session grant already consumed; its rotation chain cannot continue",
        ));
    }

    // 6. Mint a new grant with the same subject + scope + audience.
    let audience = prior_grant.audience.clone();
    let scopes: Vec<String> = prior_grant
        .scope
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    let new_material = issue_session_grant_for_audience(
        &*clock,
        &url_builder,
        &cokret_config,
        &key_store,
        &browser_session,
        verification.jwk.clone(),
        audience,
        scopes,
        Some(&prior_grant.subject),
        Some(verification.jkt.clone()),
    )
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    let persisted = persist_session_grant(
        &mut repo,
        &mut rng,
        &*clock,
        &browser_session,
        &new_material,
    )
    .await
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantRefreshOutcome {
        grant_id: persisted.id.to_string(),
        grant_jwt: new_material.grant_jwt,
        session_public_key: new_material.session_public_key,
        expires_at: new_material.expires_at_timestamp,
        audience: new_material.audience,
        scopes: new_material.scopes,
        dpop_jkt: verification.jkt,
        // The prior grant was atomically consumed by the CAS above.
        previous_grant_id: prior_grant.id.to_string(),
    }))
}
