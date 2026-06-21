use chrono::{DateTime, Duration, Utc};
use coauth_data::{SessionGrant, User};
use coauth_jose::jwk::{PublicJsonWebKey, PublicJsonWebKeySet};
use coauth_jose::jwt::Jwt;
use cokret_core::error::ERROR_CODE_SCHEMA_VIOLATION;
use cokret_core::{
    FreshnessState, SessionGrantIntrospectGrant as SessionGrantIntrospectionGrant,
    SessionGrantIntrospectOutcome as SessionGrantIntrospectionOutcome,
    SessionGrantIntrospectRequestBody as SessionGrantIntrospectionRequestBody,
    SessionGrantIntrospectStatus as SessionGrantIntrospectionStatus,
    SessionGrantIntrospectionProof, SessionGrantProofKind,
};
use salvo::prelude::*;
use sha2::Digest as _;
use ulid::Ulid;

use super::*;
use crate::handlers::cokret::*;

fn introspection_grant_record(grant: &SessionGrant) -> SessionGrantIntrospectionGrant {
    // `cnf.jkt` is not stored as its own column — it lives inside the signed
    // grant payload. Parse it back out of the persisted `grant_jwt` (the same
    // way the refresh / logout paths read the prior grant's binding). A grant
    // minted without DPoP binding has no `cnf`, so this stays `None`.
    let parsed_payload = Jwt::<SessionGrantPayload>::try_from(grant.grant_jwt.as_str())
        .ok()
        .map(|jwt| jwt.payload().clone());
    let cnf_jkt = parsed_payload
        .as_ref()
        .and_then(|payload| payload.cnf.as_ref().map(|cnf| cnf.jkt.clone()));
    SessionGrantIntrospectionGrant {
        id: grant.id.to_string(),
        issuer: grant.issuer.clone(),
        subject: grant.subject.clone(),
        service_account_id: grant.subject.rsplit_once(":users:").map_or_else(
            || grant.browser_session_id.to_string(),
            |(_, id)| id.to_owned(),
        ),
        device_id: grant.device_id.clone(),
        audience: grant.audience.clone(),
        scopes: grant
            .scope
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
        expires_at: grant.expires_at,
        revoked_at: grant.revoked_at,
        revocation_ref: format!("ck:session:{}", grant.browser_session_id),
        session_public_key: grant.session_public_key.clone(),
        cnf_jkt,
        proof_kind: parsed_payload
            .as_ref()
            .and_then(|payload| payload.proof_kind),
        scope_details: parsed_payload
            .as_ref()
            .map(|payload| payload.scope_details.clone())
            .unwrap_or(serde_json::Value::Null),
        freshness_state: None,
    }
}

fn stateless_agent_introspection(
    grant_jwt: &str,
    key_store: &coauth_keystore::Keystore,
    audience: Option<&str>,
    now: DateTime<Utc>,
) -> Option<SessionGrantIntrospectionOutcome> {
    let jwt = Jwt::<SessionGrantPayload>::try_from(grant_jwt).ok()?;
    if jwt.verify_with_jwks(&key_store.public_jwks()).is_err() {
        return None;
    }
    let payload = jwt.payload();
    if payload.proof_kind != Some(SessionGrantProofKind::AgentKeyProof) {
        return None;
    }
    if audience.is_some_and(|audience| audience != payload.audience) {
        return Some(SessionGrantIntrospectionOutcome {
            active: false,
            status: SessionGrantIntrospectionStatus::AudienceMismatch,
            proof_required: false,
            one_time_use_consumed: false,
            grant: None,
        });
    }

    let status = if payload.expires_at <= now {
        SessionGrantIntrospectionStatus::Expired
    } else {
        SessionGrantIntrospectionStatus::Active
    };
    let active = status == SessionGrantIntrospectionStatus::Active;
    let grant = (status != SessionGrantIntrospectionStatus::AudienceMismatch).then(|| {
        SessionGrantIntrospectionGrant {
            id: session_grant_jwt_hash(grant_jwt),
            issuer: payload.issuer.clone(),
            subject: payload.subject.clone(),
            service_account_id: payload.service_account_id.clone(),
            device_id: payload.device_id.clone(),
            audience: payload.audience.clone(),
            scopes: payload.scopes.clone(),
            expires_at: payload.expires_at,
            revoked_at: None,
            revocation_ref: payload.revocation_ref.clone(),
            session_public_key: payload.session_public_key.clone(),
            cnf_jkt: payload.cnf.as_ref().map(|cnf| cnf.jkt.clone()),
            proof_kind: payload.proof_kind,
            scope_details: payload.scope_details.clone(),
            freshness_state: active.then_some(FreshnessState::Fresh),
        }
    });

    Some(SessionGrantIntrospectionOutcome {
        active,
        status,
        proof_required: false,
        one_time_use_consumed: false,
        grant,
    })
}

pub(crate) fn introspection_status(
    grant: &SessionGrant,
    user: Option<&User>,
    now: DateTime<Utc>,
    audience: Option<&str>,
) -> SessionGrantIntrospectionStatus {
    if audience.is_some_and(|audience| audience != grant.audience) {
        return SessionGrantIntrospectionStatus::AudienceMismatch;
    }

    if grant.revoked_at.is_some() {
        return SessionGrantIntrospectionStatus::Revoked;
    }

    if grant.expires_at <= now {
        return SessionGrantIntrospectionStatus::Expired;
    }

    if let Some(user) = user {
        if user.locked_at.is_some() {
            return SessionGrantIntrospectionStatus::Locked;
        }

        if user.deactivated_at.is_some() {
            return SessionGrantIntrospectionStatus::Suspended;
        }
    }

    SessionGrantIntrospectionStatus::Active
}

pub(crate) fn session_grant_jwt_hash(grant_jwt: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(grant_jwt.as_bytes()))
    )
}

fn verify_session_grant_introspection_proof(
    grant: &SessionGrant,
    proof: Option<&SessionGrantIntrospectionProof>,
    now: DateTime<Utc>,
) -> SessionGrantIntrospectionStatus {
    let Some(proof) = proof else {
        return SessionGrantIntrospectionStatus::ProofRequired;
    };
    if proof.challenge.trim().is_empty() || proof.proof_jwt.trim().is_empty() {
        return SessionGrantIntrospectionStatus::InvalidProof;
    }

    let Ok(jwt) = Jwt::<SessionGrantIntrospectionProofClaims>::try_from(proof.proof_jwt.as_str())
    else {
        return SessionGrantIntrospectionStatus::InvalidProof;
    };
    let Ok(public_key) = serde_json::from_str::<PublicJsonWebKey>(&grant.session_public_key) else {
        return SessionGrantIntrospectionStatus::InvalidProof;
    };
    let jwks = PublicJsonWebKeySet::new(vec![public_key]);
    if jwt.verify_with_jwks(&jwks).is_err() {
        return SessionGrantIntrospectionStatus::InvalidProof;
    }

    let claims = jwt.payload();
    let max_future_skew = Duration::try_seconds(30).unwrap();
    if claims.kind != "ck.session_grant.introspection_proof.v1"
        || claims.grant_id != grant.id.to_string()
        || claims.grant_jwt_hash != session_grant_jwt_hash(&grant.grant_jwt)
        || claims.audience != grant.audience
        || claims.challenge != proof.challenge
        || claims.expires_at <= now
        || claims.issued_at > now + max_future_skew
    {
        return SessionGrantIntrospectionStatus::InvalidProof;
    }

    SessionGrantIntrospectionStatus::Active
}

#[handler]
pub async fn introspect_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantIntrospectionOutcome>, CokretRouteError> {
    let body: SessionGrantIntrospectionRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;

    // Exactly one of `id` / `grant_jwt` identifies the grant. Reject both
    // missing AND both present, rather than silently preferring `id` and
    // ignoring `grant_jwt` — an ambiguous selector should be a hard error so a
    // caller never believes it introspected the JWT it sent.
    // The body parsed fine; it just fails the `oneOf` selector constraint, so
    // this is a schema_violation (not bad_json, which means unparseable JSON).
    match (body.id.is_some(), body.grant_jwt.is_some()) {
        (false, false) => {
            return Err(CokretRouteError::coded(
                StatusCode::BAD_REQUEST,
                ERROR_CODE_SCHEMA_VIOLATION,
                "exactly one of id or grant_jwt is required",
            ));
        }
        (true, true) => {
            return Err(CokretRouteError::coded(
                StatusCode::BAD_REQUEST,
                ERROR_CODE_SCHEMA_VIOLATION,
                "id and grant_jwt are mutually exclusive",
            ));
        }
        _ => {}
    }

    let _ = require_session_grant_caller(req, depot).await?;
    let clock = crate::handlers::make_clock();
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let mut repo = depot.repo().await?;

    let grant = if let Some(id) = body.id.as_deref() {
        let id = Ulid::from_string(id)
            .map_err(|_| CokretRouteError::BadRequest("invalid session grant id".into()))?;
        repo.oauth_session_grant()
            .lookup(id)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    } else if let Some(grant_jwt) = body.grant_jwt.as_deref() {
        repo.oauth_session_grant()
            .lookup_by_grant_jwt(grant_jwt)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    } else {
        None
    };

    let Some(grant) = grant else {
        if let Some(grant_jwt) = body.grant_jwt.as_deref()
            && let Some(outcome) = stateless_agent_introspection(
                grant_jwt,
                &key_store,
                body.audience.as_deref(),
                clock.now(),
            )
        {
            repo.cancel()
                .await
                .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
            return Ok(Json(outcome));
        }
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Ok(Json(SessionGrantIntrospectionOutcome {
            active: false,
            status: SessionGrantIntrospectionStatus::NotFound,
            proof_required: true,
            one_time_use_consumed: false,
            grant: None,
        }));
    };

    let user = if let Some(user_id) =
        parse_local_user_did_for(&url_builder, &cokret_config, &grant.subject)
    {
        repo.user()
            .lookup(user_id)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    } else {
        None
    };
    let mut status =
        introspection_status(&grant, user.as_ref(), clock.now(), body.audience.as_deref());
    let proof_required = status == SessionGrantIntrospectionStatus::Active;
    if proof_required {
        status = verify_session_grant_introspection_proof(&grant, body.proof.as_ref(), clock.now());
    }
    let mut active = status == SessionGrantIntrospectionStatus::Active;

    // The grant's authentication context (browser session) being logged out
    // MUST make the grant read inactive here, even if this grant row was not
    // individually revoked — otherwise a grant rotated out just before logout
    // could keep introspecting `active` until self-expiry. Auth Server fail
    // closed per account-lifecycle §4.1.
    if active {
        let logged_out = repo
            .browser_session()
            .lookup(grant.browser_session_id)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
            .map_or(true, |session| session.finished_at.is_some());
        if logged_out {
            status = SessionGrantIntrospectionStatus::Revoked;
            active = false;
        }
    }

    let grant_record = (status != SessionGrantIntrospectionStatus::NotFound
        && status != SessionGrantIntrospectionStatus::AudienceMismatch)
        .then(|| introspection_grant_record(&grant));

    // Introspection is READ-ONLY. The session grant is the (minutes-to-hours,
    // multi-day-via-rotation) refresh credential: the legitimate device
    // re-exchanges it for fresh short bearers, each presenting a fresh holder
    // proof, so it MUST remain valid within its TTL. Consumption/rotation is the
    // `session-grants/refresh` endpoint's job (revoke-old + issue-new), NOT
    // introspection's — revoking here made the grant single-use at the first
    // Principal Server exchange and silently broke the refresh chain.
    repo.cancel()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantIntrospectionOutcome {
        active,
        status,
        proof_required,
        one_time_use_consumed: false,
        grant: grant_record,
    }))
}
