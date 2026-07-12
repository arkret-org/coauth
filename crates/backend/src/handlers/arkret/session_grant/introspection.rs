use arkret_core::error::ERROR_CODE_SCHEMA_VIOLATION;
use arkret_core::{
    DeviceId, SessionGrantIntrospectGrant, SessionGrantIntrospectOutcome,
    SessionGrantIntrospectRequestBody, SessionGrantIntrospectStatus,
    SessionGrantIntrospectionProof,
};
use chrono::{DateTime, Duration, Utc};
use coauth_data::{BrowserSession, SessionGrant, User};
use coauth_jose::jwk::{PublicJsonWebKey, PublicJsonWebKeySet};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;
use sha2::Digest as _;

use super::*;
use crate::handlers::arkret::*;

fn introspection_grant_record(
    grant: &SessionGrant,
    browser_session: Option<&BrowserSession>,
) -> Result<SessionGrantIntrospectGrant, ArkretRouteError> {
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
    let service_account_id = browser_session
        .map(|session| session.user.id.to_string())
        .or_else(|| {
            grant
                .subject
                .rsplit_once(":users:")
                .map(|(_, id)| id.to_owned())
        })
        .or_else(|| grant.browser_session_id.map(|id| id.to_string()))
        .unwrap_or_else(|| grant.subject.clone());
    let revocation_ref = grant
        .browser_session_id
        .map(|id| format!("ak:session:{id}"))
        .unwrap_or_else(|| format!("ak:session-grant:{}", grant.grant_id));
    let scope_details = parsed_payload
        .as_ref()
        .map_or(serde_json::Value::Null, |payload| {
            payload.scope_details.clone()
        });

    let device_id = grant
        .device_id
        .as_ref()
        .map(|device_id| DeviceId::new(device_id.clone()))
        .transpose()
        .map_err(|error| {
            ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "stored session grant device_id is invalid: {error}"
            )))
        })?;

    Ok(SessionGrantIntrospectGrant {
        id: grant.grant_id.clone(),
        issuer: grant.issuer.clone(),
        subject: grant.subject.clone(),
        service_account_id,
        device_id,
        audience: grant.audience.clone(),
        scopes: grant
            .scope
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
        expires_at: grant.expires_at,
        revoked_at: grant.revoked_at,
        revocation_ref,
        session_public_key: grant.session_public_key.clone(),
        cnf_jkt,
        proof_kind: parsed_payload
            .as_ref()
            .and_then(|payload| payload.proof_kind),
        scope_details,
        freshness_state: None,
    })
}

pub(crate) fn introspection_status(
    grant: &SessionGrant,
    user: Option<&User>,
    now: DateTime<Utc>,
    audience: Option<&str>,
) -> SessionGrantIntrospectStatus {
    if audience.is_some_and(|audience| audience != grant.audience) {
        return SessionGrantIntrospectStatus::AudienceMismatch;
    }

    if grant.revoked_at.is_some() {
        return SessionGrantIntrospectStatus::Revoked;
    }

    if grant.expires_at <= now {
        return SessionGrantIntrospectStatus::Expired;
    }

    if let Some(user) = user {
        if user.locked_at.is_some() {
            return SessionGrantIntrospectStatus::Locked;
        }

        if user.deactivated_at.is_some() {
            return SessionGrantIntrospectStatus::Suspended;
        }
    }

    SessionGrantIntrospectStatus::Active
}

pub(crate) fn session_grant_jwt_hash(grant_jwt: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(grant_jwt.as_bytes()))
    )
}

/// Whether the persisted grant carries a grant-binding confirmation key: a `cnf`
/// confirmation claim inside the signed grant payload. A bound grant MUST NOT
/// introspect as usable without a grant-binding DPoP proof; an unbound grant has no
/// grant-bound confirmation key, so its grant-binding proof stays optional.
fn session_grant_has_grant_binding(grant: &SessionGrant) -> bool {
    Jwt::<SessionGrantPayload>::try_from(grant.grant_jwt.as_str())
        .ok()
        .is_some_and(|jwt| jwt.payload().cnf.is_some())
}

fn verify_session_grant_introspection_proof(
    grant: &SessionGrant,
    proof: &SessionGrantIntrospectionProof,
    now: DateTime<Utc>,
) -> SessionGrantIntrospectStatus {
    if proof.challenge.trim().is_empty() || proof.proof_jwt.trim().is_empty() {
        return SessionGrantIntrospectStatus::InvalidProof;
    }

    let Ok(jwt) = Jwt::<SessionGrantIntrospectionProofClaims>::try_from(proof.proof_jwt.as_str())
    else {
        return SessionGrantIntrospectStatus::InvalidProof;
    };
    let Ok(public_key) = serde_json::from_str::<PublicJsonWebKey>(&grant.session_public_key) else {
        return SessionGrantIntrospectStatus::InvalidProof;
    };
    let jwks = PublicJsonWebKeySet::new(vec![public_key]);
    if jwt.verify_with_jwks(&jwks).is_err() {
        return SessionGrantIntrospectStatus::InvalidProof;
    }

    let claims = jwt.payload();
    let max_future_skew = Duration::try_seconds(30).unwrap();
    if claims.kind != "ak.session_grant.introspection_proof.v1"
        || claims.grant_id != grant.grant_id.to_string()
        || claims.grant_jwt_hash != session_grant_jwt_hash(&grant.grant_jwt)
        || claims.audience != grant.audience
        || claims.challenge != proof.challenge
        || claims.expires_at <= now
        || claims.issued_at > now + max_future_skew
    {
        return SessionGrantIntrospectStatus::InvalidProof;
    }

    SessionGrantIntrospectStatus::Active
}

#[handler]
pub async fn introspect_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantIntrospectOutcome>, ArkretRouteError> {
    let body: SessionGrantIntrospectRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;

    // Exactly one of `id` / `grant_jwt` identifies the grant. Reject both
    // missing AND both present, rather than silently preferring `id` and
    // ignoring `grant_jwt` — an ambiguous selector should be a hard error so a
    // caller never believes it introspected the JWT it sent.
    // The body parsed fine; it just fails the `oneOf` selector constraint, so
    // this is a schema_violation (not bad_json, which means unparseable JSON).
    match (body.id.is_some(), body.grant_jwt.is_some()) {
        (false, false) => {
            return Err(ArkretRouteError::coded(
                StatusCode::BAD_REQUEST,
                ERROR_CODE_SCHEMA_VIOLATION,
                "exactly one of id or grant_jwt is required",
            ));
        }
        (true, true) => {
            return Err(ArkretRouteError::coded(
                StatusCode::BAD_REQUEST,
                ERROR_CODE_SCHEMA_VIOLATION,
                "id and grant_jwt are mutually exclusive",
            ));
        }
        _ => {}
    }

    let caller = require_session_grant_caller(req, depot).await?;
    let clock = crate::handlers::make_clock();
    let arkret_config = depot.arkret_config()?;
    let mut repo = depot.repo().await?;

    let grant = if let Some(id) = body.id.as_ref() {
        repo.oauth_session_grant()
            .lookup_by_grant_id(id)
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    } else if let Some(grant_jwt) = body.grant_jwt.as_deref() {
        repo.oauth_session_grant()
            .lookup_by_grant_jwt(grant_jwt)
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    } else {
        None
    };

    let Some(grant) = grant else {
        repo.cancel()
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        return Ok(Json(SessionGrantIntrospectOutcome {
            active: false,
            status: SessionGrantIntrospectStatus::NotFound,
            proof_required: false,
            one_time_use_consumed: false,
            grant: None,
        }));
    };

    // SEC-SG-ENUM: a Principal Server caller may only introspect grants for an
    // audience it is authorized for. A grant minted for any other audience is
    // reported as an audience mismatch (with no grant metadata) so a Principal
    // Server cannot probe grants belonging to other audiences.
    if let Some(allowed) = caller.allowed_audiences.as_deref() {
        if !allowed.iter().any(|audience| audience == &grant.audience) {
            repo.cancel()
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            return Ok(Json(SessionGrantIntrospectOutcome {
                active: false,
                status: SessionGrantIntrospectStatus::AudienceMismatch,
                proof_required: false,
                one_time_use_consumed: false,
                grant: None,
            }));
        }
    }

    let browser_session = if let Some(browser_session_id) = grant.browser_session_id {
        repo.browser_session()
            .lookup(browser_session_id)
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    } else {
        None
    };

    let user = if let Some(browser_session) = browser_session.as_ref() {
        Some(browser_session.user.clone())
    } else if let Some(user_id) = parse_local_user_did_for(&arkret_config, &grant.subject) {
        repo.user()
            .lookup(user_id)
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    } else {
        None
    };
    let mut status =
        introspection_status(&grant, user.as_ref(), clock.now(), body.audience.as_deref());
    let mut proof_required = false;
    if status == SessionGrantIntrospectStatus::Active {
        match body.proof.as_ref() {
            Some(proof) => {
                status = verify_session_grant_introspection_proof(&grant, proof, clock.now());
            }
            // A `cnf`-bound grant surfaces `proof_required` as an ADVISORY
            // signal: a stricter caller MAY re-introspect with a device-signed
            // grant-binding proof. But per `service-operation-dtos.schema.json`, the
            // default Principal Server grant+DPoP path does NOT require this
            // client-carried introspection proof — it verifies the request DPoP
            // locally against the returned `cnf_jkt`. So the grant MUST still
            // report active WITH metadata over this authenticated S2S channel;
            // only the advisory flag is raised. (Forcing `active=false` /
            // withholding metadata here broke every Principal Server session:
            // soland never reached its own DPoP check and read "not active".)
            None if session_grant_has_grant_binding(&grant) => {
                proof_required = true;
            }
            // Unbound grant: the grant-binding proof is genuinely optional.
            None => {}
        }
    }
    let mut active = status == SessionGrantIntrospectStatus::Active;

    // The grant's authentication context (browser session) being logged out
    // MUST make the grant read inactive here, even if this grant row was not
    // individually revoked — otherwise a grant rotated out just before logout
    // could keep introspecting `active` until self-expiry. Auth Server fail
    // closed per account-lifecycle §4.1.
    if active && grant.browser_session_id.is_some() {
        let logged_out = browser_session
            .as_ref()
            .is_none_or(|session| session.finished_at.is_some());
        if logged_out {
            status = SessionGrantIntrospectStatus::Revoked;
            active = false;
        }
    }

    // Agent session use-time gate (key-management §3.6.1): a grant issued
    // from an agent key MUST fail closed once that key authorization is
    // revoked (pause / deactivate / runtime replacement supersede) — it MUST
    // NOT live out its natural TTL. Introspection is the per-request use-time
    // check, so the revocation freshness window collapses to one lookup. The
    // issuing authorization ref rides the signed grant payload's
    // `scope_details`; an agent grant without it (or whose authorization row
    // is gone) fails closed too.
    if active {
        let parsed_payload = Jwt::<SessionGrantPayload>::try_from(grant.grant_jwt.as_str())
            .ok()
            .map(|jwt| jwt.payload().clone());
        let is_agent_grant = parsed_payload.as_ref().is_some_and(|payload| {
            payload.proof_kind == Some(arkret_core::SessionGrantProofKind::AgentKeyProof)
        });
        if is_agent_grant {
            let authorization_ref = parsed_payload.as_ref().and_then(|payload| {
                payload
                    .scope_details
                    .get("agent_key_authorization_ref")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            });
            let authorization = match authorization_ref.as_deref() {
                Some(authorization_ref) => repo
                    .agent_key_authorization()
                    .lookup_by_event_id(authorization_ref)
                    .await
                    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
                None => None,
            };
            let key_alive = authorization.as_ref().is_some_and(|authorization| {
                authorization.revoked_at.is_none()
                    && authorization
                        .expires_at
                        .is_none_or(|expires_at| expires_at > clock.now())
            });
            if !key_alive {
                status = SessionGrantIntrospectStatus::Revoked;
                active = false;
            }
        }
    }

    // Non-secret grant metadata (subject / device_id / audience / scopes /
    // expiry / session_public_key / cnf_jkt) is returned over this authenticated
    // S2S channel so the Principal Server can bind the request DPoP to `cnf_jkt`.
    // Only NotFound / AudienceMismatch withhold it — a `proof_required` advisory
    // does NOT, or the default grant+DPoP path could never obtain the cnf_jkt it
    // must verify against.
    let grant_record = (status != SessionGrantIntrospectStatus::NotFound
        && status != SessionGrantIntrospectStatus::AudienceMismatch)
        .then(|| introspection_grant_record(&grant, browser_session.as_ref()))
        .transpose()?;

    // Introspection is READ-ONLY. The session grant is the (minutes-to-hours,
    // multi-day-via-rotation) refresh credential: the legitimate device
    // re-exchanges it for fresh short bearers, each presenting a fresh grant-binding
    // proof, so it MUST remain valid within its TTL. Consumption/rotation is the
    // `session-grants/refresh` endpoint's job (revoke-old + issue-new), NOT
    // introspection's — revoking here made the grant single-use at the first
    // Principal Server exchange and silently broke the refresh chain.
    repo.cancel()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantIntrospectOutcome {
        active,
        status,
        proof_required,
        one_time_use_consumed: false,
        grant: grant_record,
    }))
}
