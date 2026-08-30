use arkret_identifiers::{DeviceId, DidCoreId};
use arkret_models_collaboration::session_grant_bodies::{
    SESSION_GRANT_INTROSPECTION_PROOF_CLAIMS_KIND, SessionGrantIntrospectGrant,
    SessionGrantIntrospectOutcome, SessionGrantIntrospectRequestBody, SessionGrantIntrospectStatus,
    SessionGrantIntrospectionProof, SessionGrantIntrospectionProofClaims,
};
use chrono::{DateTime, Duration, Utc};
use coauth_data::user::PrincipalDidRepository as _;
use coauth_data::{BrowserSession, SessionGrant, User};
use coauth_jose::jwk::{PublicJsonWebKey, PublicJsonWebKeySet};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

use super::*;
use crate::handlers::arkret::*;

fn introspection_grant_record(
    grant: &SessionGrant,
    _browser_session: Option<&BrowserSession>,
) -> Result<SessionGrantIntrospectGrant, ArkretRouteError> {
    // The thumbprint is derived from the signed session_public_key; it is not
    // duplicated as an independently authorable claim or database column.
    let parsed_jwt = Jwt::<SignedSessionGrantClaims>::try_from(grant.grant_jwt.as_str())
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    parsed_jwt.payload().validate().map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "stored session grant claims are invalid: {error}"
        )))
    })?;
    let parsed_payload = parsed_jwt.payload().clone();
    let cnf_jkt = parsed_payload
        .session_public_key
        .thumbprint_sha256()
        .map_err(|error| {
            ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "stored session public key is invalid: {error}"
            )))
        })?;
    let service_account_id = grant.service_account_id.clone();
    let revocation_ref = grant.browser_session_id.map_or_else(
        || format!("org.arkret.coauth.session_grant:{}", grant.grant_id),
        |id| format!("org.arkret.coauth.browser_session:{id}"),
    );
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
    let audience_id = grant.audience_id.clone();

    Ok(SessionGrantIntrospectGrant {
        id: grant.grant_id.clone(),
        issuer_id: grant.issuer_id.clone(),
        subject_id: parsed_payload.subject_id,
        service_account_id,
        device_id,
        device_binding: parsed_payload.device_binding,
        audience_id,
        scopes: grant
            .scope
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
        expires_at: grant.expires_at,
        revoked_at: grant.revoked_at,
        revocation_ref,
        session_public_key: arkret_models_identity::CanonicalSessionPublicJwk::new(
            &grant.session_public_key,
        )
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        cnf_jkt,
        credential_class: parsed_payload.credential_class,
        holder_binding: parsed_payload.holder_binding,
    })
}

pub(crate) fn introspection_status(
    grant: &SessionGrant,
    user: Option<&User>,
    now: DateTime<Utc>,
    audience_id: Option<&str>,
) -> SessionGrantIntrospectStatus {
    if audience_id.is_some_and(|audience_id| audience_id != grant.audience_id.as_str()) {
        return SessionGrantIntrospectStatus::AudienceMismatch;
    }

    match grant.lifecycle_state {
        coauth_data::SessionGrantLifecycleState::Revoked => {
            return SessionGrantIntrospectStatus::Revoked;
        }
        coauth_data::SessionGrantLifecycleState::Superseded => {
            return SessionGrantIntrospectStatus::Superseded;
        }
        coauth_data::SessionGrantLifecycleState::Active => {}
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

pub(crate) fn session_grant_jwt_digest(grant_jwt: &str) -> String {
    arkret_canonical::sha256_digest(grant_jwt.as_bytes())
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
    if claims.kind != SESSION_GRANT_INTROSPECTION_PROOF_CLAIMS_KIND
        || claims.session_grant_id != grant.grant_id.to_string()
        || claims.grant_jwt_digest != session_grant_jwt_digest(&grant.grant_jwt)
        || claims.audience_id != grant.audience_id
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
    // `json_invalid` (400) means the bytes are not JSON; a body that parses but
    // breaks the request contract — such as carrying both selectors, or
    // neither — is `schema_violation` (422). Deserializing straight into the
    // typed body would collapse both onto `json_invalid`.
    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    let body: SessionGrantIntrospectRequestBody =
        serde_json::from_value(raw_body).map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::UNPROCESSABLE_ENTITY,
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                error.to_string(),
            )
        })?;

    let caller = require_session_grant_caller(req, depot).await?;
    let clock = crate::handlers::make_clock();
    let arkret_config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let mut repo = depot.repo().await?;

    let (grant, requested_audience, presented_proof) = match body {
        SessionGrantIntrospectRequestBody::ById(body) => (
            repo.oauth_session_grant()
                .lookup_by_grant_id(&body.id)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
            body.audience_id,
            body.proof,
        ),
        SessionGrantIntrospectRequestBody::ByJwt(body) => (
            repo.oauth_session_grant()
                .lookup_by_grant_jwt(&body.grant_jwt)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
            body.audience_id,
            body.proof,
        ),
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

    // SEC-SG-ENUM: a Station caller may only introspect grants for an
    // audience_id it is authorized for. A grant minted for any other audience_id is
    // reported as an audience_id mismatch (with no grant metadata) so a Principal
    // Server cannot probe grants belonging to other audiences.
    if let Some(allowed) = caller.allowed_audiences.as_deref()
        && !allowed
            .iter()
            .any(|audience_id| audience_id == grant.audience_id.as_str())
    {
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

    let browser_session = if let Some(browser_session_id) = grant.browser_session_id {
        repo.browser_session()
            .lookup(browser_session_id)
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    } else {
        None
    };

    let bound_user_id = if browser_session.is_none() {
        let mut principal_ids = repo.principal_did();
        principal_ids
            .get_by_principal_id_and_audience(grant.subject_id.as_str(), grant.audience_id.as_str())
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
            .map(|binding| binding.user_id)
    } else {
        None
    };

    let user = if let Some(browser_session) = browser_session.as_ref() {
        Some(browser_session.user.clone())
    } else if let Some(user_id) = bound_user_id {
        repo.user()
            .lookup(user_id)
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    } else {
        None
    };
    let mut status = introspection_status(
        &grant,
        user.as_ref(),
        clock.now(),
        requested_audience.as_ref().map(DidCoreId::as_str),
    );
    let mut proof_required = false;
    if status == SessionGrantIntrospectStatus::Active {
        match presented_proof.as_ref() {
            Some(proof) => {
                status = verify_session_grant_introspection_proof(&grant, proof, clock.now());
            }
            // Every grant is `cnf`-bound and surfaces `proof_required` as an ADVISORY
            // signal: a stricter caller MAY re-introspect with a device-signed
            // grant-binding proof. But per `service-operation-dtos.schema.json`, the
            // default Station grant+DPoP path does NOT require this
            // client-carried introspection proof — it verifies the request DPoP
            // locally against the returned `cnf_jkt`. So the grant MUST still
            // report active WITH metadata over this authenticated S2S channel;
            // only the advisory flag is raised. (Forcing `active=false` /
            // withholding metadata here broke every Station session:
            // soland never reached its own DPoP check and read "not active".)
            None => {
                proof_required = true;
            }
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
        let parsed_payload = Jwt::<SignedSessionGrantClaims>::try_from(grant.grant_jwt.as_str())
            .ok()
            .map(|jwt| jwt.payload().clone());
        let is_agent_grant = parsed_payload.as_ref().is_some_and(|payload| {
            payload.proof_kind == Some(arkret_models_identity::SessionGrantProofKind::AgentKeyProof)
        });
        if is_agent_grant {
            let lifecycle_alive =
                crate::handlers::account::agents::enforce_authoritative_agent_lifecycle(
                    &http_client,
                    &arkret_config,
                    grant.subject_id.as_str(),
                )
                .await
                .is_ok();
            let authorization_ref = parsed_payload.as_ref().and_then(|payload| {
                payload
                    .scope_details
                    .as_ref()
                    .and_then(|details| details.get("agent_key_authorization_ref"))
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
            let key_alive = lifecycle_alive
                && authorization.as_ref().is_some_and(|authorization| {
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

    // Non-secret grant metadata (subject_id / device_id / audience_id / scopes /
    // expiry / session_public_key / cnf_jkt) is returned over this authenticated
    // S2S channel so the Station can bind the request DPoP to `cnf_jkt`.
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
    // Station exchange and silently broke the refresh chain.
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
