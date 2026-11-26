use arkret_identifiers::DidCoreId;
use arkret_models_collaboration::session_grants::{
    SessionGrantHolderProof, SessionGrantHolderProofClaims, SessionGrantValidationInput,
    SessionGrantValidationMetadata, SessionGrantValidationResponseBody,
};
use arkret_models_identity::SessionGrantAdminIntrospectionStatus;
use chrono::{DateTime, Utc};
use coauth_data::user::PrincipalDidRepository as _;
use coauth_data::{BrowserSession, SessionGrant, User};
use coauth_jose::jwk::{PublicJsonWebKey, PublicJsonWebKeySet};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

use crate::handlers::arkret::*;

fn introspection_grant_record(
    grant: &SessionGrant,
    _browser_session: Option<&BrowserSession>,
) -> Result<SessionGrantValidationMetadata, ArkretRouteError> {
    let revocation_ref = grant.browser_session_id.map_or_else(
        || {
            format!(
                "org.arkret.coauth.session_grant:{}:{}",
                grant.issuer_id, grant.grant_id
            )
        },
        |id| format!("org.arkret.coauth.browser_session:{id}"),
    );
    let record = SessionGrantValidationMetadata {
        metadata: grant.metadata.clone(),
        revoked_at: grant.revoked_at,
        revocation_ref,
    };
    record.validate().map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "stored session grant introspection projection is invalid: {error}"
        )))
    })?;
    Ok(record)
}

pub(crate) fn introspection_status(
    grant: &SessionGrant,
    user: Option<&User>,
    now: DateTime<Utc>,
    audience_id: Option<&str>,
) -> SessionGrantAdminIntrospectionStatus {
    if audience_id.is_some_and(|audience_id| audience_id != grant.audience_id.as_str()) {
        return SessionGrantAdminIntrospectionStatus::AudienceMismatch;
    }

    match grant.lifecycle_state {
        coauth_data::SessionGrantLifecycleState::Revoked => {
            return SessionGrantAdminIntrospectionStatus::Revoked;
        }
        coauth_data::SessionGrantLifecycleState::Superseded => {
            return SessionGrantAdminIntrospectionStatus::Superseded;
        }
        coauth_data::SessionGrantLifecycleState::Active => {}
    }

    if now < grant.metadata.not_before {
        return SessionGrantAdminIntrospectionStatus::InvalidProof;
    }
    if grant.expires_at <= now {
        return SessionGrantAdminIntrospectionStatus::Expired;
    }

    if let Some(user) = user {
        if user.locked_at.is_some() {
            return SessionGrantAdminIntrospectionStatus::Locked;
        }

        if user.deactivated_at.is_some() {
            return SessionGrantAdminIntrospectionStatus::Suspended;
        }
        use arkret_models_collaboration::objects::account_status::AccountStatus;
        match user.status {
            AccountStatus::Active => {}
            AccountStatus::Locked => return SessionGrantAdminIntrospectionStatus::Locked,
            AccountStatus::SoftLoggedOut => return SessionGrantAdminIntrospectionStatus::Revoked,
            AccountStatus::Suspended
            | AccountStatus::Deactivated
            | AccountStatus::ErasurePending => {
                return SessionGrantAdminIntrospectionStatus::Suspended;
            }
        }
    }

    SessionGrantAdminIntrospectionStatus::Active
}

fn verify_session_grant_introspection_proof(
    grant: &SessionGrant,
    proof: &SessionGrantHolderProof,
    now: DateTime<Utc>,
) -> SessionGrantAdminIntrospectionStatus {
    if proof.challenge.trim().is_empty() || proof.proof_jwt.trim().is_empty() {
        return SessionGrantAdminIntrospectionStatus::InvalidProof;
    }

    let Ok(jwt) = Jwt::<SessionGrantHolderProofClaims>::try_from(proof.proof_jwt.as_str()) else {
        return SessionGrantAdminIntrospectionStatus::InvalidProof;
    };
    let Ok(public_key) = serde_json::from_str::<PublicJsonWebKey>(&grant.session_public_key) else {
        return SessionGrantAdminIntrospectionStatus::InvalidProof;
    };
    let jwks = PublicJsonWebKeySet::new(vec![public_key]);
    if jwt.verify_with_jwks(&jwks).is_err() {
        return SessionGrantAdminIntrospectionStatus::InvalidProof;
    }

    if jwt
        .payload()
        .validate_binding(
            &grant.metadata.grant_ref(),
            &grant.session_grant,
            &grant.audience_id,
            &proof.challenge,
            now,
        )
        .is_err()
    {
        return SessionGrantAdminIntrospectionStatus::InvalidProof;
    }

    SessionGrantAdminIntrospectionStatus::Active
}

#[handler]
pub async fn introspect_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantValidationResponseBody>, ArkretRouteError> {
    // `json_invalid` (400) means the bytes are not JSON; a body that parses but
    // breaks the request contract — such as carrying both selectors, or
    // neither — is `schema_violation` (422). Deserializing straight into the
    // typed body would collapse both onto `json_invalid`.
    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    let body: SessionGrantValidationInput = serde_json::from_value(raw_body).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            error.to_string(),
        )
    })?;

    let caller = require_session_grant_caller(req, depot, true).await?;
    let clock = crate::handlers::make_clock();
    let arkret_config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let keyring = depot.keyring()?;
    let mut repo = depot.read_repo().await?;

    let issuer_id = crate::services::station_trust::owning_station_id_for(&arkret_config);
    let (grant, requested_audience, presented_proof) = match body {
        SessionGrantValidationInput::ById(body) => (
            repo.oauth_session_grant()
                .lookup_by_grant_id(&issuer_id, &body.id)
                .await?,
            body.audience_id,
            body.proof,
        ),
        SessionGrantValidationInput::BySecret(body) => (
            repo.oauth_session_grant()
                .lookup_by_secret(&issuer_id, &body.session_grant)
                .await?,
            Some(body.audience_id),
            body.proof,
        ),
    };

    let Some(grant) = grant else {
        repo.cancel().await?;
        return Ok(Json(SessionGrantValidationResponseBody {
            active: false,
            status: SessionGrantAdminIntrospectionStatus::NotFound,
            proof_required: false,
            one_time_use_consumed: false,
            grant: None,
        }));
    };

    // SEC-SG-ENUM: a Station caller may only introspect grants for an
    // audience_id it is authorized for. A grant minted for any other audience_id is
    // reported as an audience_id mismatch (with no grant metadata) so a Station
    // cannot probe grants belonging to other audiences.
    if let Some(allowed) = caller.allowed_audiences.as_deref()
        && !allowed
            .iter()
            .any(|audience_id| audience_id == grant.audience_id.as_str())
    {
        repo.cancel().await?;
        return Ok(Json(SessionGrantValidationResponseBody {
            active: false,
            status: SessionGrantAdminIntrospectionStatus::AudienceMismatch,
            proof_required: false,
            one_time_use_consumed: false,
            grant: None,
        }));
    }

    let browser_session = if let Some(browser_session_id) = grant.browser_session_id {
        repo.browser_session().lookup(browser_session_id).await?
    } else {
        None
    };

    let controller = grant
        .metadata
        .scope_details
        .as_ref()
        .map(|scope| &scope.controller_principal_id);
    let bound_principal = controller.unwrap_or(&grant.subject_id);
    let principal_binding = repo
        .principal_did()
        .get_by_principal_id_and_audience(bound_principal.as_str(), grant.audience_id.as_str())
        .await?;
    let binding_matches = principal_binding.as_ref().is_some_and(|binding| {
        binding.principal_id == *bound_principal
            && binding.account_id.station_id == grant.metadata.account_id.station_id
            && (controller.is_some() || binding.account_id == grant.metadata.account_id)
            && binding.user_id.to_string() == grant.local_account_id.as_str()
    });
    let user = if let Some(binding) = principal_binding.as_ref().filter(|_| binding_matches) {
        repo.user().lookup(binding.user_id).await?
    } else {
        None
    };
    let mut status = introspection_status(
        &grant,
        user.as_ref(),
        clock.now(),
        requested_audience.as_ref().map(DidCoreId::as_str),
    );
    if !binding_matches || user.is_none() {
        status = SessionGrantAdminIntrospectionStatus::Revoked;
    }
    let proof_required = false;
    // Without a presented proof the resource server checks the actual request
    // DPoP independently against the authenticated issuer's key binding.
    if status == SessionGrantAdminIntrospectionStatus::Active
        && let Some(proof) = presented_proof.as_ref()
    {
        status = verify_session_grant_introspection_proof(&grant, proof, clock.now());
    }
    let mut active = status == SessionGrantAdminIntrospectionStatus::Active;

    // The grant's authentication context (browser session) being logged out
    // MUST make the grant read inactive here, even if this grant row was not
    // individually revoked — otherwise a grant rotated out just before logout
    // could keep introspecting `active` until self-expiry. Account Authority fail
    // closed per account-lifecycle §4.1.
    if active && grant.browser_session_id.is_some() {
        let logged_out = browser_session
            .as_ref()
            .is_none_or(|session| session.finished_at.is_some());
        if logged_out {
            status = SessionGrantAdminIntrospectionStatus::Revoked;
            active = false;
        }
    }

    // Agent session use-time gate (key-management §3.6.1): a grant issued
    // from an agent key MUST fail closed once that key authorization is
    // revoked (pause / deactivate / runtime replacement supersede) — it MUST
    // NOT live out its natural TTL. Introspection is the per-request use-time
    // check, so the revocation freshness window collapses to one lookup. The
    // issuing authorization ref belongs to the immutable issuer record's
    // `scope_details`; an agent grant without it (or whose authorization row
    // is gone) fails closed too.
    if active {
        let payload = &grant.metadata;
        let is_agent_grant = payload.proof_kind
            == Some(arkret_models_identity::SessionGrantProofKind::AgentKeyProof);
        if is_agent_grant {
            let current_view =
                crate::handlers::account::agents::enforce_authoritative_agent_lifecycle(
                    &http_client,
                    &arkret_config,
                    &keyring,
                    grant.subject_id.as_str(),
                )
                .await
                .ok();
            let authorization_ref = payload
                .scope_details
                .as_ref()
                .map(|scope| scope.agent_key_authorization_ref.as_str());
            let mut key_alive = false;
            if let (Some(view), Some(reference)) = (current_view.as_ref(), authorization_ref)
                && let Some(method) = view
                    .key_state
                    .as_ref()
                    .and_then(|state| state.authorized_verification_method.as_ref())
                && let Ok(retained) =
                    crate::handlers::account::agents::resolve_retained_agent_pairing(
                        &mut repo,
                        view,
                        reference,
                        grant.subject_id.as_str(),
                        method.as_str(),
                    )
                    .await
            {
                key_alive = crate::handlers::account::agents::validate_authoritative_agent_session_evidence(
                            &retained,view,&payload.scopes,&depot.encrypter()?,&arkret_config,clock.now(),
                        ).is_ok() && view.key_state.as_ref().and_then(|state| state.current_key_authorization.as_ref()).and_then(|source| source.reducer_input()).and_then(|event| {
                            arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(event).ok()
                        }).is_some_and(|current| current.expires_at.is_none_or(|expiry| expiry > clock.now()));
            }
            if !key_alive {
                status = SessionGrantAdminIntrospectionStatus::Revoked;
                active = false;
            }
        }
    }

    // Non-secret grant metadata (account / device / audience / scopes /
    // expiry / session_public_key / cnf_jkt) is returned over this authenticated
    // S2S channel so the Station can bind the request DPoP to `cnf_jkt`.
    // NotFound and AudienceMismatch withhold metadata.
    let grant_record = (status != SessionGrantAdminIntrospectionStatus::NotFound
        && status != SessionGrantAdminIntrospectionStatus::AudienceMismatch)
        .then(|| introspection_grant_record(&grant, browser_session.as_ref()))
        .transpose()?;

    // Exact issuer lookup is read-only; only the atomic refresh endpoint supersedes a predecessor.
    repo.cancel().await?;

    Ok(Json(SessionGrantValidationResponseBody {
        active,
        status,
        proof_required,
        one_time_use_consumed: false,
        grant: grant_record,
    }))
}
