//! Current qualification for byte-exact issuer outcome delivery, never new issuance.
use chrono::{DateTime, Utc};
use coauth_data::user::PrincipalDidRepository as _;
use coauth_data::{RepositoryAccess as _, SessionGrant};
use salvo::prelude::*;

use super::acquire_private_current_device_admission;
use crate::handlers::arkret::*;

pub(crate) fn require_outer_dpop_fresh(
    valid_through: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ArkretRouteError> {
    crate::services::dpop::require_proof_fresh_at(valid_through, now).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            error.to_string(),
        )
    })
}

pub(crate) fn require_current_authority_fresh(
    deadline: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ArkretRouteError> {
    if now >= deadline {
        return Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            "current qualification expired before outcome delivery; retry the identical request",
        ));
    }
    Ok(())
}

pub(crate) fn current_agent_key_expiry(
    view: &arkret_models_collaboration::agent_operations::AgentView,
) -> Result<Option<DateTime<Utc>>, ArkretRouteError> {
    view.key_state
        .as_ref()
        .and_then(|state| state.current_key_authorization.as_ref())
        .and_then(|source| source.reducer_input())
        .and_then(|event| {
            arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
                event,
            )
            .ok()
        })
        .map(|key| key.expires_at)
        .ok_or_else(|| {
            ArkretRouteError::Unauthorized("current Agent runtime-key source is unavailable".into())
        })
}

/// Upper bound of this request's real current qualification, not a portable
/// permission. A caller with later blocking locks must recheck this deadline.
pub(crate) async fn acquire_current_replay_authority(
    depot: &Depot,
    grant: &SessionGrant,
    holder_jkt: &str,
    intent_digest: arkret_wire::Hash,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, ArkretRouteError> {
    let mut valid_until = grant.expires_at;
    let config = depot.arkret_config()?;
    if grant.issuer_id != crate::services::station_trust::owning_station_id_for(&config)
        || grant.metadata.cnf_jkt != holder_jkt
        || grant.metadata.not_before > now
    {
        return Err(ArkretRouteError::Unauthorized(
            "replay holder or issuer mismatch".into(),
        ));
    }
    grant.metadata.validate()?;
    let mut repo = depot.read_repo().await?;
    let local_id = grant.local_account_id.as_str().parse().map_err(|_| {
        ArkretRouteError::Unauthorized("invalid issuer-local account binding".into())
    })?;
    let user =
        repo.user().lookup(local_id).await?.ok_or_else(|| {
            ArkretRouteError::Unauthorized("replay account is unavailable".into())
        })?;
    use arkret_models_collaboration::objects::account_status::AccountStatus;
    let allowed = user.status == AccountStatus::Active;
    if !allowed {
        return Err(ArkretRouteError::coded(
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "current account lifecycle forbids outcome delivery",
        ));
    }
    if let Some(session_id) = grant.browser_session_id {
        let session = repo
            .browser_session()
            .lookup(session_id)
            .await?
            .ok_or_else(|| {
                ArkretRouteError::Unauthorized("replay browser session is unavailable".into())
            })?;
        if session.user.id != user.id || session.finished_at.is_some() {
            return Err(ArkretRouteError::Unauthorized(
                "replay browser session has ended".into(),
            ));
        }
    }
    let controller = grant
        .metadata
        .scope_details
        .as_ref()
        .map(|scope| &scope.controller_principal_id);
    let principal = controller.unwrap_or(&grant.metadata.account_id.principal_id);
    let binding = repo
        .principal_did()
        .get_for_user_and_audience(&user, grant.audience_id.as_str())
        .await?
        .filter(|binding| {
            &binding.principal_id == principal
                && binding.account_id.station_id == grant.metadata.account_id.station_id
        })
        .ok_or_else(|| ArkretRouteError::Unauthorized("replay principal binding changed".into()))?;
    if controller.is_none() && binding.account_id != grant.metadata.account_id {
        return Err(ArkretRouteError::Unauthorized(
            "replay full Account changed".into(),
        ));
    }
    repo.cancel().await?;
    match &grant.metadata.holder_binding {
        arkret_models_identity::SessionGrantHolderBinding::HumanDevice { .. } => {
            let expected = grant.metadata.device_binding.as_ref().ok_or_else(|| {
                ArkretRouteError::Unauthorized("replay has no accepted device binding".into())
            })?;
            let current = acquire_private_current_device_admission(
                depot,
                &grant.metadata.account_id,
                expected.device_id.clone(),
                arkret_wire::DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
                Some(expected),
                None,
                intent_digest,
                now,
            )
            .await?;
            valid_until = valid_until.min(current.expires_at());
            if &current.binding != expected {
                return Err(ArkretRouteError::Unauthorized(
                    "replay device generation changed".into(),
                ));
            }
        }
        arkret_models_identity::SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            agent_key_authorization_ref,
            verification_method,
        } => {
            let http_client = depot.http_client()?;
            let keyring = depot.keyring()?;
            let view = crate::handlers::account::agents::enforce_authoritative_agent_lifecycle(
                &http_client,
                &config,
                &keyring,
                agent_id.as_str(),
            )
            .await
            .map_err(|rejection| {
                ArkretRouteError::coded(rejection.http_status(), rejection.code(), rejection.code())
            })?;
            let key_expiry = current_agent_key_expiry(&view)?;
            if key_expiry.is_some_and(|expiry| expiry <= now) {
                return Err(ArkretRouteError::Unauthorized(
                    "replay Agent runtime key has expired".into(),
                ));
            }
            if let Some(expiry) = key_expiry {
                valid_until = valid_until.min(expiry);
            }
            let mut repo = depot.read_repo().await?;
            let retained = crate::handlers::account::agents::resolve_retained_agent_pairing(
                &mut repo,
                &view,
                agent_key_authorization_ref.as_str(),
                agent_id.as_str(),
                verification_method.as_str(),
            )
            .await
            .map_err(|error| {
                ArkretRouteError::coded(error.http_status(), error.code(), error.code())
            })?;
            crate::handlers::account::agents::validate_authoritative_agent_session_evidence(
                &retained,
                &view,
                &grant.metadata.scopes,
                &depot.encrypter()?,
                &config,
                now,
            )
            .map_err(|error| {
                ArkretRouteError::coded(error.http_status(), error.code(), error.code())
            })?;
            repo.cancel().await?;
            let scope = grant.metadata.scope_details.as_ref().ok_or_else(|| {
                ArkretRouteError::Unauthorized("replay Agent scope is missing".into())
            })?;
            let scope = serde_json::to_value(scope)?
                .as_object()
                .cloned()
                .ok_or_else(|| {
                    ArkretRouteError::Unauthorized("replay Agent scope is invalid".into())
                })?;
            crate::handlers::account::agents::revalidate_content_session_scope(
                &http_client,
                &config,
                &view,
                &grant.metadata.scopes,
                &scope,
                intent_digest,
            )
            .await
            .map_err(|rejection| {
                ArkretRouteError::coded(rejection.http_status(), rejection.code(), rejection.code())
            })?;
        }
        arkret_models_identity::SessionGrantHolderBinding::RecoveryCandidateDevice { .. } => {}
    }
    // Re-read issuer lifecycle after network qualification. No repository is held
    // across another repository acquisition, including a deployment pool of one.
    let mut repo = depot.read_repo().await?;
    let current = repo
        .oauth_session_grant()
        .lookup_by_grant_id(&grant.issuer_id, &grant.grant_id)
        .await?
        .ok_or_else(|| ArkretRouteError::Unauthorized("replay issuer record disappeared".into()))?;
    let checked_at = crate::handlers::make_clock().now();
    if checked_at >= current.expires_at {
        return Err(ArkretRouteError::session_grant_replay_expired(
            current.grant_id,
        ));
    }
    if let Some(state) = super::replay_terminal_state(current.lifecycle_state) {
        return Err(ArkretRouteError::session_grant_replay_terminal(
            current.grant_id,
            state,
        ));
    }
    if current.session_grant != grant.session_grant || current.metadata != grant.metadata {
        return Err(ArkretRouteError::Unauthorized(
            "immutable replay issuer record changed".into(),
        ));
    }
    repo.cancel().await?;
    require_current_authority_fresh(valid_until, checked_at)?;
    Ok(valid_until)
}
