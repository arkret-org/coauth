//! Product-face (`/_coauth/account/session-grants`) session-grant admin
//! endpoints: list and revoke. These are NOT `/_arkret` protocol operations
//! (issue / refresh / introspect / logout live in `handlers::arkret`); they
//! reuse the protocol module's caller authorization plumbing only.

use coauth_data::Pagination;
use coauth_data::oauth::SessionGrantFilter;
use salvo::prelude::*;
use serde::Serialize;
use sha2::Digest as _;
use ulid::Ulid;

use crate::handlers::account::DepotExt as _;
use crate::handlers::arkret::{
    ArkretRouteError, SessionGrantAuthz, SessionGrantRecord, require_session_grant_caller,
};

#[derive(Debug, Serialize)]
struct SessionGrantListOutcome {
    grants: Vec<SessionGrantRecord>,
}

#[derive(Debug, Serialize)]
struct SessionGrantRevokeOutcome {
    grant: SessionGrantRecord,
}

#[handler]
pub async fn list_session_grants(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantListOutcome>, ArkretRouteError> {
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();
    let subject = req.query::<String>("subject");
    let device_id = req.query::<String>("device_id");
    let requested_audience = req.query::<String>("audience");

    let caller = require_session_grant_caller(req, depot).await?;

    // SEC-SG-ENUM: a Principal Server caller may not enumerate session-grant
    // metadata across arbitrary subjects/audiences. Pin the query to the
    // caller's own audience; an admin caller stays unrestricted.
    let audience = caller.resolve_read_audience(requested_audience.as_deref())?;

    let mut filter = SessionGrantFilter::new();

    if let Some(subject) = subject.as_deref() {
        filter = filter.for_subject(subject);
    }

    if let Some(device_id) = device_id.as_deref() {
        filter = filter.for_device(device_id);
    }

    if let Some(audience) = audience.as_deref() {
        filter = filter.for_audience(audience);
    }

    if let Some(browser_session_id) = req.query::<String>("browser_session_id") {
        let browser_session_id = Ulid::from_string(&browser_session_id)
            .map_err(|_| ArkretRouteError::BadRequest("invalid browser_session_id".into()))?;
        filter = filter.for_browser_session(browser_session_id);
    }

    if req.query::<bool>("active_only").unwrap_or(false) {
        filter = filter.active_at(clock.now());
    }

    let mut repo = depot.repo().await?;
    let page = repo
        .oauth_session_grant()
        .list(filter, Pagination::first(100))
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    repo.cancel()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantListOutcome {
        grants: page
            .edges
            .into_iter()
            .map(|edge| edge.node.into())
            .collect(),
    }))
}

#[handler]
pub async fn revoke_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantRevokeOutcome>, ArkretRouteError> {
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();
    let raw_id = req
        .param::<String>("id")
        .ok_or_else(|| ArkretRouteError::BadRequest("missing session grant id".into()))?;
    let id = Ulid::from_string(&raw_id)
        .map_err(|_| ArkretRouteError::BadRequest("invalid session grant id".into()))?;

    // Revocation is destructive — server_name scope is not enough.
    match require_session_grant_caller(req, depot).await?.authz {
        SessionGrantAuthz::Admin => {}
        SessionGrantAuthz::PrincipalServer => {
            return Err(ArkretRouteError::Forbidden(
                "session-grant revocation requires admin scope".to_owned(),
            ));
        }
    }

    let mut repo = depot.repo().await?;
    let grant = repo
        .oauth_session_grant()
        .lookup(id)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
        .ok_or(ArkretRouteError::NotFound)?;

    let canonical_intent = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "operation": "admin_revoke_session_grant",
        "grant_id": grant.grant_id,
    }))
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let canonical_intent_digest: [u8; 32] = sha2::Sha256::digest(&canonical_intent).into();
    let request_identity = format!("admin-revoke:{}", grant.grant_id);
    let now = clock.now();
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &clock,
            coauth_data::NewSessionGrantOperation {
                issuer: &grant.issuer,
                operation: coauth_data::SessionGrantOperationDescriptor::Revoke {
                    selector: coauth_data::SessionGrantRevokeTarget::Grant {
                        grant_id: grant.grant_id.clone(),
                    },
                },
                proof_kind: None,
                request_identity: &request_identity,
                canonical_intent_digest,
                canonical_intent: &canonical_intent,
                target_grant_id: None,
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
                "admin revoke identity conflicts with a different intent",
            ));
        }
        coauth_data::SessionGrantReserveOutcome::Indeterminate(_) => {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "admin revoke outcome is indeterminate",
            ));
        }
        coauth_data::SessionGrantReserveOutcome::Pending(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "admin revoke authorization is incomplete",
            ));
        }
    };
    if let Some(operation) = operation {
        let checkpoint = serde_json::json!({"kind":"admin_session_grant_revoke"});
        let outcome = repo
            .oauth_session_grant()
            .commit_revoke(
                &clock,
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
            outcome,
            coauth_data::SessionGrantRevokeOutcome::Indeterminate(_)
        ) {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "admin revoke commit is indeterminate",
            ));
        }
    }
    let grant = repo
        .oauth_session_grant()
        .lookup(id)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
        .ok_or(ArkretRouteError::NotFound)?;
    repo.save()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantRevokeOutcome {
        grant: grant.into(),
    }))
}
