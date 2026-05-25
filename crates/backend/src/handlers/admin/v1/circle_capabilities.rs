//! Admin endpoints for managing CXP-0007 `cx.circle.*` capability grants.
//!
//! Surfaces three routes consumed by sodmin and any other admin client:
//!
//! - `GET    /api/admin/v1/circles/capabilities` — list grants
//! - `POST   /api/admin/v1/circles/capabilities` — create a grant
//! - `DELETE /api/admin/v1/circles/capabilities/{id}` — revoke a grant
//!
//! Wire shape lives in
//! [`coauth_admin_types::circle_capability_admin`].
//!
//! TODO(circle-rollout-P2B.2): The current implementation persists grants
//! in a process-wide `Mutex<Vec<…>>`. Migrating this to the
//! `coauth-data` repository pattern (a new `circle_capability_grant`
//! repository + Postgres table + sqlx migration) is tracked as the
//! follow-up for the next pass. The wire shape is stable enough that
//! sodmin can integrate against it today.

use std::sync::{LazyLock, Mutex};

use chrono::Utc;
use coauth_admin_types::circle_capability_admin::{
    CircleCapabilityGrant, CreateCircleCapabilityGrant, ListCircleCapabilityGrantsResponse,
};
use salvo::{http::StatusCode, oapi::extract::PathParam, prelude::*};
use ulid::Ulid;

use crate::{JsonResult, error::AppError, handlers::admin::call_context::extract_call_context};

/// In-memory grant store. See module TODO.
static GRANTS: LazyLock<Mutex<Vec<CircleCapabilityGrant>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.circle_capabilities.list", skip_all)]
pub async fn list_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ListCircleCapabilityGrantsResponse> {
    let call_context = extract_call_context(req, depot).await?;
    call_context.repo.cancel().await?; // read-only

    let data = GRANTS
        .lock()
        .expect("circle capability grant mutex poisoned")
        .iter()
        .filter(|g| g.revoked_at.is_none())
        .cloned()
        .collect();

    Ok(Json(ListCircleCapabilityGrantsResponse { data }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.circle_capabilities.create", skip_all)]
pub async fn create_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<CircleCapabilityGrant> {
    let call_context = extract_call_context(req, depot).await?;

    let body: CreateCircleCapabilityGrant = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid grant body: {e}")))?;

    if let Err(msg) = body.validate() {
        return Err(AppError::bad_request(msg));
    }

    let actor_did = call_context
        .user
        .as_ref()
        .map(|u| format!("user:{}", u.id))
        .unwrap_or_else(|| "service".to_owned());

    let grant = CircleCapabilityGrant {
        id: Ulid::new().to_string(),
        subject: body.subject,
        realm_id: body.realm_id,
        action: body.action,
        allowed_circle_refs: body.allowed_circle_refs,
        granted_by: actor_did,
        granted_at: Utc::now().to_rfc3339(),
        revoked_at: None,
    };

    GRANTS
        .lock()
        .expect("circle capability grant mutex poisoned")
        .push(grant.clone());

    // High-risk grants should produce an admin-audit row. TODO(circle-rollout-P2B.5):
    // wire approval-proof persistence (N-of-M signers) for the High tier.
    let _ = grant.action.risk_tier();

    call_context.repo.cancel().await?; // no DB writes yet

    Ok(Json(grant))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.circle_capabilities.revoke", skip_all)]
pub async fn revoke_handler(
    req: &mut Request,
    depot: &Depot,
    grant_id: PathParam<String>,
) -> Result<StatusCode, AppError> {
    let call_context = extract_call_context(req, depot).await?;
    let grant_id = grant_id.into_inner();

    let revoked = {
        let mut grants = GRANTS
            .lock()
            .expect("circle capability grant mutex poisoned");
        match grants.iter_mut().find(|g| g.id == grant_id) {
            Some(g) if g.revoked_at.is_none() => {
                g.revoked_at = Some(Utc::now().to_rfc3339());
                Ok(StatusCode::NO_CONTENT)
            }
            Some(_) => Err(AppError::new(StatusCode::NOT_FOUND, "grant already revoked")),
            None => Err(AppError::new(StatusCode::NOT_FOUND, "grant not found")),
        }
    };

    let _ = call_context.repo.cancel().await;
    revoked
}

/// Test-only: clear the in-memory grant store between tests.
#[cfg(test)]
pub fn _reset_for_tests() {
    GRANTS
        .lock()
        .expect("circle capability grant mutex poisoned")
        .clear();
}

#[cfg(test)]
mod tests {
    use coauth_admin_types::circle_capability_admin::CircleCapabilityAction;

    use super::*;

    #[test]
    fn create_then_revoke_lifecycle() {
        _reset_for_tests();

        // Simulate what the handler bodies do, sans HTTP plumbing.
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "cx:realm:demo".into(),
            action: CircleCapabilityAction::Create,
            allowed_circle_refs: vec![],
        };
        assert!(req.validate().is_ok());

        let grant = CircleCapabilityGrant {
            id: Ulid::new().to_string(),
            subject: req.subject,
            realm_id: req.realm_id,
            action: req.action,
            allowed_circle_refs: req.allowed_circle_refs,
            granted_by: "service".into(),
            granted_at: Utc::now().to_rfc3339(),
            revoked_at: None,
        };
        GRANTS.lock().unwrap().push(grant.clone());

        // List should contain it.
        let listed: Vec<_> = GRANTS
            .lock()
            .unwrap()
            .iter()
            .filter(|g| g.revoked_at.is_none())
            .cloned()
            .collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, grant.id);

        // Revoke.
        for g in GRANTS.lock().unwrap().iter_mut() {
            if g.id == grant.id {
                g.revoked_at = Some(Utc::now().to_rfc3339());
            }
        }

        let listed_after: Vec<_> = GRANTS
            .lock()
            .unwrap()
            .iter()
            .filter(|g| g.revoked_at.is_none())
            .cloned()
            .collect();
        assert!(listed_after.is_empty());

        _reset_for_tests();
    }
}
