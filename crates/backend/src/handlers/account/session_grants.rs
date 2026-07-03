use coauth_data::Pagination;
use coauth_data::oauth::SessionGrantFilter;
use salvo::prelude::*;
use serde::Serialize;
use ulid::Ulid;

use super::*;
use crate::handlers::cokret::*;

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
) -> Result<Json<SessionGrantListOutcome>, CokretRouteError> {
    let clock = crate::handlers::make_clock();
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
            .map_err(|_| CokretRouteError::BadRequest("invalid browser_session_id".into()))?;
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
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
    repo.cancel()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

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
) -> Result<Json<SessionGrantRevokeOutcome>, CokretRouteError> {
    let clock = crate::handlers::make_clock();
    let raw_id = req
        .param::<String>("id")
        .ok_or_else(|| CokretRouteError::BadRequest("missing session grant id".into()))?;
    let id = Ulid::from_string(&raw_id)
        .map_err(|_| CokretRouteError::BadRequest("invalid session grant id".into()))?;

    // Revocation is destructive — server_name scope is not enough.
    match require_session_grant_caller(req, depot).await?.authz {
        SessionGrantAuthz::Admin => {}
        SessionGrantAuthz::PrincipalServer => {
            return Err(CokretRouteError::Forbidden(
                "session-grant revocation requires admin scope".to_owned(),
            ));
        }
    }

    let mut repo = depot.repo().await?;
    let grant = repo
        .oauth_session_grant()
        .lookup(id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or(CokretRouteError::NotFound)?;

    let grant = repo
        .oauth_session_grant()
        .revoke(&clock, grant)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantRevokeOutcome {
        grant: grant.into(),
    }))
}
