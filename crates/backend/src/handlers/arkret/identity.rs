use std::collections::BTreeMap;

use arkret_identifiers::Did;
use arkret_identity::DidBindingPurpose;
use arkret_models_identity::http_bodies::IdentityDocumentViewOutcome;
use arkret_models_identity::{
    IdentityDocumentView, IdentityResolveOutcome, IdentityResolveRequestBody,
};
use salvo::prelude::*;

use super::*;
use crate::handlers::common::{DepotExt, extract_bound_activity_tracker};
use crate::services::did_binding;

#[handler]
pub async fn identity_resolve(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityResolveOutcome>, ArkretRouteError> {
    let body: IdentityResolveRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    enforce_identity_resolution_rate_limit(req, depot).await?;
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let binding_store = depot.verified_did_binding_store()?;
    let mut repo = depot.repo().await?;

    // coauth no longer fabricates DID documents for its own users, and this
    // endpoint is an ordinary read (`did-usage-and-verification.md` §3): it
    // serves a *previously accepted* principal binding's pinned document and
    // never enters the authority path. None of §4's closed triggers is
    // reachable from a plain resolve request, so a miss is a not-found — the
    // handler deliberately has no resolver handle to fall back to.
    let read = did_binding::ordinary_read_document(
        &url_builder,
        &arkret_config,
        &mut repo,
        binding_store.as_ref(),
        body.did.as_str(),
        DidBindingPurpose::Principal,
        crate::handlers::make_clock().now(),
    )
    .await
    .map_err(map_did_binding_read_error)?;

    Ok(Json(IdentityResolveOutcome {
        did_document: did_document_object(read.document)?,
        key_log_head: read.history_head,
        seq: None,
        receipts: Vec::new(),
        method_evidence: None,
    }))
}

/// Ordinary-read binding lookups translate a miss into the same `not_found`
/// the resolver-backed handler produced for an unknown DID. Anything else is a
/// deployment/configuration fault.
fn map_did_binding_read_error(
    error: crate::services::did_binding::DidBindingError,
) -> ArkretRouteError {
    use crate::services::did_binding::DidBindingError;
    match error {
        DidBindingError::NoAcceptedBinding { .. } | DidBindingError::NotAuthorityGrade { .. } => {
            ArkretRouteError::NotFound
        }
        DidBindingError::Document(message) => {
            ArkretRouteError::BadRequest(format!("invalid did: {message}"))
        }
        other => ArkretRouteError::Internal(Box::new(other)),
    }
}

#[handler]
pub async fn identity_document(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityDocumentViewOutcome>, ArkretRouteError> {
    enforce_identity_resolution_rate_limit(req, depot).await?;
    let did = req
        .query::<String>("did")
        .ok_or_else(|| ArkretRouteError::BadRequest("missing did query parameter".into()))?;
    let did = parse_did_field("did", did)?;
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let binding_store = depot.verified_did_binding_store()?;
    let mut repo = depot.repo().await?;

    // Ordinary read — see `identity_resolve`. No local user-document
    // fabrication and no live resolution.
    let read = did_binding::ordinary_read_document(
        &url_builder,
        &arkret_config,
        &mut repo,
        binding_store.as_ref(),
        did.as_str(),
        DidBindingPurpose::Principal,
        crate::handlers::make_clock().now(),
    )
    .await
    .map_err(map_did_binding_read_error)?;

    Ok(Json(IdentityDocumentViewOutcome(IdentityDocumentView {
        did_document: did_document_object(read.document)?,
        seq: None,
        receipts: Vec::new(),
    })))
}

async fn enforce_identity_resolution_rate_limit(
    req: &Request,
    depot: &Depot,
) -> Result<(), ArkretRouteError> {
    let limiter = depot.limiter()?;
    let requester = extract_bound_activity_tracker(req, depot).requester_fingerprint();
    limiter
        .check_identity_resolution(requester)
        .await
        .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::TOO_MANY_REQUESTS,
                arkret_wire::ErrorCode::RATE_LIMITED,
                error.to_string(),
            )
        })
}

fn parse_did_field(field: &str, value: String) -> Result<Did, ArkretRouteError> {
    Did::new(value)
        .map_err(|error| ArkretRouteError::BadRequest(format!("invalid {field}: {error}")))
}

fn did_document_object(
    document: DidDocument,
) -> Result<BTreeMap<String, serde_json::Value>, ArkretRouteError> {
    parse_did_field("did_document.id", document.id.clone())?;
    Ok(serde_json::from_value(serde_json::to_value(document)?)?)
}
