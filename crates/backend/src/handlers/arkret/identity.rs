use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use arkret_identifiers::DidFullId;
use arkret_identity::DidBindingPurpose;
use arkret_models_discovery::{
    DirectoryHandleResolutionOutcome, DirectoryResolveHandleRequestBody,
};
use arkret_models_identity::http_bodies::{IdentityDescribeOutcome, IdentityDocumentViewOutcome};
use arkret_models_identity::{
    IdentityDescription, IdentityDocumentView, IdentityResolveOutcome, IdentityResolveRequestBody,
};
use coauth_data::RepositoryAccess;
use salvo::prelude::*;

use super::*;
use crate::handlers::RequesterFingerprint;
use crate::handlers::common::{DepotExt, extract_bound_activity_tracker};
use crate::services::did_binding;

const DIRECTORY_RESOLVE_FAILURE_FLOOR: Duration = Duration::from_millis(25);

#[handler]
pub async fn identity_describe(
    depot: &Depot,
) -> Result<Json<IdentityDescribeOutcome>, ArkretRouteError> {
    let arkret_config = depot.arkret_config()?;
    let registry_mode = if delegated_identity_registry_descriptor(&arkret_config).is_some() {
        "delegated_resolver"
    } else {
        "local_bindings"
    };

    Ok(Json(IdentityDescribeOutcome(IdentityDescription {
        service_id: service_id_for(&arkret_config),
        registry_mode: registry_mode.to_owned(),
        supported_receipts: Vec::new(),
        protocol_version: ARKRET_PROTOCOL_VERSION.to_owned(),
        profiles: Vec::new(),
    })))
}

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
        head_event_digest: read.history_head,
        seq: None,
        receipts: Vec::new(),
    })))
}

async fn enforce_identity_resolution_rate_limit(
    req: &Request,
    depot: &Depot,
) -> Result<(), ArkretRouteError> {
    let limiter = depot.limiter()?;
    let requester = extract_bound_activity_tracker(req, depot)
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);
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

#[handler]
pub async fn directory_resolve_handle(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DirectoryHandleResolutionOutcome>, ArkretRouteError> {
    let started_at = Instant::now();
    let body: DirectoryResolveHandleRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let binding_store = depot.verified_did_binding_store()?;
    let limiter = depot.limiter()?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);
    limiter
        .check_directory_lookup(requester)
        .await
        .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::TOO_MANY_REQUESTS,
                arkret_wire::ErrorCode::RATE_LIMITED,
                error.to_string(),
            )
        })?;

    if !directory_resolve_request_has_disclosure_gate(&body) {
        return Err(directory_resolve_not_found(started_at).await);
    }
    let Some(handle) = parse_local_handle(&url_builder, &body.handle) else {
        return Err(directory_resolve_not_found(started_at).await);
    };

    let mut repo = depot.repo().await?;
    let Some(user) = repo
        .user()
        .find_by_handle(&handle)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    else {
        return Err(directory_resolve_not_found(started_at).await);
    };

    // Resolve only a verified principal binding. Unbound accounts have no
    // principal identity and remain undiscoverable.
    let principal_binding = principal_did_binding_for_user(&mut repo, &arkret_config, &user)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let Some(principal_binding) = principal_binding else {
        return Err(directory_resolve_not_found(started_at).await);
    };
    let principal_id = principal_binding.principal_id.clone();

    let verified = body
        .expected_principal_id
        .as_ref()
        .is_some_and(|expected| expected == &principal_id);
    if !verified {
        return Err(directory_resolve_not_found(started_at).await);
    }
    // §3: directory rendering is an ordinary read. The handle endorsement check
    // below runs against the *pinned* document of an already accepted principal
    // binding; a miss is blinded into the same not-found every other
    // non-disclosable case produces, and never into a live resolution.
    let read = did_binding::ordinary_read_document(
        &url_builder,
        &arkret_config,
        &mut repo,
        binding_store.as_ref(),
        principal_binding.full_id.as_str(),
        DidBindingPurpose::Principal,
        crate::handlers::make_clock().now(),
    )
    .await;
    let Ok(read) = read else {
        return Err(directory_resolve_not_found(started_at).await);
    };
    let canonical_handle = user_handle(&url_builder, &user);
    if !did_document_endorses_handle(&read.document, &canonical_handle) {
        return Err(directory_resolve_not_found(started_at).await);
    }
    let clock = crate::handlers::make_clock();
    let handle_claim_audience = directory_handle_claim_audience(&body, &principal_binding.audience);
    let member_delivery_binding = directory_handle_delivery_binding(&principal_binding)?;
    let claim_material = issue_handle_claim(
        &*clock,
        &url_builder,
        &arkret_config,
        &key_store,
        &user,
        principal_id.as_str(),
        arkret_models_identity::HandleClaimKind::HandleBinding,
        handle_claim_audience.clone(),
        member_delivery_binding,
    )
    .map_err(map_handle_claim_issue_error)?;
    claim_material.payload.validate().map_err(|error| {
        ArkretRouteError::Internal(Box::new(std::io::Error::other(format!(
            "issued handle claim failed SDK validation: {error}"
        ))))
    })?;

    Ok(Json(DirectoryHandleResolutionOutcome {
        principal_id,
        handle: canonical_handle,
        verified,
        claims: Some(vec![claim_material.payload.clone()]),
        audience: Some(handle_claim_audience),
        member_delivery_binding: claim_material.payload.member_delivery_binding.clone(),
        handle_claim: Some(claim_material.payload),
        as_of: Some(clock.now()),
        source_refs: vec![claim_material.claim_digest],
        policy_revision: None,
        stale: false,
        divergent: false,
        via_services: Vec::new(),
    }))
}

fn directory_handle_claim_audience(
    body: &DirectoryResolveHandleRequestBody,
    principal_audience: &str,
) -> String {
    body.audience
        .clone()
        .or_else(|| body.realm_id.as_ref().map(ToString::to_string))
        .or_else(|| body.requester.as_ref().map(ToString::to_string))
        .unwrap_or_else(|| principal_audience.to_owned())
}

fn directory_handle_delivery_binding(
    principal_binding: &PrincipalDidBinding,
) -> Result<arkret_models_identity::DeliveryBindingHint, ArkretRouteError> {
    let recipient_service_id = principal_binding.accepted_service_id.clone();
    Ok(arkret_models_identity::DeliveryBindingHint {
        recipient_service_id,
        recipient_service_kind: arkret_models_identity::RecipientServiceKind::PrincipalServer,
        binding_source: arkret_models_identity::HandleHintBindingSource::Explicit,
        delivery_modes: BTreeSet::from([
            arkret_models_identity::DeliveryMode::Events,
            arkret_models_identity::DeliveryMode::Sync,
            arkret_models_identity::DeliveryMode::ToDevice,
            arkret_models_identity::DeliveryMode::Push,
            arkret_models_identity::DeliveryMode::KeyPackages,
        ]),
        service_acceptance_ref: None,
        policy_event_ref: None,
    })
}

fn map_handle_claim_issue_error(error: SessionGrantError) -> ArkretRouteError {
    match error {
        SessionGrantError::HandleClaimSubject(error) => ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::INVALID_PARAM,
            error.to_string(),
        ),
        SessionGrantError::PrincipalUnknown => ArkretRouteError::coded(
            StatusCode::NOT_FOUND,
            arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
            "principal_unknown",
        ),
        other => ArkretRouteError::Internal(Box::new(other)),
    }
}

fn did_document_endorses_handle(document: &DidDocument, canonical_handle: &str) -> bool {
    let Some((_, domain)) = canonical_handle.split_once(':') else {
        return false;
    };
    document
        .also_known_as
        .iter()
        .any(|alias| normalize_handle_alias(alias, domain).as_deref() == Some(canonical_handle))
}

fn normalize_handle_alias(alias: &str, default_domain: &str) -> Option<String> {
    let trimmed = alias.trim().to_ascii_lowercase();
    let without_acct = trimmed.strip_prefix("acct:").unwrap_or(trimmed.as_str());
    let without_at_prefix = without_acct.strip_prefix('@').unwrap_or(without_acct);
    let (localpart, authority) =
        if let Some((localpart, authority)) = without_at_prefix.rsplit_once('@') {
            (localpart, authority)
        } else if let Some((localpart, authority)) = without_at_prefix.split_once(':') {
            (localpart, authority)
        } else {
            (without_at_prefix, default_domain)
        };
    let localpart = localpart.trim();
    let authority = authority.trim();
    if localpart.is_empty() || authority.is_empty() {
        return None;
    }
    Some(format!("{localpart}:{authority}"))
}

async fn directory_resolve_not_found(started_at: Instant) -> ArkretRouteError {
    let elapsed = started_at.elapsed();
    if let Some(remaining) = DIRECTORY_RESOLVE_FAILURE_FLOOR.checked_sub(elapsed) {
        tokio::time::sleep(remaining).await;
    }
    ArkretRouteError::NotFound
}

fn directory_resolve_request_has_disclosure_gate(body: &DirectoryResolveHandleRequestBody) -> bool {
    let intent_allowed = body.intent.as_ref().is_some_and(|intent| {
        matches!(
            intent.as_str(),
            "lookup" | "mention" | "invite" | "member_add"
        )
    });
    let challenge_present = body
        .proof_challenge
        .as_deref()
        .is_some_and(|challenge| !challenge.trim().is_empty());

    intent_allowed
        && body.expected_principal_id.is_some()
        && body.requester.is_some()
        && challenge_present
        && !body.proofs.is_empty()
}

fn parse_did_field(field: &str, value: String) -> Result<DidFullId, ArkretRouteError> {
    DidFullId::new(value)
        .map_err(|error| ArkretRouteError::BadRequest(format!("invalid {field}: {error}")))
}

fn did_document_object(
    document: DidDocument,
) -> Result<BTreeMap<String, serde_json::Value>, ArkretRouteError> {
    parse_did_field("did_document.id", document.id.clone())?;
    serde_json::from_value(
        serde_json::to_value(document)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}
