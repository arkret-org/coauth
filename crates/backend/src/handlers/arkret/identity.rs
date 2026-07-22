use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use arkret_core::Did;
use arkret_core::http::{IdentityDescribeOutcome, IdentityDocumentViewOutcome};
use arkret_core::models::{
    DirectoryHandleResolutionOutcome, DirectoryResolveHandleRequestBody, IdentityDescription,
    IdentityDocumentView, IdentityResolveOutcome, IdentityResolveRequestBody,
};
use coauth_data::RepositoryAccess;
use salvo::prelude::*;

use super::*;
use crate::handlers::RequesterFingerprint;
use crate::handlers::common::{DepotExt, extract_bound_activity_tracker};

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
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;

    // coauth no longer fabricates DID documents for its own users. User
    // principal DIDs are `did:webvh:…` documents hosted by the principal
    // server and resolve through the normal chain below.
    let resolution = did_resolver
        .resolve_did_document(
            &http_client,
            &url_builder,
            &arkret_config,
            &key_store,
            &mut repo,
            body.did.as_str(),
        )
        .await
        .map_err(map_did_resolve_error)?;
    repo.cancel()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    Ok(Json(IdentityResolveOutcome {
        did_document: did_document_object(resolution.document)?,
        key_log_head: resolution.key_log_head,
        seq: None,
        receipts: Vec::new(),
    }))
}

#[handler]
pub async fn identity_document(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityDocumentViewOutcome>, ArkretRouteError> {
    let did = req
        .query::<String>("did")
        .ok_or_else(|| ArkretRouteError::BadRequest("missing did query parameter".into()))?;
    let did = parse_did_field("did", did)?;
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;

    // No local user-document fabrication — see `identity_resolve`.
    let resolution = did_resolver
        .resolve_did_document(
            &http_client,
            &url_builder,
            &arkret_config,
            &key_store,
            &mut repo,
            did.as_str(),
        )
        .await
        .map_err(map_did_resolve_error)?;
    repo.cancel()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    Ok(Json(IdentityDocumentViewOutcome(IdentityDocumentView {
        did_document: did_document_object(resolution.document)?,
        head_event_digest: resolution.key_log_head,
        seq: None,
        receipts: Vec::new(),
    })))
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
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
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
    let did = principal_binding.did.clone();

    let verified = body
        .expected_did
        .as_ref()
        .is_some_and(|expected| expected.as_str() == did);
    if !verified {
        return Err(directory_resolve_not_found(started_at).await);
    }
    let resolution = did_resolver
        .resolve_did_document(
            &http_client,
            &url_builder,
            &arkret_config,
            &key_store,
            &mut repo,
            &did,
        )
        .await;
    let Ok(resolution) = resolution else {
        return Err(directory_resolve_not_found(started_at).await);
    };
    let canonical_handle = user_handle(&url_builder, &user);
    if !did_document_endorses_handle(&resolution.document, &canonical_handle) {
        return Err(directory_resolve_not_found(started_at).await);
    }
    let clock = crate::handlers::make_clock();
    let handle_claim_audience = directory_handle_claim_audience(&body, &principal_binding.audience);
    let member_delivery_binding =
        directory_handle_delivery_binding(&arkret_config, &principal_binding)?;
    let claim_material = issue_handle_claim(
        &*clock,
        &url_builder,
        &arkret_config,
        &key_store,
        &user,
        &did,
        arkret_core::HandleClaimKind::HandleBinding,
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
        did: parse_did_field("did", did)?,
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
    arkret_config: &ArkretConfig,
    principal_binding: &PrincipalDidBinding,
) -> Result<arkret_core::DeliveryBindingHint, ArkretRouteError> {
    let recipient_service_id = principal_binding
        .principal_server_did
        .as_ref()
        .and_then(|did| arkret_core::Did::new(did.clone()).ok())
        .or_else(|| arkret_core::Did::new(principal_binding.audience.clone()).ok())
        .or_else(|| Some(service_id_for(arkret_config)))
        .ok_or_else(|| {
            ArkretRouteError::Internal(Box::new(std::io::Error::other(
                "no valid DID available for handle claim delivery binding",
            )))
        })?;
    Ok(arkret_core::DeliveryBindingHint {
        recipient_service_id,
        recipient_service_type: arkret_core::RecipientServiceType::PrincipalServer,
        binding_source: arkret_core::HandleHintBindingSource::Explicit,
        delivery_modes: BTreeSet::from([
            arkret_core::DeliveryMode::Events,
            arkret_core::DeliveryMode::Sync,
            arkret_core::DeliveryMode::ToDevice,
            arkret_core::DeliveryMode::Push,
            arkret_core::DeliveryMode::KeyPackages,
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
        error @ SessionGrantError::DidWebPrincipalNotExplicit => ArkretRouteError::coded(
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
        && body.expected_did.is_some()
        && body.requester.is_some()
        && challenge_present
        && !body.proofs.is_empty()
}

fn parse_did_field(field: &str, value: String) -> Result<Did, ArkretRouteError> {
    Did::new(value)
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
