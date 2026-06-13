use coauth_data::RepositoryAccess;
use cokret_core::Did;
use cokret_core::http::{
    DirectoryDescribeOutcome, IdentityDescribeOutcome, IdentityDocumentViewOutcome,
};
use cokret_core::model::{
    DidDocumentRef, DirectoryDescription, DirectoryHandleResolutionOutcome,
    DirectoryResolveHandleRequestBody, IdentityDescription, IdentityDocumentView,
    IdentityResolveOutcome, IdentityResolveRequestBody,
};
use salvo::prelude::*;
use serde_json::json;

use super::*;
use crate::handlers::common::DepotExt;

#[handler]
pub async fn identity_describe(
    depot: &Depot,
) -> Result<Json<IdentityDescribeOutcome>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let registry_mode = if delegated_identity_registry_descriptor(&cokret_config).is_some() {
        "delegated_resolver"
    } else {
        "local_bindings"
    };

    Ok(Json(IdentityDescribeOutcome(IdentityDescription {
        service_did: parse_did_field("service_did", service_did_for(&url_builder, &cokret_config))?,
        registry_mode: registry_mode.to_owned(),
        supported_receipts: Vec::new(),
        protocol_version: COKRET_PROTOCOL_VERSION.to_owned(),
        profiles: Vec::new(),
    })))
}

#[handler]
pub async fn identity_resolve(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityResolveOutcome>, CokretRouteError> {
    let body: IdentityResolveRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;

    // coauth no longer fabricates DID documents for its own users — the
    // legacy `did:web:<coauth-host>:users:<ulid>` form is dead; user
    // principal DIDs are `did:webvh:…` documents hosted by the principal
    // server and resolve through the normal chain below.
    let resolution = did_resolver
        .resolve_did_document(
            &http_client,
            &url_builder,
            &cokret_config,
            &key_store,
            &mut repo,
            body.did.as_str(),
        )
        .await
        .map_err(map_did_resolve_error)?;
    repo.cancel()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(IdentityResolveOutcome {
        did_document: did_document_ref(resolution.document)?,
        key_log_head: None,
        seq: None,
        receipts: Vec::new(),
        method_evidence: resolution.method_evidence,
    }))
}

#[handler]
pub async fn identity_document(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityDocumentViewOutcome>, CokretRouteError> {
    let did = req
        .query::<String>("did")
        .ok_or_else(|| CokretRouteError::BadRequest("missing did query parameter".into()))?;
    let did = parse_did_field("did", did)?;
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;

    // No local user-document fabrication — see `identity_resolve`.
    let resolution = did_resolver
        .resolve_did_document(
            &http_client,
            &url_builder,
            &cokret_config,
            &key_store,
            &mut repo,
            did.as_str(),
        )
        .await
        .map_err(map_did_resolve_error)?;
    repo.cancel()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(IdentityDocumentViewOutcome(IdentityDocumentView {
        did_document: did_document_ref(resolution.document)?,
        head_event_digest: None,
        seq: None,
        receipts: Vec::new(),
    })))
}

#[handler]
pub async fn directory_describe(
    depot: &Depot,
) -> Result<Json<DirectoryDescribeOutcome>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;

    Ok(Json(DirectoryDescribeOutcome(DirectoryDescription {
        service_did: parse_did_field("service_did", service_did_for(&url_builder, &cokret_config))?,
        resource_types: vec!["actor".to_owned(), "handle".to_owned()],
        discovery_profiles: Vec::new(),
        restricted_query_proof: Some(false),
    })))
}

#[handler]
pub async fn directory_resolve_handle(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DirectoryHandleResolutionOutcome>, CokretRouteError> {
    let body: DirectoryResolveHandleRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let Some(handle) = parse_local_handle(&url_builder, &body.handle) else {
        return Err(CokretRouteError::NotFound);
    };

    let mut repo = depot.repo().await?;
    let Some(user) = repo
        .user()
        .find_by_handle(&handle)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    else {
        return Err(CokretRouteError::NotFound);
    };

    // The handle resolves to the user's MINTED principal DID
    // (`did:webvh:…` hosted by the principal server) — never a fabricated
    // `did:web:<coauth-host>:users:<ulid>` form, which no DID service
    // hosts. Principal DIDs are minted per audience; walk the configured
    // principal servers in order and take the first minted one. A user
    // who has never bound to a principal server has no resolvable DID
    // yet — fail closed with 404 rather than synthesising an identifier.
    let mut did = None;
    for server in &cokret_config.principal_servers {
        if let Some(minted) = repo
            .principal_did()
            .get_for_user_and_audience(&user, &server.audience)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        {
            did = Some(minted.did);
            break;
        }
    }
    let Some(did) = did else {
        return Err(CokretRouteError::NotFound);
    };

    let verified = body
        .expected_did
        .as_ref()
        .is_none_or(|expected| expected.as_str() == did);

    Ok(Json(DirectoryHandleResolutionOutcome {
        did: parse_did_field("did", did)?,
        handle: user_handle(&url_builder, &user),
        verified,
        claims: json!([]),
        audience: body.audience,
        member_delivery_binding: None,
        handle_claim: None,
        as_of: None,
        source_refs: Vec::new(),
        policy_revision: None,
        stale: false,
        divergent: false,
        via_services: Vec::new(),
    }))
}

fn parse_did_field(field: &str, value: String) -> Result<Did, CokretRouteError> {
    Did::new(value)
        .map_err(|error| CokretRouteError::BadRequest(format!("invalid {field}: {error}")))
}

fn did_document_ref(document: DidDocument) -> Result<DidDocumentRef, CokretRouteError> {
    let did = parse_did_field("did_document.id", document.id.clone())?;
    let document = serde_json::to_value(document)
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
    Ok(DidDocumentRef { did, document })
}
