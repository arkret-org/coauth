use coauth_data::RepositoryAccess;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::*;
use crate::handlers::common::DepotExt;

#[derive(Debug, Serialize)]
struct IdentityDescribeOutcome {
    service_did: String,
    registry_mode: &'static str,
    supported_receipts: Vec<String>,
    protocol_version: &'static str,
    profiles: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_registry: Option<IdentityRegistryDescriptor>,
}

#[derive(Debug, Serialize)]
struct IdentityResolveOutcome {
    did_document: DidDocument,
    key_log_head: Option<String>,
    seq: Option<u64>,
    receipts: Option<Vec<serde_json::Value>>,
    method_evidence: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct IdentityDocumentView {
    did_document: DidDocument,
    head_event_digest: Option<String>,
    seq: Option<u64>,
    receipts: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
struct DirectoryDescribeOutcome {
    service_did: String,
    resource_types: Vec<&'static str>,
    discovery_profiles: Vec<&'static str>,
    restricted_query_proof: bool,
}

#[derive(Debug, Serialize)]
struct ResolveHandleOutcome {
    did: String,
    handle: String,
    verified: bool,
    claims: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ResolveIdentityRequestBody {
    did: String,
}

#[derive(Debug, Deserialize)]
struct ResolveHandleRequestBody {
    handle: String,
    expected_did: Option<String>,
}

#[handler]
pub async fn identity_describe(
    depot: &Depot,
) -> Result<Json<IdentityDescribeOutcome>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let identity_registry = delegated_identity_registry_descriptor(&cokret_config);

    Ok(Json(IdentityDescribeOutcome {
        service_did: service_did_for(&url_builder, &cokret_config),
        registry_mode: if identity_registry.is_some() {
            "delegated_resolver"
        } else {
            "local_bindings"
        },
        supported_receipts: Vec::new(),
        protocol_version: COKRET_PROTOCOL_VERSION,
        profiles: Vec::new(),
        identity_registry,
    }))
}

#[handler]
pub async fn identity_resolve(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityResolveOutcome>, CokretRouteError> {
    let body: ResolveIdentityRequestBody = req
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
            &body.did,
        )
        .await
        .map_err(map_did_resolve_error)?;
    repo.cancel()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(IdentityResolveOutcome {
        did_document: resolution.document,
        key_log_head: None,
        seq: None,
        receipts: None,
        method_evidence: Some(resolution.method_evidence),
    }))
}

#[handler]
pub async fn identity_document(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityDocumentView>, CokretRouteError> {
    let did = req
        .query::<String>("did")
        .ok_or_else(|| CokretRouteError::BadRequest("missing did query parameter".into()))?;
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
            &did,
        )
        .await
        .map_err(map_did_resolve_error)?;
    repo.cancel()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(IdentityDocumentView {
        did_document: resolution.document,
        head_event_digest: None,
        seq: None,
        receipts: None,
    }))
}

#[handler]
pub async fn directory_describe(
    depot: &Depot,
) -> Result<Json<DirectoryDescribeOutcome>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;

    Ok(Json(DirectoryDescribeOutcome {
        service_did: service_did_for(&url_builder, &cokret_config),
        resource_types: vec!["actor", "handle"],
        discovery_profiles: Vec::new(),
        restricted_query_proof: false,
    }))
}

#[handler]
pub async fn directory_resolve_handle(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResolveHandleOutcome>, CokretRouteError> {
    let body: ResolveHandleRequestBody = req
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
        .as_deref()
        .is_none_or(|expected| expected == did);

    Ok(Json(ResolveHandleOutcome {
        did,
        handle: user_handle(&url_builder, &user),
        verified,
        claims: Vec::new(),
    }))
}
