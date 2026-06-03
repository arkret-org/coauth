use coauth_data::RepositoryAccess;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::*;
use crate::handlers::common::DepotExt;

#[derive(Debug, Serialize)]
struct IdentityDescribeResBody {
    service_did: String,
    registry_mode: &'static str,
    supported_receipts: Vec<String>,
    protocol_version: &'static str,
    profiles: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_registry: Option<IdentityRegistryDescriptor>,
}

#[derive(Debug, Serialize)]
struct IdentityResolveResBody {
    did_document: DidDocument,
    key_log_head: Option<String>,
    seq: Option<u64>,
    receipts: Option<Vec<serde_json::Value>>,
    method_evidence: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct IdentityDocumentResBody {
    did_document: DidDocument,
    head_event_digest: Option<String>,
    seq: Option<u64>,
    receipts: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
struct DirectoryDescribeResBody {
    service_did: String,
    resource_types: Vec<&'static str>,
    discovery_profiles: Vec<&'static str>,
    restricted_query_proof: bool,
}

#[derive(Debug, Serialize)]
struct ResolveHandleResponse {
    did: String,
    handle: String,
    verified: bool,
    claims: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ResolveIdentityRequest {
    did: String,
}

#[derive(Debug, Deserialize)]
struct ResolveHandleRequest {
    handle: String,
    expected_did: Option<String>,
}

#[handler]
pub async fn identity_describe(
    depot: &Depot,
) -> Result<Json<IdentityDescribeResBody>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let identity_registry = delegated_identity_registry_descriptor(&cokret_config);

    Ok(Json(IdentityDescribeResBody {
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
) -> Result<Json<IdentityResolveResBody>, CokretRouteError> {
    let body: ResolveIdentityRequest = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;
    let as_of = did_document_as_of_query(req)?;

    if let Some(did_document) =
        local_user_did_document_if_owned(&mut repo, &url_builder, &cokret_config, &body.did, as_of)
            .await?
    {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Ok(Json(IdentityResolveResBody {
            did_document,
            key_log_head: None,
            seq: None,
            receipts: None,
            method_evidence: Some(serde_json::json!({
                "resolver": "local_user",
                "verified_local_binding": true,
            })),
        }));
    }

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

    Ok(Json(IdentityResolveResBody {
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
) -> Result<Json<IdentityDocumentResBody>, CokretRouteError> {
    let did = req
        .query::<String>("did")
        .ok_or_else(|| CokretRouteError::BadRequest("missing did query parameter".into()))?;
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;
    let as_of = did_document_as_of_query(req)?;

    if let Some(did_document) =
        local_user_did_document_if_owned(&mut repo, &url_builder, &cokret_config, &did, as_of)
            .await?
    {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Ok(Json(IdentityDocumentResBody {
            did_document,
            head_event_digest: None,
            seq: None,
            receipts: None,
        }));
    }

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

    Ok(Json(IdentityDocumentResBody {
        did_document: resolution.document,
        head_event_digest: None,
        seq: None,
        receipts: None,
    }))
}

#[handler]
pub async fn directory_describe(
    depot: &Depot,
) -> Result<Json<DirectoryDescribeResBody>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;

    Ok(Json(DirectoryDescribeResBody {
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
) -> Result<Json<ResolveHandleResponse>, CokretRouteError> {
    let body: ResolveHandleRequest = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let did_resolver = depot.did_resolver_service()?;
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

    let did = did_resolver.user_did(&url_builder, &cokret_config, &user);
    let verified = body.expected_did.as_deref().is_none_or(|expected| {
        did_resolver.verify_user_binding(&url_builder, &cokret_config, &user, expected)
            == crate::services::did_resolver::DidBindingVerification::Verified
    });

    Ok(Json(ResolveHandleResponse {
        did,
        handle: user_handle(&url_builder, &user),
        verified,
        claims: Vec::new(),
    }))
}
