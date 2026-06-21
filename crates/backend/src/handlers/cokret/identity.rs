use std::time::{Duration, Instant};

use coauth_data::RepositoryAccess;
use cokret_core::Did;
use cokret_core::error::ERROR_CODE_RATE_LIMITED;
use cokret_core::http::{
    DirectoryDescribeOutcome, IdentityDescribeOutcome, IdentityDocumentViewOutcome,
};
use cokret_core::models::{
    DidDocumentRef, DirectoryDescription, DirectoryHandleResolutionOutcome,
    DirectoryResolveHandleRequestBody, IdentityDescription, IdentityDocumentView,
    IdentityResolveOutcome, IdentityResolveRequestBody,
};
use salvo::prelude::*;
use serde_json::json;

use super::*;
use crate::handlers::RequesterFingerprint;
use crate::handlers::common::{DepotExt, extract_bound_activity_tracker};

const DIRECTORY_RESOLVE_FAILURE_FLOOR: Duration = Duration::from_millis(25);

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

    // coauth no longer fabricates DID documents for its own users. User
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
    let service_did =
        parse_did_field("service_did", service_did_for(&url_builder, &cokret_config))?;
    let trust_domain =
        cokret_core::TypedTrustDomainId::new(trust_domain_for(&url_builder, &cokret_config))
            .map_err(|error| {
                CokretRouteError::Internal(Box::new(std::io::Error::other(format!(
                    "invalid trust_domain: {error}"
                ))))
            })?;
    let supported_profiles = vec!["ck.profile.directory_service.v1".to_owned()];
    let supported_features = vec![
        "directory.resolve".to_owned(),
        "directory.handle_lookup".to_owned(),
    ];
    let description = DirectoryDescription {
        service_did,
        trust_domain,
        service_type: "directory_service".to_owned(),
        protocol_version: COKRET_PROTOCOL_VERSION.to_owned(),
        supported_profiles: supported_profiles.clone(),
        supported_operations: vec![
            "ck.find.directory.query.describe".to_owned(),
            "ck.find.directory.query.resolve_handle".to_owned(),
        ],
        supported_bindings: vec![
            cokret_core::SupportedBinding::new("http_json")
                .with_base_url(url_builder.http_base().to_string()),
        ],
        supported_features: supported_features.clone(),
        auth_metadata: cokret_core::AuthMetadata::minimal("public_no_auth"),
        limits: json!({}),
        plaintext_visibility: cokret_core::PlaintextVisibility::none(),
        privacy_derivation: None,
        implemented_features: supported_features,
        claimed_profiles: supported_profiles
            .iter()
            .map(cokret_core::ClaimedProfileEntry::self_claimed)
            .collect(),
        verified_profiles: Vec::new(),
        experimental_features: Vec::new(),
        compat_surfaces: Vec::new(),
        development_mode: false,
        rate_limit_policy: Some(cokret_core::RateLimitPolicy::unspecified()),
        rate_limit_policy_id: None,
        egress_network_policy: Some(cokret_core::EgressNetworkPolicy::deny_private_defaults()),
        resource_types: vec![
            cokret_core::models::DirectoryResourceKind::Actor,
            cokret_core::models::DirectoryResourceKind::Handle,
        ],
        discovery_profiles: supported_profiles,
        restricted_query_proof: Some(true),
        ingest_modes: vec![cokret_core::DirectoryIngestMode::Push],
        accept_policy_kind: Some(cokret_core::DirectoryAcceptPolicyKind::Open),
        accept_policy_ref: None,
        default_ttl_seconds: Some(86_400),
        max_ttl_seconds: Some(604_800),
        revalidation_grace_seconds: Some(3_600),
        accepted_resource_kinds: vec![
            cokret_core::models::DirectoryResourceKind::Actor,
            cokret_core::models::DirectoryResourceKind::Handle,
        ],
        accepted_did_methods: vec![
            "did:web".to_owned(),
            "did:webvh".to_owned(),
            "did:key".to_owned(),
        ],
        takedown_contact: None,
        rate_limits: Some(json!({})),
        supported_reducer_profiles: Vec::new(),
        supported_schema_profiles: Vec::new(),
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        reducer_profile: None,
        last_materialized_at: None,
    };
    description.validate().map_err(|error| {
        CokretRouteError::Internal(Box::new(std::io::Error::other(format!(
            "invalid directory describe: {error}"
        ))))
    })?;

    Ok(Json(DirectoryDescribeOutcome(description)))
}

#[handler]
pub async fn directory_resolve_handle(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DirectoryHandleResolutionOutcome>, CokretRouteError> {
    let started_at = Instant::now();
    let body: DirectoryResolveHandleRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let limiter = depot.limiter()?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);
    limiter
        .check_directory_lookup(requester)
        .await
        .map_err(|error| {
            CokretRouteError::coded(
                StatusCode::TOO_MANY_REQUESTS,
                ERROR_CODE_RATE_LIMITED,
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
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    else {
        return Err(directory_resolve_not_found(started_at).await);
    };

    // The handle resolves to the user's MINTED principal DID
    // (`did:webvh:…` hosted by the principal server) — never a fabricated
    // `did:web:<coauth-host>:users:<ulid>` form, which no DID service
    // hosts. Principal DIDs are minted per audience; walk the configured
    // principal servers in order and take the first minted one. A user
    // who has never bound to a principal server has no resolvable DID
    // yet — fail closed with 404 rather than synthesising an identifier.
    let did = principal_did_for_user(&mut repo, &cokret_config, &user)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
    let Some(did) = did else {
        return Err(directory_resolve_not_found(started_at).await);
    };

    let verified = body
        .expected_did
        .as_ref()
        .is_some_and(|expected| expected.as_str() == did);
    if !verified {
        return Err(directory_resolve_not_found(started_at).await);
    }

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

async fn directory_resolve_not_found(started_at: Instant) -> CokretRouteError {
    let elapsed = started_at.elapsed();
    if elapsed < DIRECTORY_RESOLVE_FAILURE_FLOOR {
        tokio::time::sleep(DIRECTORY_RESOLVE_FAILURE_FLOOR - elapsed).await;
    }
    CokretRouteError::NotFound
}

fn directory_resolve_request_has_disclosure_gate(body: &DirectoryResolveHandleRequestBody) -> bool {
    let intent_allowed = body
        .intent
        .as_deref()
        .is_some_and(|intent| matches!(intent, "lookup" | "mention" | "invite" | "member_add"));
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
