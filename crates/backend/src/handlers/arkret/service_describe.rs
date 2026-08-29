use arkret_models_discovery::{
    AccountAuthority, AuthGrantExchange, AuthGrantExchangeKind, AuthMetadata, AuthMethod,
    AuthMethodKind, ClaimedProfileEntry, InteropSurfaceEntry, PlaintextVisibility, ServerLimits,
    ServiceDescribe, TransportBinding,
};
use coauth_config::ArkretConfig;
use coauth_data::{RepositoryAccess, UrlBuilder};
use salvo::prelude::*;
use serde::Serialize;

use super::*;
use crate::app_state::DepotExt as _;
use crate::handlers::common::DepotExt;

const CLAIMED_PROFILE_IDS: &[&str] = &[arkret_wire::ProfileId::AUTH_SERVER_V1];

pub(crate) const SUPPORTED_OPERATION_BUNDLES: &[&str] = &[
    "ak.operation_bundle.auth_server.account_authority.v1",
    "ak.operation_bundle.auth_server.describe.v1",
    "ak.operation_bundle.auth_server.http_core.v1",
];

pub(crate) fn supports_advertised_http_operation(
    operation: arkret_wire::ServiceOperationId,
) -> bool {
    SUPPORTED_OPERATION_BUNDLES.iter().any(|bundle_id| {
        arkret_wire::operation_bundle_descriptor(bundle_id)
            .is_some_and(|bundle| bundle.contains(operation, arkret_wire::BindingKind::HttpJson))
    })
}

#[derive(Debug, Clone, Serialize)]
struct PrincipalServerDescriptor {
    name: String,
    audience: Option<arkret_identifiers::DidCoreId>,
    endpoint: String,
    service_id: Option<arkret_identifiers::DidCoreId>,
}

#[derive(Debug, Serialize)]
pub(crate) struct IdentityRegistryDescriptor {
    kind: &'static str,
    resolver: String,
    proof_required_for_pairwise: bool,
}

#[derive(Debug, Serialize)]
struct IdentityRegistryResolverDescriptor {
    mode: &'static str,
    endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegated_resolver: Option<IdentityRegistryDescriptor>,
}

#[derive(Debug, Serialize)]
struct ServiceBoundaryDescriptor {
    authoritative_for: Vec<&'static str>,
    not_authoritative_for: Vec<&'static str>,
    delegated_to: Vec<&'static str>,
    principal_server_authorization: &'static str,
}

#[derive(Debug, Serialize)]
struct ProblemDetailsDescriptor {
    schema: &'static str,
    content_type: &'static str,
    example: ProblemDetailsExample,
    codes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct ProblemDetailsExample {
    #[serde(rename = "type")]
    problem_type: &'static str,
    title: &'static str,
    status: u16,
    detail: &'static str,
    instance: &'static str,
}

#[derive(Debug, Serialize)]
struct OAuthClientHintDescriptor {
    id: String,
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_method: Option<String>,
}

// `auth_metadata` is the SDK-canonical `arkret_models_discovery::AuthMetadata`
// (wave 0). coauth-proprietary fields that have no first-class slot on the
// strong type — `issuer_did`, `token_endpoint_auth_methods`,
// `supported_grant_types`, `required_audience`, `admin_audience`,
// `session_grant_scope`, `oidc_clients` — are carried through the type's
// `extra` (`additionalProperties: true`) flatten map so they round-trip on
// the wire exactly as before without resurrecting a hand-rolled struct.

pub(crate) fn delegated_identity_registry_descriptor(
    arkret_config: &ArkretConfig,
) -> Option<IdentityRegistryDescriptor> {
    arkret_config
        .identity_registry
        .as_ref()
        .map(|registry| IdentityRegistryDescriptor {
            kind: "public_did_resolver",
            resolver: registry.resolver.to_string(),
            proof_required_for_pairwise: registry.proof_required_for_pairwise,
        })
}

fn identity_registry_resolver_descriptor(
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
) -> IdentityRegistryResolverDescriptor {
    let delegated_resolver = delegated_identity_registry_descriptor(arkret_config);
    IdentityRegistryResolverDescriptor {
        mode: if delegated_resolver.is_some() {
            "delegated_resolver"
        } else {
            "local_bindings"
        },
        endpoint: url_builder
            .absolute_url("/_arkret/root/identity/resolve")
            .to_string(),
        delegated_resolver,
    }
}

fn service_boundary_descriptor() -> ServiceBoundaryDescriptor {
    ServiceBoundaryDescriptor {
        authoritative_for: vec![
            "service_account",
            "device_session",
            "session_grant",
            "claim_attestation",
            "admin_action",
        ],
        not_authoritative_for: vec![
            "did_document_registry",
            "did_key_log",
            "identity_registry_receipt",
            "principal_server_write_authorization",
        ],
        delegated_to: vec!["identity_registry", "principal_server_authorization_engine"],
        principal_server_authorization: "server_name writes are decided by the downstream authorization engine from session grants, capabilities, and Space policy.",
    }
}

fn problem_details_descriptor() -> ProblemDetailsDescriptor {
    ProblemDetailsDescriptor {
        schema: arkret_wire::SchemaId::HTTP_PROBLEM_DETAILS_V1,
        content_type: "application/problem+json",
        example: ProblemDetailsExample {
            problem_type: "https://arkret.org/problems/not_found",
            title: "Not found",
            status: 404,
            detail: "not found",
            instance: "ak:request:01964137-0000-7000-8000-000000000000",
        },
        codes: vec!["json_invalid", "not_found", "internal_error"],
    }
}

/// Validate coauth's self-claimed profiles once during process startup.
///
/// Profile requirements are a startup claim guard, not request-routing or
/// authorization input. Callers must abort startup on any error.
pub fn validate_claimed_profiles_at_startup() -> Result<(), arkret_wire::WireError> {
    let advertised_pairs = SUPPORTED_OPERATION_BUNDLES
        .iter()
        .map(|bundle_id| {
            arkret_wire::operation_bundle_descriptor(bundle_id).ok_or_else(|| {
                arkret_wire::WireError::Protocol(format!(
                    "coauth advertises unknown operation bundle {bundle_id}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flat_map(|bundle| bundle.members.iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    for profile_id in CLAIMED_PROFILE_IDS {
        let requirements = arkret_wire::generated::profile_requirements::requirements_for(
            profile_id,
        )
        .ok_or_else(|| {
            arkret_wire::WireError::Protocol(format!("coauth claims unknown profile {profile_id}"))
        })?;
        for requirement in requirements.provide_requirements() {
            let pair = arkret_wire::OperationBindingPair {
                operation_id: requirement.operation_id,
                binding_kind: requirement.binding_kind,
            };
            if !advertised_pairs.contains(&pair) {
                return Err(arkret_wire::WireError::Protocol(format!(
                    "coauth profile {profile_id} requires advertised operation/binding pair {}/{}",
                    requirement.operation_id.as_str(),
                    requirement.binding_kind.as_str(),
                )));
            }
        }
    }
    Ok(())
}

/// G4.T3 — convert the loader's `VerifiedProfileArtifactEntry` into the wire
/// shape expected by `ServiceDescribe.verified_profiles[]`. Also
/// enforces the local cross-check: any entry whose `profile_id` is not in
/// coauth's hard-coded claimed-profile set is dropped with a `warn!` line.
///
/// The claimed-profile set here MUST stay in lockstep with the
/// `claimed_profiles: vec![...]` literal inside `service_describe_response`.
/// If a future task widens coauth's claimed profiles (e.g. adds an
/// `identity_resolver` profile claim), this set MUST grow accordingly —
/// otherwise the cross-check will silently drop legitimate verified
/// entries.
fn build_verified_profile_descriptors(
    loaded: &[arkret_models_discovery::VerifiedProfileArtifactEntry],
) -> Vec<arkret_models_discovery::VerifiedProfileEntry> {
    loaded
        .iter()
        .filter_map(|entry| {
            if !CLAIMED_PROFILE_IDS.contains(&entry.profile_id.as_str()) {
                tracing::warn!(
                    target: "verified_profiles",
                    profile_id = %entry.profile_id,
                    "dropping verified-profile entry: profile_id absent from coauth claimed_profiles"
                );
                return None;
            }
            Some(arkret_models_discovery::VerifiedProfileEntry {
                profile_id: entry.profile_id.clone(),
                claim_kind: arkret_models_discovery::ConformanceVerifiedKind::ConformanceVerified,
                verification_run_id: entry.verification_run_id.clone(),
                artifact_digest: entry.artifact_digest.clone(),
                artifact_ref: entry.artifact_ref.clone(),
                verifier_id: entry.verifier_id.clone(),
                signature: entry.signature.clone(),
                timestamp: entry.timestamp,
                expires_at: entry.expires_at,
                extra: std::collections::BTreeMap::default(),
            })
        })
        .collect()
}

/// Build the SDK-canonical `auth_metadata` block for coauth's describe.
///
/// coauth is the deployment's Auth Server / Account Authority. It advertises
/// one `oidc` auth method (its own issuer + discovery) whose `grant_exchange`
/// creates the AccountHandoff that later authenticates session issuance. When the
/// deployment fronts principal servers, it also publishes the
/// `account_authority` block so clients derive every `/_arkret/gate/account/*`
/// request from `gate_account_base_url`.
///
/// Proprietary fields with no first-class slot on `AuthMetadata` are inserted
/// into `extra` so they keep serializing at the top level of the
/// `auth_metadata` object.
fn build_auth_metadata(url_builder: &UrlBuilder, arkret_config: &ArkretConfig) -> AuthMetadata {
    use serde_json::json;

    let issuer = url_builder.oidc_issuer().to_string();
    let openid_configuration = url_builder.oidc_discovery().to_string();
    let admin_audience = required_audience_for(url_builder, arkret_config);
    let gate_account_base_url = url_builder
        .absolute_url("/_arkret/gate/account")
        .to_string();
    let origin =
        arkret_identifiers::WebOrigin::new(url_builder.http_base().origin().ascii_serialization())
            .expect("configured HTTP base must have a canonical Web Origin");
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "issuer_did".to_owned(),
        json!(issuer_did_for(arkret_config)),
    );
    extra.insert(
        "token_endpoint_auth_methods".to_owned(),
        json!([
            "private_key_jwt",
            "client_secret_basic",
            "client_secret_post"
        ]),
    );
    extra.insert(
        "supported_grant_types".to_owned(),
        json!(["authorization_code", "refresh_token", "device_code"]),
    );
    extra.insert(
        "required_audience".to_owned(),
        json!(required_audience_for(url_builder, arkret_config)),
    );
    extra.insert("admin_audience".to_owned(), json!(admin_audience));
    extra.insert(
        "session_grant_scope".to_owned(),
        json!(PRINCIPAL_SERVER_SESSION_BIND_SCOPE),
    );
    if issuer_did_for(arkret_config).method() == "web" {
        extra.insert("service_id_history_evidence_kind".to_owned(), json!("none"));
        extra.insert(
            "service_id_trust_profile".to_owned(),
            json!("no_history_service"),
        );
    }

    AuthMetadata {
        account_authority: Some(AccountAuthority {
            origin,
            gate_account_base_url,
        }),
        methods: vec![AuthMethod {
            method: AuthMethodKind::Oidc,
            issuer_uri: Some(issuer.clone()),
            provider_uri: None,
            openid_configuration_url: Some(openid_configuration.clone()),
            client_id: None,
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            grant_exchange: AuthGrantExchange {
                kind: AuthGrantExchangeKind::AccountHandoff,
            },
        }],
        did_binding_methods: vec![
            "did_controller_key".to_owned(),
            "device_key".to_owned(),
            "passkey".to_owned(),
            "oidc_binding_proof".to_owned(),
            "vc_presentation".to_owned(),
        ],
        read: None,
        extra,
    }
}

/// Inject the discovered authorization-code OIDC clients into `auth_metadata`.
/// Carried through `extra.oidc_clients` so the strong type stays canonical.
fn set_auth_metadata_oidc_clients(
    auth_metadata: &mut AuthMetadata,
    clients: Vec<OAuthClientHintDescriptor>,
) {
    if clients.is_empty() {
        auth_metadata.extra.remove("oidc_clients");
        return;
    }
    auth_metadata.extra.insert(
        "oidc_clients".to_owned(),
        serde_json::to_value(clients).unwrap_or(serde_json::Value::Null),
    );
    // Populate the first client's id onto the advertised oidc method so
    // clients that read `methods[].client_id` get a concrete value.
    if let Some(first_client_id) = auth_metadata
        .extra
        .get("oidc_clients")
        .and_then(|value| value.as_array())
        .and_then(|array| array.first())
        .and_then(|client| client.get("client_id"))
        .and_then(|id| id.as_str())
        .map(ToOwned::to_owned)
        && let Some(method) = auth_metadata
            .methods
            .iter_mut()
            .find(|method| matches!(method.method, AuthMethodKind::Oidc))
    {
        method.client_id = Some(first_client_id);
    }
}

pub(crate) fn service_describe_response(
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    loaded_verified_profiles: &[arkret_models_discovery::VerifiedProfileArtifactEntry],
    development_mode: bool,
) -> ServiceDescribe {
    let principal_servers: Vec<PrincipalServerDescriptor> = arkret_config
        .principal_servers
        .iter()
        .map(|server| {
            let service_id =
                crate::services::principal_server_trust::effective_audience_shared(server);
            PrincipalServerDescriptor {
                name: server.name.clone(),
                audience: service_id.clone(),
                endpoint: server.endpoint.to_string(),
                service_id,
            }
        })
        .collect();
    let admin_audience = required_audience_for(url_builder, arkret_config);
    let verified_profiles = if development_mode {
        Vec::new()
    } else {
        build_verified_profile_descriptors(loaded_verified_profiles)
    };
    let mut claimed_profile = ClaimedProfileEntry::self_claimed(CLAIMED_PROFILE_IDS[0]);
    claimed_profile.notes = Some(
        "Auth-server-shaped profile: issues short-lived audience-bound ak.session.grant, exposes \
         ak.server.read.describe.v1, MAY expose ak.policy.check. NOT an identity registry (DID \
         resolution is delegated; see interop_surfaces)."
            .to_owned(),
    );
    let interop_surfaces = [
        (
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_REGISTRY_READ_DESCRIBE_V1,
            "delegated-resolver interop: reports the upstream registry coauth proxies to; does not assert canonical ownership.",
        ),
        (
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_READ_RESOLVE_V1,
            "delegated-resolver interop: DID resolution is performed against the configured identity_registry_resolver; coauth caches but does not author DID documents.",
        ),
        (
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET_V1,
            "delegated-resolver interop: returns the cached/resolved DID document; coauth holds no authoritative key log for external DIDs.",
        ),
    ]
    .into_iter()
    .map(|(name, notes)| {
        let mut entry = InteropSurfaceEntry::delegated_resolver(name);
        entry.notes = Some(notes.to_owned());
        entry
    })
    .collect();
    let mut limits_extensions = std::collections::BTreeMap::new();
    limits_extensions.insert("max_body_bytes".to_owned(), serde_json::json!(1_048_576));
    limits_extensions.insert("max_page_size".to_owned(), serde_json::json!(100));
    limits_extensions.insert(
        "session_grant_ttl_seconds".to_owned(),
        serde_json::json!(arkret_config.session_grant_ttl.num_seconds()),
    );
    let mut extensions = std::collections::BTreeMap::new();
    extensions.insert(
        "x_coauth_service_roles".to_owned(),
        serde_json::json!(["auth_server", "identity_resolver", "account_registry"]),
    );
    extensions.insert(
        "x_coauth_admin_audience".to_owned(),
        serde_json::json!(admin_audience),
    );
    if !principal_servers.is_empty() {
        extensions.insert(
            "x_coauth_principal_servers".to_owned(),
            serde_json::to_value(&principal_servers).unwrap_or(serde_json::Value::Null),
        );
        extensions.insert(
            "x_coauth_principal_server_delegation_targets".to_owned(),
            serde_json::to_value(&principal_servers).unwrap_or(serde_json::Value::Null),
        );
    }
    extensions.insert(
        "x_coauth_identity_registry_resolver".to_owned(),
        serde_json::to_value(identity_registry_resolver_descriptor(
            url_builder,
            arkret_config,
        ))
        .unwrap_or(serde_json::Value::Null),
    );
    extensions.insert(
        "x_coauth_service_boundary".to_owned(),
        serde_json::to_value(service_boundary_descriptor()).unwrap_or(serde_json::Value::Null),
    );
    extensions.insert(
        "x_coauth_problem_details".to_owned(),
        serde_json::to_value(problem_details_descriptor()).unwrap_or(serde_json::Value::Null),
    );

    let service_id = service_id_for(arkret_config);
    let service_did = issuer_did_for(arkret_config);
    let service_version_id = arkret_config
        .runtime_service_identity
        .state()
        .identity()
        .expect("ready runtime service identity has current control state")
        .version_id
        .clone();
    ServiceDescribe {
        service_id,
        service_resolution: arkret_models_identity::ResolutionCommitment {
            did: service_did,
            method_history_head: service_version_id.clone(),
            version_id: service_version_id,
        },
        trust_domain: arkret_wire::TrustDomainId::new(trust_domain_for(url_builder, arkret_config))
            .expect("validated coauth trust domain"),
        service_kind: arkret_wire::ServiceKind::AuthServer,
        protocol_version: ARKRET_PROTOCOL_VERSION.to_owned(),
        supported_profiles: Vec::new(),
        profile_bindings: std::collections::BTreeMap::default(),
        supported_operation_bundles: SUPPORTED_OPERATION_BUNDLES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        transport_bindings: vec![TransportBinding::HttpJson {
            base_url: url_builder.http_base().to_string(),
            extension_profile_required: (),
        }],
        supported_features: Vec::new(),
        calendar_tzdb_versions: Vec::new(),
        auth_metadata: build_auth_metadata(url_builder, arkret_config),
        limits: ServerLimits {
            extensions: limits_extensions,
        },
        plaintext_visibility: PlaintextVisibility::none(),
        privacy_derivation: None,
        receive_policy_constraints: None,
        claimed_profiles: vec![claimed_profile],
        verified_profiles,
        interop_surfaces,
        invite_addressing: None,
        development_mode,
        rate_limit_policy: Some(arkret_models_discovery::RateLimitPolicy::unspecified()),
        rate_limit_policy_id: None,
        private_contact_discovery: None,
        egress_network_policy: None,
        resource_kinds: Vec::new(),
        restricted_query_proof: None,
        ingest_modes: Vec::new(),
        accept_policy_kind: None,
        accept_policy_ref: None,
        default_ttl_seconds: None,
        max_ttl_seconds: None,
        revalidation_grace_seconds: None,
        accepted_resource_kinds: Vec::new(),
        accepted_did_methods: Vec::new(),
        takedown_contact: None,
        rate_limits: None,
        supported_reducer_profiles: Vec::new(),
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        last_materialized_at: None,
        extensions: arkret_wire::XExtensionMap::new(extensions)
            .expect("coauth describe extension keys are registered x_* names"),
    }
}

#[handler]
pub async fn server_describe(
    depot: &Depot,
    req: &Request,
) -> Result<Json<ServiceDescribe>, ArkretRouteError> {
    if let Some(service_kind) = req.query::<String>("service_kind")
        && service_kind != arkret_wire::ServiceKind::AuthServer.as_str()
    {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::PARAM_INVALID,
            format!("service_kind {service_kind:?} is not available on this binding"),
        ));
    }
    Ok(Json(service_describe_from_depot(depot).await?))
}

pub(crate) async fn service_describe_from_depot(
    depot: &Depot,
) -> Result<ServiceDescribe, ArkretRouteError> {
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let mut repo = depot.repo().await?;
    let oidc_clients = repo
        .oauth_client()
        .all_static()
        .await?
        .into_iter()
        .filter(|client| {
            client.grant_types.iter().any(|grant_type| {
                matches!(
                    grant_type,
                    coauth_oauth_types::requests::GrantType::AuthorizationCode
                )
            })
        })
        .map(|client| OAuthClientHintDescriptor {
            id: client.id.to_string(),
            client_id: client.client_id.clone(),
            client_name: client.client_name.clone(),
            redirect_uris: client
                .redirect_uris
                .iter()
                .map(ToString::to_string)
                .collect(),
            grant_types: client.grant_types.iter().map(ToString::to_string).collect(),
            token_endpoint_auth_method: client
                .token_endpoint_auth_method
                .as_ref()
                .map(ToString::to_string),
        })
        .collect::<Vec<_>>();
    repo.cancel().await?;

    // G4.T3 — pull the loaded verified-profile descriptors out of the
    // depot. Empty Arc when COAUTH_VERIFIED_PROFILES_ARTIFACT is unset.
    let verified_profiles_loaded: std::sync::Arc<
        Vec<arkret_models_discovery::VerifiedProfileArtifactEntry>,
    > = depot
        .get::<std::sync::Arc<Vec<arkret_models_discovery::VerifiedProfileArtifactEntry>>>(
            "verified_profiles",
        )
        .cloned()
        .unwrap_or_else(|_| std::sync::Arc::new(Vec::new()));
    let mut response = service_describe_response(
        &url_builder,
        &arkret_config,
        verified_profiles_loaded.as_ref(),
        depot
            .get::<bool>("development_mode")
            .copied()
            .unwrap_or(true),
    );
    let pool = depot.get_pg_pool().ok_or_else(|| {
        ArkretRouteError::Internal(Box::new(std::io::Error::other(
            "PostgreSQL pool is unavailable",
        )))
    })?;
    let bundle = crate::services::service_identity::load_durable_identity_bundle(pool)
        .await
        .map_err(|error| {
            ArkretRouteError::Internal(Box::new(std::io::Error::other(error.to_string())))
        })?;
    if bundle.identity.identity.service_id != response.service_id
        || bundle.identity.identity.did != response.service_resolution.did
        || bundle.identity.identity.version_id != response.service_resolution.version_id
    {
        return Err(ArkretRouteError::Internal(Box::new(std::io::Error::other(
            "durable service identity differs from ServiceDescribe",
        ))));
    }
    let head = bundle.webvh_history_entries.last().ok_or_else(|| {
        ArkretRouteError::Internal(Box::new(std::io::Error::other(
            "durable service WebVH history is empty",
        )))
    })?;
    let computed_head = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(head)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let registered_head = &bundle.identity.registration_receipt.log_head_digest;
    if computed_head.as_ref() != registered_head {
        return Err(ArkretRouteError::Internal(Box::new(std::io::Error::other(
            "durable WebVH history head differs from the accepted registration receipt",
        ))));
    }
    response.service_resolution.method_history_head = registered_head.clone();
    response.rate_limit_policy = Some(depot.limiter()?.advertised_public_lookup_policy());
    set_auth_metadata_oidc_clients(&mut response.auth_metadata, oidc_clients);
    response
        .validate()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    Ok(response)
}
