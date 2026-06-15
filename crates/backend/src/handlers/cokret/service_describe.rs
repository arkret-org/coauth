use coauth_config::{CokretConfig, IdentityRegistryKind};
use coauth_data::{RepositoryAccess, UrlBuilder};
use salvo::prelude::*;
use serde::Serialize;

use super::*;
use crate::handlers::common::DepotExt;

#[derive(Debug, Serialize)]
struct SupportedBinding {
    binding: &'static str,
    base_url: String,
}

#[derive(Debug, Clone, Serialize)]
struct PrincipalServerDescriptor {
    name: String,
    audience: String,
    endpoint: String,
    did: Option<String>,
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
struct StandardErrorEnvelopeDescriptor {
    schema: &'static str,
    content_type: &'static str,
    example: StandardErrorEnvelopeExample,
    codes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct StandardErrorEnvelopeExample {
    ok: bool,
    error: StandardErrorExampleBody,
    request_id: &'static str,
}

#[derive(Debug, Serialize)]
struct StandardErrorExampleBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct ServiceLimitsDescriptor {
    max_body_bytes: u64,
    max_page_size: u32,
    session_grant_ttl_seconds: i64,
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

#[derive(Debug, Serialize)]
struct AuthMetadata {
    oauth_issuer: String,
    openid_configuration: String,
    issuer_did: String,
    supported_auth_methods: Vec<&'static str>,
    token_endpoint_auth_methods: Vec<&'static str>,
    supported_grant_types: Vec<&'static str>,
    did_binding_methods: Vec<&'static str>,
    required_audience: String,
    admin_audience: String,
    session_grant_scope: &'static str,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    oidc_clients: Vec<OAuthClientHintDescriptor>,
}

/// Plaintext boundary declaration (`service-describe.schema.json`
/// `plaintext_visibility`, a `required` field). coauth is an auth/OIDC
/// server: it receives no canonical plaintext or reversible derived event
/// content, so it declares `max_visibility = "none"` with an empty
/// `data_classes`. Omission is not allowed — peers read this object to
/// decide whether the service may be registered as plaintext-visible.
#[derive(Debug, Serialize)]
struct PlaintextVisibilityDescriptor {
    max_visibility: &'static str,
    data_classes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ServiceDescribeOutcome {
    // --- canonical `ck.schema.service_describe.v1` fields, in the schema's
    //     property order (see service-describe.schema.json). ---
    service_did: String,
    /// Round 4 (spec a77b995) — deployment-scope trust domain (wire
    /// form `ck:trust_domain:<scope>`). Explicit configuration wins;
    /// otherwise coauth derives a stable deployment-local value from the
    /// public host so the service-describe schema can require it.
    trust_domain: String,
    service_type: &'static str,
    protocol_version: &'static str,
    supported_profiles: Vec<&'static str>,
    supported_operations: Vec<&'static str>,
    supported_bindings: Vec<SupportedBinding>,
    supported_features: Vec<&'static str>,
    auth_metadata: AuthMetadata,
    limits: ServiceLimitsDescriptor,
    /// Required by `service-describe.schema.json`; see
    /// [`PlaintextVisibilityDescriptor`].
    plaintext_visibility: PlaintextVisibilityDescriptor,
    /// T6.1 — feature ids the service has implementation code for but
    /// does NOT claim conformance for. Schema:
    /// `ck.schema.service_describe.v1` (see service-surface.md §3.0).
    implemented_features: Vec<&'static str>,
    /// T6.1 — self-claimed profiles. `claim_kind` MUST be `self_claimed`.
    claimed_profiles: Vec<ClaimedProfileDescriptor>,
    /// T6.1 — cotest-verified profiles. MUST be empty when
    /// `development_mode=true` (§3.0).
    verified_profiles: Vec<VerifiedProfileDescriptor>,
    /// T6.1 — features the service exposes but does NOT promise stable
    /// interop for.
    experimental_features: Vec<&'static str>,
    /// T6.1 — external interop surfaces outside Cokret v1 conformance.
    compat_surfaces: Vec<CompatSurfaceDescriptor>,
    /// Mirror of the service's development-mode flag. coauth has no
    /// dedicated dev toggle today, so this is always `false`; if a toggle
    /// is added later the `verified_profiles=[]` invariant MUST be
    /// re-enforced.
    development_mode: bool,

    // --- coauth-proprietary extension fields. NOTE: these are not part of
    //     `service-describe.schema.json`; a strict validator with
    //     `additionalProperties:false` would reject them unless they are
    //     adopted into the schema or moved under the `x_*` extension
    //     namespace. Kept here as the service's richer self-description;
    //     promoting them is a spec-maintainer decision. ---
    /// T6.3 — explicit Cokret v1 role declaration. A coauth instance can
    /// simultaneously act as `auth_server` (OIDC token issuer),
    /// `identity_resolver` (DID / handle resolution proxy), and
    /// `account_registry` (internal service-account management).
    service_roles: Vec<&'static str>,
    supported_reducer_profiles: Vec<&'static str>,
    supported_schema_profiles: Vec<&'static str>,
    admin_audience: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    principal_servers: Vec<PrincipalServerDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    principal_server_delegation_targets: Vec<PrincipalServerDescriptor>,
    identity_registry_resolver: IdentityRegistryResolverDescriptor,
    service_boundary: ServiceBoundaryDescriptor,
    standard_error_envelope: StandardErrorEnvelopeDescriptor,
}

/// T6.1 — self-claimed profile entry. `claim_kind = "self_claimed"`;
/// cotest-verified entries belong in `verified_profiles`.
#[derive(Debug, Serialize)]
struct ClaimedProfileDescriptor {
    profile_id: &'static str,
    claim_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'static str>,
}

/// T6.1 — cotest-verified profile entry. Required `cotest_run_id`,
/// `artifact_digest`, `artifact_ref`, `cotest_issuer_did`, `signature`,
/// `timestamp`. Dev-mode posture MUST NOT advertise any such entry (§3.0).
#[derive(Debug, Serialize)]
struct VerifiedProfileDescriptor {
    profile_id: String,
    claim_kind: &'static str,
    cotest_run_id: String,
    artifact_digest: String,
    artifact_ref: String,
    cotest_issuer_did: String,
    signature: String,
    timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

/// T6.1 — external-interop surface entry. `kind` is schema-defined.
#[derive(Debug, Serialize)]
struct CompatSurfaceDescriptor {
    name: &'static str,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'static str>,
}

fn identity_registry_kind(kind: &IdentityRegistryKind) -> &'static str {
    match kind {
        IdentityRegistryKind::PublicDidResolver => "public_did_resolver",
        IdentityRegistryKind::External => "external",
    }
}

pub(crate) fn delegated_identity_registry_descriptor(
    cokret_config: &CokretConfig,
) -> Option<IdentityRegistryDescriptor> {
    cokret_config
        .identity_registry
        .as_ref()
        .map(|registry| IdentityRegistryDescriptor {
            kind: identity_registry_kind(&registry.kind),
            resolver: registry.resolver.to_string(),
            proof_required_for_pairwise: registry.proof_required_for_pairwise,
        })
}

fn identity_registry_resolver_descriptor(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
) -> IdentityRegistryResolverDescriptor {
    let delegated_resolver = delegated_identity_registry_descriptor(cokret_config);
    IdentityRegistryResolverDescriptor {
        mode: if delegated_resolver.is_some() {
            "delegated_resolver"
        } else {
            "local_bindings"
        },
        endpoint: url_builder
            .absolute_url("/_cokret/root/identity/resolve")
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

fn standard_error_envelope_descriptor() -> StandardErrorEnvelopeDescriptor {
    StandardErrorEnvelopeDescriptor {
        schema: "ck.error.envelope.v1",
        content_type: "application/json",
        example: StandardErrorEnvelopeExample {
            ok: false,
            error: StandardErrorExampleBody {
                code: "machine_readable_code",
                message: "human-readable message",
            },
            request_id: "ck:request:01964137-0000-7000-8000-000000000000",
        },
        codes: vec!["bad_json", "not_found", "internal_error"],
    }
}

/// G4.T3 — convert the loader's `VerifiedProfileDescriptor` into the wire
/// shape expected by `ServiceDescribeOutcome.verified_profiles[]`. Also
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
    loaded: &[crate::services::verified_profiles::VerifiedProfileDescriptor],
) -> Vec<VerifiedProfileDescriptor> {
    const CLAIMED_PROFILE_IDS: &[&str] = &["ck.profile.auth_server.v1"];
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
            Some(VerifiedProfileDescriptor {
                profile_id: entry.profile_id.clone(),
                claim_kind: "cotest_verified",
                cotest_run_id: entry.cotest_run_id.clone(),
                artifact_digest: entry.artifact_digest.clone(),
                artifact_ref: entry.artifact_ref.clone(),
                cotest_issuer_did: entry.cotest_issuer_did.clone(),
                signature: entry.signature.clone(),
                timestamp: entry.timestamp.to_rfc3339(),
                expires_at: entry.expires_at.map(|ts| ts.to_rfc3339()),
            })
        })
        .collect()
}

pub(crate) fn service_describe_response(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    loaded_verified_profiles: &[crate::services::verified_profiles::VerifiedProfileDescriptor],
) -> ServiceDescribeOutcome {
    let principal_servers: Vec<PrincipalServerDescriptor> = cokret_config
        .principal_servers
        .iter()
        .map(|server| PrincipalServerDescriptor {
            name: server.name.clone(),
            audience: server.audience.clone(),
            endpoint: server.endpoint.to_string(),
            did: server.did.clone(),
        })
        .collect();
    let admin_audience = required_audience_for(url_builder, cokret_config);

    ServiceDescribeOutcome {
        service_did: service_did_for(url_builder, cokret_config),
        // Round 4 — surface the deployment trust domain so federation
        // peers can verify cross-deployment replay protection (see
        // `cokret-spec` round-4 §f9bd7eb).
        trust_domain: trust_domain_for(url_builder, cokret_config),
        // service_type is the SDK-side `ServiceType` discriminant. coauth's
        // primary role is OIDC issuance, so this is kept as "auth_server".
        // The richer multi-role posture is expressed via `service_roles`
        // (T6.3) — consumers that need the full picture MUST read that
        // array.
        service_type: "auth_server",
        // T6.3 — declare all roles this coauth instance carries. Each
        // role is independent: any subset may be deployed off elsewhere
        // (e.g. dedicated starid for identity_resolver, dedicated
        // account-registry service) without affecting the others.
        //   - "auth_server"        : OIDC / token issuance, the canonical role.
        //   - "identity_resolver"  : DID / handle resolution proxy. NOT canonical identity
        //     registry; backed by `ck.identity.*` proxy operations that ultimately route to an
        //     upstream registry (configured via `identity_registry_resolver`).
        //   - "account_registry"   : internal service-account / recovery / claim-attestation
        //     management.
        service_roles: vec!["auth_server", "identity_resolver", "account_registry"],
        protocol_version: COKRET_PROTOCOL_VERSION,
        supported_profiles: Vec::new(),
        supported_features: vec![
            "oidc",
            "account_first_onboarding",
            "session_grant",
            "did_binding",
            "did_resolution",
            "handle_resolution",
            "account_recovery",
            "claim_attestation",
            "policy_hook",
        ],
        supported_reducer_profiles: vec!["ck.reducer.v1"],
        // T6.3 — replace the historical `ck.schema.v1` placeholder with
        // the actual spec-declared schemas this surface emits. The
        // `ck.schema.service_describe.v1` schema covers the very
        // payload being served here; `ck.schema.core.v1` matches the
        // soland / SDK convention for the core-event-store schema
        // profile and is the umbrella the OIDC + account artefacts hash
        // under. Older `ck.schema.v1` is no longer published.
        supported_schema_profiles: vec!["ck.schema.core.v1", "ck.schema.service_describe.v1"],
        supported_bindings: vec![SupportedBinding {
            binding: COKRET_HTTP_BINDING,
            base_url: url_builder.http_base().to_string(),
        }],
        supported_operations: vec![
            "ck.server.query.describe",
            "ck.root.identity.registry.query.describe",
            "ck.root.identity.query.resolve",
            "ck.root.identity.document.resource.get",
            "ck.find.directory.query.describe",
            "ck.find.directory.query.resolve_handle",
            "ck.self.policy.query.check",
        ],
        // Required `service-describe.schema.json` field: coauth receives no
        // canonical plaintext / reversible derived content, so it declares
        // no plaintext classes.
        plaintext_visibility: PlaintextVisibilityDescriptor {
            max_visibility: "none",
            data_classes: Vec::new(),
        },
        // T6.1 — claim-level partition. See service-surface.md §3.0.
        //
        // implemented_features mirrors supported_features: coauth has
        // code for each of these but does not claim conformance for any
        // of them today. Any future cotest run that produces a passing
        // artifact for a coauth profile MUST land in `verified_profiles`,
        // never here.
        implemented_features: vec![
            "oidc",
            "account_first_onboarding",
            "session_grant",
            "did_binding",
            "did_resolution",
            "handle_resolution",
            "account_recovery",
            "claim_attestation",
            "policy_hook",
        ],
        // T6.3 / G3.C3 — claimed_profiles carries the auth-server slot.
        //
        // coauth wears three roles (see `service_roles` above). The only
        // canonical v1 profile whose role + required surface coauth
        // actually serves is `ck.profile.auth_server.v1` (added under
        // G3.C3 to `cokret-spec/spec/v1/artifacts/profiles/conformance-profiles.json`).
        // The other directory-role profiles that would superficially
        // apply are NOT claimed and the reason is documented inline:
        //
        //   * `ck.profile.identity_registry.v1`   — role=directory. coauth's `ck.identity.*` ops
        //     are a DELEGATED proxy onto an upstream resolver, not a canonical registry. Claiming
        //     this profile would lie about authority over DID documents.
        //   * `ck.profile.directory_service.v1`   — role=directory. coauth exposes
        //     `ck.find.directory.query.resolve_handle` only for local handles it issued; it does
        //     NOT publish a network-wide actor directory.
        //   * `ck.profile.public_network_identity.v1` — role=directory. Same reason — coauth is a
        //     service-local issuer, not the network identity authority.
        //   * `ck.profile.principal_server.v1`    — role=server. coauth is not Realm-authoritative;
        //     principal-server event acceptance is soland's role.
        //
        // The boundary against those non-claimed profiles is still
        // surfaced via `service_roles` + `compat_surfaces` (the
        // delegated identity ops) so cotest's ProfileValidator does
        // not flag a role mismatch.
        claimed_profiles: vec![ClaimedProfileDescriptor {
            profile_id: "ck.profile.auth_server.v1",
            claim_kind: "self_claimed",
            notes: Some(
                "Auth-server-shaped profile: issues short-lived audience-bound ck.session.grant, exposes ck.server.query.describe, MAY expose ck.policy.check. NOT an identity registry (DID resolution is delegated; see compat_surfaces).",
            ),
        }],
        // G4.T3 — verified_profiles populated by the cotest artifact loader
        // (`crate::services::verified_profiles::load_from_env`). Every loaded
        // entry's profile_id is cross-checked against the local
        // `claimed_profiles[]` set; entries that fail the cross-check are
        // dropped here (warn-logged) so coauth never advertises a verified
        // profile it does not also self-claim.
        //
        // dev-mode invariant (service-surface.md §3.0): coauth has no
        // runtime dev toggle today, so the only way this surface contains
        // an entry is for COAUTH_VERIFIED_PROFILES_ARTIFACT to point at a
        // valid cotest-produced artifact. Env var unset → empty Vec → the
        // dev-mode posture is preserved without any extra branching here.
        verified_profiles: build_verified_profile_descriptors(loaded_verified_profiles),
        // experimental_features: surfaces still maturing inside coauth.
        // Listed here explicitly so callers don't treat them as stable
        // interop.
        experimental_features: vec![
            "session_grant_exchange",
            "did_webvh_embedded_registration",
            "principal_server_delegation_targets",
        ],
        // T6.3 — compat_surfaces declares non-canonical surfaces. The
        // `ck.identity.*` operations are exposed for client
        // convenience but are a DELEGATED resolver shim onto an
        // upstream registry (starid, public DID network, etc.); coauth
        // is NOT the canonical identity authority for any DID it
        // returns. Schema only allows the broad `external_interop` kind;
        // each note preserves the delegated-resolver boundary explicitly.
        compat_surfaces: vec![
            CompatSurfaceDescriptor {
                name: "ck.root.identity.registry.query.describe",
                kind: "external_interop",
                notes: Some(
                    "delegated-resolver interop: reports the upstream registry coauth proxies to; does not assert canonical ownership.",
                ),
            },
            CompatSurfaceDescriptor {
                name: "ck.root.identity.query.resolve",
                kind: "external_interop",
                notes: Some(
                    "delegated-resolver interop: DID resolution is performed against the configured identity_registry_resolver; coauth caches but does not author DID documents.",
                ),
            },
            CompatSurfaceDescriptor {
                name: "ck.root.identity.document.resource.get",
                kind: "external_interop",
                notes: Some(
                    "delegated-resolver interop: returns the cached/resolved DID document; coauth holds no authoritative key log for external DIDs.",
                ),
            },
        ],
        development_mode: false,
        admin_audience: admin_audience.clone(),
        principal_servers: principal_servers.clone(),
        principal_server_delegation_targets: principal_servers,
        identity_registry_resolver: identity_registry_resolver_descriptor(
            url_builder,
            cokret_config,
        ),
        service_boundary: service_boundary_descriptor(),
        auth_metadata: AuthMetadata {
            oauth_issuer: url_builder.oidc_issuer().to_string(),
            openid_configuration: url_builder.oidc_discovery().to_string(),
            issuer_did: issuer_did_for(url_builder, cokret_config),
            supported_auth_methods: vec![
                "password",
                "oidc",
                "device_pairing",
                "recovery_challenge",
            ],
            token_endpoint_auth_methods: vec![
                "private_key_jwt",
                "client_secret_basic",
                "client_secret_post",
            ],
            supported_grant_types: vec!["authorization_code", "refresh_token", "device_code"],
            did_binding_methods: vec![
                "did_controller_key",
                "device_key",
                "passkey",
                "oidc_binding_proof",
                "vc_presentation",
            ],
            required_audience: required_audience_for(url_builder, cokret_config),
            admin_audience,
            session_grant_scope: PRINCIPAL_SERVER_SESSION_BIND_SCOPE,
            oidc_clients: Vec::new(),
        },
        limits: ServiceLimitsDescriptor {
            max_body_bytes: 1_048_576,
            max_page_size: 100,
            session_grant_ttl_seconds: cokret_config.session_grant_ttl.num_seconds(),
        },
        standard_error_envelope: standard_error_envelope_descriptor(),
    }
}

#[handler]
pub async fn server_describe(
    depot: &Depot,
) -> Result<Json<ServiceDescribeOutcome>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
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
                    oauth_types::requests::GrantType::AuthorizationCode
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
        Vec<crate::services::verified_profiles::VerifiedProfileDescriptor>,
    > = depot
        .get::<std::sync::Arc<Vec<crate::services::verified_profiles::VerifiedProfileDescriptor>>>(
            "verified_profiles",
        )
        .cloned()
        .unwrap_or_else(|_| std::sync::Arc::new(Vec::new()));
    let mut response = service_describe_response(
        &url_builder,
        &cokret_config,
        verified_profiles_loaded.as_ref(),
    );
    response.auth_metadata.oidc_clients = oidc_clients;
    Ok(Json(response))
}
