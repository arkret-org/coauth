//! OIDC authorization-code → `ak.session.grant` exchange core.
//!
//! This module is the Account Authority's OIDC proof validator. It used to
//! also serve the product-private `/_coauth/.../auth/oidc/{browser-bridge,
//! exchange}` bridge endpoints; those are removed (account-lifecycle §4.1,
//! service-surface.md §2.5.1). The canonical entry point is now the spec
//! operation `POST /_arkret/gate/account/session-grants` with
//! `proof.proof_kind = "oidc_code_exchange"` — see
//! [`crate::handlers::arkret::session_grant::issue_session_grant`], which
//! calls [`exchange_oidc_code_for_session_grant`] here.

// `IntegrationManifest` (and the nested `IntegrationManifestDependency`
// / `IntegrationManifestSurface`) live in
// `coauth_admin_types::integration_manifest_admin` so the sodmin admin SPA
// decodes them through the same typed shape. The `integration_describe`
// endpoint below returns the shared `IntegrationManifest` directly.
use arkret_identifiers::{DeviceId, DidCoreId, DidFullId};
use coauth_admin_types::{
    IntegrationManifest, IntegrationManifestDependency, IntegrationManifestSurface,
};
use coauth_data::{
    BoxRepository, RepositoryAccess, SessionGrantCommitOutcome, SessionGrantExactOutcome,
    SessionGrantOperation, SessionGrantProofAuthorization, UpstreamOAuthProviderDiscoveryMode,
    User,
};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_oauth_types::errors::{ClientError, ClientErrorCode};
use coauth_oauth_types::requests::{
    AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant as OAuthAuthorizationCodeGrant,
};
use http::header::ACCEPT;
use mime::APPLICATION_JSON;
use salvo::prelude::*;
use sha2::Digest as _;
use soland_contracts::admin::AccountLocalpartAddRequestBody;
use ulid::Ulid;

use super::{DepotExt, DpopSessionBinding, RouteError, make_clock, make_rng};
use crate::handlers::arkret::{self, SessionGrantMaterial};
use crate::oidc_client::requests::discovery;
use crate::oidc_client::types::client_credentials::ClientCredentials;
use crate::outbound_http::{self, RequestBuilderExt as _};
use crate::services::upstream_oidc::UpstreamOidcExchangeMode;
use crate::services::upstream_oidc_mapping::{TrustedIssuerPolicySet, map_upstream_id_token};

/// Typed input for the canonical OIDC authorization-code exchange. Mirrors the
/// `oidc_code_exchange` branch of
/// `service-operation-dtos.schema.json#/$defs/SessionGrantRequestBody` — the
/// `token_endpoint` / `userinfo_endpoint` are NOT supplied by the client;
/// the Account Authority derives them from the issuer's OIDC discovery
/// document.
pub(crate) struct OidcCodeExchangeInput {
    /// `proof.authorization_code`.
    pub authorization_code: String,
    /// `proof.code_verifier` (PKCE S256).
    pub code_verifier: String,
    /// `proof.redirect_uri`.
    pub redirect_uri: String,
    /// `proof.issuer`.
    pub issuer: String,
    /// `proof.client_id`.
    pub client_id: String,
    /// `proof.state` — bound to the authorization request.
    pub state: String,
    /// `proof.nonce` — bound to the authorization request and id_token.
    pub nonce: String,
    /// `body.device_id` — the protocol device id (`ak:device:<uuidv7>`) the
    /// grant is bound to via `cnf.jkt`.
    pub device_id: String,
    /// Existing principal DID the grant request is bound to.
    pub expected_principal_id: String,
    /// `proof.audience` — the requested principal-server audience.
    pub requested_audience: Option<String>,
}

/// Successful OIDC exchange result. The caller (the canonical session-grant
/// handler) turns this into a `SessionGrantOutcome`.
pub(crate) struct OidcExchangeSuccess {
    pub principal_id: DidCoreId,
    pub device_id: String,
    pub session_grant: SessionGrantMaterial,
    pub persisted_grant_id: String,
}

#[allow(clippy::too_many_arguments)]
async fn commit_oidc_session_grant(
    depot: &Depot,
    mut repo: BoxRepository,
    clock: &dyn coauth_data::Clock,
    operation: &SessionGrantOperation,
    dpop_binding: &DpopSessionBinding,
    browser_session_id: Ulid,
    principal_id: &DidCoreId,
    device_id: &str,
    material: &SessionGrantMaterial,
) -> Result<coauth_data::SessionGrant, OidcExchangeError> {
    let device_id_typed = arkret_identifiers::DeviceId::new(device_id.to_owned())
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    let audience = arkret_identifiers::DidCoreId::new(material.audience.clone())
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    let session_public_key =
        arkret_models_identity::CanonicalSessionPublicJwk::new(&material.session_public_key)
            .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    let wire_outcome = arkret_models_collaboration::session_grant_bodies::SessionGrantOutcome {
        principal_id: principal_id.clone(),
        device_id: Some(device_id_typed),
        session_grant: material.grant_jwt.clone(),
        expires_at: material.expires_at_timestamp,
        grant_id: material.grant_id.clone(),
        session_public_key,
        audience,
        granted_scope: material.scopes.clone(),
        scope_details: None,
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&wire_outcome)
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    let outcome_digest: [u8; 32] = sha2::Sha256::digest(&canonical_outcome).into();
    let checkpoint = serde_json::json!({
        "kind": "oidc_code_exchange",
        "principal_id": principal_id,
        "device_id": device_id,
        "browser_session_id": browser_session_id.to_string(),
        "grant_id": material.grant_id,
        "issuance_digest": hex::encode(material.issuance_digest),
        "material": material,
        "wire_outcome": wire_outcome,
    });
    let authorization_ref = format!("oidc:{}", operation.request_identity);
    let proof_expires_at = clock.now() + chrono::Duration::minutes(5);
    let authorization = SessionGrantProofAuthorization {
        authorization_ref: &authorization_ref,
        checkpoint: &checkpoint,
        proof_expires_at,
    };

    let inserted = repo
        .dpop_replay()
        .consume_jti(crate::services::dpop::dpop_replay_record(
            &dpop_binding.jti,
            clock.now(),
        ))
        .await
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    if !inserted {
        return Err(OidcExchangeError::proof_invalid(
            "grant-binding DPoP proof JTI was already consumed",
        ));
    }
    repo.oauth_session_grant()
        .checkpoint_authorization(clock, operation.id, authorization)
        .await
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    // Once durable, this checkpoint lets Authorized retries finish from the
    // exact prepared material without calling the token endpoint again. The
    // unavoidable crash window between an external provider consuming the
    // code and this save remains fail-closed as indeterminate.
    repo.save()
        .await
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;

    let mut repo = depot
        .repo()
        .await
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    let authorization = SessionGrantProofAuthorization {
        authorization_ref: &authorization_ref,
        checkpoint: &checkpoint,
        proof_expires_at,
    };
    let exact_outcome = SessionGrantExactOutcome {
        canonical_response: &canonical_outcome,
        response_digest: outcome_digest,
    };
    let mut rng = crate::handlers::make_rng();
    let committed = repo
        .oauth_session_grant()
        .commit_issuance(
            &mut rng,
            clock,
            operation.id,
            authorization,
            exact_outcome,
            arkret::new_session_grant_record(Some(browser_session_id), material),
        )
        .await
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    let grant = match committed {
        SessionGrantCommitOutcome::Committed(grant) => grant,
        SessionGrantCommitOutcome::Replay(operation) => {
            let grant_id = operation.result_grant_id.as_ref().ok_or_else(|| {
                OidcExchangeError::new(
                    "session_grant_replay_indeterminate",
                    "committed operation has no result grant identity",
                )
            })?;
            repo.oauth_session_grant()
                .lookup_by_grant_id(grant_id)
                .await
                .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?
                .ok_or_else(|| {
                    OidcExchangeError::new(
                        "session_grant_replay_indeterminate",
                        "committed result grant is unavailable",
                    )
                })?
        }
        SessionGrantCommitOutcome::Indeterminate(_) => {
            return Err(OidcExchangeError::new(
                "session_grant_replay_indeterminate",
                "session-grant commit outcome is indeterminate",
            ));
        }
    };
    repo.save()
        .await
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    Ok(grant)
}

/// Successful OIDC authentication used to create a short-lived account
/// handoff. No principal binding or device-bound session grant exists yet.
pub(crate) struct OidcHandoffExchangeSuccess {
    pub user: User,
    pub browser_session_id: Option<Ulid>,
    pub audience: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OidcExchangeIntent {
    SessionGrant,
    AccountHandoff,
}

enum OidcExchangeResult {
    // Both payloads are boxed: each is several hundred bytes, so an inline
    // variant would size every exchange result by the larger of the two.
    SessionGrant(Box<OidcExchangeSuccess>),
    AccountHandoff(Box<OidcHandoffExchangeSuccess>),
}

/// Typed failure of the OIDC exchange, carrying the registry error code the
/// HTTP layer surfaces as the envelope `code`. Binding failures (state,
/// nonce, redirect_uri, principal, device, audience) map to `proof_invalid`.
pub(crate) struct OidcExchangeError {
    pub code: &'static str,
    pub message: String,
}

impl OidcExchangeError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn proof_invalid(message: impl Into<String>) -> Self {
        Self::new(arkret_wire::ReasonCode::PROOF_INVALID, message)
    }
}

fn validate_returned_nonce(grant_nonce: Option<&str>, expected_nonce: &str) -> Result<(), String> {
    let returned_nonce = grant_nonce.unwrap_or_default();
    // Constant-time compare (COA-SEC-04): the nonce binds the proof to the
    // authorization grant; compare without leaking a matching-prefix timing
    // side channel.
    if crate::util::constant_time_token_eq(returned_nonce, expected_nonce) {
        return Ok(());
    }
    // The recorded nonce is an internal binding value; keep it out of the
    // client-facing envelope and only surface the detail at debug level.
    tracing::debug!(
        target: "coauth.oidc_exchange",
        expected_nonce = %expected_nonce,
        grant_nonce = %if returned_nonce.is_empty() { "missing" } else { returned_nonce },
        "authorization_code nonce mismatch",
    );
    Err(
        "authorization_code nonce mismatch: the proof nonce does not match the authorization_code"
            .to_owned(),
    )
}

pub(crate) fn is_protocol_device_id(value: &str) -> bool {
    DeviceId::new(value.to_owned()).is_ok()
}

pub(super) fn principal_session_grant_scopes(device_id: &str) -> Vec<String> {
    vec![
        arkret::PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned(),
        format!("urn:arkret:client:device:{device_id}"),
    ]
}

fn soland_account_register_endpoint(principal_endpoint: &str) -> Result<url::Url, String> {
    let base = url::Url::parse(principal_endpoint)
        .map_err(|error| format!("invalid principal server endpoint: {error}"))?;
    base.join("/_arkret/gate/account/register")
        .map_err(|error| format!("invalid principal account register endpoint: {error}"))
}

fn soland_account_localparts_endpoint(
    principal_endpoint: &str,
    principal_did: &str,
) -> Result<url::Url, String> {
    let mut endpoint = url::Url::parse(principal_endpoint)
        .map_err(|error| format!("invalid principal server endpoint: {error}"))?;
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    endpoint
        .path_segments_mut()
        .map_err(|_| "principal server endpoint cannot be a base URL".to_owned())?
        .clear()
        .push("_soland")
        .push("accounts")
        .push(principal_did)
        .push("localparts");
    Ok(endpoint)
}

pub(crate) fn principal_server_operation_bearer<'a>(
    arkret_config: &'a coauth_config::ArkretConfig,
    audience: &str,
) -> Option<&'a str> {
    arkret_config
        .principal_servers
        .iter()
        .find(|server| {
            crate::services::resolved_principal_audiences::effective_audience_shared(server)
                .as_ref()
                .is_some_and(|effective| effective.as_str() == audience)
        })
        .and_then(|server| server.embedded_webvh_registration_bearer.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Deployment-private projection command. This deliberately does not reuse
/// the public `AccountRegisterRequestBody`: only the Account Authority may
/// invoke it after the canonical binding flow has completed.
#[derive(Debug, serde::Serialize)]
struct AccountProjectionRegisterRequestBody {
    principal_id: DidCoreId,
    full_id: DidFullId,
    display_name: Option<String>,
    device_id: Option<DeviceId>,
}

fn soland_account_register_body(
    principal: &VerifiedPrincipalIdentity,
    display_name: Option<&str>,
    device_id: Option<&str>,
) -> Result<AccountProjectionRegisterRequestBody, String> {
    Ok(AccountProjectionRegisterRequestBody {
        principal_id: principal.principal_id.clone(),
        full_id: principal.full_id.clone(),
        display_name: display_name.map(ToOwned::to_owned),
        device_id: device_id
            .map(|value| {
                DeviceId::new(value.to_owned())
                    .map_err(|error| format!("device_id is invalid for account register: {error}"))
            })
            .transpose()?,
    })
}

async fn send_soland_account_register(
    http_client: &reqwest::Client,
    endpoint: &url::Url,
    bearer: &str,
    body: &AccountProjectionRegisterRequestBody,
) -> Result<(reqwest::StatusCode, String), String> {
    let body_bytes = arkret_canonical::canonical_json_bytes(body)
        .map_err(|error| format!("canonicalize principal account register request: {error}"))?;
    let response =
        outbound_http::send_with_policy(outbound_http::soland_policy("account_register"), || {
            http_client
                .post(endpoint.clone())
                .bearer_auth(bearer)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_bytes.clone())
        })
        .await
        .map_err(|error| format!("principal account register request failed: {error}"))?;
    let status = response.status();
    if status.is_success() {
        return Ok((status, String::new()));
    }
    let body = response.text().await.unwrap_or_default();
    Ok((status, body))
}

async fn send_soland_primary_localpart(
    http_client: &reqwest::Client,
    endpoint: &url::Url,
    bearer: &str,
    localpart: &str,
) -> Result<(reqwest::StatusCode, String), String> {
    let body = AccountLocalpartAddRequestBody {
        localpart: localpart.to_owned(),
        is_primary: Some(true),
    };
    let body_bytes = arkret_canonical::canonical_json_bytes(&body)
        .map_err(|error| format!("canonicalize principal localpart request: {error}"))?;
    let response = outbound_http::send_with_policy(
        outbound_http::soland_policy("account_primary_localpart_sync"),
        || {
            http_client
                .post(endpoint.clone())
                .bearer_auth(bearer)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_bytes.clone())
        },
    )
    .await
    .map_err(|error| format!("principal account primary localpart sync failed: {error}"))?;
    let status = response.status();
    if status.is_success() {
        return Ok((status, String::new()));
    }
    let body = response.text().await.unwrap_or_default();
    Ok((status, body))
}

fn soland_account_register_failure(status: reqwest::StatusCode, body: &str) -> String {
    format!(
        "principal account register returned {status}: {}",
        body.chars().take(256).collect::<String>()
    )
}

fn soland_account_localpart_failure(status: reqwest::StatusCode, body: &str) -> String {
    format!(
        "principal account primary localpart sync returned {status}: {}",
        body.chars().take(256).collect::<String>()
    )
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedPrincipalIdentity {
    pub principal_id: DidCoreId,
    pub full_id: DidFullId,
    pub authority_instance: arkret_wire::PrincipalAuthorityInstance,
}

/// Load the stable principal id and its registration-time full DID snapshot.
pub(super) async fn load_verified_principal_did(
    repo: &mut coauth_data::BoxRepository,
    user: &User,
    audience: &str,
) -> Result<VerifiedPrincipalIdentity, String> {
    repo.principal_did()
        .get_for_user_and_audience(user, audience)
        .await
        .map_err(|error| format!("principal binding lookup failed: {error}"))?
        .map(|binding| {
            let principal_id = binding.principal_id;
            binding
                .authority_instance
                .validate()
                .map_err(|error| format!("stored authority instance is invalid: {error}"))?;
            if binding.authority_instance.principal_id != principal_id
                || binding.authority_instance.principal_server_id.as_str() != audience
            {
                return Err("stored authority instance does not match principal binding".to_owned());
            }
            Ok(VerifiedPrincipalIdentity {
                principal_id,
                full_id: binding.verified_full_id,
                authority_instance: binding.authority_instance,
            })
        })
        .transpose()?
        .ok_or_else(|| "principal binding is missing".to_owned())
}

/// Load a verified principal DID in an isolated read transaction.
pub(crate) async fn load_verified_principal_did_committed(
    depot: &Depot,
    user: &User,
    audience: &str,
) -> Result<VerifiedPrincipalIdentity, String> {
    let mut did_repo = depot
        .repo()
        .await
        .map_err(|error| format!("principal DID repository unavailable: {error}"))?;
    let principal_did = match load_verified_principal_did(&mut did_repo, user, audience).await {
        Ok(principal_did) => principal_did,
        Err(error) => {
            did_repo.cancel().await.ok();
            return Err(error);
        }
    };
    did_repo.cancel().await.ok();
    Ok(principal_did)
}

pub(crate) async fn ensure_soland_account_registered(
    http_client: &reqwest::Client,
    principal_endpoint: Option<&str>,
    principal: &VerifiedPrincipalIdentity,
    operation_bearer: Option<&str>,
    display_name: Option<&str>,
    device_id: Option<&str>,
    primary_localpart: &str,
) -> Result<(), String> {
    let Some(principal_endpoint) = principal_endpoint else {
        return Ok(());
    };
    let primary_localpart = primary_localpart.trim();
    if primary_localpart.is_empty() {
        return Err("principal account primary localpart is required".to_owned());
    }
    let bearer = operation_bearer
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "canonical principal account registration requires embedded_webvh_registration_bearer"
                .to_owned()
        })?;
    let endpoint = soland_account_register_endpoint(principal_endpoint)?;
    let request_body = soland_account_register_body(principal, display_name, device_id)?;
    let (status, response_body) =
        send_soland_account_register(http_client, &endpoint, bearer, &request_body).await?;
    if !status.is_success() {
        return Err(soland_account_register_failure(status, &response_body));
    }
    let endpoint =
        soland_account_localparts_endpoint(principal_endpoint, principal.principal_id.as_str())?;
    let (status, response_body) =
        send_soland_primary_localpart(http_client, &endpoint, bearer, primary_localpart).await?;
    if status.is_success() {
        return Ok(());
    }
    Err(soland_account_localpart_failure(status, &response_body))
}

/// Account Authority OIDC authorization-code → `ak.session.grant` exchange.
///
/// This is the core that the canonical
/// `POST /_arkret/gate/account/session-grants`
/// (`proof.proof_kind = "oidc_code_exchange"`) handler calls. It:
///
/// 1. resolves the issuer's live OIDC discovery metadata (local coauth issuer or a configured
///    federated upstream) and derives `token_endpoint` / `userinfo_endpoint` from it,
/// 2. exchanges `authorization_code` + `code_verifier` at the `token_endpoint`,
/// 3. validates issuer / state / nonce / redirect_uri / id_token nonce / principal binding / device
///    binding (`cnf.jkt` from the grant-binding DPoP key) / audience, and
/// 4. mints + persists a device-bound `ak.session.grant`.
///
/// Binding failures surface as `proof_invalid`; transport / discovery failures
/// surface as their own registry codes.
pub(crate) async fn exchange_oidc_code_for_session_grant(
    req: &mut Request,
    depot: &Depot,
    dpop_binding: Option<DpopSessionBinding>,
    input: OidcCodeExchangeInput,
    operation: coauth_data::SessionGrantOperation,
) -> Result<OidcExchangeSuccess, OidcExchangeError> {
    match exchange_oidc_code(
        req,
        depot,
        dpop_binding,
        input,
        OidcExchangeIntent::SessionGrant,
        Some(operation),
    )
    .await?
    {
        OidcExchangeResult::SessionGrant(success) => Ok(*success),
        OidcExchangeResult::AccountHandoff(_) => unreachable!("session-grant exchange intent"),
    }
}

/// Validate the same OIDC authorization-code proof for account-first
/// registration without requiring a pre-existing principal or device.
pub(crate) async fn exchange_oidc_code_for_account_handoff(
    req: &mut Request,
    depot: &Depot,
    dpop_binding: DpopSessionBinding,
    input: OidcCodeExchangeInput,
) -> Result<OidcHandoffExchangeSuccess, OidcExchangeError> {
    match exchange_oidc_code(
        req,
        depot,
        Some(dpop_binding),
        input,
        OidcExchangeIntent::AccountHandoff,
        None,
    )
    .await?
    {
        OidcExchangeResult::AccountHandoff(success) => Ok(*success),
        OidcExchangeResult::SessionGrant(_) => unreachable!("account-handoff exchange intent"),
    }
}

async fn exchange_oidc_code(
    req: &mut Request,
    depot: &Depot,
    dpop_binding: Option<DpopSessionBinding>,
    input: OidcCodeExchangeInput,
    intent: OidcExchangeIntent,
    session_grant_operation: Option<coauth_data::SessionGrantOperation>,
) -> Result<OidcExchangeResult, OidcExchangeError> {
    let mut rng = make_rng();
    let clock = make_clock();
    let url_builder = depot
        .url_builder()
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    let arkret_config = depot
        .arkret_config()
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    let key_store = depot
        .key_store()
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    let encrypter = depot
        .encrypter()
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    let upstream_oidc = depot
        .upstream_oidc_service()
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    let http_client = depot
        .get::<reqwest::Client>("http_client")
        .cloned()
        .map_err(|_| OidcExchangeError::new("internal_error", "http_client not found in depot"))?;
    let service_activity_tracker = depot
        .get::<crate::handlers::ActivityTracker>("activity_tracker")
        .cloned()
        .map_err(|_| {
            OidcExchangeError::new("internal_error", "activity_tracker not found in depot")
        })?;
    let mut repo = depot
        .repo()
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;

    // The DPoP proof binds either the issued session grant or the handoff to
    // `cnf.jkt`; both exchanges fail closed without it.
    let Some(dpop_binding) = dpop_binding else {
        return Err(OidcExchangeError::proof_invalid(
            "OIDC exchange requires a valid grant-binding DPoP proof",
        ));
    };

    // --- structural validation of the proof / body fields ---------------
    if input.code_verifier.trim().is_empty() {
        return Err(OidcExchangeError::proof_invalid(
            "code_verifier is required and the authorization_code must have been issued with PKCE",
        ));
    }
    if input.authorization_code.trim().is_empty()
        || input.redirect_uri.trim().is_empty()
        || input.issuer.trim().is_empty()
        || input.client_id.trim().is_empty()
        || input.state.trim().is_empty()
        || input.nonce.trim().is_empty()
    {
        return Err(OidcExchangeError::proof_invalid(
            "authorization_code, redirect_uri, issuer, client_id, state, and nonce are required for oidc_code_exchange",
        ));
    }
    let device_id = match intent {
        OidcExchangeIntent::SessionGrant => {
            let device_id = input.device_id.trim().to_owned();
            if !is_protocol_device_id(&device_id) {
                return Err(OidcExchangeError::proof_invalid(
                    "device_id must be a ak:device:<uuidv7> protocol identifier",
                ));
            }
            device_id
        }
        OidcExchangeIntent::AccountHandoff => String::new(),
    };

    let redirect_uri = url::Url::parse(input.redirect_uri.trim()).map_err(|_| {
        OidcExchangeError::proof_invalid("redirect_uri must be a valid absolute URI")
    })?;
    let issuer = url::Url::parse(input.issuer.trim())
        .map_err(|_| OidcExchangeError::proof_invalid("issuer must be a valid absolute URI"))?;

    let enabled_upstream_providers = repo
        .upstream_oauth_provider()
        .all_enabled()
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    let exchange_mode = upstream_oidc
        .exchange_mode_for_issuer(
            &url_builder,
            &enabled_upstream_providers,
            &issuer,
            input.client_id.trim(),
        )
        .map_err(OidcExchangeError::proof_invalid)?;

    // Resolve the issuer's live discovery document and derive the
    // token / userinfo endpoints from it (the client never supplies them).
    let discovery_result = match &exchange_mode {
        UpstreamOidcExchangeMode::LocalCoauth => {
            if issuer.scheme() == "https" {
                discovery::discover(&http_client, issuer.as_str()).await
            } else {
                tracing::warn!(
                    target: "coauth.oidc_exchange",
                    %issuer,
                    "OIDC discovery is running in insecure (non-https) mode for the local issuer; \
                     this bypasses TLS validation and must only be used in development environments",
                );
                discovery::insecure_discover(&http_client, issuer.as_str()).await
            }
        }
        UpstreamOidcExchangeMode::Federated { provider } => match provider.discovery_mode {
            UpstreamOAuthProviderDiscoveryMode::Oidc => {
                discovery::discover(&http_client, issuer.as_str()).await
            }
            UpstreamOAuthProviderDiscoveryMode::Insecure => {
                tracing::warn!(
                    target: "coauth.oidc_exchange",
                    %issuer,
                    provider = %provider.human_name.as_deref().unwrap_or(provider.client_id.as_str()),
                    "OIDC discovery is running in insecure mode for a federated upstream provider; \
                     this bypasses validation and must only be used in development environments",
                );
                discovery::insecure_discover(&http_client, issuer.as_str()).await
            }
            UpstreamOAuthProviderDiscoveryMode::Disabled => {
                return Err(OidcExchangeError::new(
                    "invalid_discovery_binding",
                    "federated OIDC exchange requires discovery-enabled upstream provider metadata",
                ));
            }
        },
    };
    let discovered_metadata = discovery_result.map_err(|error| {
        OidcExchangeError::new(
            "invalid_discovery_binding",
            format!(
                "OIDC exchange could not fetch live discovery metadata for issuer={issuer}: {error}"
            ),
        )
    })?;

    // Endpoints come from discovery (with federated provider overrides), then
    // are validated against the issuer/provider binding the same way the old
    // bridge validated the client-supplied endpoints.
    let (token_endpoint, userinfo_endpoint) = match &exchange_mode {
        UpstreamOidcExchangeMode::LocalCoauth => (
            discovered_metadata.token_endpoint().clone(),
            discovered_metadata.userinfo_endpoint().clone(),
        ),
        UpstreamOidcExchangeMode::Federated { provider } => (
            provider
                .token_endpoint_override
                .clone()
                .unwrap_or_else(|| discovered_metadata.token_endpoint().clone()),
            provider
                .userinfo_endpoint_override
                .clone()
                .unwrap_or_else(|| discovered_metadata.userinfo_endpoint().clone()),
        ),
    };
    if let Err(message) = upstream_oidc.validate_exchange_endpoints(
        &url_builder,
        &exchange_mode,
        &discovered_metadata,
        &token_endpoint,
        &userinfo_endpoint,
    ) {
        return Err(OidcExchangeError::new("invalid_discovery_binding", message));
    }

    // ─── Federated branch ───────────────────────────────────────────────
    if let UpstreamOidcExchangeMode::Federated { provider } = exchange_mode {
        let jwks_uri = provider
            .jwks_uri_override
            .clone()
            .unwrap_or_else(|| discovered_metadata.jwks_uri().clone());
        let federated_exchange = upstream_oidc
            .exchange_federated_authorization_code(
                &http_client,
                &key_store,
                &encrypter,
                &provider,
                &issuer,
                &token_endpoint,
                &userinfo_endpoint,
                &jwks_uri,
                input.authorization_code.trim(),
                redirect_uri.clone(),
                input.code_verifier.trim(),
                // Bind the client-supplied nonce to the upstream id_token. The
                // `state` parameter is intentionally NOT validated here: in the
                // federated flow the client (and, where applicable, the upstream
                // provider) owns the authorization-request <-> callback `state`
                // round-trip, so coauth never recorded an expected state to
                // compare against. coauth's binding obligation is the nonce.
                Some(input.nonce.trim()),
                clock.now(),
                &mut rng,
            )
            .await
            .map_err(|error| {
                OidcExchangeError::new(
                    "invalid_authorization_code",
                    format!("federated upstream OIDC exchange failed: {error}"),
                )
            })?;

        // Trusted-issuer mapping (advisory): emit a typed mapping event when a
        // policy is configured; the `find_by_subject` strand stays the source
        // of truth.
        if let (Ok(trusted_issuers), Some(id_token)) = (
            depot.get::<TrustedIssuerPolicySet>("upstream_oidc_trusted_issuers"),
            federated_exchange.token_response.id_token.as_deref(),
        ) && !trusted_issuers.is_empty()
        {
            match map_upstream_id_token(issuer.as_str(), id_token, trusted_issuers, clock.now()) {
                Ok(mapped) => tracing::debug!(
                    target: "coauth.upstream_oidc_mapping",
                    issuer = %issuer, sub = %mapped.sub, role = %mapped.role,
                    "trusted-issuer mapping applied",
                ),
                Err(error) => tracing::warn!(
                    target: "coauth.upstream_oidc_mapping",
                    issuer = %issuer, error = %error, "trusted-issuer mapping failed",
                ),
            }
        }

        let upstream_subject = federated_exchange.userinfo.sub.clone();
        let upstream_link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, upstream_subject.as_str())
            .await
            .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?
            .ok_or_else(|| {
                // Do not reflect the upstream subject identifier in the
                // client-facing envelope; it is an internal value.
                tracing::debug!(
                    target: "coauth.oidc_exchange",
                    upstream_subject = %upstream_subject,
                    provider = %provider.human_name.as_deref().unwrap_or(provider.client_id.as_str()),
                    "federated upstream subject is not linked to a local account",
                );
                OidcExchangeError::new(
                    "upstream_link_required",
                    "federated upstream subject is not linked to a local account",
                )
            })?;
        let user_id = upstream_link.user_id.ok_or_else(|| {
            tracing::debug!(
                target: "coauth.oidc_exchange",
                upstream_subject = %upstream_subject,
                "federated upstream link is unassociated with a local account",
            );
            OidcExchangeError::new(
                "upstream_link_required",
                "federated upstream subject has an unassociated upstream link; complete account linking before issuing a grant",
            )
        })?;
        let user = repo
            .user()
            .lookup(user_id)
            .await
            .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?
            .ok_or_else(|| {
                OidcExchangeError::new(
                    "internal_error",
                    format!(
                        "federated upstream link={} points to missing user={user_id}",
                        upstream_link.id
                    ),
                )
            })?;
        if !user.is_valid() {
            let code = match user.status {
                arkret_models_collaboration::objects::account_status::AccountStatus::Locked => {
                    "account_locked"
                }
                arkret_models_collaboration::objects::account_status::AccountStatus::Suspended => {
                    "account_suspended"
                }
                arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated => {
                    "account_deactivated"
                }
                arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending => {
                    "account_erased"
                }
                arkret_models_collaboration::objects::account_status::AccountStatus::SoftLoggedOut => {
                    "account_unavailable"
                }
                arkret_models_collaboration::objects::account_status::AccountStatus::Active => {
                    unreachable!("active accounts are valid")
                }
            };
            return Err(OidcExchangeError::new(
                code,
                format!(
                    "linked local account username={} has status {}",
                    user.localpart,
                    user.status.as_str(),
                ),
            ));
        }

        let user_agent = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &*clock, &user, user_agent)
            .await
            .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
        let grant_target = upstream_oidc
            .session_grant_target_for_requested_audience(
                &http_client,
                &url_builder,
                &arkret_config,
                crate::services::resolved_principal_audiences::shared(),
                input.requested_audience.as_deref(),
            )
            .await
            .map_err(|message| OidcExchangeError::new("invalid_audience", message))?;
        if intent == OidcExchangeIntent::AccountHandoff {
            let success = OidcHandoffExchangeSuccess {
                user,
                browser_session_id: Some(browser_session.id),
                audience: grant_target.audience,
            };
            repo.save()
                .await
                .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
            return Ok(OidcExchangeResult::AccountHandoff(Box::new(success)));
        }
        let principal = load_verified_principal_did_committed(depot, &user, &grant_target.audience)
            .await
            .map_err(|message| OidcExchangeError::new("principal_unknown", message))?;

        validate_expected_principal(&principal.principal_id, &input.expected_principal_id)?;

        let operation_bearer =
            principal_server_operation_bearer(&arkret_config, &grant_target.audience);
        ensure_soland_account_registered(
            &http_client,
            grant_target.principal_server_endpoint.as_deref(),
            &principal,
            operation_bearer,
            user.display_name.as_deref(),
            Some(device_id.as_str()),
            user.localpart.as_str(),
        )
        .await
        .map_err(|message| {
            OidcExchangeError::new("principal_account_registration_failed", message)
        })?;

        let issuance_seed = arkret::SessionGrantIssuanceSeed::from_operation(
            session_grant_operation
                .as_ref()
                .expect("session grant exchange must carry a reserved operation"),
        )
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
        let session_grant = arkret::issue_session_grant_for_audience(
            &issuance_seed,
            &*clock,
            &arkret_config,
            &key_store,
            &browser_session,
            dpop_binding.public_jwk.clone(),
            grant_target.audience.clone(),
            DeviceId::new(device_id.clone()).map_err(|error| {
                OidcExchangeError::new("device_binding_invalid", error.to_string())
            })?,
            principal_session_grant_scopes(&device_id),
            Some(principal.principal_id.as_str()),
            &principal.authority_instance,
            dpop_binding.jkt.clone(),
            arkret_models_identity::SessionGrantProofKind::OidcCodeExchange,
        )
        .map_err(|error| OidcExchangeError::new("session_grant_denied", error.to_string()))?;
        let persisted = commit_oidc_session_grant(
            depot,
            repo,
            &*clock,
            session_grant_operation
                .as_ref()
                .expect("session grant exchange must carry a reserved operation"),
            &dpop_binding,
            browser_session.id,
            &principal.principal_id,
            device_id.as_str(),
            &session_grant,
        )
        .await?;

        let _ = &service_activity_tracker;
        let _ = &grant_target;
        return Ok(OidcExchangeResult::SessionGrant(Box::new(
            OidcExchangeSuccess {
                principal_id: principal.principal_id,
                device_id,
                session_grant,
                persisted_grant_id: persisted.grant_id.to_string(),
            },
        )));
    }

    // ─── Local coauth issuer branch ─────────────────────────────────────
    let authz_grant = repo
        .oauth_authorization_grant()
        .find_by_code(input.authorization_code.trim())
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?
        .ok_or_else(|| {
            OidcExchangeError::new(
                "invalid_authorization_code",
                "authorization_code was not issued by this coauth OAuth authorization server",
            )
        })?;
    let authz_code = authz_grant.code.as_ref().ok_or_else(|| {
        OidcExchangeError::new(
            "invalid_authorization_code",
            "authorization_code grant does not contain an authorization_code payload",
        )
    })?;
    let pkce = authz_code.pkce.as_ref().ok_or_else(|| {
        OidcExchangeError::proof_invalid(
            "authorization_code was not issued with PKCE; OIDC exchange requires S256 PKCE",
        )
    })?;
    pkce.verify(input.code_verifier.trim()).map_err(|error| {
        OidcExchangeError::proof_invalid(format!(
            "PKCE verifier did not match authorization_code challenge: {error}"
        ))
    })?;

    // State binding: the proof's `state` MUST equal the state coauth recorded
    // on the authorization grant when the authorize request was issued.
    // Constant-time compare (COA-SEC-04): avoid a matching-prefix timing side
    // channel on the recorded grant state.
    if let Some(expected_state) = authz_grant.state.as_deref()
        && !crate::util::constant_time_token_eq(input.state.trim(), expected_state)
    {
        // The expected state is an internal value bound to the grant; never
        // reflect it (or the supplied state) in the client-facing envelope.
        tracing::debug!(
            target: "coauth.oidc_exchange",
            expected_state = %expected_state,
            supplied_state = %input.state.trim(),
            "callback state mismatch",
        );
        return Err(OidcExchangeError::proof_invalid(
            "callback state mismatch: the proof state does not match the authorization_code",
        ));
    }
    // Nonce binding (id_token nonce equivalent for the local issuer).
    validate_returned_nonce(authz_grant.nonce.as_deref(), input.nonce.trim())
        .map_err(OidcExchangeError::proof_invalid)?;

    let exchangeable_oauth_session_id = match &authz_grant.stage {
        coauth_data::AuthorizationGrantStage::Fulfilled { session_id, .. } => Some(*session_id),
        _ => None,
    };

    if authz_grant.redirect_uri != redirect_uri {
        return Err(OidcExchangeError::proof_invalid(format!(
            "authorization_code was issued for redirect_uri={} rather than {}",
            authz_grant.redirect_uri, redirect_uri
        )));
    }

    let oauth_client = repo
        .oauth_client()
        .lookup(authz_grant.client_id)
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?
        .ok_or_else(|| {
            OidcExchangeError::new(
                "invalid_authorization_code",
                format!(
                    "authorization_code references missing oauth_client={}",
                    authz_grant.client_id
                ),
            )
        })?;
    if oauth_client
        .resolve_redirect_uri(&Some(redirect_uri.clone()))
        .is_err()
    {
        return Err(OidcExchangeError::proof_invalid(format!(
            "authorization_code client={} no longer allows redirect_uri={}",
            oauth_client.client_id, redirect_uri
        )));
    }
    if oauth_client.client_id != input.client_id.trim() {
        return Err(OidcExchangeError::new(
            "invalid_client",
            format!(
                "authorization_code was issued for client_id={} rather than {}",
                oauth_client.client_id,
                input.client_id.trim()
            ),
        ));
    }
    if oauth_client.token_endpoint_auth_method.as_ref()
        != Some(&OAuthClientAuthenticationMethod::None)
    {
        return Err(OidcExchangeError::new(
            "invalid_client",
            format!(
                "authorization_code client_id={} requires token_endpoint_auth_method={}; the OIDC bridge only supports public clients with token_endpoint_auth_method=none",
                oauth_client.client_id,
                oauth_client
                    .token_endpoint_auth_method
                    .as_ref()
                    .map_or_else(|| "missing".to_owned(), ToString::to_string)
            ),
        ));
    }

    let oauth_code_grant = OAuthAuthorizationCodeGrant {
        code: input.authorization_code.trim().to_owned(),
        redirect_uri: Some(redirect_uri.clone()),
        code_verifier: Some(input.code_verifier.trim().to_owned()),
    };
    let oauth_token_request = AccessTokenRequest::AuthorizationCode(oauth_code_grant);
    let local_token_credentials = ClientCredentials::None {
        client_id: oauth_client.client_id.clone(),
    };
    let oauth_token_http_request = local_token_credentials
        .authenticated_form(
            http_client
                .post(token_endpoint.as_str())
                .header(ACCEPT, APPLICATION_JSON.as_ref()),
            &oauth_token_request,
            clock.now(),
            &mut rng,
        )
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    // Release the repository session before the nested HTTP request back into
    // coauth's own token endpoint, which needs its own repo access.
    repo.cancel()
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    let oauth_token_http_response = oauth_token_http_request
        .send_traced()
        .await
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    if !oauth_token_http_response.status().is_success() {
        let status = oauth_token_http_response.status();
        let token_error = oauth_token_http_response.json::<ClientError>().await;
        if status.is_server_error() {
            return Err(OidcExchangeError::new(
                "internal_error",
                match token_error {
                    Ok(error) => {
                        format!("local OAuth token endpoint returned server_error: {error:?}")
                    }
                    Err(error) => format!(
                        "local OAuth token endpoint returned {status} and its error body could not be decoded: {error}"
                    ),
                },
            ));
        }
        return match token_error {
            Ok(error) => {
                let error_description = error
                    .error_description
                    .as_deref()
                    .unwrap_or(
                        "local OAuth token endpoint rejected the authorization_code exchange",
                    )
                    .to_owned();
                let lower_description = error_description.to_ascii_lowercase();
                let (code, error_kind) = match error.error {
                    ClientErrorCode::InvalidGrant if lower_description.contains("pkce") => (
                        arkret_wire::ReasonCode::PROOF_INVALID,
                        format!("pkce verification failed: {error_description}"),
                    ),
                    ClientErrorCode::InvalidGrant => {
                        ("invalid_authorization_code", error_description)
                    }
                    ClientErrorCode::InvalidClient | ClientErrorCode::UnauthorizedClient => {
                        ("invalid_client", error_description)
                    }
                    ClientErrorCode::InvalidRequest => ("invalid_request", error_description),
                    _ => ("invalid_authorization_code", error_description),
                };
                Err(OidcExchangeError::new(
                    code,
                    format!(
                        "local OAuth token endpoint rejected the authorization_code exchange: {error_kind}"
                    ),
                ))
            }
            Err(decode_error) => {
                // A 4xx with an undecodable body is still a client-side
                // rejection of this exchange, not a coauth fault: classify by
                // status code instead of collapsing everything to
                // `internal_error`. The raw decode error stays in the log.
                tracing::debug!(
                    target: "coauth.oidc_exchange",
                    %status,
                    error = %decode_error,
                    "local OAuth token endpoint error body could not be decoded",
                );
                let code = match status {
                    http::StatusCode::UNAUTHORIZED | http::StatusCode::FORBIDDEN => {
                        "invalid_client"
                    }
                    http::StatusCode::BAD_REQUEST => "invalid_request",
                    _ => "invalid_authorization_code",
                };
                Err(OidcExchangeError::new(
                    code,
                    format!(
                        "local OAuth token endpoint rejected the authorization_code exchange with {status} and an undecodable error body"
                    ),
                ))
            }
        };
    }
    let oauth_token_reply: AccessTokenResponse = oauth_token_http_response
        .json()
        .await
        .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    let mut repo = depot
        .repo()
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;

    let oauth_session_id = exchangeable_oauth_session_id.ok_or_else(|| {
        OidcExchangeError::new(
            "internal_error",
            "authorization_code exchanged successfully without a fulfilled oauth session id",
        )
    })?;
    let oauth_session = repo
        .oauth_session()
        .lookup(oauth_session_id)
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?
        .ok_or_else(|| {
            OidcExchangeError::new(
                "internal_error",
                format!(
                    "authorization_code exchange succeeded but oauth_session={oauth_session_id} could not be loaded"
                ),
            )
        })?;
    if oauth_session.client_id != authz_grant.client_id {
        return Err(OidcExchangeError::new(
            "internal_error",
            format!(
                "authorization_code exchange succeeded with mismatched client binding: grant client={} session client={}",
                authz_grant.client_id, oauth_session.client_id
            ),
        ));
    }

    let user_session_id = oauth_session.user_session_id.ok_or_else(|| {
        OidcExchangeError::new(
            "invalid_authorization_code",
            "authorization_code is not bound to a browser user session",
        )
    })?;
    let browser_session = repo
        .browser_session()
        .lookup(user_session_id)
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?
        .ok_or_else(|| {
            OidcExchangeError::new(
                "invalid_authorization_code",
                format!("authorization_code references missing browser_session={user_session_id}"),
            )
        })?;
    let expected_subject = arkret::oidc_subject_for_user(&arkret_config, &browser_session.user);
    let expected_issuer = url_builder.oidc_issuer();
    let oauth_introspection = match crate::handlers::oauth::introspection_service::introspect_token(
        &mut repo,
        &clock,
        &url_builder,
        &arkret_config,
        &service_activity_tracker,
        &oauth_token_reply.access_token,
        Some(coauth_iana::oauth::OAuthTokenTypeHint::AccessToken),
        // Internal self-introspection of a token this bridge just minted;
        // the full device/principal/session association is required here.
        crate::handlers::oauth::introspection_service::ArkretAssociationDisclosure::Full,
    )
    .await
    {
        Ok(reply) => reply,
        Err(
            crate::handlers::oauth::introspection_service::IntrospectionError::Repository(_)
            | crate::handlers::oauth::introspection_service::IntrospectionError::CantLoadOAuthSession(_)
            | crate::handlers::oauth::introspection_service::IntrospectionError::CantLoadPersonalSession(_)
            | crate::handlers::oauth::introspection_service::IntrospectionError::CantLoadUser(_)
            | crate::handlers::oauth::introspection_service::IntrospectionError::CantLoadOAuthClient(_),
        ) => {
            return Err(OidcExchangeError::new(
                "internal_error",
                "fresh OAuth token could not be introspected because local session state could not be loaded",
            ));
        }
        Err(error) => {
            return Err(OidcExchangeError::new(
                "invalid_authorization_code",
                format!("fresh OAuth access token failed local introspection: {error}"),
            ));
        }
    };
    if !oauth_introspection.active {
        return Err(OidcExchangeError::new(
            "invalid_authorization_code",
            "fresh OAuth access token was minted but not reported active by local introspection",
        ));
    }
    if oauth_introspection.iss.as_deref() != Some(expected_issuer.as_str()) {
        // Do not echo the expected issuer or the introspected issuer to the
        // client; both are internal binding values.
        tracing::debug!(
            target: "coauth.oidc_exchange",
            expected_issuer = %expected_issuer,
            introspected_issuer = %oauth_introspection.iss.as_deref().unwrap_or("missing"),
            "fresh OAuth access token issuer mismatch",
        );
        return Err(OidcExchangeError::new(
            "invalid_discovery_binding",
            "fresh OAuth access token issuer mismatch",
        ));
    }
    if oauth_introspection.sub.as_deref() != Some(expected_subject.as_str()) {
        // The expected subject is the user's DID and the introspected subject is
        // an internal value; keep both out of the client-facing envelope.
        tracing::debug!(
            target: "coauth.oidc_exchange",
            expected_subject = %expected_subject,
            introspected_subject = %oauth_introspection.sub.as_deref().unwrap_or("missing"),
            "fresh OAuth access token subject mismatch",
        );
        return Err(OidcExchangeError::proof_invalid(
            "fresh OAuth access token subject mismatch",
        ));
    }
    let expected_oauth_client_id = oauth_session.client_id.to_string();
    if oauth_introspection.client_id.as_deref() != Some(expected_oauth_client_id.as_str()) {
        return Err(OidcExchangeError::new(
            "invalid_client",
            format!(
                "fresh OAuth access token client mismatch: expected {} but introspection returned {}",
                expected_oauth_client_id,
                oauth_introspection
                    .client_id
                    .as_deref()
                    .unwrap_or("missing")
            ),
        ));
    }
    let expected_oauth_session_id = oauth_session_id.to_string();
    if oauth_introspection.arkret_session_id.as_deref() != Some(expected_oauth_session_id.as_str())
    {
        return Err(OidcExchangeError::new(
            "invalid_authorization_code",
            format!(
                "fresh OAuth access token session mismatch: expected {} but introspection returned {}",
                expected_oauth_session_id,
                oauth_introspection
                    .arkret_session_id
                    .as_deref()
                    .unwrap_or("missing")
            ),
        ));
    }
    // Release the repo before validating userinfo through the local HTTP
    // endpoint, which also needs repo-backed token/session access.
    repo.cancel()
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    let (oauth_userinfo, _userinfo_response_signed) = upstream_oidc
        .fetch_local_oidc_userinfo(
            &http_client,
            &key_store,
            &userinfo_endpoint,
            &expected_issuer,
            &oauth_token_reply.access_token,
            &oauth_client.client_id,
            oauth_client.userinfo_signed_response_alg.as_ref(),
        )
        .await
        .map_err(|error| {
            OidcExchangeError::new(
                "invalid_authorization_code",
                format!("fresh OAuth access token failed local userinfo validation: {error}"),
            )
        })?;
    let repo = depot
        .repo()
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    if oauth_userinfo.sub != expected_subject {
        return Err(OidcExchangeError::proof_invalid(format!(
            "fresh OAuth userinfo subject mismatch: expected {} but userinfo returned {}",
            expected_subject, oauth_userinfo.sub
        )));
    }
    // `org.arkret.principal_id` is optional and only carries a persisted,
    // method-allowed principal DID. The local OAuth proof binds the account
    // with `sub` + session id; the audience-specific principal DID must already
    // have a verified binding before session-grant issuance.
    if oauth_userinfo.session_id.as_deref() != Some(expected_oauth_session_id.as_str()) {
        return Err(OidcExchangeError::new(
            "invalid_authorization_code",
            format!(
                "fresh OAuth userinfo session mismatch: expected {} but userinfo returned {}",
                expected_oauth_session_id,
                oauth_userinfo.session_id.as_deref().unwrap_or("missing")
            ),
        ));
    }

    let grant_target = upstream_oidc
        .session_grant_target_for_requested_audience(
            &http_client,
            &url_builder,
            &arkret_config,
            crate::services::resolved_principal_audiences::shared(),
            input.requested_audience.as_deref(),
        )
        .await
        .map_err(|message| OidcExchangeError::new("invalid_audience", message))?;
    let user = &browser_session.user;
    if intent == OidcExchangeIntent::AccountHandoff {
        let success = OidcHandoffExchangeSuccess {
            user: user.clone(),
            browser_session_id: Some(browser_session.id),
            audience: grant_target.audience,
        };
        repo.cancel()
            .await
            .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
        return Ok(OidcExchangeResult::AccountHandoff(Box::new(success)));
    }
    let principal = load_verified_principal_did_committed(depot, user, &grant_target.audience)
        .await
        .map_err(|message| OidcExchangeError::new("principal_unknown", message))?;

    validate_expected_principal(&principal.principal_id, &input.expected_principal_id)?;

    let operation_bearer =
        principal_server_operation_bearer(&arkret_config, &grant_target.audience);
    ensure_soland_account_registered(
        &http_client,
        grant_target.principal_server_endpoint.as_deref(),
        &principal,
        operation_bearer,
        user.display_name.as_deref(),
        Some(device_id.as_str()),
        user.localpart.as_str(),
    )
    .await
    .map_err(|message| OidcExchangeError::new("principal_account_registration_failed", message))?;

    let issuance_seed = arkret::SessionGrantIssuanceSeed::from_operation(
        session_grant_operation
            .as_ref()
            .expect("session grant exchange must carry a reserved operation"),
    )
    .map_err(|error| OidcExchangeError::new("internal_error", error.to_string()))?;
    let session_grant = arkret::issue_session_grant_for_audience(
        &issuance_seed,
        &clock,
        &arkret_config,
        &key_store,
        &browser_session,
        dpop_binding.public_jwk.clone(),
        grant_target.audience.clone(),
        DeviceId::new(device_id.clone())
            .map_err(|error| OidcExchangeError::new("device_binding_invalid", error.to_string()))?,
        principal_session_grant_scopes(&device_id),
        Some(principal.principal_id.as_str()),
        &principal.authority_instance,
        dpop_binding.jkt.clone(),
        arkret_models_identity::SessionGrantProofKind::OidcCodeExchange,
    )
    .map_err(|error| OidcExchangeError::new("session_grant_denied", error.to_string()))?;
    let persisted = commit_oidc_session_grant(
        depot,
        repo,
        &clock,
        session_grant_operation
            .as_ref()
            .expect("session grant exchange must carry a reserved operation"),
        &dpop_binding,
        browser_session.id,
        &principal.principal_id,
        device_id.as_str(),
        &session_grant,
    )
    .await?;

    let _ = &grant_target;
    Ok(OidcExchangeResult::SessionGrant(Box::new(
        OidcExchangeSuccess {
            principal_id: principal.principal_id,
            device_id,
            session_grant,
            persisted_grant_id: persisted.grant_id.to_string(),
        },
    )))
}

/// The request principal DID must equal the verified service-account binding.
fn validate_expected_principal(
    resolved_principal_id: &DidCoreId,
    expected_principal_id: &str,
) -> Result<(), OidcExchangeError> {
    let expected = expected_principal_id.trim();
    if expected.is_empty() {
        return Err(OidcExchangeError::new(
            "principal_unknown",
            "principal_id must name an existing verified principal binding",
        ));
    }
    if expected != resolved_principal_id.as_str() {
        // Do not echo the resolved principal DID back to the client: it is an
        // internal binding value the caller does not necessarily own.
        tracing::debug!(
            target: "coauth.oidc_exchange",
            request_principal_id = %expected,
            resolved_principal_id = %resolved_principal_id,
            "principal binding mismatch",
        );
        return Err(OidcExchangeError::proof_invalid(
            "principal binding mismatch: the request principal_id does not match the authenticated user",
        ));
    }
    Ok(())
}

#[endpoint]
pub async fn integration_describe() -> Result<Json<IntegrationManifest>, RouteError> {
    Ok(Json(IntegrationManifest {
        contract: "arkret.rest.integration_manifest.v1".to_owned(),
        service: "coauth".to_owned(),
        service_kind: "account_authority".to_owned(),
        api_base_path: "/_coauth".to_owned(),
        describe_path: "/_coauth/account/integration/describe".to_owned(),
        dependencies: vec![
            IntegrationManifestDependency {
                service: "soland".to_owned(),
                purpose: "principal_server_session_exchange".to_owned(),
                required_contract: "arkret.rest.principal_bridge.v1".to_owned(),
                discovery_path: "/_arkret/describe".to_owned(),
                mode: "remote_service_contract".to_owned(),
            },
            IntegrationManifestDependency {
                service: "public_did_resolver".to_owned(),
                purpose: "principal_did_resolution".to_owned(),
                required_contract: "did_method_resolution".to_owned(),
                discovery_path: "deployment-configured identity_registry.resolver".to_owned(),
                mode: "remote_public_resolver".to_owned(),
            },
        ],
        surfaces: vec![
            IntegrationManifestSurface {
                name: "session_grants".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/gate/account/session-grants".to_owned(),
                contract: "ak.gate.account.command.issue_session_grant".to_owned(),
            },
            IntegrationManifestSurface {
                name: "passkey_auth".to_owned(),
                method: "POST".to_owned(),
                path: "/_coauth/account/auth/passkey/{register,auth}/{start,finish}".to_owned(),
                contract: "arkret.rest.passkey_auth.v1".to_owned(),
            },
            IntegrationManifestSurface {
                name: "admin_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/_coauth/admin/bridge/describe".to_owned(),
                contract: "arkret.rest.coauth_admin_bridge.v1".to_owned(),
            },
            IntegrationManifestSurface {
                name: "account_claims".to_owned(),
                method: "GET".to_owned(),
                path: "/_coauth/admin/accounts/{account_id}/claims".to_owned(),
                contract: "arkret.rest.coauth_account_claims.v1".to_owned(),
            },
        ],
    }))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request as WiremockRequest, ResponseTemplate};

    use super::*;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    const TEST_PRINCIPAL_ID: &str = "ak:did_core:webvh:scid:local.host";
    const TEST_PRINCIPAL_FULL_ID: &str = "did:webvh:scid:local.host:webvh:01k";
    const TEST_DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";
    const TEST_OPERATION_BEARER: &str = "account-operation-secret";
    const ACCOUNT_REGISTER_PATH: &str = "/_arkret/gate/account/register";

    fn test_principal() -> VerifiedPrincipalIdentity {
        let principal_id = DidCoreId::new(TEST_PRINCIPAL_ID).unwrap();
        VerifiedPrincipalIdentity {
            authority_instance: arkret_wire::PrincipalAuthorityInstance::new(
                principal_id.clone(),
                DidCoreId::new("ak:did_core:web:principal-server.test").unwrap(),
                arkret_identifiers::RealmId::new(
                    "ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO",
                )
                .unwrap(),
                arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            )
            .unwrap(),
            principal_id,
            full_id: DidFullId::new(TEST_PRINCIPAL_FULL_ID).unwrap(),
        }
    }

    fn wire_error(code: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "ok": false,
            "error": {
                "code": code,
                "message": message,
            },
            "request_id": "ak:request:01964137-0000-7000-8000-000000000001",
        })
    }

    fn request_json(request: &WiremockRequest) -> serde_json::Value {
        serde_json::from_slice(&request.body).unwrap_or(serde_json::Value::Null)
    }

    fn request_has_bearer(expected: &'static str) -> impl Fn(&WiremockRequest) -> bool {
        move |request| {
            request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == format!("Bearer {expected}"))
        }
    }

    #[test]
    fn protocol_device_id_validation_matches_soland_boundary() {
        assert!(is_protocol_device_id(
            "ak:device:01964137-0000-7000-8000-000000000001"
        ));
        assert!(!is_protocol_device_id("dev_inkson"));
        assert!(!is_protocol_device_id(
            "ak:device:01964137-0000-6000-8000-000000000001"
        ));
    }

    #[test]
    fn principal_session_grant_scopes_include_device_binding() {
        let scopes =
            principal_session_grant_scopes("ak:device:01964137-0000-7000-8000-000000000001");

        assert!(scopes.contains(&arkret::PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()));
        assert!(scopes.contains(
            &"urn:arkret:client:device:ak:device:01964137-0000-7000-8000-000000000001".to_owned()
        ));
    }

    #[test]
    fn returned_nonce_validation_is_exact() {
        assert!(validate_returned_nonce(Some("nonce"), "nonce").is_ok());
        // Mismatch and missing both reject with a generic message; the recorded
        // nonce value is an internal binding secret (COA-SEC-04) and MUST NOT be
        // echoed into the client-facing error (it is only logged at debug).
        let error = validate_returned_nonce(Some("other"), "nonce").unwrap_err();
        assert!(error.contains("nonce mismatch"));
        assert!(!error.contains("other"));
        let error = validate_returned_nonce(None, "nonce").unwrap_err();
        assert!(error.contains("nonce mismatch"));
    }

    #[test]
    fn expected_principal_binding_is_exact() {
        let principal = DidCoreId::new("ak:did_core:webvh:scid:host").unwrap();
        // Matching client assertion → ok.
        assert!(validate_expected_principal(&principal, principal.as_str()).is_ok());
        let error = validate_expected_principal(&principal, "").unwrap_err();
        assert_eq!(error.code, "principal_unknown");
        let error = validate_expected_principal(&principal, "   ").unwrap_err();
        assert_eq!(error.code, "principal_unknown");
        // A present-but-mismatched assertion is still a hard binding failure.
        let error = validate_expected_principal(&principal, "ak:did_core:webvh:other").unwrap_err();
        assert_eq!(error.code, "proof_invalid");
        assert!(error.message.contains("principal binding mismatch"));
    }

    #[test]
    fn soland_account_register_endpoint_uses_arkret_gate_path() {
        let endpoint = soland_account_register_endpoint("https://local.host/base/path").unwrap();

        // The standard account-register route lives at the service root;
        // the join must also discard any base path on the endpoint URL.
        assert_eq!(
            endpoint.as_str(),
            "https://local.host/_arkret/gate/account/register"
        );
    }

    #[test]
    fn soland_account_localparts_endpoint_encodes_principal_did_segment() {
        let endpoint =
            soland_account_localparts_endpoint("https://local.host/base/path", TEST_PRINCIPAL_ID)
                .unwrap();

        assert_eq!(
            endpoint.as_str(),
            "https://local.host/_soland/accounts/ak:did_core:webvh:scid:local.host/localparts"
        );
    }

    #[tokio::test]
    async fn soland_account_projection_registers_account_then_syncs_primary_localpart() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ACCOUNT_REGISTER_PATH))
            .and(request_has_bearer(TEST_OPERATION_BEARER))
            .and(|request: &WiremockRequest| request_json(request).get("handle").is_none())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "principal_id": TEST_PRINCIPAL_ID,
                "state": "active",
                "devices": [],
                "handle_claim_digests": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let localparts_path = soland_account_localparts_endpoint(&server.uri(), TEST_PRINCIPAL_ID)
            .unwrap()
            .path()
            .to_owned();
        Mock::given(method("POST"))
            .and(path(localparts_path))
            .and(request_has_bearer(TEST_OPERATION_BEARER))
            .and(|request: &WiremockRequest| {
                request_json(request)
                    == serde_json::json!({
                        "localpart": "alice",
                        "is_primary": true,
                    })
            })
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "localpart": {
                    "id": "01964137-0000-7000-8000-000000000002",
                    "localpart": "alice",
                    "is_primary": true,
                    "created_at": "2026-07-23T00:00:00.000Z",
                    "updated_at": "2026-07-23T00:00:00.000Z"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        ensure_soland_account_registered(
            &reqwest::Client::new(),
            Some(&server.uri()),
            &test_principal(),
            Some(TEST_OPERATION_BEARER),
            Some("Alice"),
            Some(TEST_DEVICE_ID),
            "alice",
        )
        .await
        .expect("canonical account projection should succeed");
    }

    #[tokio::test]
    async fn soland_account_register_failed_precondition_is_not_swallowed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ACCOUNT_REGISTER_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(wire_error(
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "account registration is closed",
            )))
            .expect(1)
            .mount(&server)
            .await;

        let error = ensure_soland_account_registered(
            &reqwest::Client::new(),
            Some(&server.uri()),
            &test_principal(),
            Some(TEST_OPERATION_BEARER),
            Some("Alice"),
            Some(TEST_DEVICE_ID),
            "alice",
        )
        .await
        .expect_err("registration policy failures must block grant issuance");

        assert!(error.contains("account registration is closed"));
    }

    #[tokio::test]
    async fn soland_primary_localpart_conflict_blocks_grant_issuance() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ACCOUNT_REGISTER_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "principal_id": TEST_PRINCIPAL_ID,
                "state": "active",
                "devices": [],
                "handle_claim_digests": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let localparts_path = soland_account_localparts_endpoint(&server.uri(), TEST_PRINCIPAL_ID)
            .unwrap()
            .path()
            .to_owned();
        Mock::given(method("POST"))
            .and(path(localparts_path))
            .respond_with(ResponseTemplate::new(409).set_body_json(wire_error(
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "localpart is already assigned",
            )))
            .expect(1)
            .mount(&server)
            .await;

        let error = ensure_soland_account_registered(
            &reqwest::Client::new(),
            Some(&server.uri()),
            &test_principal(),
            Some(TEST_OPERATION_BEARER),
            Some("Alice"),
            Some(TEST_DEVICE_ID),
            "alice",
        )
        .await
        .expect_err("primary localpart conflicts must block grant issuance");

        assert!(error.contains("primary localpart sync returned"));
        assert!(error.contains("localpart is already assigned"));
    }

    #[tokio::test]
    async fn soland_account_projection_rejects_empty_primary_localpart_before_registration() {
        let server = MockServer::start().await;

        let error = ensure_soland_account_registered(
            &reqwest::Client::new(),
            Some(&server.uri()),
            &test_principal(),
            Some(TEST_OPERATION_BEARER),
            Some("Alice"),
            Some(TEST_DEVICE_ID),
            " ",
        )
        .await
        .expect_err("an empty primary localpart must fail before any projection request");

        assert_eq!(error, "principal account primary localpart is required");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn soland_account_register_requires_operation_bearer() {
        let server = MockServer::start().await;
        let error = ensure_soland_account_registered(
            &reqwest::Client::new(),
            Some(&server.uri()),
            &test_principal(),
            None,
            Some("Alice"),
            Some(TEST_DEVICE_ID),
            "alice",
        )
        .await
        .expect_err("missing deployment bearer must fail closed");

        assert!(error.contains("embedded_webvh_registration_bearer"));
    }

    /// The canonical Account Authority grant endpoint rejects an
    /// `oidc_code_exchange` proof that arrives without a grant-binding DPoP proof:
    /// the grant has no device key to bind to (`proof_invalid`). Exercised
    /// against the real router so the route wiring is covered too.
    #[tokio::test]
    async fn session_grant_oidc_exchange_requires_dpop_holder_proof() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool(pool.clone()).await.unwrap();

        let response = state
            .request(Request::post("/_arkret/gate/account/session-grants").json(
                serde_json::json!({
                    "principal_id": "did:webvh:scid:offline.invalid:webvh:01k",
                    "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
                    "proof": {
                        "proof_kind": "oidc_code_exchange",
                        "challenge": "0123456789abcdef0123",
                        "request_canonical_digest": format!("sha256:{}", "0".repeat(64)),
                        "audience": "https://soland.example.com/api",
                        "signature": "unused-for-oidc",
                        "issuer": "https://offline.invalid",
                        "client_id": "inkson",
                        "redirect_uri": "http://localhost:8080/auth/callback",
                        "state": "ak.state-0123456789abcdef",
                        "nonce": "ak.nonce-0123456789abcdef",
                        "authorization_code": "stale-code",
                        "code_verifier": "0123456789012345678901234567890123456789012"
                    }
                }),
            ))
            .await;

        // No DPoP header -> proof_invalid (device binding cannot be established).
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "proof_invalid");
    }
}
