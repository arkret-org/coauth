//! OIDC authorization-code → `ck.session.grant` exchange core.
//!
//! This module is the Account Authority's OIDC proof validator. It used to
//! also serve the product-private `/_coauth/.../auth/oidc/{browser-bridge,
//! exchange}` bridge endpoints; those are removed (account-lifecycle §4.1,
//! service-surface.md §2.5.1). The canonical entry point is now the spec
//! operation `POST /_cokret/gate/account/session-grants` with
//! `proof.proof_kind = "oidc_code_exchange"` — see
//! [`crate::handlers::cokret::session_grant::issue_session_grant`], which
//! calls [`exchange_oidc_code_for_session_grant`] here.

// `IntegrationManifest` (and the nested `IntegrationManifestDependency`
// / `IntegrationManifestSurface`) live in
// `coauth_admin_types::integration_manifest_admin` so the sodmin admin SPA
// decodes them through the same typed shape. The `integration_describe`
// endpoint below returns the shared `IntegrationManifest` directly.
use coauth_admin_types::{
    IntegrationManifest, IntegrationManifestDependency, IntegrationManifestSurface,
};
use coauth_data::{RepositoryAccess, UpstreamOAuthProviderDiscoveryMode, User};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_oauth_types::errors::{ClientError, ClientErrorCode};
use coauth_oauth_types::requests::{
    AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant as OAuthAuthorizationCodeGrant,
};
use cokret_core::error::REASON_PROOF_INVALID;
use cokret_core::{AccountRegisterRequestBody, DeviceId, Did, ErrorEnvelope};
use http::header::ACCEPT;
use mime::APPLICATION_JSON;
use salvo::prelude::*;

use super::{DepotExt, DpopSessionBinding, RouteError, make_clock, make_rng};
use crate::handlers::cokret::{self, SessionGrantMaterial};
use crate::oidc_client::requests::discovery;
use crate::oidc_client::types::client_credentials::ClientCredentials;
use crate::outbound_http::{self, RequestBuilderExt as _};
use crate::services::soland_webvh;
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
    /// `body.device_id` — the protocol device id (`ck:device:<uuidv7>`) the
    /// grant is bound to via `cnf.jkt`.
    pub device_id: String,
    /// `body.principal_id` — the principal DID the client expects the grant
    /// to be bound to. Optional for first sign-in (② contract D5): when the
    /// client does not yet know its principal DID it omits this, and the
    /// Account Authority derives + returns the DID it minted/resolved. When
    /// present, the exchange independently mints / resolves the principal DID
    /// for the authenticated user and rejects a mismatch with `proof_invalid`
    /// (principal binding failure).
    pub expected_principal_id: Option<String>,
    /// `proof.audience` — the requested principal-server audience.
    pub requested_audience: Option<String>,
}

/// Successful OIDC exchange result. The caller (the canonical session-grant
/// handler) turns this into a `SessionGrantOutcome`.
pub(crate) struct OidcExchangeSuccess {
    pub principal_did: String,
    pub device_id: String,
    pub session_grant: SessionGrantMaterial,
    pub persisted_grant_id: String,
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
        Self::new(REASON_PROOF_INVALID, message)
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
    let Some(uuid) = value.strip_prefix("ck:device:") else {
        return false;
    };
    is_lowercase_uuidv7(uuid)
}

fn is_lowercase_uuidv7(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.iter().any(u8::is_ascii_uppercase) {
        return false;
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        match index {
            8 | 13 | 18 | 23 if byte != b'-' => return false,
            8 | 13 | 18 | 23 => {}
            _ if !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')) => return false,
            _ => {}
        }
    }
    bytes[14] == b'7' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

pub(super) fn principal_session_grant_scopes(device_id: &str) -> Vec<String> {
    vec![
        cokret::PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned(),
        format!("urn:cokret:client:device:{device_id}"),
    ]
}

fn soland_account_register_endpoint(principal_endpoint: &str) -> Result<url::Url, String> {
    let base = url::Url::parse(principal_endpoint)
        .map_err(|error| format!("invalid principal server endpoint: {error}"))?;
    base.join("/_cokret/gate/account/register")
        .map_err(|error| format!("invalid principal account register endpoint: {error}"))
}

/// Build the Principal Server localpart directory endpoint for `principal_did`.
///
/// RULING: DEPLOYMENT-INTERNAL S2S CONVENTION, NOT A PROTOCOL-FACE OPERATION.
/// This `/_soland/accounts/{did}/
/// localparts` edge is used during OIDC token exchange to *list and sync* the
/// account's primary localpart binding on the Principal Server
/// (`ensure_soland_account_localpart_bound`). It is intentionally NOT migrated
/// to the protocol directory reads `ck.find.directory.query.list_handles_for_
/// subject` / `resolve_handle`: those are read-only handle lookups and cannot
/// perform the write/sync binding this provisioning flow requires. coauth and
/// soland share this static-bearer-gated `/_soland/*` edge as a deployment-local
/// account-provisioning convention; it is registered here as such rather than as
/// a `/_cokret/*` protocol surface.
fn soland_account_localparts_endpoint(
    principal_endpoint: &str,
    principal_did: &str,
) -> Result<url::Url, String> {
    let base = url::Url::parse(principal_endpoint)
        .map_err(|error| format!("invalid principal server endpoint: {error}"))?;
    let account_did_path: String =
        form_urlencoded::byte_serialize(principal_did.as_bytes()).collect();
    base.join(&format!("/_soland/accounts/{account_did_path}/localparts"))
        .map_err(|error| format!("invalid principal account localparts endpoint: {error}"))
}

pub(super) fn principal_server_operation_bearer<'a>(
    cokret_config: &'a coauth_config::CokretConfig,
    audience: &str,
) -> Option<&'a str> {
    cokret_config
        .principal_servers
        .iter()
        .find(|server| server.audience == audience)
        .and_then(|server| server.embedded_webvh_registration_bearer.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn soland_account_register_body(
    principal_did: &str,
    handle: Option<&str>,
    display_name: Option<&str>,
    device_id: Option<&str>,
) -> Result<AccountRegisterRequestBody, String> {
    Ok(AccountRegisterRequestBody {
        principal_id: Did::new(principal_did.to_owned())
            .map_err(|error| format!("principal DID is invalid: {error}"))?,
        handle: handle.map(ToOwned::to_owned),
        display_name: display_name.map(ToOwned::to_owned),
        device_id: device_id
            .map(|value| {
                DeviceId::new(value.to_owned())
                    .map_err(|error| format!("device_id is invalid for account register: {error}"))
            })
            .transpose()?,
        policy_evidence: None,
        proof: None,
    })
}

async fn send_soland_account_register(
    http_client: &reqwest::Client,
    endpoint: &url::Url,
    body: &AccountRegisterRequestBody,
) -> Result<(reqwest::StatusCode, String), String> {
    let response =
        outbound_http::send_with_policy(outbound_http::soland_policy("account_register"), || {
            http_client.post(endpoint.clone()).json(body)
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

#[derive(Debug, serde::Serialize)]
struct AccountLocalpartSyncRequestBody<'a> {
    localpart: &'a str,
    is_primary: bool,
}

#[derive(Debug, serde::Deserialize)]
struct SolandAccountLocalpartListOutcome {
    localparts: Vec<SolandAccountLocalpartView>,
}

#[derive(Debug, serde::Deserialize)]
struct SolandAccountLocalpartView {
    localpart: String,
    is_primary: bool,
}

async fn fetch_soland_account_localparts(
    http_client: &reqwest::Client,
    endpoint: &url::Url,
    bearer: &str,
) -> Result<SolandAccountLocalpartListOutcome, String> {
    let response =
        outbound_http::send_with_policy(outbound_http::soland_policy("account_localparts"), || {
            http_client
                .get(endpoint.clone())
                .bearer_auth(bearer)
                .header(ACCEPT, APPLICATION_JSON.as_ref())
        })
        .await
        .map_err(|error| format!("principal account localparts request failed: {error}"))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(soland_account_localparts_failure("list", status, &body));
    }
    serde_json::from_str(&body)
        .map_err(|error| format!("principal account localparts response was invalid: {error}"))
}

async fn send_soland_account_localpart_sync(
    http_client: &reqwest::Client,
    endpoint: &url::Url,
    bearer: &str,
    localpart: &str,
) -> Result<(), String> {
    let body = AccountLocalpartSyncRequestBody {
        localpart,
        is_primary: true,
    };
    let response =
        outbound_http::send_with_policy(outbound_http::soland_policy("account_localparts"), || {
            http_client
                .post(endpoint.clone())
                .bearer_auth(bearer)
                .header(ACCEPT, APPLICATION_JSON.as_ref())
                .json(&body)
        })
        .await
        .map_err(|error| format!("principal account localpart sync request failed: {error}"))?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    Err(soland_account_localparts_failure("sync", status, &body))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SolandAccountRegisterConflict {
    AccountAlreadyExists,
    HandleAlreadyTaken,
}

fn classify_soland_account_register_conflict(
    status: reqwest::StatusCode,
    body: &str,
) -> Option<SolandAccountRegisterConflict> {
    if status != reqwest::StatusCode::CONFLICT {
        return None;
    }
    let envelope = serde_json::from_str::<ErrorEnvelope>(body).ok()?;
    if envelope.code() != cokret_core::error::ERROR_CODE_DUPLICATE_CONFLICT {
        return None;
    }
    match envelope.message() {
        "account already exists" => Some(SolandAccountRegisterConflict::AccountAlreadyExists),
        message
            if message.starts_with("handle localpart ")
                && message.ends_with("is already taken") =>
        {
            Some(SolandAccountRegisterConflict::HandleAlreadyTaken)
        }
        _ => None,
    }
}

fn soland_account_register_failure(status: reqwest::StatusCode, body: &str) -> String {
    format!(
        "principal account register returned {status}: {}",
        body.chars().take(256).collect::<String>()
    )
}

fn soland_account_localparts_failure(
    action: &str,
    status: reqwest::StatusCode,
    body: &str,
) -> String {
    format!(
        "principal account localparts {action} returned {status}: {}",
        body.chars().take(256).collect::<String>()
    )
}

async fn ensure_soland_account_localpart_bound(
    http_client: &reqwest::Client,
    principal_endpoint: &str,
    principal_did: &str,
    bearer: Option<&str>,
    localpart: Option<&str>,
) -> Result<(), String> {
    let Some(localpart) = localpart.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let Some(bearer) = bearer else {
        return Err(
            "principal account localpart sync requires embedded_webvh_registration_bearer"
                .to_owned(),
        );
    };
    let endpoint = soland_account_localparts_endpoint(principal_endpoint, principal_did)?;
    let current = fetch_soland_account_localparts(http_client, &endpoint, bearer).await?;
    if current
        .localparts
        .iter()
        .any(|record| record.localpart == localpart && record.is_primary)
    {
        return Ok(());
    }
    send_soland_account_localpart_sync(http_client, &endpoint, bearer, localpart).await
}

/// Resolve the `principal_did` for `user` against the targeted principal
/// server. The audience must correspond to a `PrincipalServerConfig` with
/// an embedded webvh provider; this mints (or re-uses) a
/// `did:webvh:<scid>:<principal_host>:webvh:<user_ulid>` through soland's
/// protocol DID operation endpoint so the DID's authority matches the host
/// that owns the identity registry.
pub(super) async fn ensure_principal_did_for_user(
    repo: &mut coauth_data::BoxRepository,
    rng: &mut coauth_data::BoxRng,
    clock: &coauth_data::BoxClock,
    encrypter: &coauth_keystore::Encrypter,
    http_client: &reqwest::Client,
    url_builder: &coauth_data::UrlBuilder,
    cokret_config: &coauth_config::CokretConfig,
    user: &User,
    audience: &str,
) -> Result<String, String> {
    let Some(principal_server) = cokret_config
        .principal_servers
        .iter()
        .find(|server| server.audience == audience)
    else {
        return Err(format!(
            "no principal-server config matches audience {audience}"
        ));
    };
    let operation_bearer = principal_server
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let also_known_as = vec![cokret::user_handle(url_builder, user)];
    let enrollment_authority_did =
        crate::services::device_enrollment_authority::enrollment_authority()
            .did()
            .to_owned();
    soland_webvh::ensure_principal_did_minted(
        repo,
        &mut **rng,
        &**clock,
        encrypter,
        http_client,
        user,
        &principal_server.audience,
        &principal_server.endpoint,
        operation_bearer,
        &also_known_as,
        &enrollment_authority_did,
    )
    .await
    .map_err(|error| format!("principal DID minting failed: {error}"))
}

/// Mint or load the principal DID in its own transaction.
///
/// DID issuance has an external side effect on the principal server. Keep the
/// local update-key row durable as soon as that side effect succeeds so a later
/// account-registration or session-grant failure cannot make the next retry
/// mint a second principal DID for the same user/audience.
pub(crate) async fn ensure_principal_did_for_user_committed(
    depot: &Depot,
    rng: &mut coauth_data::BoxRng,
    clock: &coauth_data::BoxClock,
    encrypter: &coauth_keystore::Encrypter,
    http_client: &reqwest::Client,
    url_builder: &coauth_data::UrlBuilder,
    cokret_config: &coauth_config::CokretConfig,
    user: &User,
    audience: &str,
) -> Result<String, String> {
    let mut did_repo = depot
        .repo()
        .await
        .map_err(|error| format!("principal DID repository unavailable: {error}"))?;
    let principal_did = match ensure_principal_did_for_user(
        &mut did_repo,
        rng,
        clock,
        encrypter,
        http_client,
        url_builder,
        cokret_config,
        user,
        audience,
    )
    .await
    {
        Ok(principal_did) => principal_did,
        Err(error) => {
            did_repo.cancel().await.ok();
            return Err(error);
        }
    };
    did_repo
        .save()
        .await
        .map_err(|error| format!("principal DID repository commit failed: {error}"))?;
    Ok(principal_did)
}

/// Canonical registration handle (`<localpart>:<domain>`) for the configured
/// principal server endpoint. The handle domain MUST be the principal server's
/// own host, not the OIDC issuer host (`auth.<domain>`) and not a domain
/// inferred from a DID method-specific identifier. soland owns principal DID
/// issuance, so coauth must not couple handle publication to `did:web`.
pub(super) fn registration_handle_for_principal_endpoint(
    principal_endpoint: Option<&str>,
    localpart: &str,
) -> Option<String> {
    let domain = principal_handle_domain_for_endpoint(principal_endpoint?)?;
    Some(format!("{}:{}", localpart.to_ascii_lowercase(), domain))
}

fn principal_handle_domain_for_endpoint(principal_endpoint: &str) -> Option<String> {
    let endpoint = url::Url::parse(principal_endpoint).ok()?;
    let host = endpoint.host_str()?.trim().trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase().replace(':', "."))
}

pub(super) async fn ensure_soland_account_registered(
    http_client: &reqwest::Client,
    principal_endpoint: Option<&str>,
    principal_did: &str,
    localpart_sync_bearer: Option<&str>,
    localpart: Option<&str>,
    handle: Option<&str>,
    display_name: Option<&str>,
    device_id: Option<&str>,
) -> Result<(), String> {
    let Some(principal_endpoint) = principal_endpoint else {
        return Ok(());
    };
    let endpoint = soland_account_register_endpoint(principal_endpoint)?;
    let request_body =
        soland_account_register_body(principal_did, handle, display_name, device_id)?;
    let (status, response_body) =
        send_soland_account_register(http_client, &endpoint, &request_body).await?;
    if status.is_success() {
        return ensure_soland_account_localpart_bound(
            http_client,
            principal_endpoint,
            principal_did,
            localpart_sync_bearer,
            localpart,
        )
        .await;
    }
    match classify_soland_account_register_conflict(status, &response_body) {
        Some(SolandAccountRegisterConflict::AccountAlreadyExists) => {
            ensure_soland_account_localpart_bound(
                http_client,
                principal_endpoint,
                principal_did,
                localpart_sync_bearer,
                localpart,
            )
            .await
        }
        Some(SolandAccountRegisterConflict::HandleAlreadyTaken) => {
            Err(soland_account_register_failure(status, &response_body))
        }
        _ => Err(soland_account_register_failure(status, &response_body)),
    }
}

/// Account Authority OIDC authorization-code → `ck.session.grant` exchange.
///
/// This is the core that the canonical
/// `POST /_cokret/gate/account/session-grants`
/// (`proof.proof_kind = "oidc_code_exchange"`) handler calls. It:
///
/// 1. resolves the issuer's live OIDC discovery metadata (local coauth issuer or a configured
///    federated upstream) and derives `token_endpoint` / `userinfo_endpoint` from it,
/// 2. exchanges `authorization_code` + `code_verifier` at the `token_endpoint`,
/// 3. validates issuer / state / nonce / redirect_uri / id_token nonce / principal binding / device
///    binding (`cnf.jkt` from the DPoP holder key) / audience, and
/// 4. mints + persists a device-bound `ck.session.grant`.
///
/// Binding failures surface as `proof_invalid`; transport / discovery failures
/// surface as their own registry codes.
pub(crate) async fn exchange_oidc_code_for_session_grant(
    req: &mut Request,
    depot: &Depot,
    dpop_binding: Option<DpopSessionBinding>,
    input: OidcCodeExchangeInput,
) -> Result<OidcExchangeSuccess, OidcExchangeError> {
    let mut rng = make_rng();
    let clock = make_clock();
    let url_builder = depot
        .url_builder()
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    let cokret_config = depot
        .cokret_config()
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

    // The DPoP holder proof is what binds the issued grant to the device key
    // (`cnf.jkt`). It is mandatory for an OIDC-issued session grant — without
    // it there is no device binding to validate.
    let Some(dpop_binding) = dpop_binding else {
        return Err(OidcExchangeError::proof_invalid(
            "OIDC session grants require a valid DPoP holder proof for device binding",
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
        || input.device_id.trim().is_empty()
    {
        return Err(OidcExchangeError::proof_invalid(
            "authorization_code, redirect_uri, issuer, client_id, state, nonce, and device_id are required for oidc_code_exchange",
        ));
    }
    let device_id = input.device_id.trim().to_owned();
    if !is_protocol_device_id(&device_id) {
        return Err(OidcExchangeError::proof_invalid(
            "device_id must be a ck:device:<uuidv7> protocol identifier",
        ));
    }

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
            return Err(OidcExchangeError::new(
                "account_unavailable",
                format!(
                    "linked local account username={} is locked or deactivated",
                    user.localpart
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
                &url_builder,
                &cokret_config,
                input.requested_audience.as_deref(),
            )
            .map_err(|message| OidcExchangeError::new("invalid_audience", message))?;
        let principal_did = ensure_principal_did_for_user_committed(
            depot,
            &mut rng,
            &clock,
            &encrypter,
            &http_client,
            &url_builder,
            &cokret_config,
            &user,
            &grant_target.audience,
        )
        .await
        .map_err(|message| OidcExchangeError::new("principal_did_minting_failed", message))?;

        validate_expected_principal(&principal_did, input.expected_principal_id.as_deref())?;

        let account_handle = registration_handle_for_principal_endpoint(
            grant_target.principal_server_endpoint.as_deref(),
            &user.localpart,
        );
        let localpart_sync_bearer =
            principal_server_operation_bearer(&cokret_config, &grant_target.audience);
        ensure_soland_account_registered(
            &http_client,
            grant_target.principal_server_endpoint.as_deref(),
            &principal_did,
            localpart_sync_bearer,
            Some(&user.localpart),
            account_handle.as_deref(),
            user.display_name.as_deref(),
            Some(device_id.as_str()),
        )
        .await
        .map_err(|message| {
            OidcExchangeError::new("principal_account_registration_failed", message)
        })?;

        let session_grant = cokret::issue_session_grant_for_audience(
            &*clock,
            &cokret_config,
            &key_store,
            &browser_session,
            dpop_binding.public_jwk.clone(),
            grant_target.audience.clone(),
            principal_session_grant_scopes(&device_id),
            Some(&principal_did),
            Some(dpop_binding.jkt.clone()),
        )
        .map_err(|error| OidcExchangeError::new("session_grant_denied", error.to_string()))?;
        let persisted = cokret::persist_session_grant(
            &mut repo,
            &mut rng,
            &*clock,
            &browser_session,
            &session_grant,
        )
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
        repo.save()
            .await
            .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;

        let _ = &service_activity_tracker;
        let _ = &grant_target;
        return Ok(OidcExchangeSuccess {
            principal_did,
            device_id,
            session_grant,
            persisted_grant_id: persisted.grant_id.to_string(),
        });
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
                        REASON_PROOF_INVALID,
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
    let expected_subject = cokret::user_did_for(&cokret_config, &browser_session.user);
    let expected_issuer = url_builder.oidc_issuer();
    let oauth_introspection = match crate::handlers::oauth::introspection_service::introspect_token(
        &mut repo,
        &clock,
        &url_builder,
        &cokret_config,
        &service_activity_tracker,
        &oauth_token_reply.access_token,
        Some(coauth_iana::oauth::OAuthTokenTypeHint::AccessToken),
        // Internal self-introspection of a token this bridge just minted;
        // the full device/principal/session association is required here.
        crate::handlers::oauth::introspection_service::CokretAssociationDisclosure::Full,
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
    if oauth_introspection.cokret_session_id.as_deref() != Some(expected_oauth_session_id.as_str())
    {
        return Err(OidcExchangeError::new(
            "invalid_authorization_code",
            format!(
                "fresh OAuth access token session mismatch: expected {} but introspection returned {}",
                expected_oauth_session_id,
                oauth_introspection
                    .cokret_session_id
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
    let mut repo = depot
        .repo()
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    if oauth_userinfo.sub != expected_subject {
        return Err(OidcExchangeError::proof_invalid(format!(
            "fresh OAuth userinfo subject mismatch: expected {} but userinfo returned {}",
            expected_subject, oauth_userinfo.sub
        )));
    }
    // `org.cokret.principal_did` is optional and only carries a persisted,
    // method-allowed principal DID. The local OAuth proof binds the account
    // with `sub` + session id; the audience-specific principal DID is minted
    // or loaded below before issuing the session grant.
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
            &url_builder,
            &cokret_config,
            input.requested_audience.as_deref(),
        )
        .map_err(|message| OidcExchangeError::new("invalid_audience", message))?;
    let user = &browser_session.user;
    let principal_did = ensure_principal_did_for_user_committed(
        depot,
        &mut rng,
        &clock,
        &encrypter,
        &http_client,
        &url_builder,
        &cokret_config,
        user,
        &grant_target.audience,
    )
    .await
    .map_err(|message| OidcExchangeError::new("principal_did_minting_failed", message))?;

    validate_expected_principal(&principal_did, input.expected_principal_id.as_deref())?;

    let account_handle = registration_handle_for_principal_endpoint(
        grant_target.principal_server_endpoint.as_deref(),
        &user.localpart,
    );
    let localpart_sync_bearer =
        principal_server_operation_bearer(&cokret_config, &grant_target.audience);
    ensure_soland_account_registered(
        &http_client,
        grant_target.principal_server_endpoint.as_deref(),
        &principal_did,
        localpart_sync_bearer,
        Some(&user.localpart),
        account_handle.as_deref(),
        user.display_name.as_deref(),
        Some(device_id.as_str()),
    )
    .await
    .map_err(|message| OidcExchangeError::new("principal_account_registration_failed", message))?;

    let session_grant = cokret::issue_session_grant_for_audience(
        &clock,
        &cokret_config,
        &key_store,
        &browser_session,
        dpop_binding.public_jwk,
        grant_target.audience.clone(),
        principal_session_grant_scopes(&device_id),
        Some(&principal_did),
        Some(dpop_binding.jkt),
    )
    .map_err(|error| OidcExchangeError::new("session_grant_denied", error.to_string()))?;
    let persisted = cokret::persist_session_grant(
        &mut repo,
        &mut rng,
        &clock,
        &browser_session,
        &session_grant,
    )
    .await
    .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;
    repo.save()
        .await
        .map_err(|e| OidcExchangeError::new("internal_error", e.to_string()))?;

    let _ = &grant_target;
    Ok(OidcExchangeSuccess {
        principal_did,
        device_id,
        session_grant,
        persisted_grant_id: persisted.grant_id.to_string(),
    })
}

/// Principal binding check: when the client asserts a `principal_id` in the
/// request body, the principal DID the Account Authority resolved / minted for
/// the authenticated user MUST equal it. A mismatch is a `proof_invalid`
/// binding failure — the client tried to bind the OIDC authentication to a DID
/// it does not actually own.
///
/// First sign-in (② contract D5) omits `principal_id` because the client does
/// not yet know its DID; in that case there is nothing to bind against and the
/// caller uses the AA-derived DID returned in `SessionGrantOutcome.principal_id`.
fn validate_expected_principal(
    resolved_principal_did: &str,
    expected_principal_id: Option<&str>,
) -> Result<(), OidcExchangeError> {
    // Treat a present-but-blank `principal_id` the same as omitted: the client
    // has nothing to bind, so the AA-derived DID stands.
    let Some(expected) = expected_principal_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    if expected != resolved_principal_did {
        // Do not echo the resolved principal DID back to the client: it is an
        // internal binding value the caller does not necessarily own.
        tracing::debug!(
            target: "coauth.oidc_exchange",
            request_principal_id = %expected,
            resolved_principal_did = %resolved_principal_did,
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
        contract: "cokret.rest.integration_manifest.v1".to_owned(),
        version: "2026-05-17-validated".to_owned(),
        service: "coauth".to_owned(),
        service_kind: "account_authority".to_owned(),
        api_base_path: "/_coauth".to_owned(),
        describe_path: "/_coauth/account/integration/describe".to_owned(),
        dependencies: vec![
            IntegrationManifestDependency {
                service: "soland".to_owned(),
                purpose: "principal_server_session_exchange".to_owned(),
                required_contract: "cokret.rest.principal_bridge.v1".to_owned(),
                discovery_path: "/_cokret/describe".to_owned(),
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
                path: "/_cokret/gate/account/session-grants".to_owned(),
                contract: "ck.gate.account.command.issue_session_grant".to_owned(),
                stability: "validated".to_owned(),
                todo: "canonical Account Authority grant issuance; proof.proof_kind=oidc_code_exchange exchanges the OIDC authorization code, validates issuer/state/nonce/redirect_uri/principal/device/audience, and mints the device-bound ck.session.grant.".to_owned(),
            },
            IntegrationManifestSurface {
                name: "passkey_auth".to_owned(),
                method: "POST".to_owned(),
                path: "/_coauth/account/auth/passkey/{register,auth}/{start,finish}".to_owned(),
                contract: "cokret.rest.passkey_auth.v1".to_owned(),
                stability: "preview".to_owned(),
                todo: "WebAuthn challenge and finish use the production passkey service; finish currently returns credential identity and still relies on the session-grant follow-up path.".to_owned(),
            },
            IntegrationManifestSurface {
                name: "admin_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/_coauth/admin/bridge/describe".to_owned(),
                contract: "cokret.rest.coauth_admin_bridge.v1".to_owned(),
                stability: "validated".to_owned(),
                todo: "risk-action proposals and approvals are persisted with admin audit trail.".to_owned(),
            },
            IntegrationManifestSurface {
                name: "account_claims".to_owned(),
                method: "GET".to_owned(),
                path: "/_coauth/admin/accounts/{account_id}/claims".to_owned(),
                contract: "cokret.rest.coauth_account_claims.v1".to_owned(),
                stability: "preview".to_owned(),
                todo: "claim inventory is backed by account-claims service and subject to PG isolation coverage.".to_owned(),
            },
            IntegrationManifestSurface {
                name: "account_session_grants".to_owned(),
                method: "GET".to_owned(),
                path: "/_coauth/admin/accounts/{account_id}/session-grants".to_owned(),
                contract: "cokret.rest.coauth_account_session_grants.v1".to_owned(),
                stability: "preview".to_owned(),
                todo: "session-grant inventory exposes persisted grant metadata and will gain broader PG isolation coverage.".to_owned(),
            },
        ],
        examples: serde_json::json!({
            "compose_strand": {
                "step_1": {
                    "service": "principal_server",
                    "path": "/_cokret/describe",
                    "method": "GET",
                    "note": "read auth_metadata.account_authority + methods[].oidc"
                },
                "step_2": {
                    "service": "oidc_issuer",
                    "path": "{methods[].oidc.openid_configuration}",
                    "method": "GET",
                    "note": "standard OIDC discovery -> PKCE authorize -> callback code"
                },
                "step_3": {
                    "service": "account_authority",
                    "path": "/_cokret/gate/account/session-grants",
                    "method": "POST",
                    "note": "proof.proof_kind=oidc_code_exchange"
                },
                "step_4": {
                    "service": "principal_server",
                    "path": "/_cokret/edge/push/register-device",
                    "method": "POST"
                }
            }
        }),
        todos: vec![],
    }))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request as WiremockRequest, ResponseTemplate};

    use super::*;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    const TEST_PRINCIPAL_DID: &str = "did:webvh:scid:local.host:webvh:01k";
    const TEST_DEVICE_ID: &str = "ck:device:01964137-0000-7000-8000-000000000001";
    const TEST_LOCALPARTS_BEARER: &str = "localparts-secret";
    const ACCOUNT_REGISTER_PATH: &str = "/_cokret/gate/account/register";

    fn account_localparts_path() -> String {
        let account_did_path: String =
            form_urlencoded::byte_serialize(TEST_PRINCIPAL_DID.as_bytes()).collect();
        format!("/_soland/accounts/{account_did_path}/localparts")
    }

    fn wire_error(code: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "ok": false,
            "error": {
                "code": code,
                "message": message,
            },
            "request_id": "ck:request:01964137-0000-7000-8000-000000000001",
        })
    }

    fn request_json(request: &WiremockRequest) -> serde_json::Value {
        serde_json::from_slice(&request.body).unwrap_or(serde_json::Value::Null)
    }

    fn request_has_handle(expected: &'static str) -> impl Fn(&WiremockRequest) -> bool {
        move |request| {
            request_json(request)
                .get("handle")
                .and_then(|value| value.as_str())
                == Some(expected)
        }
    }

    fn request_has_localpart(expected: &'static str) -> impl Fn(&WiremockRequest) -> bool {
        move |request| {
            request_json(request)
                .get("localpart")
                .and_then(|value| value.as_str())
                == Some(expected)
        }
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
            "ck:device:01964137-0000-7000-8000-000000000001"
        ));
        assert!(!is_protocol_device_id("dev_yougen"));
        assert!(!is_protocol_device_id(
            "ck:device:01964137-0000-6000-8000-000000000001"
        ));
    }

    #[test]
    fn principal_session_grant_scopes_include_device_binding() {
        let scopes =
            principal_session_grant_scopes("ck:device:01964137-0000-7000-8000-000000000001");

        assert!(scopes.contains(&cokret::PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()));
        assert!(scopes.contains(
            &"urn:cokret:client:device:ck:device:01964137-0000-7000-8000-000000000001".to_owned()
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
        // Matching client assertion → ok.
        assert!(
            validate_expected_principal(
                "did:webvh:scid:host:webvh:01k",
                Some("did:webvh:scid:host:webvh:01k")
            )
            .is_ok()
        );
        // First sign-in (② D5): omitted / blank principal_id is allowed — the
        // AA-derived DID stands, nothing to bind against.
        assert!(validate_expected_principal("did:webvh:scid:host:webvh:01k", None).is_ok());
        assert!(validate_expected_principal("did:webvh:scid:host:webvh:01k", Some("")).is_ok());
        assert!(validate_expected_principal("did:webvh:scid:host:webvh:01k", Some("   ")).is_ok());
        // A present-but-mismatched assertion is still a hard binding failure.
        let error = validate_expected_principal("did:webvh:a", Some("did:webvh:b"))
            .err()
            .unwrap();
        assert_eq!(error.code, "proof_invalid");
        assert!(error.message.contains("principal binding mismatch"));
    }

    #[test]
    fn soland_account_register_endpoint_uses_cokret_gate_path() {
        let endpoint = soland_account_register_endpoint("https://local.host/base/path").unwrap();

        // The standard account-register route lives at the service root;
        // the join must also discard any base path on the endpoint URL.
        assert_eq!(
            endpoint.as_str(),
            "https://local.host/_cokret/gate/account/register"
        );
    }

    #[test]
    fn registration_handle_uses_principal_endpoint_host() {
        assert_eq!(
            registration_handle_for_principal_endpoint(Some("https://local.host/"), "Alice")
                .as_deref(),
            Some("alice:local.host")
        );
        assert_eq!(
            registration_handle_for_principal_endpoint(
                Some("https://local.host/base/path"),
                "Alice"
            )
            .as_deref(),
            Some("alice:local.host")
        );
        assert_eq!(
            registration_handle_for_principal_endpoint(None, "Alice"),
            None
        );
    }

    #[tokio::test]
    async fn soland_account_register_handle_conflict_blocks_grant() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ACCOUNT_REGISTER_PATH))
            .and(request_has_handle("alice:local.host"))
            .respond_with(ResponseTemplate::new(409).set_body_json(wire_error(
                cokret_core::error::ERROR_CODE_DUPLICATE_CONFLICT,
                "handle localpart `alice` is already taken",
            )))
            .expect(1)
            .mount(&server)
            .await;

        let error = ensure_soland_account_registered(
            &reqwest::Client::new(),
            Some(&server.uri()),
            TEST_PRINCIPAL_DID,
            Some(TEST_LOCALPARTS_BEARER),
            Some("alice"),
            Some("alice:local.host"),
            Some("Alice"),
            Some(TEST_DEVICE_ID),
        )
        .await
        .expect_err("handle/localpart conflicts must block grant issuance");

        assert!(error.contains("handle localpart `alice` is already taken"));
    }

    #[tokio::test]
    async fn soland_account_register_failed_precondition_is_not_swallowed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ACCOUNT_REGISTER_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(wire_error(
                cokret_core::error::ERROR_CODE_FAILED_PRECONDITION,
                "account registration is closed",
            )))
            .expect(1)
            .mount(&server)
            .await;

        let error = ensure_soland_account_registered(
            &reqwest::Client::new(),
            Some(&server.uri()),
            TEST_PRINCIPAL_DID,
            Some(TEST_LOCALPARTS_BEARER),
            Some("alice"),
            Some("alice:local.host"),
            Some("Alice"),
            Some(TEST_DEVICE_ID),
        )
        .await
        .expect_err("registration policy failures must block grant issuance");

        assert!(error.contains("account registration is closed"));
    }

    #[tokio::test]
    async fn soland_account_register_existing_account_conflict_syncs_localpart() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ACCOUNT_REGISTER_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(wire_error(
                cokret_core::error::ERROR_CODE_DUPLICATE_CONFLICT,
                "account already exists",
            )))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(account_localparts_path()))
            .and(request_has_bearer(TEST_LOCALPARTS_BEARER))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "account_did": TEST_PRINCIPAL_DID,
                "primary_localpart": null,
                "localparts": [],
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(account_localparts_path()))
            .and(request_has_bearer(TEST_LOCALPARTS_BEARER))
            .and(request_has_localpart("alice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "localpart": {
                    "id": "ck:account_localpart:01964137-0000-7000-8000-000000000002",
                    "localpart": "alice",
                    "is_primary": true,
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        ensure_soland_account_registered(
            &reqwest::Client::new(),
            Some(&server.uri()),
            TEST_PRINCIPAL_DID,
            Some(TEST_LOCALPARTS_BEARER),
            Some("alice"),
            Some("alice:local.host"),
            Some("Alice"),
            Some(TEST_DEVICE_ID),
        )
        .await
        .expect("existing account conflict still syncs localpart");
    }

    /// The canonical Account Authority grant endpoint rejects an
    /// `oidc_code_exchange` proof that arrives without a DPoP holder proof:
    /// the grant has no device key to bind to (`proof_invalid`). Exercised
    /// against the real router so the route wiring is covered too.
    #[tokio::test]
    async fn session_grant_oidc_exchange_requires_dpop_holder_proof() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool(pool.clone()).await.unwrap();

        let response = state
            .request(Request::post("/_cokret/gate/account/session-grants").json(
                serde_json::json!({
                    "principal_id": "did:webvh:scid:offline.invalid:webvh:01k",
                    "device_id": "ck:device:01964137-0000-7000-8000-000000000001",
                    "proof": {
                        "proof_kind": "oidc_code_exchange",
                        "challenge": "0123456789abcdef0123",
                        "request_canonical_digest": format!("sha256:{}", "0".repeat(64)),
                        "audience": "https://soland.example.com/api",
                        "signature": "unused-for-oidc",
                        "issuer": "https://offline.invalid",
                        "client_id": "yougen",
                        "redirect_uri": "http://localhost:8080/auth/callback",
                        "state": "ck-state-0123456789abcdef",
                        "nonce": "ck-nonce-0123456789abcdef",
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
