//! OIDC authorization-code → AccountHandoff authentication core.
//!
//! This module is the Account Authority's OIDC proof validator. It used to
//! also serve the product-private `/_coauth/.../auth/oidc/{browser-bridge,
//! exchange}` bridge endpoints; those are removed (account-lifecycle §4.1,
//! service-surface.md §2.5.1). The canonical entry point is now the spec
//! operation `POST /_arkret/gate/account/authentication-handoffs`. SessionGrant
//! issuance consumes only the resulting AccountHandoff and never exchanges an
//! OIDC authorization code directly.

// `IntegrationManifest` (and the nested `IntegrationManifestDependency`
// / `IntegrationManifestSurface`) live in
// `coauth_admin_types::integration_manifest_admin` so the sodmin admin SPA
// decodes them through the same typed shape. The `integration_describe`
// endpoint below returns the shared `IntegrationManifest` directly.
use arkret_identifiers::{DeviceId, Did, DidCoreId};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use coauth_admin_types::{
    IntegrationManifest, IntegrationManifestDependency, IntegrationManifestSurface,
};
use coauth_data::upstream_oauth::provider;
use coauth_data::{AuthorizationGrant, BoxRepository, RepositoryAccess, Session, User};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_oauth_types::errors::{ClientError, ClientErrorCode};
use coauth_oauth_types::requests::{
    AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant as OAuthAuthorizationCodeGrant,
};
use http::header::ACCEPT;
use mime::APPLICATION_JSON;
use salvo::prelude::*;
use soland_contracts::admin::AccountLocalpartAddRequestBody;
use ulid::Ulid;

use super::{DepotExt, DpopSessionBinding, RouteError, make_clock, make_rng};
use crate::handlers::arkret;
use crate::handlers::oauth::token_service::{
    AuthorizationCodeExchangeError, ValidatedAuthorizationCode, end_session_on_code_reuse,
    validate_authorization_code,
};
use crate::oidc_client::requests::discovery;
use crate::oidc_client::types::client_credentials::ClientCredentials;
use crate::outbound_http::{self, RequestBuilderExt as _};
use crate::services::upstream_oidc::UpstreamOidcExchangeMode;
use crate::services::upstream_oidc_mapping::{TrustedIssuerPolicySet, map_upstream_id_token};

/// Typed input for the AccountHandoff OIDC authorization-code exchange. The
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
    /// `proof.audience` — the requested station audience.
    pub requested_audience: Option<String>,
}

/// Successful OIDC authentication used to create a short-lived account
/// handoff. No principal binding or device-bound session grant exists yet.
pub(crate) struct OidcHandoffExchangeSuccess {
    pub user: User,
    pub browser_session_id: Option<Ulid>,
    pub audience: String,
}

/// Coauth's declared v1 recovery policy permits fresh OIDC account
/// authentication to produce only the short-lived AccountHandoff for a
/// deactivated account. Every ordinary session/grant path still applies the
/// active-account gate, and only recovery completion may restore the status.
fn account_handoff_auth_status_allowed(status: AccountStatus) -> bool {
    matches!(status, AccountStatus::Active | AccountStatus::Deactivated)
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

fn soland_account_register_endpoint(principal_endpoint: &str) -> Result<url::Url, String> {
    let base = url::Url::parse(principal_endpoint)
        .map_err(|error| format!("invalid Station endpoint: {error}"))?;
    base.join(soland_contracts::ACCOUNT_PROJECTION_PATH)
        .map_err(|error| format!("invalid principal account register endpoint: {error}"))
}

fn soland_account_localparts_endpoint(
    principal_endpoint: &str,
    principal_id: &str,
) -> Result<url::Url, String> {
    let endpoint = url::Url::parse(principal_endpoint)
        .map_err(|error| format!("invalid Station endpoint: {error}"))?;
    let principal_id = DidCoreId::new(principal_id.to_owned())
        .map_err(|error| format!("invalid principal id: {error}"))?;
    soland_contracts::account_localparts_endpoint(endpoint, &principal_id)
        .map_err(|error| error.to_string())
}

fn soland_account_register_body(
    principal: &VerifiedPrincipalIdentity,
    display_name: Option<&str>,
    device_id: Option<&str>,
) -> Result<soland_contracts::AccountProjectionRequestBody, String> {
    Ok(soland_contracts::AccountProjectionRequestBody {
        principal_id: principal.principal_id.clone(),
        did: principal.did.clone(),
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
    body: &soland_contracts::AccountProjectionRequestBody,
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
    pub did: Did,
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

/// Validate an OIDC authorization code to create an AccountHandoff. This is
/// the only current-v1 OIDC code consumer.
pub(crate) async fn exchange_oidc_code_for_account_handoff(
    req: &mut Request,
    depot: &Depot,
    dpop_binding: DpopSessionBinding,
    input: OidcCodeExchangeInput,
) -> Result<OidcHandoffExchangeSuccess, OidcExchangeError> {
    exchange_oidc_code(req, depot, dpop_binding, input).await
}

/// Successful in-process local-issuer authentication for account-handoff
/// creation. Carries the authoritative rows the caller needs to finish the
/// handoff in its own transaction: the user, the bound sessions, and the
/// still-unconsumed authorization grant (row-locked `FOR UPDATE`).
pub(crate) struct LocalHandoffAuthentication {
    pub user: User,
    pub browser_session_id: Ulid,
    pub oauth_session: Session,
    pub authorization_grant: AuthorizationGrant,
    pub audience: String,
}

/// Authenticate a local-issuer OIDC authorization-code proof for account
/// handoff creation without any issuer self-call.
///
/// This replaces the old discovery/token/introspection/userinfo HTTP loop for
/// the `LocalCoauth` handoff path. It performs the same binding checks the
/// bridge always applied locally (PKCE, state, nonce, exact redirect URI,
/// client id, public-client authentication method), delegates the grant
/// stage/session/client/PKCE validation to the shared
/// [`validate_authorization_code`] core (which row-locks the grant
/// `FOR UPDATE`), and keeps the safety gates the skipped HTTP handlers used
/// to enforce: an active OAuth session, an active account, and the `openid`
/// scope.
///
/// The grant is NOT consumed here: the caller consumes it with `exchange` in
/// its own transaction so code consumption and the handoff outcome commit
/// atomically. The repository is never saved or cancelled by this function,
/// and no outbound HTTP is performed.
pub(crate) async fn authenticate_local_handoff_code(
    depot: &Depot,
    repo: &mut BoxRepository,
    clock: &impl coauth_data::Clock,
    input: &OidcCodeExchangeInput,
) -> Result<LocalHandoffAuthentication, OidcExchangeError> {
    let url_builder = depot.url_builder().map_err(exchange_internal_error)?;
    let arkret_config = depot.arkret_config().map_err(exchange_internal_error)?;
    let upstream_oidc = depot
        .upstream_oidc_service()
        .map_err(exchange_internal_error)?;

    // This helper only serves the local issuer; the caller routes federated
    // issuers to `exchange_oidc_code_for_account_handoff`.
    let issuer = url::Url::parse(input.issuer.trim())
        .map_err(|_| OidcExchangeError::proof_invalid("issuer must be a valid absolute URI"))?;
    if issuer != url_builder.oidc_issuer() {
        return Err(OidcExchangeError::new(
            "internal_error",
            "local handoff authentication called for a non-local issuer",
        ));
    }

    // --- structural validation of the proof fields ------------------------
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
    let redirect_uri = url::Url::parse(input.redirect_uri.trim()).map_err(|_| {
        OidcExchangeError::proof_invalid("redirect_uri must be a valid absolute URI")
    })?;

    // --- handoff-specific binding checks (unchanged from the self-call) ---
    let authz_grant = repo
        .oauth_authorization_grant()
        .find_by_code(input.authorization_code.trim())
        .await
        .map_err(exchange_internal_error)?
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
        .map_err(exchange_internal_error)?
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

    // --- shared grant/session validation core (locks the grant row) -------
    let oauth_code_grant = OAuthAuthorizationCodeGrant {
        code: input.authorization_code.trim().to_owned(),
        redirect_uri: Some(redirect_uri),
        code_verifier: Some(input.code_verifier.trim().to_owned()),
    };
    let validated = match validate_authorization_code(repo, clock, &oauth_code_grant, &oauth_client)
        .await
    {
        Ok(validated) => validated,
        Err(AuthorizationCodeExchangeError::AlreadyExchanged {
            session_id,
            beyond_reuse_window,
            ..
        }) => {
            // Preserve the token endpoint's replay defence: a code replayed
            // beyond the reuse window ends the potentially compromised
            // session. This transaction holds the grant row lock and must
            // stay rollback-clean, so the session termination commits through
            // a separate repository (it only touches the session row, so the
            // lock order cannot cycle).
            if beyond_reuse_window {
                let kill_repo = depot.repo().await.map_err(exchange_internal_error)?;
                end_session_on_code_reuse(kill_repo, clock, session_id)
                    .await
                    .map_err(|error| {
                        OidcExchangeError::new(
                            "internal_error",
                            format!(
                                "failed to end the session bound to a replayed authorization_code: {error}"
                            ),
                        )
                    })?;
            }
            return Err(OidcExchangeError::new(
                "invalid_authorization_code",
                "authorization_code was already exchanged",
            ));
        }
        Err(error) => return Err(map_local_authorization_code_error(error)),
    };
    let ValidatedAuthorizationCode {
        authorization_grant,
        session: oauth_session,
        browser_session,
    } = validated;

    // --- gates previously enforced by the self-introspection / userinfo ---
    // The skipped HTTP handlers rejected an inactive OAuth session, an
    // inactive account, and a session without the `openid` scope; apply the
    // same gates directly to the authoritative rows.
    if !oauth_session.is_valid() {
        return Err(OidcExchangeError::new(
            "invalid_authorization_code",
            "authorization_code is bound to an inactive OAuth session",
        ));
    }
    let user = browser_session.user.clone();
    if !account_handoff_auth_status_allowed(user.status) {
        return Err(OidcExchangeError::new(
            "invalid_authorization_code",
            "authorization_code is bound to an inactive account",
        ));
    }
    if !oauth_session
        .scope
        .contains(&coauth_oauth_types::scope::OPENID)
    {
        return Err(OidcExchangeError::new(
            "invalid_authorization_code",
            "authorization_code OAuth session does not carry the openid scope",
        ));
    }

    // Purely local, fail-closed audience resolution: no network refresh may
    // happen while the caller's transaction is open.
    let grant_target = upstream_oidc
        .session_grant_target_for_configured_audience(
            &url_builder,
            &arkret_config,
            crate::services::station_trust::shared(),
            input.requested_audience.as_deref(),
        )
        .map_err(|message| OidcExchangeError::new("invalid_audience", message))?;

    Ok(LocalHandoffAuthentication {
        user,
        browser_session_id: browser_session.id,
        oauth_session,
        authorization_grant,
        audience: grant_target.audience,
    })
}

/// Map the shared authorization-code validation failures onto the exchange
/// error codes the removed self-call path produced from the token endpoint's
/// HTTP responses, so the client-visible envelope stays unchanged. The
/// mapping is exhaustive over the typed error instead of matching on the
/// token endpoint's error description strings.
fn map_local_authorization_code_error(error: AuthorizationCodeExchangeError) -> OidcExchangeError {
    match error {
        AuthorizationCodeExchangeError::UnauthorizedClient(_)
        | AuthorizationCodeExchangeError::UnexpectedClient { .. } => OidcExchangeError::new(
            "invalid_client",
            format!("local authorization_code validation rejected the client: {error}"),
        ),
        AuthorizationCodeExchangeError::GrantNotFound
        | AuthorizationCodeExchangeError::InvalidGrant(_)
        | AuthorizationCodeExchangeError::AlreadyExchanged { .. } => OidcExchangeError::new(
            "invalid_authorization_code",
            format!("local authorization_code validation rejected the grant: {error}"),
        ),
        AuthorizationCodeExchangeError::PkceVerification(_) => OidcExchangeError::proof_invalid(
            format!("PKCE verifier did not match authorization_code challenge: {error}"),
        ),
        AuthorizationCodeExchangeError::BadRequest => OidcExchangeError::new(
            "invalid_request",
            "local authorization_code validation rejected the request: missing or mismatched PKCE parameters",
        ),
        AuthorizationCodeExchangeError::NoSuchBrowserSession(_)
        | AuthorizationCodeExchangeError::NoSuchOAuthSession(_)
        | AuthorizationCodeExchangeError::ProvisionDeviceFailed(_)
        | AuthorizationCodeExchangeError::Repository(_)
        | AuthorizationCodeExchangeError::Internal(_) => OidcExchangeError::new(
            "internal_error",
            format!("local authorization_code validation failed: {error}"),
        ),
    }
}

/// Wrap a depot-resolution or repository failure as the exchange's
/// `internal_error`.
///
/// Every dependency this endpoint pulls out of the depot is placed there by
/// `server::routers` at boot, so a miss is a wiring bug rather than anything
/// the caller can influence.
fn exchange_internal_error(error: impl std::fmt::Display) -> OidcExchangeError {
    OidcExchangeError::new("internal_error", error.to_string())
}

/// Reject an `oidc_code_exchange` body that cannot describe a PKCE-bound
/// authorization-code redemption, before any depot dependency or repository
/// transaction is touched.
///
/// Returns the two parsed absolute URIs the exchange needs downstream.
fn validate_oidc_code_exchange_input(
    input: &OidcCodeExchangeInput,
) -> Result<(url::Url, url::Url), OidcExchangeError> {
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
    let redirect_uri = url::Url::parse(input.redirect_uri.trim()).map_err(|_| {
        OidcExchangeError::proof_invalid("redirect_uri must be a valid absolute URI")
    })?;
    let issuer = url::Url::parse(input.issuer.trim())
        .map_err(|_| OidcExchangeError::proof_invalid("issuer must be a valid absolute URI"))?;
    Ok((redirect_uri, issuer))
}

async fn exchange_oidc_code(
    req: &mut Request,
    depot: &Depot,
    _dpop_binding: DpopSessionBinding,
    input: OidcCodeExchangeInput,
) -> Result<OidcHandoffExchangeSuccess, OidcExchangeError> {
    let (redirect_uri, issuer) = validate_oidc_code_exchange_input(&input)?;

    let mut rng = make_rng();
    let clock = make_clock();
    let url_builder = depot.url_builder().map_err(exchange_internal_error)?;
    let arkret_config = depot.arkret_config().map_err(exchange_internal_error)?;
    let keyring = depot.keyring().map_err(exchange_internal_error)?;
    let encrypter = depot.encrypter().map_err(exchange_internal_error)?;
    let upstream_oidc = depot
        .upstream_oidc_service()
        .map_err(exchange_internal_error)?;
    let http_client = depot
        .get::<reqwest::Client>("http_client")
        .cloned()
        .map_err(|_| exchange_internal_error("http_client not found in depot"))?;
    let service_activity_tracker = depot
        .get::<crate::handlers::ActivityTracker>("activity_tracker")
        .cloned()
        .map_err(|_| exchange_internal_error("activity_tracker not found in depot"))?;
    let mut repo = depot.repo().await.map_err(exchange_internal_error)?;

    let enabled_upstream_providers = repo
        .upstream_oauth_provider()
        .all_enabled()
        .await
        .map_err(exchange_internal_error)?;
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
            provider::DiscoveryMode::Oidc => {
                discovery::discover(&http_client, issuer.as_str()).await
            }
            provider::DiscoveryMode::Insecure => {
                tracing::warn!(
                    target: "coauth.oidc_exchange",
                    %issuer,
                    provider = %provider.human_name.as_deref().unwrap_or(provider.client_id.as_str()),
                    "OIDC discovery is running in insecure mode for a federated upstream provider; \
                     this bypasses validation and must only be used in development environments",
                );
                discovery::insecure_discover(&http_client, issuer.as_str()).await
            }
            provider::DiscoveryMode::Disabled => {
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
                &keyring,
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
        // policy is configured; the `find_by_subject` flow stays the source
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
            .map_err(exchange_internal_error)?
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
            .map_err(exchange_internal_error)?
            .ok_or_else(|| {
                OidcExchangeError::new(
                    "internal_error",
                    format!(
                        "federated upstream link={} points to missing user={user_id}",
                        upstream_link.id
                    ),
                )
            })?;
        if !account_handoff_auth_status_allowed(user.status) {
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
            .map_err(exchange_internal_error)?;
        let grant_target = upstream_oidc
            .session_grant_target_for_requested_audience(
                &url_builder,
                &arkret_config,
                crate::services::station_trust::shared(),
                input.requested_audience.as_deref(),
            )
            .map_err(|message| OidcExchangeError::new("invalid_audience", message))?;
        let success = OidcHandoffExchangeSuccess {
            user,
            browser_session_id: Some(browser_session.id),
            audience: grant_target.audience,
        };
        repo.save().await.map_err(exchange_internal_error)?;
        let _ = &service_activity_tracker;
        return Ok(success);
    }

    // ─── Local coauth issuer branch ─────────────────────────────────────
    let authz_grant = repo
        .oauth_authorization_grant()
        .find_by_code(input.authorization_code.trim())
        .await
        .map_err(exchange_internal_error)?
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
        .map_err(exchange_internal_error)?
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
    repo.cancel().await.map_err(exchange_internal_error)?;
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
    let mut repo = depot.repo().await.map_err(exchange_internal_error)?;

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
        .map_err(exchange_internal_error)?
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
        .map_err(exchange_internal_error)?
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
    repo.cancel().await.map_err(exchange_internal_error)?;
    let (oauth_userinfo, _userinfo_response_signed) = upstream_oidc
        .fetch_local_oidc_userinfo(
            &http_client,
            &keyring,
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

    let _ = (&browser_session, &upstream_oidc, &service_activity_tracker);
    Err(OidcExchangeError::new(
        "internal_error",
        "local AccountHandoff OIDC must use the in-process authorization-code validator",
    ))
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
                purpose: "station_session_exchange".to_owned(),
                required_contract: "arkret.rest.principal_bridge.v1".to_owned(),
                discovery_path: "/_arkret/describe".to_owned(),
                mode: "remote_service_contract".to_owned(),
            },
            IntegrationManifestDependency {
                service: "public_did_resolver".to_owned(),
                purpose: "principal_id_resolution".to_owned(),
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
                contract:
                    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT_V1
                        .to_owned(),
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request as WiremockRequest, ResponseTemplate};

    use super::*;

    const TEST_PRINCIPAL_ID: &str = "ak:did_core:webvh:scid:local.host";
    const TEST_PRINCIPAL_DID: &str = "did:webvh:scid:local.host:webvh:01k";
    const TEST_DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";
    const TEST_OPERATION_BEARER: &str = "account-operation-secret";
    const ACCOUNT_REGISTER_PATH: &str = soland_contracts::ACCOUNT_PROJECTION_PATH;

    fn test_principal() -> VerifiedPrincipalIdentity {
        let principal_id = DidCoreId::new(TEST_PRINCIPAL_ID).unwrap();
        VerifiedPrincipalIdentity {
            principal_id,
            did: Did::new(TEST_PRINCIPAL_DID).unwrap(),
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
    fn account_handoff_auth_allows_only_active_or_recovery_candidate() {
        assert!(account_handoff_auth_status_allowed(AccountStatus::Active));
        assert!(account_handoff_auth_status_allowed(
            AccountStatus::Deactivated
        ));
        for status in [
            AccountStatus::SoftLoggedOut,
            AccountStatus::Locked,
            AccountStatus::Suspended,
            AccountStatus::ErasurePending,
        ] {
            assert!(!account_handoff_auth_status_allowed(status));
        }
    }

    #[test]
    fn soland_account_register_endpoint_uses_private_projection_path() {
        let endpoint = soland_account_register_endpoint("https://local.host/base/path").unwrap();

        // The standard account-register route lives at the service root;
        // the join must also discard any base path on the endpoint URL.
        assert_eq!(
            endpoint.as_str(),
            "https://local.host/_soland/gate/account/project"
        );
    }

    #[test]
    fn soland_account_localparts_endpoint_encodes_principal_id_segment() {
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

    /// The typed mapping of shared validation-core failures must reproduce
    /// the exchange error codes the removed self-call derived from the token
    /// endpoint's HTTP status + error-description strings.
    #[test]
    fn local_code_error_mapping_matches_self_call_baseline() {
        let pkce_failure = coauth_data::Pkce {
            challenge_method: coauth_iana::oauth::PkceCodeChallengeMethod::S256,
            challenge: "A".repeat(43),
        }
        .verify(&"B".repeat(43))
        .expect_err("a mismatched verifier must fail PKCE verification");

        let cases: [(AuthorizationCodeExchangeError, &str); 10] = [
            (
                AuthorizationCodeExchangeError::GrantNotFound,
                "invalid_authorization_code",
            ),
            (
                AuthorizationCodeExchangeError::InvalidGrant(Ulid::generate()),
                "invalid_authorization_code",
            ),
            (
                AuthorizationCodeExchangeError::AlreadyExchanged {
                    grant_id: Ulid::generate(),
                    session_id: Ulid::generate(),
                    beyond_reuse_window: false,
                },
                "invalid_authorization_code",
            ),
            (
                AuthorizationCodeExchangeError::PkceVerification(pkce_failure),
                arkret_wire::ReasonCode::PROOF_INVALID,
            ),
            (
                AuthorizationCodeExchangeError::BadRequest,
                "invalid_request",
            ),
            (
                AuthorizationCodeExchangeError::UnauthorizedClient(Ulid::generate()),
                "invalid_client",
            ),
            (
                AuthorizationCodeExchangeError::UnexpectedClient {
                    was: Ulid::generate(),
                    expected: Ulid::generate(),
                },
                "invalid_client",
            ),
            (
                AuthorizationCodeExchangeError::NoSuchOAuthSession(Ulid::generate()),
                "internal_error",
            ),
            (
                AuthorizationCodeExchangeError::NoSuchBrowserSession(Ulid::generate()),
                "internal_error",
            ),
            (
                AuthorizationCodeExchangeError::Internal("boom".into()),
                "internal_error",
            ),
        ];
        for (error, expected_code) in cases {
            let mapped = map_local_authorization_code_error(error);
            assert_eq!(mapped.code, expected_code);
        }
    }
}
