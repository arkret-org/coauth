//! Business logic for OAuth token endpoint grant types.
//!
//! This module extracts the core grant-type handling out of the token endpoint
//! HTTP handler (`oauth::token`) so that the handler is responsible only for
//! HTTP-level concerns (request parsing, client authentication, metrics,
//! response formatting) while the actual authorization/token logic lives here.

use coauth_data::{Client, RepositoryError};
use coauth_iana::oauth::{OAuthClientAuthenticationMethod, PkceCodeChallengeMethod};
use coauth_oauth_types::pkce::CodeChallengeError;
use coauth_oauth_types::requests::GrantType;
use coauth_oauth_types::scope;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::oauth::IdTokenSignatureError;

mod authorization_code;
mod client_credentials;
mod device_code;
mod refresh_token;

#[cfg(test)]
mod tests;

pub use authorization_code::exchange_authorization_code;
pub use client_credentials::handle_client_credentials;
pub use device_code::exchange_device_code;
pub use refresh_token::handle_refresh_token;

/// Clamp a configured access-token TTL to the hard ceiling
/// (`MAX_ACCESS_TOKEN_TTL_SECS`, 15 minutes).
///
/// Bearer access tokens are not revocation-checked on each request, so their
/// lifetime is the window an attacker retains access after a leak. The
/// configuration schema already caps the value, but we clamp again at issuance
/// as defence in depth so a tampered or legacy config can never mint a
/// long-lived bearer token. This matches the soland-side
/// `capped_bearer_expiry <= 15min` rule.
#[must_use]
pub(crate) fn capped_access_token_ttl(ttl: chrono::Duration) -> chrono::Duration {
    let ceiling = chrono::Duration::seconds(coauth_config::MAX_ACCESS_TOKEN_TTL_SECS);
    ttl.min(ceiling)
}

/// Public authorization-code clients must use PKCE. Confidential clients can
/// still use PKCE, but do not require it under OIDC Core.
#[must_use]
pub(crate) fn authorization_code_pkce_required(client: &Client) -> bool {
    client.grant_types.contains(&GrantType::AuthorizationCode)
        && matches!(
            client.token_endpoint_auth_method.as_ref(),
            Some(OAuthClientAuthenticationMethod::None)
        )
}

/// Whether a given PKCE challenge method is acceptable.
///
/// SECURITY: `plain` is rejected universally — for both public *and*
/// confidential clients — because it offers no protection against an
/// authorization-code interception attack. RFC 7636 §4.2 marks `plain`
/// as deprecated and OAuth 2.1 (§7.5) outright bans it. Since this
/// project has no released clients, there is no compatibility cost.
#[must_use]
pub(crate) fn required_pkce_method_is_allowed(method: &PkceCodeChallengeMethod) -> bool {
    *method == PkceCodeChallengeMethod::S256
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during authorization code exchange.
#[derive(Debug, Error)]
pub enum AuthorizationCodeExchangeError {
    #[error("client is not authorized to use the authorization_code grant type")]
    UnauthorizedClient(Ulid),

    #[error("authorization grant not found")]
    GrantNotFound,

    #[error("invalid grant {0}")]
    InvalidGrant(Ulid),

    #[error("pkce verification failed")]
    PkceVerification(#[from] CodeChallengeError),

    #[error("bad request (missing or mismatched PKCE)")]
    BadRequest,

    #[error("unexpected client {was} (expected {expected})")]
    UnexpectedClient { was: Ulid, expected: Ulid },

    #[error("failed to load browser session {0}")]
    NoSuchBrowserSession(Ulid),

    #[error("failed to load oauth session {0}")]
    NoSuchOAuthSession(Ulid),

    #[error("failed to provision device")]
    ProvisionDeviceFailed(#[source] anyhow::Error),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<coauth_i18n::FormatError> for AuthorizationCodeExchangeError {
    fn from(e: coauth_i18n::FormatError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<coauth_i18n::icu_locid::ParseError> for AuthorizationCodeExchangeError {
    fn from(e: coauth_i18n::icu_locid::ParseError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<coauth_templates::TemplateError> for AuthorizationCodeExchangeError {
    fn from(e: coauth_templates::TemplateError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<IdTokenSignatureError> for AuthorizationCodeExchangeError {
    fn from(e: IdTokenSignatureError) -> Self {
        Self::Internal(Box::new(e))
    }
}

/// Errors that can occur during refresh token exchange.
#[derive(Debug, Error)]
pub enum RefreshTokenExchangeError {
    #[error("client is not authorized to use the refresh_token grant type")]
    UnauthorizedClient(Ulid),

    #[error("refresh token not found")]
    RefreshTokenNotFound,

    #[error("refresh token {0} is invalid")]
    RefreshTokenInvalid(Ulid),

    #[error("session {0} is invalid")]
    SessionInvalid(Ulid),

    #[error("client id mismatch: expected {expected}, got {actual}")]
    ClientIdMismatch { expected: Ulid, actual: Ulid },

    #[error("failed to load oauth session {0}")]
    NoSuchOAuthSession(Ulid),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Errors that can occur during client credentials grant.
#[derive(Debug, Error)]
pub enum ClientCredentialsGrantError {
    #[error("client is not authorized to use the client_credentials grant type")]
    UnauthorizedClient(Ulid),

    #[error("policy denied the request: {0}")]
    DeniedByPolicy(coauth_policy::EvaluationResult),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<coauth_policy::EvaluationError> for ClientCredentialsGrantError {
    fn from(e: coauth_policy::EvaluationError) -> Self {
        Self::Internal(Box::new(e))
    }
}

/// Errors that can occur during device code exchange.
#[derive(Debug, Error)]
pub enum DeviceCodeExchangeError {
    #[error("client is not authorized to use the device_code grant type")]
    UnauthorizedClient(Ulid),

    #[error("grant not found")]
    GrantNotFound,

    #[error("client id mismatch: expected {expected}, got {actual}")]
    ClientIdMismatch { expected: Ulid, actual: Ulid },

    #[error("device code grant expired")]
    DeviceCodeExpired,

    #[error("device code grant is still pending")]
    DeviceCodePending,

    #[error("device code grant was rejected")]
    DeviceCodeRejected,

    #[error("device code grant was already exchanged")]
    DeviceCodeExchanged,

    #[error("failed to load browser session {0}")]
    NoSuchBrowserSession(Ulid),

    #[error("failed to provision device")]
    ProvisionDeviceFailed(#[source] anyhow::Error),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<IdTokenSignatureError> for DeviceCodeExchangeError {
    fn from(e: IdTokenSignatureError) -> Self {
        Self::Internal(Box::new(e))
    }
}

fn scope_tokens(scope: &scope::Scope) -> Vec<String> {
    scope
        .iter()
        .map(|token| token.as_str().to_owned())
        .collect()
}

fn client_device_ids(scope: &scope::Scope) -> Vec<String> {
    scope
        .iter()
        .filter_map(|token| {
            let token = token.as_str();
            token
                .strip_prefix("urn:cokret:client:device:")
                .map(str::to_owned)
        })
        .collect()
}
