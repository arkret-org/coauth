//! Business logic for OAuth token endpoint grant types.
//!
//! This module extracts the core grant-type handling out of the token endpoint
//! HTTP handler (`oauth::token`) so that the handler is responsible only for
//! HTTP-level concerns (request parsing, client authentication, metrics,
//! response formatting) while the actual authorization/token logic lives here.

use std::sync::Arc;

use chrono::Duration;
use coauth_config::ContrixConfig;
use coauth_data::{
    AuthorizationGrantStage, BoxRepository, Client, Clock, DeviceCodeGrantState, RefreshToken,
    RefreshTokenState, RepositoryAccess, RepositoryError, SiteConfig, TokenType, UrlBuilder,
    oauth::{
        OAuthAccessTokenRepository, OAuthAuthorizationGrantRepository, OAuthRefreshTokenRepository,
        OAuthSessionRepository,
    },
    user::BrowserSessionRepository,
};
use coauth_i18n::Locale;
use coauth_iana::oauth::{OAuthClientAuthenticationMethod, PkceCodeChallengeMethod};
use coauth_keystore::Keystore;
use coauth_policy::Policy;
use coauth_principal::PrincipalServerAdmin;
use coauth_templates::{DeviceNameContext, TemplateContext, Templates};
use oauth_types::{
    pkce::CodeChallengeError,
    requests::{
        AccessTokenResponse, AuthorizationCodeGrant, ClientCredentialsGrant, DeviceCodeGrant,
        GrantType, RefreshTokenGrant,
    },
    scope,
};
use thiserror::Error;
use tracing::{debug, error, warn};
use ulid::Ulid;

use crate::{
    handlers::{
        BoundActivityTracker,
        oauth::{IdTokenSignatureError, generate_id_token, generate_token_pair},
    },
    oidc_client::types::scope::ScopeToken,
    services::refresh_token_rotation::{
        RefreshTokenState as RotationRefreshTokenState, RotationDecision, RotationPolicy,
        evaluate_refresh,
    },
};

/// Public authorization-code clients must use PKCE. Confidential clients can
/// still use PKCE, but do not require it for legacy OIDC Core compatibility.
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

    #[error(
        "failed to load the next refresh token ({next:?}) from the previous one ({previous:?})"
    )]
    NoSuchNextRefreshToken { next: Ulid, previous: Ulid },

    #[error(
        "failed to load the access token ({access_token:?}) associated with the next refresh token ({refresh_token:?})"
    )]
    NoSuchNextAccessToken {
        access_token: Ulid,
        refresh_token: Ulid,
    },

    #[error("no access token associated with the refresh token {refresh_token:?}")]
    NoAccessTokenOnRefreshToken { refresh_token: Ulid },

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

fn rotation_state_from_refresh_token(refresh_token: &RefreshToken) -> RotationRefreshTokenState {
    RotationRefreshTokenState {
        chain_minted_at: refresh_token.chain_created_at,
        last_seen_at: refresh_token.last_seen_at,
        already_rotated: matches!(refresh_token.state, RefreshTokenState::Consumed { .. }),
        revoked: matches!(refresh_token.state, RefreshTokenState::Revoked { .. }),
    }
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
                .strip_prefix("urn:contrix:client:device:")
                .map(str::to_owned)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/// Exchange an authorization code for tokens.
///
/// Validates the authorization grant state, verifies PKCE if applicable,
/// generates access/refresh tokens (and optionally an ID token), provisions
/// the bound principal device, and marks the grant as exchanged.
///
/// The returned `BoxRepository` must be saved by the caller after recording
/// metrics / activity.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_authorization_code(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng + Send),
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &AuthorizationCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    principal_server: &Arc<dyn PrincipalServerAdmin>,
    templates: &Templates,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), AuthorizationCodeExchangeError> {
    debug!(
        oauth_client.id = %client.id,
        has_code_verifier = grant.code_verifier.is_some(),
        "Starting authorization_code token exchange"
    );

    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        warn!(
            oauth_client.id = %client.id,
            "Client attempted authorization_code exchange without authorization_code grant enabled"
        );
        return Err(AuthorizationCodeExchangeError::UnauthorizedClient(
            client.id,
        ));
    }

    let authz_grant = if let Some(authz_grant) = repo
        .oauth_authorization_grant()
        .find_by_code(&grant.code)
        .await?
    {
        authz_grant
    } else {
        warn!(
            oauth_client.id = %client.id,
            has_code_verifier = grant.code_verifier.is_some(),
            "Authorization code not found during token exchange"
        );
        return Err(AuthorizationCodeExchangeError::GrantNotFound);
    };
    let authorization_grant_id = authz_grant.id;

    let now = clock.now();

    let session_id = match authz_grant.stage {
        AuthorizationGrantStage::Cancelled { cancelled_at } => {
            warn!(
                oauth_client.id = %client.id,
                authorization_grant.id = %authz_grant.id,
                %cancelled_at,
                "Authorization grant was cancelled before token exchange"
            );
            return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Exchanged {
            exchanged_at,
            fulfilled_at,
            session_id,
        } => {
            warn!(
                oauth_client.id = %client.id,
                authorization_grant.id = %authz_grant.id,
                oauth_session.id = %session_id,
                %exchanged_at,
                %fulfilled_at,
                "Authorization code was already exchanged"
            );

            // Ending the session if the token was already exchanged more than 20s ago
            if now - exchanged_at > Duration::microseconds(20 * 1000 * 1000) {
                warn!(oauth_session.id = %session_id, "Ending potentially compromised session");
                let session = repo.oauth_session().lookup(session_id).await?.ok_or(
                    AuthorizationCodeExchangeError::NoSuchOAuthSession(session_id),
                )?;

                repo.oauth_session().finish(clock, session).await?;
                repo.save().await?;
            }

            return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Pending => {
            warn!(
                oauth_client.id = %client.id,
                authorization_grant.id = %authz_grant.id,
                "Authorization grant has not been fulfilled yet"
            );
            return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Fulfilled {
            session_id,
            fulfilled_at,
        } => {
            if now - fulfilled_at > Duration::microseconds(10 * 60 * 1000 * 1000) {
                warn!(
                    oauth_client.id = %client.id,
                    authorization_grant.id = %authz_grant.id,
                    oauth_session.id = %session_id,
                    %fulfilled_at,
                    "Code exchange took more than 10 minutes"
                );
                return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
            }

            session_id
        }
    };

    let mut session = if let Some(session) = repo.oauth_session().lookup(session_id).await? {
        session
    } else {
        error!(
            oauth_client.id = %client.id,
            authorization_grant.id = %authz_grant.id,
            oauth_session.id = %session_id,
            "OAuth session missing during authorization_code exchange"
        );
        return Err(AuthorizationCodeExchangeError::NoSuchOAuthSession(
            session_id,
        ));
    };

    let requested_scopes = scope_tokens(&session.scope);
    let requested_device_ids = client_device_ids(&session.scope);
    debug!(
        oauth_client.id = %client.id,
        authorization_grant.id = %authz_grant.id,
        oauth_session.id = %session.id,
        scopes = ?requested_scopes,
        openid_requested = session.scope.contains(&scope::OPENID),
        device_ids = ?requested_device_ids,
        "Loaded OAuth session for authorization_code exchange"
    );

    // Generate a device name
    let lang: Locale = authz_grant.locale.as_deref().unwrap_or("en").parse()?;
    let ctx = DeviceNameContext::new(client.clone(), user_agent.clone()).with_language(lang);
    let device_name = templates.render_device_name(&ctx)?;

    if let Some(user_agent) = user_agent {
        session = repo
            .oauth_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    // This should never happen, since we looked up in the database using the code
    let code = if let Some(code) = authz_grant.code.as_ref() {
        code
    } else {
        error!(
            oauth_client.id = %client.id,
            authorization_grant.id = %authz_grant.id,
            oauth_session.id = %session.id,
            "Authorization grant is missing embedded code payload during token exchange"
        );
        return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
    };

    if client.id != session.client_id {
        warn!(
            oauth_client.id = %client.id,
            authorization_grant.id = %authz_grant.id,
            oauth_session.id = %session.id,
            expected_client.id = %session.client_id,
            "Authorization code exchange client mismatch"
        );
        return Err(AuthorizationCodeExchangeError::UnexpectedClient {
            was: client.id,
            expected: session.client_id,
        });
    }

    let pkce_required = authorization_code_pkce_required(client);
    match (code.pkce.as_ref(), grant.code_verifier.as_ref()) {
        (None, None) if !pkce_required => {}
        (None, None) => {
            warn!(
                oauth_client.id = %client.id,
                authorization_grant.id = %authz_grant.id,
                oauth_session.id = %session.id,
                "Public authorization_code client attempted token exchange without PKCE"
            );
            return Err(AuthorizationCodeExchangeError::BadRequest);
        }
        // We have a challenge but no verifier (or vice-versa)? Bad request.
        (Some(_), None) | (None, Some(_)) => {
            warn!(
                oauth_client.id = %client.id,
                authorization_grant.id = %authz_grant.id,
                oauth_session.id = %session.id,
                has_pkce_challenge = code.pkce.is_some(),
                has_code_verifier = grant.code_verifier.is_some(),
                "PKCE parameters missing or mismatched during authorization_code exchange"
            );
            return Err(AuthorizationCodeExchangeError::BadRequest);
        }
        // If we have both, we need to check the code validity.
        //
        // SECURITY: `plain` is rejected for *all* clients (not just
        // `pkce_required` public clients) — see
        // `required_pkce_method_is_allowed`. A grant that was somehow
        // recorded with `plain` (e.g. legacy data) is treated as a
        // bad request rather than allowed through.
        (Some(pkce), Some(verifier)) => {
            if !required_pkce_method_is_allowed(&pkce.challenge_method) {
                warn!(
                    oauth_client.id = %client.id,
                    authorization_grant.id = %authz_grant.id,
                    oauth_session.id = %session.id,
                    method = %pkce.challenge_method,
                    pkce_required,
                    "Rejecting authorization_code exchange with disallowed PKCE method (only S256 is accepted)"
                );
                return Err(AuthorizationCodeExchangeError::BadRequest);
            }
            pkce.verify(verifier)?;
        }
    }

    let Some(user_session_id) = session.user_session_id else {
        warn!(
            oauth_client.id = %client.id,
            authorization_grant.id = %authz_grant.id,
            oauth_session.id = %session.id,
            "No user session associated with this OAuth session"
        );
        return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
    };

    let browser_session =
        if let Some(browser_session) = repo.browser_session().lookup(user_session_id).await? {
            browser_session
        } else {
            error!(
                oauth_client.id = %client.id,
                authorization_grant.id = %authz_grant.id,
                oauth_session.id = %session.id,
                browser_session.id = %user_session_id,
                "Browser session missing during authorization_code exchange"
            );
            return Err(AuthorizationCodeExchangeError::NoSuchBrowserSession(
                user_session_id,
            ));
        };

    let last_authentication = repo
        .browser_session()
        .get_last_authentication(&browser_session)
        .await?;

    let ttl = site_config.access_token_ttl;
    let (access_token, refresh_token) =
        generate_token_pair(rng, clock, &mut repo, &session, ttl).await?;

    let id_token = if session.scope.contains(&scope::OPENID) {
        debug!(
            oauth_client.id = %client.id,
            authorization_grant.id = %authz_grant.id,
            oauth_session.id = %session.id,
            browser_session.id = %browser_session.id,
            "Generating ID token because openid scope is present"
        );
        Some(
            generate_id_token(
                rng,
                clock,
                url_builder,
                contrix_config,
                key_store,
                client,
                Some(&authz_grant),
                Some(&session),
                &browser_session,
                Some(&access_token),
                last_authentication.as_ref(),
            )
            .map_err(|err| {
                error!(
                    oauth_client.id = %client.id,
                    authorization_grant.id = %authz_grant.id,
                    oauth_session.id = %session.id,
                    browser_session.id = %browser_session.id,
                    error = %err,
                    error_debug = ?err,
                    "ID token generation failed during authorization_code exchange"
                );
                AuthorizationCodeExchangeError::from(err)
            })?,
        )
    } else {
        None
    };

    let mut params = AccessTokenResponse::new(access_token.access_token)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token.refresh_token)
        .with_scope(session.scope.clone());

    if let Some(id_token) = id_token {
        params = params.with_id_token(id_token);
    }

    // Lock the user sync to make sure we don't get into a race condition
    repo.user()
        .acquire_lock_for_sync(&browser_session.user)
        .await?;

    // Look for device to provision
    if !requested_device_ids.is_empty() {
        debug!(
            oauth_client.id = %client.id,
            authorization_grant.id = %authz_grant.id,
            oauth_session.id = %session.id,
            browser_session.id = %browser_session.id,
            device_ids = ?requested_device_ids,
            "Provisioning client devices during authorization_code exchange"
        );
    }
    for device_id in &requested_device_ids {
        principal_server
            .upsert_device(&browser_session.user.handle, device_id, Some(&device_name))
            .await
            .map_err(|err| {
                error!(
                    oauth_client.id = %client.id,
                    authorization_grant.id = %authz_grant.id,
                    oauth_session.id = %session.id,
                    browser_session.id = %browser_session.id,
                    principal_device.id = %device_id,
                    error = %err,
                    error_debug = ?err,
                    "Failed to provision principal device during authorization_code exchange"
                );
                AuthorizationCodeExchangeError::ProvisionDeviceFailed(err)
            })?;
    }

    repo.oauth_authorization_grant()
        .exchange(clock, authz_grant)
        .await?;

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker.record_oauth_session(clock, &session).await;

    debug!(
        oauth_client.id = %client.id,
        authorization_grant.id = %authorization_grant_id,
        oauth_session.id = %session.id,
        browser_session.id = %browser_session.id,
        "Authorization_code token exchange completed"
    );

    Ok((params, repo))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use std::sync::Arc;

    use coauth_data::{
        PgRepositoryFactory, RepositoryFactory as _,
        clock::MockClock,
        oauth::{LocalizedClientMetadata, NewSessionGrant},
    };
    use oauth_types::scope::{OPENID, Scope};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use tokio_util::{sync::CancellationToken, task::TaskTracker};
    use url::Url;

    use super::*;
    use crate::handlers::ActivityTracker;

    fn client_with_auth_method(method: Option<OAuthClientAuthenticationMethod>) -> Client {
        Client {
            id: Ulid::new(),
            client_id: "client".to_owned(),
            metadata_digest: None,
            encrypted_client_secret: None,
            application_type: None,
            redirect_uris: vec![Url::parse("https://client.example/callback").unwrap()],
            grant_types: vec![GrantType::AuthorizationCode],
            client_name: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            localized_metadata: LocalizedClientMetadata::default(),
            jwks: None,
            id_token_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            token_endpoint_auth_method: method,
            token_endpoint_auth_signing_alg: None,
            initiate_login_uri: None,
        }
    }

    #[test]
    fn public_authorization_code_clients_require_s256_pkce() {
        let client = client_with_auth_method(Some(OAuthClientAuthenticationMethod::None));
        assert!(authorization_code_pkce_required(&client));
        assert!(required_pkce_method_is_allowed(
            &PkceCodeChallengeMethod::S256
        ));
        assert!(!required_pkce_method_is_allowed(
            &PkceCodeChallengeMethod::Plain
        ));
    }

    #[test]
    fn confidential_authorization_code_clients_do_not_require_pkce() {
        let client =
            client_with_auth_method(Some(OAuthClientAuthenticationMethod::ClientSecretBasic));
        assert!(!authorization_code_pkce_required(&client));
    }

    struct RefreshFixture {
        factory: PgRepositoryFactory,
        clock: Arc<MockClock>,
        activity_tracker: BoundActivityTracker,
        client: Client,
        site_config: SiteConfig,
        initial_refresh_token: RefreshToken,
        initial_access_token_id: Ulid,
        session_grant_id: Ulid,
        cancellation_token: CancellationToken,
        _task_tracker: TaskTracker,
    }

    impl RefreshFixture {
        fn shutdown(&self) {
            self.cancellation_token.cancel();
        }
    }

    async fn make_refresh_fixture(seed: u64, handle: &str) -> Option<RefreshFixture> {
        let pool = coauth_data::test_utils::setup_test_pool().await?;

        let factory = PgRepositoryFactory::new(pool);
        let clock = Arc::new(MockClock::default());
        let task_tracker = TaskTracker::new();
        let cancellation_token = CancellationToken::new();
        let activity_tracker = ActivityTracker::new(
            factory.clone().boxed(),
            std::time::Duration::from_mins(1),
            &task_tracker,
            cancellation_token.clone(),
        )
        .bind(None);
        let site_config = crate::handlers::test_utils::test_site_config();
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let mut repo = factory.create().await.unwrap();

        let client = repo
            .oauth_client()
            .add(
                &mut rng,
                &*clock,
                vec!["https://client.example/callback".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                Some(format!("{handle} client")),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*clock, handle.to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &*clock, &user, None)
            .await
            .unwrap();
        let scope = Scope::from_iter([OPENID]);
        let session = repo
            .oauth_session()
            .add_from_browser_session(&mut rng, &*clock, &client, &browser_session, scope.clone())
            .await
            .unwrap();
        let session_grant = repo
            .oauth_session_grant()
            .add(
                &mut rng,
                &*clock,
                NewSessionGrant {
                    browser_session_id: browser_session.id,
                    issuer: "did:web:issuer.example",
                    subject: "did:web:subject.example",
                    device_id: Some("device-1"),
                    audience: "did:web:audience.example",
                    scope,
                    grant_jwt: "session-grant-jwt",
                    session_public_key: "session-public-key",
                    expires_at: clock.now() + Duration::try_hours(1).unwrap(),
                },
            )
            .await
            .unwrap();
        let access_token_value = TokenType::AccessToken.generate(&mut rng);
        let access_token = repo
            .oauth_access_token()
            .add(
                &mut rng,
                &*clock,
                &session,
                access_token_value,
                Some(site_config.access_token_ttl),
            )
            .await
            .unwrap();
        let refresh_token_value = TokenType::RefreshToken.generate(&mut rng);
        let refresh_token = repo
            .oauth_refresh_token()
            .add(
                &mut rng,
                &*clock,
                &session,
                &access_token,
                refresh_token_value,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        Some(RefreshFixture {
            factory,
            clock,
            activity_tracker,
            client,
            site_config,
            initial_refresh_token: refresh_token,
            initial_access_token_id: access_token.id,
            session_grant_id: session_grant.id,
            cancellation_token,
            _task_tracker: task_tracker,
        })
    }

    async fn redeem_refresh_token(
        fixture: &RefreshFixture,
        refresh_token: String,
        rng_seed: u64,
    ) -> Result<AccessTokenResponse, RefreshTokenExchangeError> {
        let mut rng = ChaChaRng::seed_from_u64(rng_seed);
        let repo = fixture.factory.create().await.unwrap();
        let grant = RefreshTokenGrant {
            refresh_token,
            scope: None,
        };
        let (reply, repo) = handle_refresh_token(
            &mut rng,
            &fixture.clock,
            &fixture.activity_tracker,
            &grant,
            &fixture.client,
            &fixture.site_config,
            repo,
            None,
        )
        .await?;
        repo.save().await?;
        Ok(reply)
    }

    async fn find_refresh_token(fixture: &RefreshFixture, token: &str) -> RefreshToken {
        let mut repo = fixture.factory.create().await.unwrap();
        let refresh_token = repo
            .oauth_refresh_token()
            .find_by_token(token)
            .await
            .unwrap()
            .expect("refresh token should exist");
        repo.cancel().await.unwrap();
        refresh_token
    }

    async fn assert_refresh_tokens_revoked(fixture: &RefreshFixture, ids: &[Ulid]) {
        let mut repo = fixture.factory.create().await.unwrap();
        for id in ids {
            let token = repo
                .oauth_refresh_token()
                .lookup(*id)
                .await
                .unwrap()
                .expect("refresh token should exist");
            assert!(
                matches!(token.state, RefreshTokenState::Revoked { .. }),
                "refresh token {id} should be revoked, got {:?}",
                token.state
            );
        }
        repo.cancel().await.unwrap();
    }

    async fn assert_access_token_revoked(fixture: &RefreshFixture, id: Ulid) {
        let mut repo = fixture.factory.create().await.unwrap();
        let token = repo
            .oauth_access_token()
            .lookup(id)
            .await
            .unwrap()
            .expect("access token should exist");
        assert!(
            token.state.is_revoked(),
            "access token {id} should be revoked"
        );
        repo.cancel().await.unwrap();
    }

    async fn assert_session_grant_revoked(fixture: &RefreshFixture) {
        let mut repo = fixture.factory.create().await.unwrap();
        let grant = repo
            .oauth_session_grant()
            .lookup(fixture.session_grant_id)
            .await
            .unwrap()
            .expect("session grant should exist");
        assert!(grant.revoked_at.is_some());
        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn refresh_handler_revokes_chain_on_old_token_reuse() {
        let Some(fixture) = make_refresh_fixture(101, "refresh-reuse-user").await else {
            return;
        };

        let first_reply = redeem_refresh_token(
            &fixture,
            fixture.initial_refresh_token.refresh_token.clone(),
            102,
        )
        .await
        .expect("first refresh should succeed");
        let successor = find_refresh_token(
            &fixture,
            first_reply
                .refresh_token
                .as_deref()
                .expect("successor refresh token should be returned"),
        )
        .await;

        let error = redeem_refresh_token(
            &fixture,
            fixture.initial_refresh_token.refresh_token.clone(),
            103,
        )
        .await
        .expect_err("old refresh token reuse should be rejected");
        assert!(matches!(
            error,
            RefreshTokenExchangeError::RefreshTokenInvalid(id)
                if id == fixture.initial_refresh_token.id
        ));

        assert_refresh_tokens_revoked(&fixture, &[fixture.initial_refresh_token.id, successor.id])
            .await;
        assert_access_token_revoked(&fixture, fixture.initial_access_token_id).await;
        assert_session_grant_revoked(&fixture).await;
        fixture.shutdown();
    }

    #[tokio::test]
    async fn refresh_handler_revokes_chain_when_reused_successor_was_already_used() {
        let Some(fixture) = make_refresh_fixture(201, "refresh-next-used-user").await else {
            return;
        };

        let second_token_value = redeem_refresh_token(
            &fixture,
            fixture.initial_refresh_token.refresh_token.clone(),
            202,
        )
        .await
        .expect("first refresh should succeed")
        .refresh_token
        .expect("second refresh token should be returned");
        let second_token = find_refresh_token(&fixture, &second_token_value).await;
        let third_token_value = redeem_refresh_token(&fixture, second_token_value.clone(), 203)
            .await
            .expect("second refresh should succeed")
            .refresh_token
            .expect("third refresh token should be returned");
        let third_token = find_refresh_token(&fixture, &third_token_value).await;

        let error = redeem_refresh_token(&fixture, second_token_value, 204)
            .await
            .expect_err("reusing an already-used successor should be rejected");
        assert!(matches!(
            error,
            RefreshTokenExchangeError::RefreshTokenInvalid(id) if id == second_token.id
        ));

        assert_refresh_tokens_revoked(
            &fixture,
            &[
                fixture.initial_refresh_token.id,
                second_token.id,
                third_token.id,
            ],
        )
        .await;
        assert_session_grant_revoked(&fixture).await;
        fixture.shutdown();
    }

    #[tokio::test]
    async fn refresh_handler_revokes_chain_when_idle_window_expired() {
        let Some(fixture) = make_refresh_fixture(301, "refresh-idle-user").await else {
            return;
        };
        fixture
            .clock
            .advance(Duration::try_hours(13).unwrap() + Duration::try_seconds(1).unwrap());

        let error = redeem_refresh_token(
            &fixture,
            fixture.initial_refresh_token.refresh_token.clone(),
            302,
        )
        .await
        .expect_err("idle refresh token should be rejected");
        assert!(matches!(
            error,
            RefreshTokenExchangeError::RefreshTokenInvalid(id)
                if id == fixture.initial_refresh_token.id
        ));

        assert_refresh_tokens_revoked(&fixture, &[fixture.initial_refresh_token.id]).await;
        assert_access_token_revoked(&fixture, fixture.initial_access_token_id).await;
        assert_session_grant_revoked(&fixture).await;
        fixture.shutdown();
    }

    #[tokio::test]
    async fn refresh_handler_revokes_chain_when_rotation_window_expired() {
        let Some(fixture) = make_refresh_fixture(401, "refresh-rotation-user").await else {
            return;
        };
        fixture
            .clock
            .advance(Duration::try_hours(25).unwrap() + Duration::try_seconds(1).unwrap());

        let error = redeem_refresh_token(
            &fixture,
            fixture.initial_refresh_token.refresh_token.clone(),
            402,
        )
        .await
        .expect_err("expired rotation window should be rejected");
        assert!(matches!(
            error,
            RefreshTokenExchangeError::RefreshTokenInvalid(id)
                if id == fixture.initial_refresh_token.id
        ));

        assert_refresh_tokens_revoked(&fixture, &[fixture.initial_refresh_token.id]).await;
        assert_access_token_revoked(&fixture, fixture.initial_access_token_id).await;
        assert_session_grant_revoked(&fixture).await;
        fixture.shutdown();
    }

    #[tokio::test]
    async fn device_logout_chain_revoke_blocks_current_refresh_token() {
        let Some(fixture) = make_refresh_fixture(501, "refresh-device-logout-user").await else {
            return;
        };
        let current_token_value = redeem_refresh_token(
            &fixture,
            fixture.initial_refresh_token.refresh_token.clone(),
            502,
        )
        .await
        .expect("first refresh should succeed")
        .refresh_token
        .expect("current refresh token should be returned");
        let current_token = find_refresh_token(&fixture, &current_token_value).await;

        let mut repo = fixture.factory.create().await.unwrap();
        let outcome = repo
            .oauth_refresh_token()
            .revoke_chain_by_root(&fixture.clock, current_token.chain_root_id)
            .await
            .unwrap();
        assert_eq!(outcome.refresh_tokens, 2);
        repo.save().await.unwrap();

        let error = redeem_refresh_token(&fixture, current_token_value, 503)
            .await
            .expect_err("device logout chain revoke should block refresh");
        assert!(matches!(
            error,
            RefreshTokenExchangeError::RefreshTokenInvalid(id) if id == current_token.id
        ));
        assert_refresh_tokens_revoked(
            &fixture,
            &[fixture.initial_refresh_token.id, current_token.id],
        )
        .await;
        assert_session_grant_revoked(&fixture).await;
        fixture.shutdown();
    }

    #[tokio::test]
    async fn concurrent_refresh_only_one_exchange_succeeds() {
        let Some(fixture) = make_refresh_fixture(601, "refresh-concurrent-user").await else {
            return;
        };

        async fn redeem_with_owned_inputs(
            factory: PgRepositoryFactory,
            clock: Arc<MockClock>,
            activity_tracker: BoundActivityTracker,
            client: Client,
            site_config: SiteConfig,
            refresh_token: String,
            rng_seed: u64,
        ) -> Result<AccessTokenResponse, RefreshTokenExchangeError> {
            let mut rng = ChaChaRng::seed_from_u64(rng_seed);
            let repo = factory.create().await.unwrap();
            let grant = RefreshTokenGrant {
                refresh_token,
                scope: None,
            };
            let (reply, repo) = handle_refresh_token(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &site_config,
                repo,
                None,
            )
            .await?;
            repo.save().await?;
            Ok(reply)
        }

        let first = tokio::spawn(redeem_with_owned_inputs(
            fixture.factory.clone(),
            Arc::clone(&fixture.clock),
            fixture.activity_tracker.clone(),
            fixture.client.clone(),
            fixture.site_config.clone(),
            fixture.initial_refresh_token.refresh_token.clone(),
            602,
        ));
        let second = tokio::spawn(redeem_with_owned_inputs(
            fixture.factory.clone(),
            Arc::clone(&fixture.clock),
            fixture.activity_tracker.clone(),
            fixture.client.clone(),
            fixture.site_config.clone(),
            fixture.initial_refresh_token.refresh_token.clone(),
            603,
        ));

        let results = [first.await.unwrap(), second.await.unwrap()];
        let success_count = results.iter().filter(|result| result.is_ok()).count();
        let failure_count = results.iter().filter(|result| result.is_err()).count();

        assert_eq!(success_count, 1);
        assert_eq!(failure_count, 1);

        let mut repo = fixture.factory.create().await.unwrap();
        let original = repo
            .oauth_refresh_token()
            .lookup(fixture.initial_refresh_token.id)
            .await
            .unwrap()
            .expect("original refresh token should exist");
        assert!(matches!(original.state, RefreshTokenState::Consumed { .. }));
        repo.cancel().await.unwrap();
        fixture.shutdown();
    }
}

/// Exchange a refresh token for a new access/refresh token pair.
///
/// Validates the refresh token, handles double-refresh detection (where the
/// client lost the previous response), revokes old tokens, and issues
/// replacements.
#[allow(clippy::too_many_arguments)]
pub async fn handle_refresh_token(
    rng: &mut (impl rand_core::RngCore + Send),
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &RefreshTokenGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RefreshTokenExchangeError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::RefreshToken) {
        return Err(RefreshTokenExchangeError::UnauthorizedClient(client.id));
    }

    let refresh_token = repo
        .oauth_refresh_token()
        .find_by_token(&grant.refresh_token)
        .await?
        .ok_or(RefreshTokenExchangeError::RefreshTokenNotFound)?;

    let mut session = repo
        .oauth_session()
        .lookup(refresh_token.session_id)
        .await?
        .ok_or(RefreshTokenExchangeError::NoSuchOAuthSession(
            refresh_token.session_id,
        ))?;

    // Let's for now record the user agent on each refresh, that should be
    // responsive enough and not too much of a burden on the database.
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    if !session.is_valid() {
        return Err(RefreshTokenExchangeError::SessionInvalid(session.id));
    }

    if client.id != session.client_id {
        // As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        return Err(RefreshTokenExchangeError::ClientIdMismatch {
            expected: session.client_id,
            actual: client.id,
        });
    }

    let rotation_decision = evaluate_refresh(
        &rotation_state_from_refresh_token(&refresh_token),
        clock.now(),
        RotationPolicy::default(),
    );
    match rotation_decision {
        RotationDecision::Accept => {}
        RotationDecision::ReuseDetected => {
            let rejected_refresh_token_id = refresh_token.id;
            warn!(
                oauth_session.id = %session.id,
                oauth_client.id = %client.id,
                refresh_token.id = %rejected_refresh_token_id,
                refresh_token.chain_root_id = %refresh_token.chain_root_id,
                "refresh token reuse detected; revoking refresh-token chain"
            );
            let outcome = repo
                .oauth_refresh_token()
                .revoke_chain_by_root(clock, refresh_token.chain_root_id)
                .await?;
            warn!(
                oauth_session.id = %session.id,
                oauth_client.id = %client.id,
                refresh_token.id = %rejected_refresh_token_id,
                refresh_token.chain_root_id = %refresh_token.chain_root_id,
                refresh_tokens_revoked = outcome.refresh_tokens,
                access_tokens_revoked = outcome.access_tokens,
                session_grants_revoked = outcome.session_grants,
                "refresh-token chain revoked after reuse detection"
            );
            repo.save().await?;
            return Err(RefreshTokenExchangeError::RefreshTokenInvalid(
                rejected_refresh_token_id,
            ));
        }
        RotationDecision::Revoked => {
            return Err(RefreshTokenExchangeError::RefreshTokenInvalid(
                refresh_token.id,
            ));
        }
        RotationDecision::RotationWindowExpired | RotationDecision::IdleExpired => {
            let rejected_refresh_token_id = refresh_token.id;
            warn!(
                oauth_session.id = %session.id,
                oauth_client.id = %client.id,
                refresh_token.id = %rejected_refresh_token_id,
                refresh_token.chain_root_id = %refresh_token.chain_root_id,
                ?rotation_decision,
                "refresh token rejected by rotation policy; revoking refresh-token chain"
            );
            let outcome = repo
                .oauth_refresh_token()
                .revoke_chain_by_root(clock, refresh_token.chain_root_id)
                .await?;
            warn!(
                oauth_session.id = %session.id,
                oauth_client.id = %client.id,
                refresh_token.id = %rejected_refresh_token_id,
                refresh_token.chain_root_id = %refresh_token.chain_root_id,
                refresh_tokens_revoked = outcome.refresh_tokens,
                access_tokens_revoked = outcome.access_tokens,
                session_grants_revoked = outcome.session_grants,
                "refresh-token chain revoked after rotation policy rejection"
            );
            repo.save().await?;
            return Err(RefreshTokenExchangeError::RefreshTokenInvalid(
                rejected_refresh_token_id,
            ));
        }
    }

    activity_tracker.record_oauth_session(clock, &session).await;

    let ttl = site_config.access_token_ttl;
    let (new_access_token, new_refresh_token) =
        generate_token_pair(rng, clock, &mut repo, &session, ttl).await?;

    let refresh_token = repo
        .oauth_refresh_token()
        .consume(clock, refresh_token, &new_refresh_token)
        .await?;

    if let Some(access_token_id) = refresh_token.access_token_id {
        let access_token = repo.oauth_access_token().lookup(access_token_id).await?;
        if let Some(access_token) = access_token {
            // If it is a double-refresh, it might already be revoked
            if !access_token.state.is_revoked() {
                repo.oauth_access_token()
                    .revoke(clock, access_token)
                    .await?;
            }
        }
    }

    let params = AccessTokenResponse::new(new_access_token.access_token)
        .with_expires_in(ttl)
        .with_refresh_token(new_refresh_token.refresh_token)
        .with_scope(session.scope);

    Ok((params, repo))
}

/// Handle a client credentials grant.
///
/// Validates the client's authorization, runs the request through the policy
/// engine, creates a new client-credentials session, and issues an access
/// token (no refresh token for this grant type).
#[allow(clippy::too_many_arguments)]
pub async fn handle_client_credentials(
    rng: &mut (impl rand_core::RngCore + Send),
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &ClientCredentialsGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    mut policy: Policy,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), ClientCredentialsGrantError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        return Err(ClientCredentialsGrantError::UnauthorizedClient(client.id));
    }

    // Default to an empty scope if none is provided
    let scope = grant
        .scope
        .clone()
        .unwrap_or_else(|| std::iter::empty::<ScopeToken>().collect());

    // Make the request go through the policy engine
    let res = policy
        .evaluate_authorization_grant(coauth_policy::AuthorizationGrantInput {
            user: None,
            client,
            session_counts: None,
            scope: &scope,
            grant_type: coauth_policy::GrantType::ClientCredentials,
            requester: coauth_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent: user_agent.clone(),
                ..Default::default()
            },
        })
        .await?;
    if !res.valid() {
        return Err(ClientCredentialsGrantError::DeniedByPolicy(res));
    }

    // Start the session
    let mut session = repo
        .oauth_session()
        .add_from_client_credentials(rng, clock, client, scope)
        .await?;

    if let Some(user_agent) = user_agent {
        session = repo
            .oauth_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let ttl = site_config.access_token_ttl;
    let access_token_str = TokenType::AccessToken.generate(rng);

    let access_token = repo
        .oauth_access_token()
        .add(rng, clock, &session, access_token_str, Some(ttl))
        .await?;

    let mut params = AccessTokenResponse::new(access_token.access_token).with_expires_in(ttl);

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker.record_oauth_session(clock, &session).await;

    if !session.scope.is_empty() {
        // We only return the scope if it's not empty
        params = params.with_scope(session.scope);
    }

    Ok((params, repo))
}

/// Exchange a device code for tokens.
///
/// Validates the device code grant state, creates an OAuth session,
/// generates tokens (including an optional ID token and refresh token),
/// and provisions the bound principal device.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_device_code(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng + Send),
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &DeviceCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    principal_server: &Arc<dyn PrincipalServerAdmin>,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), DeviceCodeExchangeError> {
    debug!(
        oauth_client.id = %client.id,
        "Starting device_code token exchange"
    );

    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::DeviceCode) {
        warn!(
            oauth_client.id = %client.id,
            "Client attempted device_code exchange without device_code grant enabled"
        );
        return Err(DeviceCodeExchangeError::UnauthorizedClient(client.id));
    }

    let grant = if let Some(grant) = repo
        .oauth_device_code_grant()
        .find_by_device_code(&grant.device_code)
        .await?
    {
        grant
    } else {
        warn!(
            oauth_client.id = %client.id,
            "Device code grant not found during token exchange"
        );
        return Err(DeviceCodeExchangeError::GrantNotFound);
    };
    let device_code_grant_id = grant.id;

    // Check that the client match
    if client.id != grant.client_id {
        warn!(
            oauth_client.id = %client.id,
            device_code_grant.id = %grant.id,
            expected_client.id = %grant.client_id,
            "Device code exchange client mismatch"
        );
        return Err(DeviceCodeExchangeError::ClientIdMismatch {
            expected: grant.client_id,
            actual: client.id,
        });
    }

    if grant.expires_at < clock.now() {
        warn!(
            oauth_client.id = %client.id,
            device_code_grant.id = %grant.id,
            expires_at = %grant.expires_at,
            "Device code grant expired before token exchange"
        );
        return Err(DeviceCodeExchangeError::DeviceCodeExpired);
    }

    let browser_session_id = match &grant.state {
        DeviceCodeGrantState::Pending => {
            debug!(
                oauth_client.id = %client.id,
                device_code_grant.id = %grant.id,
                "Device code grant is still pending"
            );
            return Err(DeviceCodeExchangeError::DeviceCodePending);
        }
        DeviceCodeGrantState::Rejected { .. } => {
            warn!(
                oauth_client.id = %client.id,
                device_code_grant.id = %grant.id,
                "Device code grant was rejected"
            );
            return Err(DeviceCodeExchangeError::DeviceCodeRejected);
        }
        DeviceCodeGrantState::Exchanged { .. } => {
            warn!(
                oauth_client.id = %client.id,
                device_code_grant.id = %grant.id,
                "Device code grant was already exchanged"
            );
            return Err(DeviceCodeExchangeError::DeviceCodeExchanged);
        }
        DeviceCodeGrantState::Fulfilled {
            browser_session_id, ..
        } => *browser_session_id,
    };

    let browser_session =
        if let Some(browser_session) = repo.browser_session().lookup(browser_session_id).await? {
            browser_session
        } else {
            error!(
                oauth_client.id = %client.id,
                device_code_grant.id = %grant.id,
                browser_session.id = %browser_session_id,
                "Browser session missing during device_code exchange"
            );
            return Err(DeviceCodeExchangeError::NoSuchBrowserSession(
                browser_session_id,
            ));
        };

    // Start the session
    let mut session = repo
        .oauth_session()
        .add_from_browser_session(rng, clock, client, &browser_session, grant.scope.clone())
        .await?;

    let requested_scopes = scope_tokens(&session.scope);
    let requested_device_ids = client_device_ids(&session.scope);
    debug!(
        oauth_client.id = %client.id,
        device_code_grant.id = %grant.id,
        oauth_session.id = %session.id,
        browser_session.id = %browser_session.id,
        scopes = ?requested_scopes,
        openid_requested = session.scope.contains(&scope::OPENID),
        device_ids = ?requested_device_ids,
        "Started OAuth session for device_code exchange"
    );

    repo.oauth_device_code_grant()
        .exchange(clock, grant, &session)
        .await?;

    // XXX: should we get the user agent from the device code grant instead?
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let ttl = site_config.access_token_ttl;
    let access_token_str = TokenType::AccessToken.generate(rng);

    let access_token = repo
        .oauth_access_token()
        .add(rng, clock, &session, access_token_str, Some(ttl))
        .await?;

    let mut params =
        AccessTokenResponse::new(access_token.access_token.clone()).with_expires_in(ttl);

    // If the client uses the refresh token grant type, we also generate a refresh
    // token
    if client.grant_types.contains(&GrantType::RefreshToken) {
        let refresh_token_str = TokenType::RefreshToken.generate(rng);

        let refresh_token = repo
            .oauth_refresh_token()
            .add(rng, clock, &session, &access_token, refresh_token_str)
            .await?;

        params = params.with_refresh_token(refresh_token.refresh_token);
    }

    // If the client asked for an ID token, we generate one
    if session.scope.contains(&scope::OPENID) {
        debug!(
            oauth_client.id = %client.id,
            device_code_grant.id = %device_code_grant_id,
            oauth_session.id = %session.id,
            browser_session.id = %browser_session.id,
            "Generating ID token because openid scope is present"
        );
        let id_token = generate_id_token(
            rng,
            clock,
            url_builder,
            contrix_config,
            key_store,
            client,
            None,
            Some(&session),
            &browser_session,
            Some(&access_token),
            None,
        )
        .map_err(|err| {
            error!(
                oauth_client.id = %client.id,
                device_code_grant.id = %device_code_grant_id,
                oauth_session.id = %session.id,
                browser_session.id = %browser_session.id,
                error = %err,
                error_debug = ?err,
                "ID token generation failed during device_code exchange"
            );
            DeviceCodeExchangeError::from(err)
        })?;

        params = params.with_id_token(id_token);
    }

    // Lock the user sync to make sure we don't get into a race condition
    repo.user()
        .acquire_lock_for_sync(&browser_session.user)
        .await?;

    // Look for device to provision
    if !requested_device_ids.is_empty() {
        debug!(
            oauth_client.id = %client.id,
            device_code_grant.id = %device_code_grant_id,
            oauth_session.id = %session.id,
            browser_session.id = %browser_session.id,
            device_ids = ?requested_device_ids,
            "Provisioning client devices during device_code exchange"
        );
    }
    for device_id in &requested_device_ids {
        principal_server
            .upsert_device(&browser_session.user.handle, device_id, None)
            .await
            .map_err(|err| {
                error!(
                    oauth_client.id = %client.id,
                    device_code_grant.id = %device_code_grant_id,
                    oauth_session.id = %session.id,
                    browser_session.id = %browser_session.id,
                    principal_device.id = %device_id,
                    error = %err,
                    error_debug = ?err,
                    "Failed to provision principal device during device_code exchange"
                );
                DeviceCodeExchangeError::ProvisionDeviceFailed(err)
            })?;
    }

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker.record_oauth_session(clock, &session).await;

    if !session.scope.is_empty() {
        // We only return the scope if it's not empty
        params = params.with_scope(session.scope);
    }

    debug!(
        oauth_client.id = %client.id,
        device_code_grant.id = %device_code_grant_id,
        oauth_session.id = %session.id,
        browser_session.id = %browser_session.id,
        "Device_code token exchange completed"
    );

    Ok((params, repo))
}
