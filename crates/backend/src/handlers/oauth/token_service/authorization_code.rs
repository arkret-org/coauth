//! `authorization_code` grant-type exchange.

use std::sync::Arc;

use chrono::Duration;
use coauth_config::ArkretConfig;
use coauth_data::{
    AuthorizationGrant, AuthorizationGrantStage, BoxRepository, BrowserSession, Client, Clock,
    Session, SiteConfig, UrlBuilder,
};
use coauth_i18n::Locale;
use coauth_keystore::Keystore;
use coauth_oauth_types::requests::{AccessTokenResponse, AuthorizationCodeGrant, GrantType};
use coauth_oauth_types::scope;
use coauth_principal::ConnectorAdmin;
use coauth_templates::{DeviceNameContext, TemplateContext as _, Templates};
use tracing::{debug, error, warn};
use ulid::Ulid;

use super::{
    AuthorizationCodeExchangeError, authorization_code_pkce_required, client_device_ids,
    required_pkce_method_is_allowed, scope_tokens,
};
use crate::handlers::BoundActivityTracker;
use crate::handlers::oauth::{generate_id_token, generate_token_pair};

/// The validated context of an authorization-code exchange.
///
/// Produced by [`validate_authorization_code`]. Carries the locked
/// authorization grant and the sessions it is bound to so the caller can
/// finish the exchange — token issuance at the token endpoint, or local
/// account-handoff authentication — inside its own transaction boundary.
pub(crate) struct ValidatedAuthorizationCode {
    /// The authorization grant, row-locked `FOR UPDATE` until the caller
    /// commits or rolls back its transaction.
    pub authorization_grant: AuthorizationGrant,
    /// The OAuth session the grant was fulfilled with.
    pub session: Session,
    /// The browser session (and user) the OAuth session is bound to.
    pub browser_session: BrowserSession,
}

/// Validate an authorization code for consumption without consuming it.
///
/// This is the shared core of the token endpoint's `authorization_code`
/// exchange ([`exchange_authorization_code`]) and of local-issuer account
/// handoff authentication. It checks the client's grant-type authorization,
/// loads the grant with a `FOR UPDATE` row lock so concurrent consumption
/// attempts of the same code serialize, then verifies the grant stage and
/// expiry, the bound OAuth and browser sessions, the client binding, and
/// PKCE.
///
/// It never commits the repository, never generates tokens, and never
/// performs network calls. Consuming the grant (`exchange`) is the caller's
/// responsibility, inside the caller's own atomic commit.
pub(crate) async fn validate_authorization_code(
    repo: &mut BoxRepository,
    clock: &impl Clock,
    grant: &AuthorizationCodeGrant,
    client: &Client,
) -> Result<ValidatedAuthorizationCode, AuthorizationCodeExchangeError> {
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
        .find_by_code_for_update(&grant.code)
        .await?
    {
        authz_grant
    } else {
        warn!(
            oauth_client.id = %client.id,
            has_code_verifier = grant.code_verifier.is_some(),
            "Authorization code not found during authorization_code validation"
        );
        return Err(AuthorizationCodeExchangeError::GrantNotFound);
    };

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

            // The caller decides whether the bound session must be ended
            // (replay beyond the reuse window) via
            // [`end_session_on_code_reuse`].
            return Err(AuthorizationCodeExchangeError::AlreadyExchanged {
                grant_id: authz_grant.id,
                session_id,
                beyond_reuse_window: now - exchanged_at > Duration::microseconds(20 * 1000 * 1000),
            });
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

    let session = if let Some(session) = repo.oauth_session().lookup(session_id).await? {
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
        // `required_pkce_method_is_allowed`. A grant recorded with
        // `plain` is treated as a bad request rather than allowed through.
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

    Ok(ValidatedAuthorizationCode {
        authorization_grant: authz_grant,
        session,
        browser_session,
    })
}

/// End the OAuth session bound to an authorization code that was replayed
/// beyond the reuse window, committing the change immediately.
///
/// This preserves the token endpoint's defence against authorization-code
/// replay: a code presented again more than 20 seconds after its first
/// exchange ends the potentially compromised session. Callers must invoke it
/// on a repository that holds no other pending writes, because the helper
/// commits with `save()` itself.
pub(crate) async fn end_session_on_code_reuse(
    repo: BoxRepository,
    clock: &impl Clock,
    session_id: Ulid,
) -> Result<(), AuthorizationCodeExchangeError> {
    warn!(oauth_session.id = %session_id, "Ending potentially compromised session");
    let mut repo = repo;
    let session = repo.oauth_session().lookup(session_id).await?.ok_or(
        AuthorizationCodeExchangeError::NoSuchOAuthSession(session_id),
    )?;

    repo.oauth_session().finish(clock, session).await?;
    repo.save().await?;
    Ok(())
}

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
    arkret_config: &ArkretConfig,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    station: &Arc<dyn ConnectorAdmin>,
    templates: &Templates,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), AuthorizationCodeExchangeError> {
    debug!(
        oauth_client.id = %client.id,
        has_code_verifier = grant.code_verifier.is_some(),
        "Starting authorization_code token exchange"
    );

    let validated = match validate_authorization_code(&mut repo, clock, grant, client).await {
        Ok(validated) => validated,
        Err(AuthorizationCodeExchangeError::AlreadyExchanged {
            grant_id,
            session_id,
            beyond_reuse_window,
        }) => {
            // Ending the session if the code was already exchanged more than
            // 20s ago. No other writes are pending on this repository, so the
            // helper can commit the session termination itself.
            if beyond_reuse_window {
                end_session_on_code_reuse(repo, clock, session_id).await?;
            }

            return Err(AuthorizationCodeExchangeError::InvalidGrant(grant_id));
        }
        Err(error) => return Err(error),
    };
    let ValidatedAuthorizationCode {
        authorization_grant: authz_grant,
        mut session,
        browser_session,
    } = validated;
    let authorization_grant_id = authz_grant.id;

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

    let last_authentication = repo
        .browser_session()
        .get_last_authentication(&browser_session)
        .await?;

    let ttl = super::capped_access_token_ttl(site_config.access_token_ttl);
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
        let subject_did =
            crate::handlers::arkret::oidc_subject_for_user(arkret_config, &browser_session.user);
        let principal_id = crate::handlers::arkret::published_principal_id_for_user(
            &mut repo,
            arkret_config,
            &browser_session.user,
        )
        .await?;
        Some(
            generate_id_token(
                rng,
                clock,
                url_builder,
                &subject_did,
                principal_id
                    .as_ref()
                    .map(arkret_identifiers::DidCoreId::as_str),
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
        station
            .upsert_device(
                &browser_session.user.localpart,
                device_id,
                Some(&device_name),
            )
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

    // TODO: there is a potential (but unlikely) race here, where the activity for
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
