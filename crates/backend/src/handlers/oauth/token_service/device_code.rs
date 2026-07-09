//! `device_code` grant-type exchange.

use std::sync::Arc;

use coauth_config::CokretConfig;
use coauth_data::{
    BoxRepository, Client, Clock, DeviceCodeGrantState, SiteConfig, TokenType, UrlBuilder,
};
use coauth_keystore::Keystore;
use coauth_oauth_types::requests::{AccessTokenResponse, DeviceCodeGrant, GrantType};
use coauth_oauth_types::scope;
use coauth_principal::ConnectorAdmin;
use tracing::{debug, error, warn};

use super::{DeviceCodeExchangeError, client_device_ids, scope_tokens};
use crate::handlers::BoundActivityTracker;
use crate::handlers::oauth::generate_id_token;

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
    cokret_config: &CokretConfig,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    principal_server: &Arc<dyn ConnectorAdmin>,
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

    // TODO: should we get the user agent from the device code grant instead?
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let ttl = super::capped_access_token_ttl(site_config.access_token_ttl);
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
        let subject_did =
            crate::handlers::arkret::oidc_subject_for_user(cokret_config, &browser_session.user);
        let principal_did = crate::handlers::arkret::published_principal_did_for_user(
            &mut repo,
            cokret_config,
            &browser_session.user,
        )
        .await?;
        let id_token = generate_id_token(
            rng,
            clock,
            url_builder,
            &subject_did,
            principal_did.as_deref(),
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
            .upsert_device(&browser_session.user.localpart, device_id, None)
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

    // TODO: there is a potential (but unlikely) race here, where the activity for
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
