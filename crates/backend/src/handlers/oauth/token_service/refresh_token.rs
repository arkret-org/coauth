//! `refresh_token` grant-type exchange.

use coauth_data::{BoxRepository, Client, Clock, RefreshToken, RefreshTokenState, SiteConfig};
use coauth_oauth_types::requests::{AccessTokenResponse, GrantType, RefreshTokenGrant};
use tracing::warn;

use super::RefreshTokenExchangeError;
use crate::handlers::BoundActivityTracker;
use crate::handlers::oauth::generate_token_pair;
use crate::services::refresh_token_rotation::{
    RefreshTokenState as RotationRefreshTokenState, RotationDecision, RotationPolicy,
    evaluate_refresh,
};

fn rotation_state_from_refresh_token(refresh_token: &RefreshToken) -> RotationRefreshTokenState {
    RotationRefreshTokenState {
        chain_minted_at: refresh_token.chain_created_at,
        last_seen_at: refresh_token.last_seen_at,
        already_rotated: matches!(refresh_token.state, RefreshTokenState::Consumed { .. }),
        revoked: matches!(refresh_token.state, RefreshTokenState::Revoked { .. }),
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

    let ttl = super::capped_access_token_ttl(site_config.access_token_ttl);
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
