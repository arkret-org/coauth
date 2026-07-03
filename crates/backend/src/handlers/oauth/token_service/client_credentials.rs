//! `client_credentials` grant-type handling.

use coauth_data::{BoxRepository, Client, Clock, SiteConfig, TokenType};
use coauth_oauth_types::requests::{AccessTokenResponse, ClientCredentialsGrant, GrantType};
use coauth_policy::PolicyInstance;

use super::ClientCredentialsGrantError;
use crate::handlers::BoundActivityTracker;
use crate::oidc_client::types::scope::ScopeToken;

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
    mut policy: PolicyInstance,
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

    let ttl = super::capped_access_token_ttl(site_config.access_token_ttl);
    let access_token_str = TokenType::AccessToken.generate(rng);

    let access_token = repo
        .oauth_access_token()
        .add(rng, clock, &session, access_token_str, Some(ttl))
        .await?;

    let mut params = AccessTokenResponse::new(access_token.access_token).with_expires_in(ttl);

    // TODO: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker.record_oauth_session(clock, &session).await;

    if !session.scope.is_empty() {
        // We only return the scope if it's not empty
        params = params.with_scope(session.scope);
    }

    Ok((params, repo))
}
