use coauth_data::{
    BoxRepository, BoxRng, Clock, RepositoryAccess, RepositoryError, TokenType,
    oauth2::{OAuth2AccessTokenRepository, OAuth2RefreshTokenRepository, OAuth2SessionRepository},
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    user::UserRepository,
};
use coauth_iana::oauth::OAuthTokenTypeHint;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::BoundActivityTracker;

/// Errors that can occur during token revocation business logic.
#[derive(Debug, Error)]
pub enum RevocationError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error("unsupported token type")]
    UnsupportedTokenType,

    #[error("unknown token")]
    UnknownToken,

    #[error("client is unauthorized to revoke this session")]
    UnauthorizedClient,
}

/// Look up a token by its string value, verify ownership by the given client,
/// and revoke the entire associated OAuth 2.0 session.
///
/// The caller is responsible for client authentication and HTTP-level
/// concerns. This function only touches the repository.
pub async fn revoke_token(
    repo: &mut BoxRepository,
    rng: &mut BoxRng,
    clock: &dyn Clock,
    activity_tracker: &BoundActivityTracker,
    token_str: &str,
    token_type_hint: Option<OAuthTokenTypeHint>,
    client_id: Option<Ulid>,
) -> Result<(), RevocationError> {
    let token_type = TokenType::check(token_str).map_err(|_| RevocationError::UnknownToken)?;

    // Find the ID of the session to end.
    let session_id = match (token_type_hint, token_type) {
        (Some(OAuthTokenTypeHint::AccessToken) | None, TokenType::AccessToken) => {
            let access_token = repo
                .oauth2_access_token()
                .find_by_token(token_str)
                .await?
                .ok_or(RevocationError::UnknownToken)?;

            if !access_token.is_valid(clock.now()) {
                return Err(RevocationError::UnknownToken);
            }
            access_token.session_id
        }

        (Some(OAuthTokenTypeHint::RefreshToken) | None, TokenType::RefreshToken) => {
            let refresh_token = repo
                .oauth2_refresh_token()
                .find_by_token(token_str)
                .await?
                .ok_or(RevocationError::UnknownToken)?;

            if !refresh_token.is_valid() {
                return Err(RevocationError::UnknownToken);
            }

            refresh_token.session_id
        }

        // Mismatch between the token type hint and the guessed token type.
        (Some(OAuthTokenTypeHint::AccessToken | OAuthTokenTypeHint::RefreshToken) | None, _) => {
            return Err(RevocationError::UnknownToken);
        }

        (Some(_), _) => return Err(RevocationError::UnsupportedTokenType),
    };

    let session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(RevocationError::UnknownToken)?;

    // Check that the session is still valid.
    if !session.is_valid() {
        return Err(RevocationError::UnknownToken);
    }

    // Check that the client ending the session is the same as the client that
    // created it.  When client_id is None (admin-secret auth), skip this
    // check so that the PrincipalServer can revoke tokens on behalf of any client.
    if let Some(client_id) = client_id {
        if client_id != session.client_id {
            return Err(RevocationError::UnauthorizedClient);
        }
    }

    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    // If the session is associated with a user, make sure we schedule a device
    // deletion job for all the devices associated with the session.
    if let Some(user_id) = session.user_id {
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or(RevocationError::UnknownToken)?;

        repo.queue_job()
            .schedule_job(rng, clock, SyncDevicesJob::new(&user))
            .await?;
    }

    // Now that we checked everything, we can end the session.
    repo.oauth2_session().finish(clock, session).await?;

    Ok(())
}
