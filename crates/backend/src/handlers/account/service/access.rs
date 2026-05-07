use anyhow::Error as AnyhowError;
use coauth_config::ContrixConfig;
use coauth_data::{
    BoxRepository, BrowserSession, Clock, RepositoryAccess, RepositoryError, SiteConfig,
    UpstreamOAuthProvider, UrlBuilder, User,
    upstream_oauth2::UpstreamOAuthProviderRepository,
    user::{BrowserSessionRepository, UserPasswordRepository, UserRepository},
};
use coauth_matrix::HomeserverAdmin;
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::handlers::{
    Limiter, RequesterFingerprint, contrix,
    passwords::{PasswordManager, PasswordVerificationResult},
};

#[derive(Debug)]
pub struct PasswordLoginRequest {
    pub username_or_email: String,
    pub password: Zeroizing<String>,
    pub user_agent: Option<String>,
    pub requester: RequesterFingerprint,
}

#[derive(Debug)]
pub enum PasswordLoginOutcome {
    Disabled,
    InvalidCredentials,
    RateLimited,
    AccountDeactivated {
        user: User,
    },
    AccountLocked {
        user: User,
    },
    Authenticated {
        user: User,
        user_session: BrowserSession,
    },
}

#[derive(Debug, Error)]
pub enum PasswordLoginError {
    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn load_enabled_upstream_providers<R: RepositoryAccess>(
    repo: &mut R,
) -> Result<Vec<UpstreamOAuthProvider>, R::Error> {
    repo.upstream_oauth_provider().all_enabled().await
}

pub async fn login_with_password(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    limiter: &Limiter,
    homeserver: &dyn HomeserverAdmin,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    site_config: &SiteConfig,
    request: PasswordLoginRequest,
) -> Result<PasswordLoginOutcome, PasswordLoginError> {
    if !site_config.password_login_enabled {
        return Ok(PasswordLoginOutcome::Disabled);
    }

    // Anti-enumeration: when the username or email is unknown we return
    // the same `InvalidCredentials` outcome the caller would see for a
    // wrong password. Do NOT introduce a more specific "user_not_found"
    // signal — the HTTP response shape is the only thing exposed to the
    // attacker, and giving them a way to distinguish "user exists but
    // bad password" from "no such user" is exactly the leak we are
    // trying to avoid.
    let Some(user) = find_user_by_login_identifier(
        site_config,
        homeserver,
        url_builder,
        contrix_config,
        &mut repo,
        &request.username_or_email,
    )
    .await?
    else {
        return Ok(PasswordLoginOutcome::InvalidCredentials);
    };

    if limiter
        .check_password(request.requester, &user)
        .await
        .is_err()
    {
        return Ok(PasswordLoginOutcome::RateLimited);
    }

    let Some(user_password) = repo.user_password().active(&user).await? else {
        return Ok(PasswordLoginOutcome::InvalidCredentials);
    };

    let user_password = match password_manager
        .verify_and_upgrade(
            &mut *rng,
            user_password.version,
            request.password,
            user_password.hashed_password.clone(),
        )
        .await
    {
        Ok(PasswordVerificationResult::Matched(Some((version, new_password_hash)))) => {
            repo.user_password()
                .add(
                    &mut *rng,
                    clock,
                    &user,
                    version,
                    new_password_hash,
                    Some(&user_password),
                )
                .await?
        }
        Ok(PasswordVerificationResult::Matched(None)) => user_password,
        Ok(PasswordVerificationResult::NotMatched) => {
            return Ok(PasswordLoginOutcome::InvalidCredentials);
        }
        Err(error) => return Err(PasswordLoginError::Password(error.into())),
    };

    if user.deactivated_at.is_some() {
        return Ok(PasswordLoginOutcome::AccountDeactivated { user });
    }

    if user.locked_at.is_some() {
        return Ok(PasswordLoginOutcome::AccountLocked { user });
    }

    debug_assert!(user.is_valid());

    let user_session = repo
        .browser_session()
        .add(&mut *rng, clock, &user, request.user_agent)
        .await?;

    repo.browser_session()
        .authenticate_with_password(&mut *rng, clock, &user_session, &user_password)
        .await?;

    repo.save().await?;

    Ok(PasswordLoginOutcome::Authenticated { user, user_session })
}

pub async fn logout_browser_session(
    mut repo: BoxRepository,
    clock: &dyn Clock,
    session_id: Option<Ulid>,
) -> Result<Option<BrowserSession>, RepositoryError> {
    let maybe_session = if let Some(session_id) = session_id {
        let maybe_session = repo.browser_session().lookup(session_id).await?;

        if let Some(session) = maybe_session {
            if session.finished_at.is_none() {
                repo.browser_session()
                    .finish(clock, session.clone())
                    .await?;
                Some(session)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    repo.save().await?;

    Ok(maybe_session)
}

async fn find_user_by_email_or_by_username(
    site_config: &SiteConfig,
    repo: &mut BoxRepository,
    username_or_email: &str,
) -> Result<Option<User>, RepositoryError> {
    if site_config.login_with_email_allowed && username_or_email.contains('@') {
        let maybe_user_email = repo.user_email().find_by_email(username_or_email).await?;

        if let Some(user_email) = maybe_user_email {
            let user = repo.user().lookup(user_email.user_id).await?;

            if user.is_some() {
                return Ok(user);
            }
        }
    }

    repo.user().find_by_username(username_or_email).await
}

async fn find_user_by_login_identifier(
    site_config: &SiteConfig,
    homeserver: &dyn HomeserverAdmin,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    repo: &mut BoxRepository,
    identifier: &str,
) -> Result<Option<User>, RepositoryError> {
    if let Some(user_id) =
        contrix::parse_local_user_did_for(url_builder, contrix_config, identifier)
    {
        return repo.user().lookup(user_id).await;
    }

    if let Some(username) = contrix::parse_local_handle(url_builder, identifier)
        && let Some(user) = repo.user().find_by_username(&username).await?
    {
        return Ok(Some(user));
    }

    let username_or_email = homeserver.localpart(identifier).unwrap_or(identifier);
    find_user_by_email_or_by_username(site_config, repo, username_or_email).await
}
