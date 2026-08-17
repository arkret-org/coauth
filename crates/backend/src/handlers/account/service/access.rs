use anyhow::Error as AnyhowError;
use coauth_config::ArkretConfig;
use coauth_data::upstream_oauth::UpstreamOAuthProviderRepository;
use coauth_data::user::{BrowserSessionRepository, UserPasswordRepository, UserRepository};
use coauth_data::{
    BoxRepository, BrowserSession, Clock, RepositoryAccess, RepositoryError, SiteConfig,
    UpstreamOAuthProvider, UrlBuilder, User,
};
use coauth_principal::ConnectorAdmin;
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::handlers::passwords::{PasswordManager, PasswordVerificationResult};
use crate::handlers::{Limiter, RequesterFingerprint, arkret};

#[derive(Debug)]
pub struct PasswordLoginRequestBody {
    pub username_or_email: String,
    pub password: Zeroizing<String>,
    pub user_agent: Option<String>,
    pub requester: RequesterFingerprint,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PasswordLoginOutcome {
    Disabled,
    InvalidCredentials,
    RateLimited,
    AccountDeactivated,
    AccountLocked,
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
    principal_server: &dyn ConnectorAdmin,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    site_config: &SiteConfig,
    request: PasswordLoginRequestBody,
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
    // trying to avoid. We also run a dummy password verify so the
    // response latency matches the real-verify path.
    let Some(user) = find_user_by_login_identifier(
        site_config,
        principal_server,
        url_builder,
        arkret_config,
        &mut repo,
        &request.username_or_email,
    )
    .await?
    else {
        password_manager
            .dummy_verify(&mut *rng, request.password)
            .await
            .map_err(PasswordLoginError::Password)?;
        return Ok(PasswordLoginOutcome::InvalidCredentials);
    };

    if limiter
        .check_password(request.requester, &user)
        .await
        .is_err()
    {
        return Ok(PasswordLoginOutcome::RateLimited);
    }

    // Failed-login lockout, before the password is verified: while the account
    // is locked out a correct guess MUST NOT authenticate, otherwise the
    // lockout only delays the attacker instead of stopping the run. The
    // sliding-window limiter above does not cover this — it bounds attempt
    // rate and is spent by successful logins too, so an attacker pacing
    // themselves under the rate guesses indefinitely.
    if limiter.check_login_lockout(&user).await.is_err() {
        return Ok(PasswordLoginOutcome::AccountLocked);
    }

    let Some(user_password) = repo.user_password().active(&user).await? else {
        // The account exists but has no active password (e.g. SSO-only).
        // Match the real-verify timing for the same anti-enumeration reason.
        password_manager
            .dummy_verify(&mut *rng, request.password)
            .await
            .map_err(PasswordLoginError::Password)?;
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
            limiter.record_failed_login(&user).await;
            return Ok(PasswordLoginOutcome::InvalidCredentials);
        }
        Err(error) => return Err(PasswordLoginError::Password(error)),
    };

    // The password verified and the account was not locked out when we
    // checked, so this run is over. Ordering matters: reaching this after a
    // lockout check that passed is what stops a lucky guess mid-lockout from
    // clearing the lockout it should have been refused by.
    limiter.record_successful_login(&user).await;

    if user.deactivated_at.is_some() {
        return Ok(PasswordLoginOutcome::AccountDeactivated);
    }

    if user.locked_at.is_some() {
        return Ok(PasswordLoginOutcome::AccountLocked);
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

    repo.user().find_by_handle(username_or_email).await
}

async fn find_user_by_login_identifier(
    site_config: &SiteConfig,
    principal_server: &dyn ConnectorAdmin,
    url_builder: &UrlBuilder,
    _arkret_config: &ArkretConfig,
    repo: &mut BoxRepository,
    identifier: &str,
) -> Result<Option<User>, RepositoryError> {
    if let Some(username) = arkret::parse_local_handle(url_builder, identifier)
        && let Some(user) = repo.user().find_by_handle(&username).await?
    {
        return Ok(Some(user));
    }

    let _ = principal_server;
    find_user_by_email_or_by_username(site_config, repo, identifier).await
}

#[cfg(test)]
mod lockout_wiring_tests {
    use std::num::NonZeroU32;

    use coauth_data::RepositoryAccess;
    use coauth_data::user::{UserPasswordRepository, UserRepository};
    use ulid::Ulid;

    use super::*;
    use crate::handlers::test_utils::{TestState, setup};

    const PASSWORD: &str = "this is a good enough password";

    async fn attempt(
        state: &TestState,
        limiter: &Limiter,
        localpart: &str,
        password: &str,
    ) -> PasswordLoginOutcome {
        login_with_password(
            state.repository().await.unwrap(),
            &mut state.rng(),
            &state.clock,
            &state.password_manager,
            limiter,
            state.principal_server_admin.as_ref(),
            &state.url_builder,
            &state.arkret_config,
            &state.site_config,
            PasswordLoginRequestBody {
                username_or_email: localpart.to_owned(),
                password: Zeroizing::new(password.to_owned()),
                user_agent: None,
                requester: RequesterFingerprint::EMPTY,
            },
        )
        .await
        .unwrap()
    }

    /// Pins the failed-login lockout to its production caller.
    ///
    /// The unit tests in `handlers::rate_limit` prove the tracker counts and
    /// locks; nothing there proves `login_with_password` consults it. That is
    /// the exact shape the 2026-07-16 finding describes: a control that exists
    /// but has no caller reads as implemented and stops nothing. Deleting
    /// either `record_failed_login` or `check_login_lockout` from the login
    /// path makes the final assertion below authenticate instead of lock.
    #[tokio::test]
    async fn login_with_password_locks_the_account_after_consecutive_failures() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool(pool.clone()).await.unwrap();

        let localpart = format!("lockout-{}", Ulid::new().to_string().to_lowercase());
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, localpart.clone())
            .await
            .unwrap();
        let (version, hashed_password) = state
            .password_manager
            .hash(state.rng(), Zeroizing::new(PASSWORD.to_owned()))
            .await
            .unwrap();
        repo.user_password()
            .add(
                &mut state.rng(),
                &state.clock,
                &user,
                version,
                hashed_password,
                None,
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let mut rate_limits = coauth_config::RateLimitingConfig::default();
        let threshold = rate_limits.login.lockout.consecutive_failures;
        assert!(threshold > 0, "the shipped default must enable the lockout");
        // This test isolates the lockout wiring. The independent per-IP quota
        // defaults to a three-attempt burst and would otherwise return
        // `RateLimited` before the shipped ten-failure lockout threshold. Keep
        // the production lockout config, but give this one requester enough
        // ordinary attempt budget to reach it and make the final assertion
        // exercise `check_login_lockout`.
        rate_limits.login.per_ip.burst = NonZeroU32::new(threshold + 1).unwrap();
        let limiter = Limiter::new(&rate_limits).unwrap();

        for _ in 0..threshold {
            assert!(
                matches!(
                    attempt(&state, &limiter, &localpart, "wrong password entirely").await,
                    PasswordLoginOutcome::InvalidCredentials
                ),
                "a wrong password must report invalid credentials, not lock immediately"
            );
        }

        // The load-bearing assertion: the CORRECT password now. Without the
        // lockout consulted here this authenticates, which is precisely the
        // brute-force run the control exists to end.
        assert!(
            matches!(
                attempt(&state, &limiter, &localpart, PASSWORD).await,
                PasswordLoginOutcome::AccountLocked
            ),
            "past the threshold even a correct password must be refused"
        );
    }
}
