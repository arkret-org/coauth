//! # Migration path
//!
//! The recovery workflow currently uses `UserRecoveryRepository` for state
//! tracking. It will be progressively migrated to use `WorkflowRepository`
//! for unified workflow state management. The flow engine
//! (`crate::handlers::flow`) can already orchestrate recovery as a
//! `default-recovery` flow.

use std::{net::IpAddr, str::FromStr};

use anyhow::{Context as _, Error as AnyhowError};
use lettre::Address;
use coauth_data::{
    BoxRepository, Clock, RepositoryAccess, RepositoryError, UserRecoverySession,
    UserRecoveryTicket,
    user::{UserEmailRepository, UserPasswordRepository, UserRecoveryRepository, UserRepository},
};
use rand_chacha::rand_core::CryptoRngCore;
use rand_core::RngCore;
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::handlers::{
    Limiter, RequesterFingerprint,
    notification_dispatch::{NotificationIntent, schedule_notification},
    passwords::PasswordManager,
};

#[derive(Debug, Error)]
pub enum StartAccountRecoveryError {
    #[error("invalid email address")]
    InvalidEmail,

    #[error("account recovery is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum LoadAccountRecoverySessionError {
    #[error("account recovery session not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum ResendAccountRecoveryError {
    #[error("account recovery session not found")]
    NotFound,

    #[error("account recovery session already consumed")]
    AlreadyConsumed,

    #[error("account recovery is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum ResendAccountRecoveryByTicketError {
    #[error("recovery ticket not found")]
    TicketNotFound,

    #[error("recovery session not found")]
    SessionNotFound,

    #[error("recovery session already consumed")]
    AlreadyConsumed,

    #[error("account recovery resend is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum CompleteAccountRecoveryError {
    #[error("password manager is disabled")]
    PasswordDisabled,

    #[error("new password is too weak")]
    PasswordTooWeak,

    #[error("recovery ticket not found")]
    TicketNotFound,

    #[error("recovery session not found")]
    SessionNotFound,

    #[error("recovery ticket already consumed")]
    AlreadyConsumed,

    #[error("recovery ticket has expired")]
    TicketExpired,

    #[error("user email not found")]
    EmailNotFound,

    #[error("user not found")]
    UserNotFound,

    #[error("user account is locked")]
    AccountLocked,

    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
enum LoadAccountRecoveryTicketError {
    #[error("recovery ticket not found")]
    TicketNotFound,

    #[error("recovery session not found")]
    SessionNotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn start_account_recovery(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    email: String,
    user_agent: String,
    ip_address: Option<IpAddr>,
    locale: String,
) -> Result<UserRecoverySession, StartAccountRecoveryError> {
    if Address::from_str(&email).is_err() {
        return Err(StartAccountRecoveryError::InvalidEmail);
    }

    if let Err(error) = limiter.check_account_recovery(requester, &email).await {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(StartAccountRecoveryError::RateLimited);
    }

    let session = repo
        .user_recovery()
        .add_session(rng, clock, email, user_agent, ip_address, locale)
        .await?;

    schedule_notification(
        &mut repo,
        rng,
        clock,
        NotificationIntent::account_recovery(&session),
    )
    .await?;
    repo.save().await?;

    Ok(session)
}

pub async fn load_account_recovery_session(
    repo: &mut BoxRepository,
    id: Ulid,
) -> Result<UserRecoverySession, LoadAccountRecoverySessionError> {
    repo.user_recovery()
        .lookup_session(id)
        .await?
        .ok_or(LoadAccountRecoverySessionError::NotFound)
}

pub async fn resend_account_recovery(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    session_id: Ulid,
) -> Result<UserRecoverySession, ResendAccountRecoveryError> {
    let session = load_account_recovery_session(&mut repo, session_id)
        .await
        .map_err(|error| match error {
            LoadAccountRecoverySessionError::NotFound => ResendAccountRecoveryError::NotFound,
            LoadAccountRecoverySessionError::Repository(error) => {
                ResendAccountRecoveryError::Repository(error)
            }
        })?;

    if session.consumed_at.is_some() {
        return Err(ResendAccountRecoveryError::AlreadyConsumed);
    }

    if let Err(error) = limiter
        .check_account_recovery(requester, &session.email)
        .await
    {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(ResendAccountRecoveryError::RateLimited);
    }

    schedule_notification(
        &mut repo,
        rng,
        clock,
        NotificationIntent::account_recovery(&session),
    )
    .await?;
    repo.save().await?;

    Ok(session)
}

pub async fn resend_account_recovery_by_ticket(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    ticket_string: &str,
) -> Result<UserRecoverySession, ResendAccountRecoveryByTicketError> {
    let (_, session) = load_account_recovery_ticket(&mut repo, ticket_string)
        .await
        .map_err(|error| match error {
            LoadAccountRecoveryTicketError::TicketNotFound => {
                ResendAccountRecoveryByTicketError::TicketNotFound
            }
            LoadAccountRecoveryTicketError::SessionNotFound => {
                ResendAccountRecoveryByTicketError::SessionNotFound
            }
            LoadAccountRecoveryTicketError::Repository(error) => {
                ResendAccountRecoveryByTicketError::Repository(error)
            }
        })?;

    match resend_account_recovery(repo, limiter, rng, clock, requester, session.id).await {
        Ok(_) => Ok(session),
        Err(ResendAccountRecoveryError::NotFound) => {
            Err(ResendAccountRecoveryByTicketError::SessionNotFound)
        }
        Err(ResendAccountRecoveryError::AlreadyConsumed) => {
            Err(ResendAccountRecoveryByTicketError::AlreadyConsumed)
        }
        Err(ResendAccountRecoveryError::RateLimited) => {
            Err(ResendAccountRecoveryByTicketError::RateLimited)
        }
        Err(ResendAccountRecoveryError::Repository(error)) => {
            Err(ResendAccountRecoveryByTicketError::Repository(error))
        }
    }
}

pub async fn complete_account_recovery(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    ticket_string: &str,
    new_password: Zeroizing<String>,
    recovery_allowed: bool,
) -> Result<(), CompleteAccountRecoveryError> {
    if !password_manager.is_enabled() || !recovery_allowed {
        return Err(CompleteAccountRecoveryError::PasswordDisabled);
    }

    if !password_manager
        .is_password_complex_enough(&new_password)
        .map_err(|error| CompleteAccountRecoveryError::Password(error.into()))?
    {
        return Err(CompleteAccountRecoveryError::PasswordTooWeak);
    }

    let (ticket, session) = load_account_recovery_ticket(&mut repo, ticket_string)
        .await
        .map_err(|error| match error {
            LoadAccountRecoveryTicketError::TicketNotFound => {
                CompleteAccountRecoveryError::TicketNotFound
            }
            LoadAccountRecoveryTicketError::SessionNotFound => {
                CompleteAccountRecoveryError::SessionNotFound
            }
            LoadAccountRecoveryTicketError::Repository(error) => {
                CompleteAccountRecoveryError::Repository(error)
            }
        })?;

    if session.consumed_at.is_some() {
        return Err(CompleteAccountRecoveryError::AlreadyConsumed);
    }

    if !ticket.active(clock.now()) {
        return Err(CompleteAccountRecoveryError::TicketExpired);
    }

    let user_email = repo
        .user_email()
        .lookup(ticket.user_email_id)
        .await?
        .context("Unknown email")
        .map_err(|_| CompleteAccountRecoveryError::EmailNotFound)?;

    let user = repo
        .user()
        .lookup(user_email.user_id)
        .await?
        .context("Invalid user")
        .map_err(|_| CompleteAccountRecoveryError::UserNotFound)?;

    if !user.is_valid() {
        return Err(CompleteAccountRecoveryError::AccountLocked);
    }

    let (version, hash) = password_manager
        .hash(make_rng_from(rng), new_password)
        .await
        .map_err(CompleteAccountRecoveryError::Password)?;

    repo.user_password()
        .add(rng, clock, &user, version, hash, None)
        .await?;

    repo.user_recovery()
        .consume_ticket(clock, ticket, session)
        .await?;

    repo.save().await?;

    Ok(())
}

#[must_use]
pub fn recovery_session_status(session: &UserRecoverySession) -> &'static str {
    if session.consumed_at.is_some() {
        "consumed"
    } else {
        "pending"
    }
}

async fn load_account_recovery_ticket(
    repo: &mut BoxRepository,
    ticket_string: &str,
) -> Result<(UserRecoveryTicket, UserRecoverySession), LoadAccountRecoveryTicketError> {
    let ticket = repo
        .user_recovery()
        .find_ticket(ticket_string)
        .await?
        .ok_or(LoadAccountRecoveryTicketError::TicketNotFound)?;

    let session = repo
        .user_recovery()
        .lookup_session(ticket.user_recovery_session_id)
        .await?
        .context("Unknown session")
        .map_err(|_| LoadAccountRecoveryTicketError::SessionNotFound)?;

    Ok((ticket, session))
}

/// Create a new RNG from the provided one, suitable for `PasswordManager::hash`
/// which requires `CryptoRng + RngCore + Send`.
fn make_rng_from(rng: &mut (dyn CryptoRngCore + Send)) -> rand_chacha::ChaChaRng {
    use rand_chacha::rand_core::SeedableRng;
    rand_chacha::ChaChaRng::from_rng(rng).expect("seeding ChaChaRng should not fail")
}
