//! # Migration path
//!
//! The recovery workflow currently uses `UserRecoveryRepository` for state
//! tracking. It will be progressively migrated to use `WorkflowRepository`
//! for unified workflow state management. The strand engine
//! (`crate::handlers::strand`) can already orchestrate recovery as a
//! `default-recovery` strand.

use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{Context as _, Error as AnyhowError};
use coauth_data::user::{
    UserEmailRepository, UserPasswordRepository, UserRecoveryRepository, UserRepository,
};
use coauth_data::{
    BoxRepository, Clock, RepositoryAccess, RepositoryError, UserRecoverySession,
    UserRecoveryTicket,
};
use coauth_email_types::Address;
use rand_chacha::rand_core::CryptoRngCore;
use rand_core::RngCore;
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::handlers::notification_dispatch::{NotificationIntent, schedule_notification};
use crate::handlers::passwords::PasswordManager;
use crate::handlers::{Limiter, RequesterFingerprint, make_rng_from};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountRecoveryCompletion {
    pub trust_boundary: AccountRecoveryTrustBoundary,
}

impl AccountRecoveryCompletion {
    #[must_use]
    pub fn password_only() -> Self {
        Self {
            trust_boundary: AccountRecoveryTrustBoundary::password_only(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountRecoveryTrustBoundary {
    pub recovery_credential_kind: &'static str,
    pub account_password_reset: bool,
    pub device_trust_reset: bool,
    pub cross_signing_reset: bool,
    pub trusted_recovery_service_used: bool,
    pub device_trust_recovery_required: bool,
}

impl AccountRecoveryTrustBoundary {
    #[must_use]
    pub fn password_only() -> Self {
        Self {
            recovery_credential_kind: "email_recovery_ticket",
            account_password_reset: true,
            device_trust_reset: false,
            cross_signing_reset: false,
            trusted_recovery_service_used: false,
            device_trust_recovery_required: true,
        }
    }
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
    // Anti-enumeration: we deliberately do NOT short-circuit on
    // "no user with this email" here. A recovery session row is created
    // for any syntactically valid address, and the schedule_notification
    // step below silently no-ops downstream when the address is unknown.
    // From the caller's perspective the success response is identical
    // for registered and unregistered emails, so an attacker cannot use
    // this endpoint to enumerate accounts.
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
) -> Result<AccountRecoveryCompletion, CompleteAccountRecoveryError> {
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

    let user_id = user.id;
    let session_id = session.id;
    let ticket_id = ticket.id;

    let (version, hash) = password_manager
        .hash(make_rng_from(rng), new_password)
        .await
        .map_err(CompleteAccountRecoveryError::Password)?;

    repo.user_password()
        .add(rng, clock, &user, version, hash, None)
        .await?;

    // Recovery has no concept of a trusted current session, so revoke *all*
    // existing browser and OAuth sessions for the account. Any session
    // established before the recovery (potentially by an attacker) is
    // terminated.
    crate::handlers::account::service::sessions::revoke_user_sessions(
        &mut repo, rng, clock, &user, None, None,
    )
    .await?;

    repo.user_recovery()
        .consume_ticket(clock, ticket, session)
        .await?;

    repo.save().await?;

    let completion = AccountRecoveryCompletion::password_only();
    tracing::info!(
        target: "account_recovery_audit",
        user_id = %user_id,
        recovery_session_id = %session_id,
        recovery_ticket_id = %ticket_id,
        recovery_credential_kind = completion.trust_boundary.recovery_credential_kind,
        account_password_reset = completion.trust_boundary.account_password_reset,
        device_trust_reset = completion.trust_boundary.device_trust_reset,
        cross_signing_reset = completion.trust_boundary.cross_signing_reset,
        trusted_recovery_service_used = completion.trust_boundary.trusted_recovery_service_used,
        "account recovery completed within password-only trust boundary",
    );

    Ok(completion)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_recovery_completion_keeps_device_trust_out_of_scope() {
        let completion = AccountRecoveryCompletion::password_only();
        let boundary = completion.trust_boundary;

        assert_eq!(boundary.recovery_credential_kind, "email_recovery_ticket");
        assert!(boundary.account_password_reset);
        assert!(!boundary.device_trust_reset);
        assert!(!boundary.cross_signing_reset);
        assert!(!boundary.trusted_recovery_service_used);
        assert!(boundary.device_trust_recovery_required);
    }
}
