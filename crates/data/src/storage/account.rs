//! Account aggregate repository.
//!
//! This module provides a unified read interface over contact points, identity
//! bindings, and security events for a given user account. Instead of reaching
//! into `UserEmailRepository`, `UserPhoneRepository`,
//! `UpstreamOAuthLinkRepository`, and `AuditRepository` separately, callers
//! can use [`AccountRepository`] to get a coherent view suitable for the user
//! portal.

use async_trait::async_trait;
use coauth_data::{AccountContactPoint, AccountIdentityBinding, AccountSecurityEvent};
use ulid::Ulid;

use crate::repository_impl;

/// A security summary for a user account.
///
/// This is a pre-aggregated snapshot that saves the caller from issuing
/// multiple queries when rendering a security overview page.
#[derive(Debug, Clone)]
pub struct AccountSecuritySummary {
    /// Whether the user has a password set.
    pub has_password: bool,
    /// The number of currently active browser/app sessions.
    pub active_sessions_count: usize,
    /// The number of verified email addresses.
    pub verified_emails_count: usize,
    /// The number of verified phone numbers.
    pub verified_phones_count: usize,
    /// The number of linked upstream identity providers.
    pub linked_providers_count: usize,
    /// Recent security events for the user (most recent first).
    pub recent_security_events: Vec<AccountSecurityEvent>,
}

/// Unified read-only repository for account-level aggregates.
///
/// This trait assembles data that is physically stored across several tables
/// (emails, phones, upstream links, sessions, passwords, audit events) into
/// coherent domain views.
#[async_trait]
pub trait AccountRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// List all contact points (emails and phones) for a user.
    ///
    /// The returned list is ordered by creation time, with the primary
    /// contact point for each channel listed first.
    ///
    /// # Parameters
    ///
    /// * `user_id`: The ID of the user whose contact points to list
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list_contact_points(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountContactPoint>, Self::Error>;

    /// List all identity bindings (upstream OAuth links, Station
    /// links, etc.) for a user.
    ///
    /// # Parameters
    ///
    /// * `user_id`: The ID of the user whose identity bindings to list
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list_identity_bindings(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountIdentityBinding>, Self::Error>;

    /// Get a security summary for a user.
    ///
    /// This aggregates password status, session counts, verified contact
    /// counts, linked provider counts, and recent security events into a
    /// single response.
    ///
    /// # Parameters
    ///
    /// * `user_id`: The ID of the user whose security summary to retrieve
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn security_summary(
        &mut self,
        user_id: Ulid,
    ) -> Result<AccountSecuritySummary, Self::Error>;
}

repository_impl!(AccountRepository:
    async fn list_contact_points(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountContactPoint>, Self::Error>;
    async fn list_identity_bindings(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountIdentityBinding>, Self::Error>;
    async fn security_summary(
        &mut self,
        user_id: Ulid,
    ) -> Result<AccountSecuritySummary, Self::Error>;
);
