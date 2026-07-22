use std::net::IpAddr;

use arkret_core::{AccountStatus, Handle};
use chrono::{DateTime, Utc};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::new_id;
use crate::pagination::Node;

/// A downstream principal account projection used by consent and viewer APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrincipalUser {
    pub principal_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub id: Ulid,
    /// Bare handle localpart (e.g. `alice` — no `@`, no `:domain`). The
    /// canonical Arkret handle `<localpart>:<domain>` is derived at read
    /// time via [`Self::canonical_handle`] using the public host name, so a
    /// service domain rename never rewrites this column. Wire/UI types keep
    /// the field name `handle` for the value the user types.
    pub localpart: String,
    pub sub: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: AccountStatus,
    pub locked_at: Option<DateTime<Utc>>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub can_request_admin: bool,
    pub is_guest: bool,
    // Profile fields synced to the downstream principal projection.
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub preferred_locale: Option<String>,
    /// Interop alias handles for this user (e.g. `acct:<local>@<host>`).
    ///
    /// Spec 7157ee8 §3.1 — the canonical Arkret handle form is
    /// `<localpart>:<domain>`, derived at read time from `localpart` + the
    /// public host name (see [`Self::canonical_handle`]). Aliases are
    /// *additional* identifiers kept for RFC 7565 / WebFinger interop and
    /// `handle_claim.handle_aliases` emission. Migration
    /// `20260520000100_handle_claims_and_audit` adds the underlying column
    /// with `DEFAULT ARRAY[]::TEXT[]`.
    pub handle_aliases: Vec<String>,
}

/// A versioned holder preference for DID `metadata.primary_handle`.
///
/// `handle = None` is a deliberate clear operation and must still be persisted
/// so historical as-of queries can distinguish "not set yet" from "explicitly
/// cleared at this time".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPrimaryHandlePreference {
    pub id: Ulid,
    pub user_id: Ulid,
    pub handle: Option<String>,
    pub effective_at: DateTime<Utc>,
    pub replaced_at: Option<DateTime<Utc>>,
    pub source_claim_id: Option<Ulid>,
    pub source_claim_digest: Option<String>,
    pub actor_user_id: Option<Ulid>,
    pub source: String,
    pub created_at: DateTime<Utc>,
}

/// Verified handle-claim evidence that can back a primary-handle preference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedUserHandleClaim {
    pub id: Ulid,
    pub user_id: Ulid,
    pub handle: String,
    pub claim_digest: String,
    pub issued_at: DateTime<Utc>,
}

/// Insert parameters for a new primary-handle preference version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUserPrimaryHandlePreference {
    pub user_id: Ulid,
    pub handle: Option<String>,
    pub source_claim_id: Option<Ulid>,
    pub source_claim_digest: Option<String>,
    pub actor_user_id: Option<Ulid>,
    pub source: String,
}

impl NewUserPrimaryHandlePreference {
    #[must_use]
    pub fn self_service(
        user_id: Ulid,
        handle: Option<String>,
        claim: Option<&VerifiedUserHandleClaim>,
        actor_user_id: Ulid,
    ) -> Self {
        Self {
            user_id,
            handle,
            source_claim_id: claim.map(|claim| claim.id),
            source_claim_digest: claim.map(|claim| claim.claim_digest.clone()),
            actor_user_id: Some(actor_user_id),
            source: "self_service".to_owned(),
        }
    }
}

impl Node<Ulid> for User {
    fn cursor(&self) -> Ulid {
        self.id
    }
}

/// Validate that an input string is already the SDK-canonical Arkret handle.
pub fn validate_canonical_handle(value: &str) -> Result<&str, (&'static str, String)> {
    let trimmed = value.trim();
    let handle = Handle::parse(trimmed)
        .map_err(|error| (arkret_core::ErrorCode::INVALID_PARAM, error.to_string()))?;
    if handle.canonical() != trimmed {
        return Err((
            arkret_core::ErrorCode::INVALID_PARAM,
            format!("handle must be canonical form {}", handle.canonical()),
        ));
    }
    Ok(trimmed)
}

impl User {
    /// Canonical Arkret handle:
    /// `<prepared-localpart>:<lowercase-A-label-domain>`.
    ///
    /// The host is supplied by the caller (typically the URL builder's
    /// public hostname); the data crate has no opinion on which host is
    /// "the" service host since the same `User` row may be addressed by
    /// multiple alias hosts.
    pub fn canonical_handle(&self, host: &str) -> arkret_wire::Result<String> {
        Ok(Handle::prepare(&format!("{}:{host}", self.localpart))?
            .canonical()
            .to_owned())
    }

    /// Interop `acct:` alias for this user against the supplied host. Used
    /// to populate `handle_claim.handle_aliases[]`. Never used as canonical.
    pub fn acct_alias(&self, host: &str) -> arkret_wire::Result<String> {
        Ok(Handle::prepare(&format!("{}:{host}", self.localpart))?.to_acct())
    }
}

impl User {
    #[must_use]
    pub fn profile(&self) -> UserProfile {
        UserProfile {
            display_name: self.display_name.clone(),
            avatar_url: self.avatar_url.clone(),
            preferred_locale: self.preferred_locale.clone(),
            updated_at: self.updated_at,
        }
    }

    /// Returns `true` unless the user is locked or deactivated.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.status == AccountStatus::Active
    }

    /// Returns `true` if the user is a valid actor, for example
    /// of a personal session.
    ///
    /// Currently: this is `true` unless the user is deactivated.
    ///
    /// This is a weaker form of validity: `is_valid` always implies
    /// `is_valid_actor`, but some users (currently: locked users)
    /// can be valid actors for personal sessions but aren't valid
    /// except through administrative access.
    #[must_use]
    pub fn is_valid_actor(&self) -> bool {
        !matches!(
            self.status,
            AccountStatus::Suspended | AccountStatus::Deactivated | AccountStatus::ErasurePending
        )
    }
}

impl User {
    #[doc(hidden)]
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut (impl RngCore + ?Sized)) -> Vec<Self> {
        vec![User {
            id: new_id(now, rng),
            localpart: "john".to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            updated_at: now,
            status: AccountStatus::Active,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: false,
            display_name: Some("John".to_owned()),
            avatar_url: None,
            preferred_locale: Some("en".to_owned()),
            handle_aliases: Vec::new(),
        }]
    }
}

/// coauth extension: user profile snapshot used for display and API responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfile {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub preferred_locale: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// coauth extension: a patch object for updating user profile fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfilePatch {
    pub display_name: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
    pub preferred_locale: Option<Option<String>>,
}

impl UserProfilePatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.display_name.is_none() && self.avatar_url.is_none() && self.preferred_locale.is_none()
    }
}

/// coauth extension: a patch object for updating user fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPatch {
    pub display_name: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
    pub preferred_locale: Option<Option<String>>,
    pub can_request_admin: Option<bool>,
    pub status: Option<AccountStatus>,
    pub locked: Option<bool>,
    pub deactivated: Option<bool>,
}

impl UserPatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.display_name.is_none()
            && self.avatar_url.is_none()
            && self.preferred_locale.is_none()
            && self.can_request_admin.is_none()
            && self.status.is_none()
            && self.locked.is_none()
            && self.deactivated.is_none()
    }
}

impl From<UserProfilePatch> for UserPatch {
    fn from(value: UserProfilePatch) -> Self {
        Self {
            display_name: value.display_name,
            avatar_url: value.avatar_url,
            preferred_locale: value.preferred_locale,
            can_request_admin: None,
            status: None,
            locked: None,
            deactivated: None,
        }
    }
}

/// coauth extension: admin-specific user patch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminUserPatch {
    pub display_name: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
    pub preferred_locale: Option<Option<String>>,
    pub can_request_admin: Option<bool>,
    pub status: Option<AccountStatus>,
    pub locked: Option<bool>,
    pub deactivated: Option<bool>,
}

impl AdminUserPatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.display_name.is_none()
            && self.avatar_url.is_none()
            && self.preferred_locale.is_none()
            && self.can_request_admin.is_none()
            && self.status.is_none()
            && self.locked.is_none()
            && self.deactivated.is_none()
    }
}

impl From<AdminUserPatch> for UserPatch {
    fn from(value: AdminUserPatch) -> Self {
        Self {
            display_name: value.display_name,
            avatar_url: value.avatar_url,
            preferred_locale: value.preferred_locale,
            can_request_admin: value.can_request_admin,
            status: value.status,
            locked: value.locked,
            deactivated: value.deactivated,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Password {
    pub id: Ulid,
    pub hashed_password: String,
    pub version: u16,
    pub upgraded_from_id: Option<Ulid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Authentication {
    pub id: Ulid,
    pub created_at: DateTime<Utc>,
    pub authentication_method: AuthenticationMethod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AuthenticationMethod {
    Password { user_password_id: Ulid },
    UpstreamOAuth { upstream_oauth_session_id: Ulid },
    Unknown,
}

/// A session to recover a user if they have lost their credentials
///
/// For each session initiated, there may be multiple [`UserRecoveryTicket`]s
/// sent to the user, either because multiple [`User`] have the same email
/// address, or because the user asked to send the recovery email again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRecoverySession {
    pub id: Ulid,
    pub email: String,
    pub user_agent: String,
    pub ip_address: Option<IpAddr>,
    pub locale: String,
    pub created_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

/// A single recovery ticket for a user recovery session
///
/// Whenever a new recovery session is initiated, a new ticket is created for
/// each email address matching in the database. That ticket is sent by email,
/// as a link that the user can click to recover their account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRecoveryTicket {
    pub id: Ulid,
    pub user_recovery_session_id: Ulid,
    pub user_email_id: Ulid,
    pub ticket: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl UserRecoveryTicket {
    #[must_use]
    pub fn active(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

/// coauth extension: a user email authentication session
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmailAuthentication {
    pub id: Ulid,
    pub user_session_id: Option<Ulid>,
    pub user_registration_id: Option<Ulid>,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// coauth extension: a user email authentication code
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmailAuthenticationCode {
    pub id: Ulid,
    pub user_email_authentication_id: Ulid,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserSession {
    pub id: Ulid,
    pub user: User,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
}

impl BrowserSession {
    #[must_use]
    pub fn active(&self) -> bool {
        self.finished_at.is_none() && self.user.is_valid()
    }
}

impl BrowserSession {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut (impl RngCore + ?Sized)) -> Vec<Self> {
        User::samples(now, rng)
            .into_iter()
            .map(|user| BrowserSession {
                id: new_id(now, rng),
                user,
                created_at: now,
                finished_at: None,
                user_agent: Some(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36".to_owned()
                ),
                last_active_at: Some(now),
                last_active_ip: None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmail {
    pub id: Ulid,
    pub user_id: Ulid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub is_primary: bool,
}

impl UserEmail {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut (impl RngCore + ?Sized)) -> Vec<Self> {
        vec![
            Self {
                id: new_id(now, rng),
                user_id: new_id(now, rng),
                email: "alice@example.com".to_owned(),
                created_at: now,
                updated_at: now,
                confirmed_at: Some(now),
                is_primary: true,
            },
            Self {
                id: new_id(now, rng),
                user_id: new_id(now, rng),
                email: "bob@example.com".to_owned(),
                created_at: now,
                updated_at: now,
                confirmed_at: None,
                is_primary: false,
            },
        ]
    }
}

/// coauth extension: a patch object for updating user email fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserEmailPatch {
    pub email: Option<String>,
    pub confirmed: Option<bool>,
    pub is_primary: Option<bool>,
}

impl UserEmailPatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.email.is_none() && self.confirmed.is_none() && self.is_primary.is_none()
    }
}

/// coauth extension: password data stored during user registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRegistrationPassword {
    pub hashed_password: String,
    pub version: u16,
}

/// coauth extension: a registration token for gated signups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRegistrationToken {
    pub id: Ulid,
    pub token: String,
    pub usage_limit: Option<u32>,
    pub times_used: u32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl UserRegistrationToken {
    /// Returns `true` if the token is still valid and can be used
    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        // Check if revoked
        if self.revoked_at.is_some() {
            return false;
        }

        // Check if expired
        if let Some(expires_at) = self.expires_at
            && now >= expires_at
        {
            return false;
        }

        // Check if usage limit exceeded
        if let Some(usage_limit) = self.usage_limit
            && self.times_used >= usage_limit
        {
            return false;
        }

        true
    }

    /// Returns `true` if the token can still be used (not expired and under
    /// usage limit)
    #[must_use]
    pub fn can_be_used(&self, now: DateTime<Utc>) -> bool {
        self.is_valid(now)
    }
}

/// coauth extension: an in-progress user registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRegistration {
    pub id: Ulid,
    /// Bare handle localpart chosen during registration (no `@` / `:domain`);
    /// carried into [`User::localpart`] on completion.
    pub localpart: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub terms_url: Option<url::Url>,
    pub email_authentication_id: Option<Ulid>,
    pub phone_authentication_id: Option<Ulid>,
    pub user_registration_token_id: Option<Ulid>,
    pub password: Option<UserRegistrationPassword>,
    pub upstream_oauth_authorization_session_id: Option<Ulid>,
    pub post_auth_action: Option<serde_json::Value>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// coauth extension: a phone number associated with a user
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPhone {
    pub id: Ulid,
    pub user_id: Ulid,
    pub phone: String,
    pub created_at: DateTime<Utc>,
}

/// coauth extension: an authentication session for a phone number
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPhoneAuthentication {
    pub id: Ulid,
    pub user_registration_id: Option<Ulid>,
    pub phone: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// coauth extension: a verification code for phone authentication
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPhoneAuthenticationCode {
    pub id: Ulid,
    pub user_phone_authentication_id: Ulid,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A TOTP authenticator configuration for a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserTotpConfig {
    pub id: Ulid,
    pub user_id: Ulid,
    pub secret: String,
    pub algorithm: String,
    pub digits: i32,
    pub period: i32,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Verified binding between a coauth service account and a principal DID.
///
/// Coauth stores no principal root, recovery, or update private material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrincipalDidBinding {
    pub id: Ulid,
    pub user_id: Ulid,
    /// Audience string of the principal server that verified the submitted DID.
    pub audience: String,
    /// Principal DID supplied by the client and verified by the authoritative host.
    pub principal_id: String,
    /// Verified DID history head returned by the authoritative host.
    pub key_log_head: arkret_core::Hash,
    /// Enrollment authority DID verified in the authoritative DID document.
    pub enrollment_authority_did: arkret_core::Did,
    /// Entry-0 delegation reference designating coauth's enrollment authority.
    pub enrollment_authority_ref: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
