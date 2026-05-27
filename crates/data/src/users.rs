use std::net::IpAddr;

use chrono::{DateTime, Utc};
use diesel::{Queryable, deserialize, pg::Pg, sql_types};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{new_id, pagination::Node};

type UserSqlType = (
    sql_types::Uuid,
    sql_types::Text,
    sql_types::Timestamptz,
    sql_types::Timestamptz,
    sql_types::Nullable<sql_types::Timestamptz>,
    sql_types::Nullable<sql_types::Timestamptz>,
    sql_types::Bool,
    sql_types::Bool,
    sql_types::Nullable<sql_types::Text>,
    sql_types::Nullable<sql_types::Text>,
    sql_types::Nullable<sql_types::Text>,
    sql_types::Bool,
    sql_types::Array<sql_types::Text>,
);

type UserSqlRow = (
    uuid::Uuid,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    bool,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    Vec<String>,
);

/// A downstream principal account projection used by consent and viewer APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrincipalUser {
    pub principal_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub id: Ulid,
    pub handle: String,
    pub sub: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub locked_at: Option<DateTime<Utc>>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub can_request_admin: bool,
    pub is_guest: bool,
    // Profile fields synced to the downstream principal projection.
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub preferred_locale: Option<String>,
    /// True when this account's primary principal DID is a managed
    /// `did:webvh:…` minted by `starid` during onboarding (see
    /// [`crate::services::starid_adapter::StaridRegistry::create_principal_did`]).
    /// False for accounts that pre-date the starid integration or were
    /// created when `[contrix.starid]` config was absent — those still
    /// resolve to the local `did:web:coauth.invalid:…` derivation.
    ///
    /// Backfill: migration `20260510000200_account_starid_backend_marker`
    /// adds this column with `DEFAULT FALSE`, so every historical row
    /// stays on the local derivation.
    pub starid_backend: bool,
    /// Interop alias handles for this user (e.g. `acct:<local>@<host>`).
    ///
    /// Spec 7157ee8 §3.1 — the canonical Contrix handle form is
    /// `<localpart>:<domain>`, derived at read time from `handle` + the
    /// public host name (see [`Self::canonical_handle`]). Aliases are
    /// *additional* identifiers kept for RFC 7565 / WebFinger interop and
    /// `handle_claim.handle_aliases` emission. Migration
    /// `20260520000100_handle_claims_and_audit` adds the underlying column
    /// with `DEFAULT ARRAY[]::TEXT[]`.
    pub handle_aliases: Vec<String>,
}

impl Queryable<UserSqlType, Pg> for User {
    type Row = UserSqlRow;

    fn build(row: Self::Row) -> deserialize::Result<Self> {
        let (
            id,
            handle,
            created_at,
            updated_at,
            locked_at,
            deactivated_at,
            can_request_admin,
            is_guest,
            display_name,
            avatar_url,
            preferred_locale,
            starid_backend,
            handle_aliases,
        ) = row;
        let id = Ulid::from(id);

        Ok(Self {
            id,
            handle,
            sub: id.to_string(),
            created_at,
            updated_at,
            locked_at,
            deactivated_at,
            can_request_admin,
            is_guest,
            display_name,
            avatar_url,
            preferred_locale,
            starid_backend,
            handle_aliases,
        })
    }
}

impl Node<Ulid> for User {
    fn cursor(&self) -> Ulid {
        self.id
    }
}

/// Error code surfaced to API callers when they supply a handle string
/// that is not in the canonical `<localpart>:<domain>` form.
///
/// Stable wire constant — the OIDC bridge / register / handle-claim issuer
/// surfaces this verbatim in their error envelopes per spec 7157ee8 §3.1.
pub const HANDLE_NOT_CANONICAL_CODE: &str = "handle_not_canonical";

/// Validate that an input string is a canonical Contrix handle of the
/// form `<lowercase-localpart>:<lowercase-domain>` per spec 7157ee8 §3.1.
///
/// Rejects:
///   * the legacy `contrix://<host>/users/<localpart>` URI form
///   * `acct:` interop aliases (those belong in `handle_aliases[]`)
///   * leading `@` (display form — strip before submitting)
///   * bare host strings, `did:` strings, display strings
///   * uppercase characters in localpart
///   * an empty localpart or empty domain
///
/// Returns the canonical form on success (lowercased exactly as supplied —
/// the validator does *not* fold uppercase into lowercase on the user's
/// behalf; callers must canonicalise before submitting).
///
/// # Errors
///
/// Returns `HANDLE_NOT_CANONICAL_CODE` paired with a short reason.
pub fn validate_canonical_handle(value: &str) -> Result<&str, (&'static str, String)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err((HANDLE_NOT_CANONICAL_CODE, "empty handle".to_owned()));
    }
    if trimmed.starts_with("acct:") {
        return Err((
            HANDLE_NOT_CANONICAL_CODE,
            "acct: alias is interop-only; supply a <localpart>:<domain> canonical handle"
                .to_owned(),
        ));
    }
    if trimmed.starts_with("contrix://") {
        return Err((
            HANDLE_NOT_CANONICAL_CODE,
            "legacy contrix:// URI form is no longer canonical; supply a <localpart>:<domain> handle"
                .to_owned(),
        ));
    }
    if trimmed.starts_with('@') {
        return Err((
            HANDLE_NOT_CANONICAL_CODE,
            "leading @ is the display form; strip it before submitting".to_owned(),
        ));
    }
    if trimmed.contains('@') {
        return Err((
            HANDLE_NOT_CANONICAL_CODE,
            "canonical handle uses <localpart>:<domain>, not <localpart>@<domain>".to_owned(),
        ));
    }
    let Some((localpart, domain)) = trimmed.split_once(':') else {
        return Err((
            HANDLE_NOT_CANONICAL_CODE,
            "canonical handle must be of the form <localpart>:<domain>".to_owned(),
        ));
    };
    if localpart.is_empty() {
        return Err((
            HANDLE_NOT_CANONICAL_CODE,
            "canonical handle localpart must be non-empty".to_owned(),
        ));
    }
    if domain.is_empty() {
        return Err((
            HANDLE_NOT_CANONICAL_CODE,
            "canonical handle domain must be non-empty".to_owned(),
        ));
    }
    // Reject any uppercase letters in localpart — spec mandates
    // lowercase localpart for canonical equality.
    if localpart.chars().any(|c| c.is_ascii_uppercase()) {
        return Err((
            HANDLE_NOT_CANONICAL_CODE,
            "canonical handle localpart must be lowercase".to_owned(),
        ));
    }
    Ok(trimmed)
}

/// Legacy alias for [`HANDLE_NOT_CANONICAL_CODE`]. Pre-R3.1 callers wired
/// to the URI-form constant; retained as a `#[deprecated]` shim for one
/// release so external consumers can migrate.
#[deprecated(
    since = "1.9.0",
    note = "use HANDLE_NOT_CANONICAL_CODE — spec 7157ee8 retires the URI form"
)]
pub const HANDLE_URI_NOT_CANONICAL_CODE: &str = HANDLE_NOT_CANONICAL_CODE;

/// Legacy alias for [`validate_canonical_handle`]. The validator now
/// requires the canonical `<localpart>:<domain>` shape.
#[deprecated(
    since = "1.9.0",
    note = "use validate_canonical_handle — spec 7157ee8 retires the URI form"
)]
pub fn validate_canonical_handle_uri(value: &str) -> Result<&str, (&'static str, String)> {
    validate_canonical_handle(value)
}

impl User {
    /// Canonical Contrix handle per spec 7157ee8:
    /// `<lowercase-localpart>:<lowercase-domain>`.
    ///
    /// The host is supplied by the caller (typically the URL builder's
    /// public hostname); the data crate has no opinion on which host is
    /// "the" service host since the same `User` row may be addressed by
    /// multiple alias hosts.
    #[must_use]
    pub fn canonical_handle(&self, host: &str) -> String {
        format!("{}:{}", self.handle.to_lowercase(), host.to_lowercase())
    }

    /// Interop `acct:` alias for this user against the supplied host. Used
    /// to populate `handle_claim.handle_aliases[]`. Never used as canonical.
    #[must_use]
    pub fn acct_alias(&self, host: &str) -> String {
        format!(
            "acct:{}@{}",
            self.handle.to_lowercase(),
            host.to_lowercase()
        )
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
        self.locked_at.is_none() && self.deactivated_at.is_none()
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
        self.deactivated_at.is_none()
    }
}

impl User {
    #[doc(hidden)]
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut (impl RngCore + ?Sized)) -> Vec<Self> {
        vec![User {
            id: new_id(now, rng),
            handle: "john".to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            updated_at: now,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: false,
            display_name: Some("John".to_owned()),
            avatar_url: None,
            preferred_locale: Some("en".to_owned()),
            starid_backend: false,
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
/// For each session intiated, there may be multiple [`UserRecoveryTicket`]s
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
    pub handle: String,
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

/// Per-user `did:webvh` update-key material minted against an embedded
/// principal-server provider (e.g. soland's
/// `POST /api/v1/identity/webvh/register`).
///
/// `update_secret_b64` is the **encrypted** ed25519 seed for the update
/// key — encryption is the caller's responsibility (use
/// `coauth_keystore::Encrypter::encrypt_to_string`); this struct stores
/// it as opaque base64 to keep the data layer agnostic to the key
/// schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrincipalDidUpdateKey {
    pub id: Ulid,
    pub user_id: Ulid,
    /// Audience string of the principal server this DID was minted for
    /// (matches `PrincipalServerConfig::audience` / session-grant `aud`).
    pub audience: String,
    /// The minted DID, e.g.
    /// `did:webvh:zQm…:local.host%3A8080:webvh:01krmccd…`.
    pub did: String,
    /// Multibase ed25519 public key recorded in the DID document's
    /// `verificationMethod[0]` — kept for cheap reads (e.g. introspection).
    pub did_public_key_multibase: String,
    /// Multibase ed25519 public key recorded in
    /// `parameters.updateKeys[0]` of the DID's webvh log.
    pub update_public_key_multibase: String,
    /// Encrypted ed25519 seed for the update key — base64 wrapper around
    /// `Encrypter::encrypt_to_string` output. Never log or expose.
    pub update_secret_b64: String,
    /// `versionId` of the latest log entry coauth has authored. Set to
    /// `Some(version_id)` after the inception entry is accepted.
    pub key_log_head: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
