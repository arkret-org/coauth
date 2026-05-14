// Copyright 2024, 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Rate limiting using Salvo's built-in `SlidingGuard` + `MokaStore`.
//!
//! Each operation has one or more keyed rate limiters. The [`Limiter`] struct
//! wraps them all and exposes `check_*` methods that mirror the old
//! governor-based API.

use std::{collections::HashMap, hash::Hash, net::IpAddr, sync::Arc};

use coauth_config::{RateLimiterConfiguration, RateLimitingConfig};
use coauth_data::{User, UserEmailAuthentication, UserPhoneAuthentication};
use salvo::rate_limiter::{CelledQuota, RateGuard, SlidingGuard};
use tokio::sync::Mutex;
use ulid::Ulid;

// ---------------------------------------------------------------------------
// Error types (unchanged public API)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum AccountRecoveryLimitedError {
    #[error("Too many account recovery requests for requester {0}")]
    Requester(RequesterFingerprint),

    #[error("Too many account recovery requests for e-mail {0}")]
    Email(String),
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum PasswordCheckLimitedError {
    #[error("Too many password checks for requester {0}")]
    Requester(RequesterFingerprint),

    #[error("Too many password checks for user {0}")]
    User(Ulid),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum RegistrationLimitedError {
    #[error("Too many account registration requests for requester {0}")]
    Requester(RequesterFingerprint),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum EmailAuthenticationLimitedError {
    #[error("Too many email authentication requests for requester {0}")]
    Requester(RequesterFingerprint),

    #[error("Too many email authentication requests for authentication session {0}")]
    Authentication(Ulid),

    #[error("Too many email authentication requests for email {0}")]
    Email(String),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum PhoneAuthenticationLimitedError {
    #[error("Too many phone authentication requests for requester {0}")]
    Requester(RequesterFingerprint),

    #[error("Too many phone authentication requests for authentication session {0}")]
    Authentication(Ulid),

    #[error("Too many phone authentication requests for phone {0}")]
    Phone(String),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DidBindingLimitedError {
    #[error("Too many DID-binding mutations for requester {0}")]
    Requester(RequesterFingerprint),

    #[error("Too many DID-binding mutations for account {0}")]
    Account(Ulid),
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum MfaTotpLimitedError {
    #[error("Too many TOTP attempts for account {0}")]
    Account(Ulid),
}

// ---------------------------------------------------------------------------
// RequesterFingerprint (unchanged)
// ---------------------------------------------------------------------------

/// Key used to rate limit requests per requester.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequesterFingerprint {
    ip: Option<IpAddr>,
}

impl std::fmt::Display for RequesterFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ip) = self.ip {
            write!(f, "{ip}")
        } else {
            f.write_str("(NO CLIENT IP)")
        }
    }
}

impl RequesterFingerprint {
    /// An anonymous key with no IP address set. This should not be used in
    /// production, and we should warn users if we can't find their client IPs.
    pub const EMPTY: Self = Self { ip: None };

    /// Create a new key from the given IP address.
    #[must_use]
    pub const fn new(ip: IpAddr) -> Self {
        Self { ip: Some(ip) }
    }
}

// ---------------------------------------------------------------------------
// Keyed rate limiter backed by Salvo components
// ---------------------------------------------------------------------------

/// A single keyed rate limiter using [`SlidingGuard`].
///
/// Each tracked key gets its own sliding-window guard kept in an in-memory
/// hash map guarded by a [`tokio::sync::Mutex`]. We previously used Salvo's
/// `MokaStore`, but its load/save semantics are eventually consistent — under
/// rapid sequential calls (microsecond-spaced) the second `load_guard` would
/// observe the pre-insert state and the limit would not be enforced. Holding
/// the map mutex across the verify call gives us the atomic
/// read-modify-write semantics rate limiting requires.
struct KeyedLimiter<K: Clone + Eq + Hash + Send + Sync + 'static> {
    guards: Mutex<HashMap<K, SlidingGuard>>,
    quota: CelledQuota,
}

impl<K: Clone + Eq + Hash + Send + Sync + 'static> KeyedLimiter<K> {
    /// Create a new keyed limiter from a [`RateLimiterConfiguration`].
    fn from_config(cfg: &RateLimiterConfiguration) -> Option<Self> {
        let (limit, period) = cfg.to_limit_and_period()?;
        let period_secs = period.as_secs_f64();
        // Use up to 10 cells for sliding-window granularity. We MUST clamp
        // `cells` to `limit` ourselves: SlidingGuard internally clamps the
        // stored quota's `cells` to `limit`, but then compares the stored
        // (clamped) quota against the caller-supplied (unclamped) one for
        // equality. If they differ — which is the case whenever `limit < 10`
        // — the guard treats every call as a fresh quota and resets its
        // sliding window, effectively disabling the limiter. Pre-clamping
        // keeps both sides equal so the window persists across calls.
        let cells = limit.min(10);
        let quota = CelledQuota::new(limit, cells, time::Duration::seconds_f64(period_secs));
        Some(Self {
            guards: Mutex::new(HashMap::new()),
            quota,
        })
    }

    /// Check whether `key` is allowed. Returns `true` if within limits.
    async fn check(&self, key: &K) -> bool {
        let mut map = self.guards.lock().await;
        let guard = map.entry(key.clone()).or_default();
        guard.verify(&self.quota).await
    }
}

// ---------------------------------------------------------------------------
// Limiter (main public type)
// ---------------------------------------------------------------------------

/// Rate limiters for the different operations.
#[derive(Clone)]
pub struct Limiter {
    inner: Arc<LimiterInner>,
}

struct LimiterInner {
    account_recovery_per_requester: KeyedLimiter<RequesterFingerprint>,
    account_recovery_per_email: KeyedLimiter<String>,
    password_check_for_requester: KeyedLimiter<RequesterFingerprint>,
    password_check_for_user: KeyedLimiter<Ulid>,
    registration_per_requester: KeyedLimiter<RequesterFingerprint>,
    email_authentication_per_requester: KeyedLimiter<RequesterFingerprint>,
    email_authentication_per_email: KeyedLimiter<String>,
    email_authentication_emails_per_session: KeyedLimiter<Ulid>,
    email_authentication_attempt_per_session: KeyedLimiter<Ulid>,
    phone_authentication_per_requester: KeyedLimiter<RequesterFingerprint>,
    phone_authentication_per_phone: KeyedLimiter<String>,
    phone_authentication_sms_per_session: KeyedLimiter<Ulid>,
    phone_authentication_attempt_per_session: KeyedLimiter<Ulid>,
    did_binding_per_requester: KeyedLimiter<RequesterFingerprint>,
    did_binding_per_account: KeyedLimiter<Ulid>,
    mfa_totp_per_account: KeyedLimiter<Ulid>,
}

impl LimiterInner {
    fn new(config: &RateLimitingConfig) -> Option<Self> {
        Some(Self {
            account_recovery_per_requester: KeyedLimiter::from_config(
                &config.account_recovery.per_ip,
            )?,
            account_recovery_per_email: KeyedLimiter::from_config(
                &config.account_recovery.per_address,
            )?,
            password_check_for_requester: KeyedLimiter::from_config(&config.login.per_ip)?,
            password_check_for_user: KeyedLimiter::from_config(&config.login.per_account)?,
            registration_per_requester: KeyedLimiter::from_config(&config.registration)?,
            email_authentication_per_requester: KeyedLimiter::from_config(
                &config.email_authentication.per_ip,
            )?,
            email_authentication_per_email: KeyedLimiter::from_config(
                &config.email_authentication.per_address,
            )?,
            email_authentication_emails_per_session: KeyedLimiter::from_config(
                &config.email_authentication.emails_per_session,
            )?,
            email_authentication_attempt_per_session: KeyedLimiter::from_config(
                &config.email_authentication.attempt_per_session,
            )?,
            phone_authentication_per_requester: KeyedLimiter::from_config(
                &config.phone_authentication.per_ip,
            )?,
            phone_authentication_per_phone: KeyedLimiter::from_config(
                &config.phone_authentication.per_phone,
            )?,
            phone_authentication_sms_per_session: KeyedLimiter::from_config(
                &config.phone_authentication.sms_per_session,
            )?,
            phone_authentication_attempt_per_session: KeyedLimiter::from_config(
                &config.phone_authentication.attempt_per_session,
            )?,
            did_binding_per_requester: KeyedLimiter::from_config(&config.did_binding.per_ip)?,
            did_binding_per_account: KeyedLimiter::from_config(&config.did_binding.per_account)?,
            mfa_totp_per_account: KeyedLimiter::from_config(&config.mfa_totp.per_account)?,
        })
    }
}

impl Limiter {
    /// Creates a new `Limiter` based on a [`RateLimitingConfig`].
    ///
    /// Returns `None` if any individual limiter configuration is invalid.
    #[must_use]
    pub fn new(config: &RateLimitingConfig) -> Option<Self> {
        Some(Self {
            inner: Arc::new(LimiterInner::new(config)?),
        })
    }

    // -----------------------------------------------------------------------
    // Account recovery
    // -----------------------------------------------------------------------

    /// Check if an account recovery can be performed.
    pub async fn check_account_recovery(
        &self,
        requester: RequesterFingerprint,
        email_address: &str,
    ) -> Result<(), AccountRecoveryLimitedError> {
        if !self
            .inner
            .account_recovery_per_requester
            .check(&requester)
            .await
        {
            return Err(AccountRecoveryLimitedError::Requester(requester));
        }

        let canonical_email = email_address.to_lowercase();
        if !self
            .inner
            .account_recovery_per_email
            .check(&canonical_email)
            .await
        {
            return Err(AccountRecoveryLimitedError::Email(canonical_email));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Password check
    // -----------------------------------------------------------------------

    /// Check if a password check can be performed.
    pub async fn check_password(
        &self,
        key: RequesterFingerprint,
        user: &User,
    ) -> Result<(), PasswordCheckLimitedError> {
        if !self.inner.password_check_for_requester.check(&key).await {
            return Err(PasswordCheckLimitedError::Requester(key));
        }

        if !self.inner.password_check_for_user.check(&user.id).await {
            return Err(PasswordCheckLimitedError::User(user.id));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Check if an account registration can be performed.
    pub async fn check_registration(
        &self,
        requester: RequesterFingerprint,
    ) -> Result<(), RegistrationLimitedError> {
        if !self
            .inner
            .registration_per_requester
            .check(&requester)
            .await
        {
            return Err(RegistrationLimitedError::Requester(requester));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Email authentication
    // -----------------------------------------------------------------------

    /// Check if an email can be sent to the address for an email
    /// authentication session.
    pub async fn check_email_authentication_email(
        &self,
        requester: RequesterFingerprint,
        email: &str,
    ) -> Result<(), EmailAuthenticationLimitedError> {
        if !self
            .inner
            .email_authentication_per_requester
            .check(&requester)
            .await
        {
            return Err(EmailAuthenticationLimitedError::Requester(requester));
        }

        let canonical_email = email.to_lowercase();
        if !self
            .inner
            .email_authentication_per_email
            .check(&canonical_email)
            .await
        {
            return Err(EmailAuthenticationLimitedError::Email(email.to_owned()));
        }

        Ok(())
    }

    /// Check if an attempt can be done on an email authentication session.
    pub async fn check_email_authentication_attempt(
        &self,
        authentication: &UserEmailAuthentication,
    ) -> Result<(), EmailAuthenticationLimitedError> {
        if !self
            .inner
            .email_authentication_attempt_per_session
            .check(&authentication.id)
            .await
        {
            return Err(EmailAuthenticationLimitedError::Authentication(
                authentication.id,
            ));
        }

        Ok(())
    }

    /// Check if a new authentication code can be sent for an email
    /// authentication session.
    pub async fn check_email_authentication_send_code(
        &self,
        requester: RequesterFingerprint,
        authentication: &UserEmailAuthentication,
    ) -> Result<(), EmailAuthenticationLimitedError> {
        self.check_email_authentication_email(requester, &authentication.email)
            .await?;

        if !self
            .inner
            .email_authentication_emails_per_session
            .check(&authentication.id)
            .await
        {
            return Err(EmailAuthenticationLimitedError::Authentication(
                authentication.id,
            ));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Phone authentication
    // -----------------------------------------------------------------------

    /// Check if an SMS can be sent to the phone number for a phone
    /// authentication session.
    pub async fn check_phone_authentication_phone(
        &self,
        requester: RequesterFingerprint,
        phone: &str,
    ) -> Result<(), PhoneAuthenticationLimitedError> {
        if !self
            .inner
            .phone_authentication_per_requester
            .check(&requester)
            .await
        {
            return Err(PhoneAuthenticationLimitedError::Requester(requester));
        }

        let canonical_phone = phone.to_owned();
        if !self
            .inner
            .phone_authentication_per_phone
            .check(&canonical_phone)
            .await
        {
            return Err(PhoneAuthenticationLimitedError::Phone(canonical_phone));
        }

        Ok(())
    }

    /// Check if an attempt can be done on a phone authentication session.
    pub async fn check_phone_authentication_attempt(
        &self,
        authentication: &UserPhoneAuthentication,
    ) -> Result<(), PhoneAuthenticationLimitedError> {
        if !self
            .inner
            .phone_authentication_attempt_per_session
            .check(&authentication.id)
            .await
        {
            return Err(PhoneAuthenticationLimitedError::Authentication(
                authentication.id,
            ));
        }

        Ok(())
    }

    /// Check if a new verification SMS can be sent for a phone
    /// authentication session.
    pub async fn check_phone_authentication_send_code(
        &self,
        requester: RequesterFingerprint,
        authentication: &UserPhoneAuthentication,
    ) -> Result<(), PhoneAuthenticationLimitedError> {
        self.check_phone_authentication_phone(requester, &authentication.phone)
            .await?;

        if !self
            .inner
            .phone_authentication_sms_per_session
            .check(&authentication.id)
            .await
        {
            return Err(PhoneAuthenticationLimitedError::Authentication(
                authentication.id,
            ));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // DID binding
    // -----------------------------------------------------------------------

    /// Check whether a DID-binding mutation (attach / remove) may proceed
    /// for the given source IP and target account.
    pub async fn check_did_binding(
        &self,
        requester: RequesterFingerprint,
        account_id: Ulid,
    ) -> Result<(), DidBindingLimitedError> {
        if !self.inner.did_binding_per_requester.check(&requester).await {
            return Err(DidBindingLimitedError::Requester(requester));
        }

        if !self.inner.did_binding_per_account.check(&account_id).await {
            return Err(DidBindingLimitedError::Account(account_id));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // MFA / TOTP attempts
    // -----------------------------------------------------------------------

    /// Check whether another TOTP verification attempt may proceed for
    /// `account_id`. Tightened (5 attempts / 15 min by default) to make
    /// brute-forcing the 6-digit code infeasible — at one attempt every
    /// 3 minutes the expected time-to-guess is 200 days.
    pub async fn check_mfa_totp(&self, account_id: Ulid) -> Result<(), MfaTotpLimitedError> {
        if !self.inner.mfa_totp_per_account.check(&account_id).await {
            return Err(MfaTotpLimitedError::Account(account_id));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use coauth_data::{Clock, User, UserPhoneAuthentication, clock::MockClock};
    use rand_core::SeedableRng;

    use super::*;

    #[tokio::test]
    async fn test_password_check_limiter() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();

        let requesters: Vec<_> = (0..=255u8)
            .flat_map(|a| (0..3u8).map(move |b| RequesterFingerprint::new([a, a, b, b].into())))
            .collect();

        let alice = User {
            id: coauth_data::new_id(now, &mut rng),
            handle: "alice".to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            updated_at: now,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: true,
            display_name: Some("alice".to_owned()),
            avatar_url: None,
            preferred_locale: Some("en".to_owned()),
            starid_backend: false,
        };

        let bob = User {
            id: coauth_data::new_id(now, &mut rng),
            handle: "bob".to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            updated_at: now,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: true,
            display_name: Some("bob".to_owned()),
            avatar_url: None,
            preferred_locale: Some("en".to_owned()),
            starid_backend: false,
        };

        // Three times the same IP should be allowed (burst=3 for per_ip)
        assert!(limiter.check_password(requesters[0], &alice).await.is_ok());
        assert!(limiter.check_password(requesters[0], &alice).await.is_ok());
        assert!(limiter.check_password(requesters[0], &alice).await.is_ok());

        // Fourth time from same IP should be rejected
        assert!(limiter.check_password(requesters[0], &alice).await.is_err());
        // Different user, same IP: still rejected (IP limit)
        assert!(limiter.check_password(requesters[0], &bob).await.is_err());

        // Different IP should work (alice's per-account limit not hit yet)
        assert!(limiter.check_password(requesters[1], &alice).await.is_ok());

        // Bob isn't rate-limited from a fresh IP
        assert!(limiter.check_password(requesters[2], &bob).await.is_ok());
    }

    #[tokio::test]
    async fn test_phone_authentication_limiter() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(7);

        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();
        let requester = RequesterFingerprint::new([127, 0, 0, 1].into());
        let auth = UserPhoneAuthentication {
            id: coauth_data::new_id(now, &mut rng),
            user_registration_id: None,
            phone: "+8613800138000".to_owned(),
            created_at: now,
            completed_at: None,
        };

        assert!(
            limiter
                .check_phone_authentication_phone(requester, &auth.phone)
                .await
                .is_ok()
        );
        assert!(
            limiter
                .check_phone_authentication_phone(requester, &auth.phone)
                .await
                .is_ok()
        );
        assert!(
            limiter
                .check_phone_authentication_phone(requester, &auth.phone)
                .await
                .is_ok()
        );

        // After 3 per-phone attempts, the phone limiter kicks in (burst=3 for
        // per_phone) OR the per-IP limiter kicks in (burst=5 for per_ip) --
        // depends on config The phone limit should be hit first since burst=3 <
        // burst=5
        assert!(
            limiter
                .check_phone_authentication_phone(requester, &auth.phone)
                .await
                .is_err()
        );
    }
}
