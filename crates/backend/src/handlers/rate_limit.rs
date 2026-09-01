// Copyright 2024, 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Rate limiting using Salvo's built-in `SlidingGuard` + `MokaStore`.
//!
//! Each operation has one or more keyed rate limiters. The [`Limiter`] struct
//! wraps them all and exposes `check_*` methods that mirror the old
//! governor-based API.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use coauth_config::{RateLimiterConfiguration, RateLimitingConfig};
use coauth_data::{User, UserEmailAuthentication, UserPhoneAuthentication};
use salvo::rate_limiter::{CelledQuota, RateGuard, SlidingGuard};
use tokio::sync::Mutex;
use ulid::Ulid;

/// Hard upper bound on the number of distinct keys a single [`KeyedLimiter`]
/// may track at once. The per-key keys (source IP / email / phone / session
/// ULID) are attacker-controllable, so without a cap an adversary rotating
/// keys could grow the guard map without bound (a DoS on the anti-abuse
/// component itself). When the cap is reached we evict the least-recently-seen
/// entries before inserting a new key.
const MAX_KEYED_GUARDS: usize = 100_000;

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

#[derive(Debug, Clone, thiserror::Error)]
pub enum DirectoryLookupLimitedError {
    #[error("Too many directory lookup requests for requester {0}")]
    Requester(RequesterFingerprint),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum IdentityResolutionLimitedError {
    #[error("Too many identity resolution requests for requester {0}")]
    Requester(RequesterFingerprint),
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("Account {account} is locked out after {failures} consecutive failed password logins")]
pub struct LoginLockedOutError {
    pub account: Ulid,
    pub failures: u32,
    pub retry_after: Duration,
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
    state: Mutex<KeyedLimiterState<K>>,
    quota: CelledQuota,
    /// The quota period as a `std::time::Duration`, precomputed for lazy
    /// eviction. A guard whose window has fully elapsed (no activity for at
    /// least one full period) is equivalent to a fresh guard, so evicting it
    /// is behaviour-preserving while reclaiming the memory.
    period: Duration,
}

struct KeyedLimiterState<K> {
    guards: HashMap<K, GuardEntry>,
    next_sweep: Instant,
}

/// A guard plus the last time it was touched, used for lazy TTL eviction.
struct GuardEntry {
    guard: SlidingGuard,
    last_seen: Instant,
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
            state: Mutex::new(KeyedLimiterState {
                guards: HashMap::new(),
                next_sweep: Instant::now() + Duration::from_secs_f64(period_secs),
            }),
            quota,
            period: Duration::from_secs_f64(period_secs),
        })
    }

    /// Check whether `key` is allowed. Returns `true` if within limits.
    ///
    /// Before verifying, expired guards (untouched for at least one full quota
    /// period) are evicted so the map does not grow without bound under
    /// attacker-controlled keys. If the map is at capacity and the key is new,
    /// the least-recently-seen entries are dropped to make room.
    async fn check(&self, key: &K) -> bool {
        let mut state = self.state.lock().await;
        let now = Instant::now();

        if now >= state.next_sweep {
            state
                .guards
                .retain(|_, entry| now.duration_since(entry.last_seen) < self.period);
            state.next_sweep = now + self.period;
        }
        let map = &mut state.guards;

        // Capacity cap: if we are about to insert a brand-new key but the map
        // is full, drop the oldest entries first. Existing keys never trigger
        // this branch (they update in place).
        if map.len() >= MAX_KEYED_GUARDS && !map.contains_key(key) {
            Self::evict_oldest(map);
        }

        let entry = map.entry(key.clone()).or_insert_with(|| GuardEntry {
            guard: SlidingGuard::default(),
            last_seen: now,
        });
        entry.last_seen = now;
        entry.guard.verify(&self.quota).await
    }

    /// Drop roughly the oldest 10% of entries by `last_seen` to make room when
    /// the capacity cap is hit. Removing a 10% slab amortises the O(n) scan
    /// cost across many insertions rather than scanning on every call.
    fn evict_oldest(map: &mut HashMap<K, GuardEntry>) {
        let target = map.len() / 10 + 1;
        let mut seen: Vec<Instant> = map.values().map(|e| e.last_seen).collect();
        // Find the `target`-th oldest timestamp as the eviction cutoff.
        seen.sort_unstable();
        let cutoff = seen[target.min(seen.len() - 1)];
        map.retain(|_, entry| entry.last_seen > cutoff);
    }
}

// ---------------------------------------------------------------------------
// Failed-login lockout
// ---------------------------------------------------------------------------

/// Consecutive failed password logins per account, and the lockout they earn.
///
/// Deliberately a separate control from [`KeyedLimiter`], not a tighter quota
/// on it. A sliding-window limiter bounds the *rate* of attempts and spends
/// its allowance on successful logins too, so an attacker who stays under the
/// rate guesses indefinitely and a legitimate user's own logins pay for the
/// attacker's traffic. This counts *failures* only, resets on success, and
/// refuses the account outright once the threshold is reached.
///
/// Keyed by account ULID, which is not attacker-mintable (an unknown handle
/// never reaches here — `login_with_password` returns `InvalidCredentials`
/// before resolving a user), so the map is bounded by the real account count.
/// The same `MAX_KEYED_GUARDS` cap and lazy sweep as `KeyedLimiter` apply
/// anyway, because an unbounded in-memory map is a DoS on the control itself.
struct FailedLoginTracker {
    state: Mutex<HashMap<Ulid, FailedLoginState>>,
    threshold: u32,
    lockout: Duration,
    failure_window: Duration,
}

#[derive(Clone, Copy)]
struct FailedLoginState {
    consecutive_failures: u32,
    last_failure: Instant,
    locked_until: Option<Instant>,
}

impl FailedLoginTracker {
    fn new(config: &coauth_config::LoginLockoutConfig) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            threshold: config.consecutive_failures,
            lockout: Duration::from_secs(config.lockout_seconds),
            failure_window: Duration::from_secs(config.failure_window_seconds),
        }
    }

    fn enabled(&self) -> bool {
        self.threshold > 0
    }

    /// The account's lockout, if it is currently locked out.
    async fn check(&self, account: Ulid) -> Result<(), LoginLockedOutError> {
        if !self.enabled() {
            return Ok(());
        }
        let now = Instant::now();
        let mut state = self.state.lock().await;
        self.sweep(&mut state, now);
        let Some(entry) = state.get(&account) else {
            return Ok(());
        };
        match entry.locked_until {
            Some(until) if until > now => Err(LoginLockedOutError {
                account,
                failures: entry.consecutive_failures,
                retry_after: until.duration_since(now),
            }),
            _ => Ok(()),
        }
    }

    /// Record one failed password verification, locking at the threshold.
    async fn record_failure(&self, account: Ulid) {
        if !self.enabled() {
            return;
        }
        let now = Instant::now();
        let mut state = self.state.lock().await;
        self.sweep(&mut state, now);
        if state.len() >= MAX_KEYED_GUARDS && !state.contains_key(&account) {
            Self::evict_oldest(&mut state);
        }
        let entry = state.entry(account).or_insert(FailedLoginState {
            consecutive_failures: 0,
            last_failure: now,
            locked_until: None,
        });
        // A failure older than the window is not part of this run: forgetting
        // it is what stops occasional typos spread over days from summing into
        // a lockout.
        if now.duration_since(entry.last_failure) >= self.failure_window {
            entry.consecutive_failures = 0;
        }
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_failure = now;
        if entry.consecutive_failures >= self.threshold {
            entry.locked_until = Some(now + self.lockout);
        }
    }

    /// Clear the run after a correct password.
    ///
    /// Callers MUST reach this only after the password verified, and MUST NOT
    /// reach it when the account is locked out — otherwise an attacker who
    /// finally guesses right during a lockout would clear their own lockout.
    async fn record_success(&self, account: Ulid) {
        if !self.enabled() {
            return;
        }
        self.state.lock().await.remove(&account);
    }

    /// Drop entries that are neither locked nor inside the failure window.
    /// Such an entry is indistinguishable from an absent one.
    fn sweep(&self, state: &mut HashMap<Ulid, FailedLoginState>, now: Instant) {
        state.retain(|_, entry| {
            entry.locked_until.is_some_and(|until| until > now)
                || now.duration_since(entry.last_failure) < self.failure_window
        });
    }

    fn evict_oldest(state: &mut HashMap<Ulid, FailedLoginState>) {
        let target = state.len() / 10 + 1;
        let mut seen: Vec<Instant> = state.values().map(|entry| entry.last_failure).collect();
        seen.sort_unstable();
        let cutoff = seen[target.min(seen.len() - 1)];
        state.retain(|_, entry| entry.last_failure > cutoff);
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
    directory_lookup_per_requester: KeyedLimiter<RequesterFingerprint>,
    identity_resolution_per_requester: KeyedLimiter<RequesterFingerprint>,
    did_binding_per_requester: KeyedLimiter<RequesterFingerprint>,
    did_binding_per_account: KeyedLimiter<Ulid>,
    failed_login: FailedLoginTracker,
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
            directory_lookup_per_requester: KeyedLimiter::from_config(
                &config.directory_lookup.per_ip,
            )?,
            identity_resolution_per_requester: KeyedLimiter::from_config(
                &config.identity_resolution.per_ip,
            )?,
            did_binding_per_requester: KeyedLimiter::from_config(&config.did_binding.per_ip)?,
            did_binding_per_account: KeyedLimiter::from_config(&config.did_binding.per_account)?,
            failed_login: FailedLoginTracker::new(&config.login.lockout),
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

    /// Per-IP gate for the recovery-completion (`set_password_by_recovery`)
    /// endpoint (COA-SEC-05). The ticket itself is 188-bit so guessing is
    /// infeasible, but the endpoint otherwise has no rate limit, so a holder can
    /// drive repeated password-hash computation. Reuses the per-requester
    /// account-recovery bucket (email is unknown until the ticket resolves, so
    /// only the per-IP dimension applies here).
    pub async fn check_account_recovery_completion(
        &self,
        requester: RequesterFingerprint,
    ) -> Result<(), AccountRecoveryLimitedError> {
        if !self
            .inner
            .account_recovery_per_requester
            .check(&requester)
            .await
        {
            return Err(AccountRecoveryLimitedError::Requester(requester));
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
    // Failed-login lockout
    // -----------------------------------------------------------------------

    /// Refuse an account that is serving a failed-login lockout.
    ///
    /// Runs before the password is verified, so a locked-out account costs the
    /// attacker a rejection instead of a password hash — and, more to the
    /// point, a correct guess made during the lockout does not authenticate.
    pub async fn check_login_lockout(&self, user: &User) -> Result<(), LoginLockedOutError> {
        self.inner.failed_login.check(user.id).await
    }

    /// Count one failed password verification against the account.
    pub async fn record_failed_login(&self, user: &User) {
        self.inner.failed_login.record_failure(user.id).await;
    }

    /// Clear the failure run after a verified password.
    pub async fn record_successful_login(&self, user: &User) {
        self.inner.failed_login.record_success(user.id).await;
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
    // Directory lookup
    // -----------------------------------------------------------------------

    /// Check whether a public directory lookup may proceed for the requester.
    pub async fn check_directory_lookup(
        &self,
        requester: RequesterFingerprint,
    ) -> Result<(), DirectoryLookupLimitedError> {
        if !self
            .inner
            .directory_lookup_per_requester
            .check(&requester)
            .await
        {
            return Err(DirectoryLookupLimitedError::Requester(requester));
        }

        Ok(())
    }

    /// Check whether a public DID resolve/document read may proceed for the
    /// requester. This is a separate bucket from handle discovery so the two
    /// public lookup surfaces cannot starve one another.
    pub async fn check_identity_resolution(
        &self,
        requester: RequesterFingerprint,
    ) -> Result<(), IdentityResolutionLimitedError> {
        if !self
            .inner
            .identity_resolution_per_requester
            .check(&requester)
            .await
        {
            return Err(IdentityResolutionLimitedError::Requester(requester));
        }
        Ok(())
    }

    /// Per-IP gate for the unauthenticated device-link user-code lookup
    /// (`device_link_get`, COA-COR-03). The endpoint maps a user code to a
    /// pending device-authorization grant_id with no attempt counter; a per-IP
    /// budget closes the user-code enumeration surface (RFC 8628 brute-force
    /// consideration). Reuses the public directory-lookup bucket (same
    /// unauthenticated per-IP read shape).
    pub async fn check_device_link_lookup(
        &self,
        requester: RequesterFingerprint,
    ) -> Result<(), DirectoryLookupLimitedError> {
        if !self
            .inner
            .directory_lookup_per_requester
            .check(&requester)
            .await
        {
            return Err(DirectoryLookupLimitedError::Requester(requester));
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
}

#[cfg(test)]
mod tests {
    use coauth_data::clock::MockClock;
    use coauth_data::{Clock, User, UserPhoneAuthentication};
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
            localpart: "alice".to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            updated_at: now,
            status: arkret_models_collaboration::objects::account_status::AccountStatus::Active,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            display_name: Some("alice".to_owned()),
            avatar_url: None,
            preferred_locale: Some(arkret_locale::UiLocale::En),
            handle_aliases: Vec::new(),
        };

        let bob = User {
            id: coauth_data::new_id(now, &mut rng),
            localpart: "bob".to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            updated_at: now,
            status: arkret_models_collaboration::objects::account_status::AccountStatus::Active,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            display_name: Some("bob".to_owned()),
            avatar_url: None,
            preferred_locale: Some(arkret_locale::UiLocale::En),
            handle_aliases: Vec::new(),
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

    #[tokio::test]
    async fn test_directory_lookup_limiter() {
        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();
        let requester = RequesterFingerprint::new([203, 0, 113, 10].into());

        for _ in 0..20 {
            assert!(limiter.check_directory_lookup(requester).await.is_ok());
        }

        assert!(limiter.check_directory_lookup(requester).await.is_err());
        assert!(
            limiter
                .check_directory_lookup(RequesterFingerprint::new([203, 0, 113, 11].into()))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_identity_resolution_limiter() {
        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();
        let requester = RequesterFingerprint::new([203, 0, 113, 12].into());

        for _ in 0..60 {
            assert!(limiter.check_identity_resolution(requester).await.is_ok());
        }
        assert!(limiter.check_identity_resolution(requester).await.is_err());
    }

    fn test_user(name: &str) -> User {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(u64::from(name.len() as u32));
        User {
            id: coauth_data::new_id(now, &mut rng),
            localpart: name.to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            updated_at: now,
            status: arkret_models_collaboration::objects::account_status::AccountStatus::Active,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            display_name: Some(name.to_owned()),
            avatar_url: None,
            preferred_locale: Some(arkret_locale::UiLocale::En),
            handle_aliases: Vec::new(),
        }
    }

    fn lockout_config(consecutive_failures: u32, lockout_seconds: u64) -> RateLimitingConfig {
        let mut config = RateLimitingConfig::default();
        config.login.lockout = coauth_config::LoginLockoutConfig {
            consecutive_failures,
            lockout_seconds,
            failure_window_seconds: 3_600,
        };
        config
    }

    /// The control the sliding-window limiters do not provide: consecutive
    /// failures against one account lock it, and the lock is what a later
    /// attempt hits — including one carrying the correct password.
    #[tokio::test]
    async fn consecutive_failed_logins_lock_the_account() {
        let limiter = Limiter::new(&lockout_config(3, 900)).unwrap();
        let alice = test_user("lockout-alice");
        let bob = test_user("lockout-bob");

        for _ in 0..2 {
            limiter.record_failed_login(&alice).await;
            assert!(
                limiter.check_login_lockout(&alice).await.is_ok(),
                "below the threshold the account stays usable"
            );
        }

        limiter.record_failed_login(&alice).await;
        let locked = limiter
            .check_login_lockout(&alice)
            .await
            .expect_err("the third consecutive failure locks the account");
        assert_eq!(locked.failures, 3);
        assert!(locked.retry_after.as_secs() > 0);

        // The lockout is per account: one account's failures must not deny
        // service to another.
        assert!(limiter.check_login_lockout(&bob).await.is_ok());
    }

    /// A verified password ends the run. Without this a user who mistypes
    /// twice, logs in, then mistypes once more would be locked out by three
    /// failures that were never consecutive.
    #[tokio::test]
    async fn a_successful_login_clears_the_failure_run() {
        let limiter = Limiter::new(&lockout_config(3, 900)).unwrap();
        let alice = test_user("lockout-reset");

        limiter.record_failed_login(&alice).await;
        limiter.record_failed_login(&alice).await;
        limiter.record_successful_login(&alice).await;

        limiter.record_failed_login(&alice).await;
        limiter.record_failed_login(&alice).await;
        assert!(
            limiter.check_login_lockout(&alice).await.is_ok(),
            "the pre-success failures must not count toward the threshold"
        );

        limiter.record_failed_login(&alice).await;
        assert!(limiter.check_login_lockout(&alice).await.is_err());
    }

    /// `consecutive_failures = 0` disables the control outright rather than
    /// locking on the first failure.
    #[tokio::test]
    async fn a_zero_threshold_disables_the_lockout() {
        let limiter = Limiter::new(&lockout_config(0, 900)).unwrap();
        let alice = test_user("lockout-disabled");

        for _ in 0..50 {
            limiter.record_failed_login(&alice).await;
        }

        assert!(limiter.check_login_lockout(&alice).await.is_ok());
    }
}
