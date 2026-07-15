//! Private (encrypted) cookie jar for Salvo

use std::sync::LazyLock;

use chrono::{DateTime, Duration, Utc};
use coauth_data::Clock;
use cookie::{Cookie, CookieJar as RawCookieJar, Key, SameSite};
use salvo::extract::{Extractible, Metadata};
use salvo::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

#[derive(Debug, Error)]
#[error("could not decode cookie")]
pub enum CookieDecodeError {
    Deserialize(#[from] serde_json::Error),
}

/// Manages cookie options and encryption key
///
/// This is meant to be accessible through Salvo's Depot
#[derive(Clone)]
pub struct CookieManager {
    options: CookieOption,
    key: Key,
}

impl CookieManager {
    #[must_use]
    pub fn new(base_url: Url, key: Key) -> Self {
        let options = CookieOption::new(base_url);
        Self { options, key }
    }

    #[must_use]
    pub fn derive_from(base_url: Url, key: &[u8]) -> Self {
        let key = Key::derive_from(key);
        Self::new(base_url, key)
    }

    #[must_use]
    pub fn cookie_jar(&self) -> CookieJar {
        let inner = cookie::CookieJar::new();
        let options = self.options.clone();

        CookieJar {
            inner,
            key: self.key.clone(),
            options,
            pending_cookies: Vec::new(),
        }
    }

    #[must_use]
    pub fn cookie_jar_from_request(&self, request_cookies: &RawCookieJar) -> CookieJar {
        let mut inner = RawCookieJar::new();

        for cookie in request_cookies.iter() {
            inner.add_original(cookie.clone());
        }

        let options = self.options.clone();
        CookieJar {
            inner,
            key: self.key.clone(),
            options,
            pending_cookies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct CookieOption {
    base_url: Url,
}

impl CookieOption {
    const fn new(base_url: Url) -> Self {
        Self { base_url }
    }

    fn secure(&self) -> bool {
        self.base_url.scheme() == "https"
    }

    fn path(&self) -> &str {
        self.base_url.path()
    }

    /// True when the deployment is mounted at the root path (`/`),
    /// HTTPS, and therefore eligible for the cookie `__Host-` prefix.
    /// `__Host-` cookies are bound to a single origin: the browser
    /// guarantees `Secure`, `Path=/`, and no `Domain` attribute, which
    /// removes a class of session-fixation tricks where a sibling
    /// subdomain plants a cookie that the auth host then reads.
    // Kept (with `apply_cross_site_hardened` below) for the `__Host-`
    // prefixed cookie profile that is not wired up yet.
    #[allow(dead_code)]
    fn host_prefix_eligible(&self) -> bool {
        self.secure() && self.path() == "/"
    }

    /// Apply the **default** baseline cookie attributes.
    ///
    /// SECURITY baseline:
    /// - `HttpOnly` — no JS access (defence vs XSS-driven token theft).
    /// - `Secure` (when the base URL is HTTPS) — never travels over plaintext HTTP.
    /// - `SameSite=Lax` — default for ordinary session cookies. We intentionally do NOT use
    ///   `Strict` at the baseline because upstream-OIDC and SSO callbacks are top-level navigations
    ///   from a foreign origin and `Strict` would drop the cookie on that round-trip.
    /// - Path defaults to the deployment's base path.
    ///
    /// For cross-site OAuth state cookies that must NOT be reused
    /// across cross-site contexts, prefer
    /// [`Self::apply_cross_site_hardened`].
    fn apply<'a>(&self, mut cookie: Cookie<'a>) -> Cookie<'a> {
        cookie.set_http_only(true);
        cookie.set_secure(self.secure());
        cookie.set_path(self.path().to_owned());
        cookie.set_same_site(SameSite::Lax);
        cookie
    }

    /// Apply the **hardened** profile used for cross-site auth state
    /// (the upstream OAuth `state` cookie, the CSRF cookie). Inherits
    /// `HttpOnly` + `Secure` from the baseline. Always sets
    /// `SameSite=Strict` because these slots are read by callers that
    /// expect a same-site response (the callback runs on our own
    /// origin once the user-agent has been redirected back). Caller
    /// renames the cookie to use the `__Host-` prefix when
    /// [`Self::host_prefix_eligible`] returns true.
    #[allow(dead_code)]
    fn apply_cross_site_hardened<'a>(&self, mut cookie: Cookie<'a>) -> Cookie<'a> {
        cookie.set_http_only(true);
        cookie.set_secure(self.secure());
        cookie.set_path(self.path().to_owned());
        cookie.set_same_site(SameSite::Strict);
        cookie
    }
}

/// How long a cookie should live in the browser.
///
/// Replaces the historical `permanent: bool` flag on
/// [`CookieJar::save`]: callers now declare the lifetime explicitly. The
/// [`MaxAge`](Self::MaxAge) variant is preferred for "remember me" cookies
/// because browsers honour `Max-Age` ahead of `Expires`, which keeps the
/// behaviour stable across clock skew. Use [`ExpiresAt`](Self::ExpiresAt)
/// when you want a hard cut-off resolved against an injected
/// [`Clock`](coauth_data::Clock) — that variant accepts a
/// `DateTime<Utc>` so callers can drive expiration from a `MockClock` in
/// tests.
#[derive(Debug, Clone, Copy)]
pub enum CookieExpiration {
    /// Browser-session cookie: no `Expires` / `Max-Age` attributes.
    Session,

    /// Relative `Max-Age` attribute. Negative durations are clamped to zero
    /// (which makes the cookie expire immediately).
    MaxAge(Duration),

    /// Absolute `Expires` attribute (clock-injected by the caller).
    ExpiresAt(DateTime<Utc>),
}

impl CookieExpiration {
    /// Long-lived cookie expiring 10 years after `now`.
    ///
    /// Convenience constructor for the historical "permanent" cookie used by
    /// the session and CSRF jars; takes `now` from an injected clock so
    /// `MockClock`-driven tests can age out the cookie deterministically.
    #[must_use]
    pub fn permanent_at(now: DateTime<Utc>) -> Self {
        Self::ExpiresAt(now + Duration::days(365 * 10))
    }

    /// Long-lived cookie that lasts 10 years, expressed as a `Max-Age`
    /// rather than an absolute `Expires` timestamp. Useful when the caller
    /// does not have a clock in scope (e.g. synchronous extension traits).
    #[must_use]
    pub fn permanent_max_age() -> Self {
        Self::MaxAge(Duration::days(365 * 10))
    }
}

/// A cookie jar which encrypts cookies & sets secure options
pub struct CookieJar {
    inner: RawCookieJar,
    key: Key,
    options: CookieOption,
    pending_cookies: Vec<Cookie<'static>>,
}

impl CookieJar {
    /// Save the given payload in a cookie with the requested
    /// [`CookieExpiration`].
    ///
    /// # Panics
    ///
    /// Panics if the payload cannot be serialized.
    #[must_use]
    pub fn save<T: Serialize>(
        mut self,
        key: &str,
        payload: &T,
        expiration: CookieExpiration,
    ) -> Self {
        let serialized =
            serde_json::to_string(payload).expect("failed to serialize cookie payload");

        let cookie = Cookie::new(key.to_owned(), serialized);
        let mut cookie = self.options.apply(cookie);

        match expiration {
            CookieExpiration::Session => {
                // Browser-session cookie: leave both Expires and Max-Age unset.
            }
            CookieExpiration::MaxAge(duration) => {
                // `time::Duration::seconds` accepts negatives but browsers
                // treat any past-Max-Age as "expire now"; clamp explicitly.
                let secs = duration.num_seconds().max(0);
                cookie.set_max_age(time::Duration::seconds(secs));
            }
            CookieExpiration::ExpiresAt(when) => {
                // `cookie::Cookie` uses `time::OffsetDateTime`; convert via
                // a Unix timestamp so we don't depend on `chrono`'s `time`
                // interop feature.
                if let Ok(odt) = time::OffsetDateTime::from_unix_timestamp(when.timestamp()) {
                    cookie.set_expires(odt);
                }
            }
        }

        // Add to the private jar (encrypts automatically)
        self.inner.private_mut(&self.key).add(cookie.clone());

        // Get the encrypted cookie for the response
        if let Some(encrypted_cookie) = self.inner.get(key) {
            self.pending_cookies
                .push(encrypted_cookie.clone().into_owned());
        }

        self
    }

    /// Remove a cookie from the jar
    #[must_use]
    pub fn remove(mut self, key: &str) -> Self {
        // Create a removal cookie
        let mut removal = Cookie::new(key.to_owned(), "");
        removal.make_removal();
        removal = self.options.apply(removal);
        self.pending_cookies.push(removal);
        self.inner.private_mut(&self.key).remove(key.to_owned());
        self
    }

    /// Load and deserialize a cookie from the jar
    ///
    /// Returns `None` if the cookie is not present
    ///
    /// # Errors
    ///
    /// Returns an error if the cookie cannot be deserialized
    pub fn load<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, CookieDecodeError> {
        let Some(cookie) = self.inner.private(&self.key).get(key) else {
            return Ok(None);
        };

        let decoded: T = serde_json::from_str(cookie.value())?;
        Ok(Some(decoded))
    }

    /// Write pending cookies to the response
    pub fn write_to_response(&self, res: &mut Response) {
        for cookie in &self.pending_cookies {
            res.add_cookie(cookie.clone());
        }
    }

    /// Write pending cookies to the response and render the given scribe.
    ///
    /// This collapses the repeated two-line pattern:
    ///
    /// ```ignore
    /// cookie_jar.write_to_response(res);
    /// res.render(Text::Html(content));
    /// ```
    ///
    /// into a single consuming call:
    ///
    /// ```ignore
    /// cookie_jar.finalize(res, Text::Html(content));
    /// ```
    pub fn finalize<S: Scribe>(self, res: &mut Response, scribe: S) {
        self.write_to_response(res);
        res.render(scribe);
    }

    /// Get the pending cookies for manual response handling
    #[must_use]
    pub fn pending_cookies(&self) -> &[Cookie<'static>] {
        &self.pending_cookies
    }
}

/// Extract `CookieJar` from request using Depot
impl CookieJar {
    /// Extract from request and depot
    pub fn extract_from_request(req: &Request, depot: &Depot) -> Result<Self, StatusError> {
        // Try to get CookieManager from depot
        if let Ok(manager) = depot.get::<CookieManager>("cookie_manager") {
            Ok(manager.cookie_jar_from_request(req.cookies()))
        } else {
            Err(StatusError::internal_server_error().brief("CookieManager not found in depot"))
        }
    }
}

/// Convenience helper used by [`TimedCookie`] implementations: returns true
/// when the timestamp encoded in `id` is older than `max_age` relative to
/// `now`. Malformed ULIDs (whose timestamp overflows `i64`) are treated as
/// expired.
#[must_use]
pub fn ulid_is_expired(id: Ulid, now: DateTime<Utc>, max_age: Duration) -> bool {
    let Ok(ts) = id.timestamp_ms().try_into() else {
        return true;
    };
    let Some(when) = DateTime::from_timestamp_millis(ts) else {
        return true;
    };
    now - when > max_age
}

/// Shared abstraction for encrypted "session list" cookies whose entries
/// auto-expire after a fixed wall-clock duration.
///
/// Implemented by [`crate::handlers::upstream_oauth::UpstreamSessionsCookie`].
/// The trait captures the load/save/expire ceremony while leaving the payload
/// shape (and expiry filter) up to the implementer.
pub trait TimedCookie: Sized + Default + Serialize + DeserializeOwned {
    /// Name of the cookie slot in the jar.
    const COOKIE_NAME: &'static str;

    /// Drop entries whose embedded timestamp is older than `now -
    /// Self::max_age()`.
    ///
    /// Implementers decide how to derive a timestamp from each entry (usually
    /// via a ULID field, see [`ulid_is_expired`]).
    fn expire(self, now: DateTime<Utc>) -> Self;

    /// Maximum wall-clock age for any entry in the cookie. Defined as a
    /// method rather than an associated constant because `chrono::Duration`
    /// has no const constructors.
    fn max_age() -> Duration;

    /// Load and deserialize the cookie, returning `Self::default()` on miss
    /// or decode error. Decode errors are logged at `warn` level.
    fn load(cookie_jar: &CookieJar) -> Self {
        match cookie_jar.load::<Self>(Self::COOKIE_NAME) {
            Ok(Some(sessions)) => sessions,
            Ok(None) => Self::default(),
            Err(e) => {
                tracing::warn!(
                    cookie = Self::COOKIE_NAME,
                    error = &e as &dyn std::error::Error,
                    "Invalid timed-cookie payload; resetting"
                );
                Self::default()
            }
        }
    }

    /// Expire old entries against `clock.now()`, then re-serialize into the
    /// jar. Implementers may override to remove the cookie entirely when the
    /// collection becomes empty.
    fn save<C: Clock>(self, cookie_jar: CookieJar, clock: &C) -> CookieJar {
        let this = self.expire(clock.now());
        cookie_jar.save(Self::COOKIE_NAME, &this, CookieExpiration::Session)
    }
}

static COOKIE_JAR_METADATA: LazyLock<Metadata> = LazyLock::new(|| Metadata::new("CookieJar"));

impl<'ex> Extractible<'ex> for CookieJar {
    fn metadata() -> &'static Metadata {
        &COOKIE_JAR_METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(req: &'ex mut Request, depot: &'ex mut Depot) -> Result<Self, StatusError> {
        Self::extract_from_request(req, depot)
    }
}
