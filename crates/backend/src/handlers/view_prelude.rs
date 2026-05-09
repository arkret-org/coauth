//! Canonical SSR prelude for view handlers (round 25).
//!
//! Every server-rendered view handler used to open with the same chunk of
//! ceremony — pull a clock, pull an RNG, resolve the locale, fetch the
//! template engine, the URL builder, the site config, the repository, the
//! cookie jar, and (often) issue a CSRF token. That preamble was ~40 lines
//! per handler × 22 handlers ≈ 880 lines of pure boilerplate.
//!
//! [`ViewContext::extract`] consolidates the work into a single async call.
//! For form-bearing handlers, [`ViewPrelude::extract`] additionally mints a
//! CSRF token and exposes a [`Flash`] slot for one-shot UI banners.
//!
//! # Migration sketch
//!
//! ```ignore
//! // Before: ~8 lines of ceremony at the top of every view handler.
//! let mut rng = common::make_rng();
//! let clock = common::make_clock();
//! let locale = preferred_language(req, depot);
//! let templates = depot.templates()?;
//! let url_builder = depot.url_builder()?;
//! let site_config = depot.site_config()?;
//! let mut repo = depot.repo().await?;
//! let cookie_jar = depot.cookie_jar(req)?;
//!
//! // After: one call, one struct.
//! let crate::handlers::view_prelude::ViewContext {
//!     mut rng, clock, locale, site_config, templates,
//!     url_builder, mut repo, cookie_jar,
//! } = ViewContext::extract(req, depot).await?;
//! ```
//!
//! `ViewContext` is intentionally `pub` field-by-field so handlers migrate
//! by simple destructuring without rewriting their bodies. `account` is
//! deliberately *not* part of the prelude — see [`ViewPrelude`] docs for the
//! reasoning.

use coauth_data::{BoxClock, BoxRepository, BoxRng, SiteConfig, UrlBuilder};
use coauth_i18n::DataLocale;
use coauth_templates::Templates;
use salvo::prelude::*;

use crate::handlers::common::DepotExt;
use crate::handlers::{make_clock, make_rng, preferred_language};
use crate::salvo_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, CsrfToken},
};

/// Per-request bundle of state every view handler needs.
pub struct ViewContext {
    pub rng: BoxRng,
    pub clock: BoxClock,
    pub locale: DataLocale,
    pub site_config: SiteConfig,
    pub templates: Templates,
    pub url_builder: UrlBuilder,
    pub repo: BoxRepository,
    pub cookie_jar: CookieJar,
}

impl ViewContext {
    /// Build the prelude from a Salvo request and depot.
    ///
    /// Performs the same eight extractions handlers used to inline,
    /// returning early on the first depot lookup miss or repository
    /// failure with the matching [`InternalError`] (so the existing
    /// `?` propagation continues to work).
    pub async fn extract(req: &Request, depot: &Depot) -> Result<Self, InternalError> {
        Ok(Self {
            rng: make_rng(),
            clock: make_clock(),
            locale: preferred_language(req, depot),
            site_config: depot.site_config()?,
            templates: depot.templates()?,
            url_builder: depot.url_builder()?,
            repo: depot.repo().await?,
            cookie_jar: depot.cookie_jar(req)?,
        })
    }
}

/// One-shot UI message rendered into the next view (e.g. "Password
/// updated", "Email verification sent"). Currently a passthrough type;
/// future iterations may persist this through the cookie jar so it
/// survives a redirect.
#[derive(Clone, Debug, Default)]
pub struct Flash {
    pub message: Option<String>,
    pub level: FlashLevel,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FlashLevel {
    #[default]
    Info,
    Success,
    Warning,
    Error,
}

/// Richer per-request prelude than [`ViewContext`]: also mints a CSRF
/// token (so handler bodies can immediately reach for `csrf_token`) and
/// carries a default-empty [`Flash`] slot.
///
/// `account` is intentionally absent because the lookup is sometimes
/// cookie-driven (browser session) and sometimes header-driven (admin
/// impersonation), and the existing fallback paths in
/// `handlers::session::load_session_or_fallback` already encode the
/// per-handler choice. Adding a third "did the prelude resolve it?"
/// lane would create a footgun where handlers branch on
/// `Option<Account>` without realising the `None` arm has multiple
/// causes. Handlers that need an account continue to call
/// `load_session_or_fallback` themselves.
pub struct ViewPrelude {
    pub rng: BoxRng,
    pub clock: BoxClock,
    pub locale: DataLocale,
    pub site_config: SiteConfig,
    pub templates: Templates,
    pub url_builder: UrlBuilder,
    pub repo: BoxRepository,
    pub cookie_jar: CookieJar,
    pub csrf_token: CsrfToken,
    pub flash: Flash,
}

impl ViewPrelude {
    /// Build the SSR prelude.
    ///
    /// Internally re-uses [`ViewContext::extract`] for the shared part,
    /// then mints a CSRF token from the cookie jar so the handler can
    /// immediately stamp the form. The cookie jar carries the updated
    /// CSRF cookie — the handler is responsible for the final
    /// `cookie_jar.finalize(res, ...)` call after rendering.
    pub async fn extract(req: &Request, depot: &Depot) -> Result<Self, InternalError> {
        let ViewContext {
            mut rng,
            clock,
            locale,
            site_config,
            templates,
            url_builder,
            repo,
            cookie_jar,
        } = ViewContext::extract(req, depot).await?;
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        Ok(Self {
            rng,
            clock,
            locale,
            site_config,
            templates,
            url_builder,
            repo,
            cookie_jar,
            csrf_token,
            flash: Flash::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flash_default_is_info_with_no_message() {
        let flash = Flash::default();
        assert_eq!(flash.level, FlashLevel::Info);
        assert!(flash.message.is_none());
    }
}
