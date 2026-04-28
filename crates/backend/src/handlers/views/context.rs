//! `ViewContext`: shared per-request prelude for view handlers.
//!
//! Every view handler (`login`, `register`, `recovery`, `logout`, the
//! upstream OAuth callback, etc.) opens with the same eight lines of
//! ceremony:
//!
//! ```ignore
//! let mut rng = common::make_rng();
//! let clock = common::make_clock();
//! let locale = preferred_language(req, depot);
//! let templates = depot.templates()?;
//! let url_builder = depot.url_builder()?;
//! let site_config = depot.site_config()?;
//! let mut repo = depot.repo().await?;
//! let cookie_jar = depot.cookie_jar(req)?;
//! ```
//!
//! Across the 36 view handlers this added up to ~290 lines of pure
//! boilerplate. [`ViewContext::extract`] consolidates the work into a
//! single async call. Adoption is opt-in and incremental — the existing
//! per-line extraction continues to work for handlers that have not been
//! migrated yet.

use coauth_data::{BoxClock, BoxRepository, BoxRng, SiteConfig, UrlBuilder};
use coauth_i18n::DataLocale;
use coauth_templates::Templates;
use salvo::prelude::*;

use crate::handlers::common::DepotExt;
use crate::handlers::{make_clock, make_rng, preferred_language};
use crate::salvo_utils::{InternalError, cookies::CookieJar};

/// Per-request bundle of state every view handler needs.
///
/// Constructed via [`ViewContext::extract`]; consumed field-by-field by
/// the handler. The struct intentionally exposes its members as `pub`
/// instead of accessor methods so existing handlers can migrate by simple
/// destructuring without rewriting their bodies.
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
