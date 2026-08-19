//! Salvo web-framework utilities for the coauth authentication service.
//!
//! Provides middleware, extractors, and helpers that sit between the Salvo
//! framework and the handler logic in [`coauth_backend::handlers`].
//!
//! # Modules
//!
//! - [`client_authorization`] — Extract and validate OAuth client credentials
//! - [`cookies`] — Encrypted cookie jar (read/write encrypted session cookies)
//! - [`session`] — Browser session extraction from cookies
//! - [`user_authorization`] — Extract and validate user bearer tokens
//! - [`fancy_error`] — User-friendly HTML error pages
//! - [`sentry`] — Sentry error-reporting integration

/// Extract and validate OAuth client credentials from requests.
pub mod client_authorization;
/// Encrypted cookie jar for session management.
pub mod cookies;
/// Render user-friendly HTML error pages.
pub mod fancy_error;
/// Sentry error-reporting integration.
pub mod sentry;
/// Browser session extraction from encrypted cookies.
pub mod session;
/// Extract and validate OAuth user bearer tokens.
pub mod user_authorization;

pub use self::fancy_error::{GenericError, InternalError};
pub use self::session::{SessionInfo, SessionInfoExt};
