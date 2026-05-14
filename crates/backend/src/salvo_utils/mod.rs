//! Salvo web-framework utilities for the coauth authentication service.
//!
//! Provides middleware, extractors, and helpers that sit between the Salvo
//! framework and the handler logic in [`coauth_backend::handlers`].
//!
//! # Modules
//!
//! - [`client_authorization`] — Extract and validate OAuth client
//!   credentials
//! - [`cookies`] — Encrypted cookie jar (read/write encrypted session cookies)
//! - [`csrf`] — CSRF token generation and verification
//! - [`jwt`] — JWT creation and verification helpers
//! - [`session`] — Browser session extraction from cookies
//! - [`user_authorization`] — Extract and validate user bearer tokens
//! - [`language_detection`] — Locale detection from `Accept-Language` headers
//! - [`error_wrapper`] — Wrap internal errors into HTTP responses
//! - [`fancy_error`] — User-friendly HTML error pages
//! - [`sentry`] — Sentry error-reporting integration

/// Extract and validate OAuth client credentials from requests.
pub mod client_authorization;
/// Encrypted cookie jar for session management.
pub mod cookies;
/// CSRF token generation and verification.
pub mod csrf;
/// Wrap internal errors into HTTP error responses.
pub mod error_wrapper;
/// Render user-friendly HTML error pages.
pub mod fancy_error;
/// JWT (JSON Web Token) creation and verification.
pub mod jwt;
/// Detect user locale from `Accept-Language` headers.
pub mod language_detection;
/// Sentry error-reporting integration.
pub mod sentry;
/// Browser session extraction from encrypted cookies.
pub mod session;
/// Extract and validate OAuth user bearer tokens.
pub mod user_authorization;

pub use self::{
    error_wrapper::ErrorWrapper,
    fancy_error::{GenericError, InternalError},
    session::{SessionInfo, SessionInfoExt},
};
