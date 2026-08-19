//! Rendering context types for page and email templates.
//!
//! Every template consumes a dedicated context struct that carries the data it
//! needs.  Context wrappers -- for locale -- can be stacked via
//! [`TemplateContext`] trait methods.
//!
//! Domain-specific contexts are organized into sub-modules; this root module
//! re-exports all public types for convenience.

mod branding;
mod device;
mod email;
mod ext;
mod features;
mod oauth;
mod pages;
mod wrappers;

// Re-export everything from sub-modules so downstream code sees a flat
// namespace.

pub use self::branding::SiteBranding;
pub use self::device::DeviceNameContext;
pub use self::email::{EmailRecoveryContext, EmailVerificationContext};
pub use self::ext::SiteConfigExt;
pub use self::features::SiteFeatures;
pub use self::oauth::FormPostContext;
pub use self::pages::{AppContext, AppErrorState, ErrorContext};
pub use self::wrappers::{EmptyContext, SampleIdentifier, TemplateContext, WithLanguage};
