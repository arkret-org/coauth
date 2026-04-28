//! Rendering context types for page and email templates.
//!
//! Every template consumes a dedicated context struct that carries the data it
//! needs.  Context wrappers -- for session, CSRF token, locale and CAPTCHA --
//! can be stacked via [`TemplateContext`] trait methods.
//!
//! Domain-specific contexts are organized into sub-modules; this root module
//! re-exports all public types for convenience.

mod branding;
mod captcha;
mod consent;
mod device;
mod email;
mod ext;
mod features;
mod login;
mod oauth;
mod pages;
mod recovery;
mod register;
mod upstream;
mod wrappers;

// Re-export everything from sub-modules so downstream code sees a flat
// namespace.

pub use self::{
    branding::SiteBranding,
    captcha::WithCaptcha,
    consent::{ConsentContext, PolicyViolationContext},
    device::{DeviceConsentContext, DeviceLinkContext, DeviceLinkFormField, DeviceNameContext},
    email::{EmailRecoveryContext, EmailVerificationContext},
    ext::SiteConfigExt,
    features::SiteFeatures,
    login::{LoginContext, LoginFormField, PostAuthContext, PostAuthContextInner},
    oauth::FormPostContext,
    pages::{AppContext, AppErrorState, ErrorContext, IndexContext, NotFoundContext},
    recovery::{
        RecoveryExpiredContext, RecoveryFinishContext, RecoveryFinishFormField,
        RecoveryProgressContext, RecoveryStartContext, RecoveryStartFormField,
    },
    register::{
        PasswordRegisterContext, RegisterContext, RegisterFormField,
        RegisterStepsDisplayNameContext, RegisterStepsDisplayNameFormField,
        RegisterStepsEmailInUseContext, RegisterStepsRegistrationTokenContext,
        RegisterStepsRegistrationTokenFormField, RegisterStepsVerifyEmailContext,
        RegisterStepsVerifyEmailFormField,
    },
    upstream::{
        UpstreamExistingLinkContext, UpstreamRegister, UpstreamRegisterFormField,
        UpstreamSuggestLink,
    },
    wrappers::{
        EmptyContext, SampleIdentifier, TemplateContext, WithCsrf, WithLanguage,
        WithOptionalSession, WithSession,
    },
};
