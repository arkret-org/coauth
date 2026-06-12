//! Rendering context types for page and email templates.
//!
//! Every template consumes a dedicated context struct that carries the data it
//! needs.  Context wrappers -- for session, CSRF token, locale and CAPTCHA --
//! can be stacked via [`TemplateContext`] trait methods.
//!
//! Domain-specific contexts are organized into sub-modules; this root module
//! re-exports all public types for convenience.

mod approval;
mod branding;
mod captcha;
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

pub use self::approval::{ApprovalContext, PolicyViolationContext};
pub use self::branding::SiteBranding;
pub use self::captcha::WithCaptcha;
pub use self::device::{
    DeviceApprovalContext, DeviceLinkContext, DeviceLinkFormField, DeviceNameContext,
};
pub use self::email::{EmailRecoveryContext, EmailVerificationContext};
pub use self::ext::SiteConfigExt;
pub use self::features::SiteFeatures;
pub use self::login::{LoginContext, LoginFormField, PostAuthContext, PostAuthContextInner};
pub use self::oauth::FormPostContext;
pub use self::pages::{AppContext, AppErrorState, ErrorContext, IndexContext, NotFoundContext};
pub use self::recovery::{
    RecoveryExpiredContext, RecoveryFinishContext, RecoveryFinishFormField,
    RecoveryProgressContext, RecoveryStartContext, RecoveryStartFormField,
};
pub use self::register::{
    PasswordRegisterContext, RegisterContext, RegisterFormField, RegisterStepsDisplayNameContext,
    RegisterStepsDisplayNameFormField, RegisterStepsEmailInUseContext,
    RegisterStepsRegistrationTokenContext, RegisterStepsRegistrationTokenFormField,
    RegisterStepsVerifyEmailContext, RegisterStepsVerifyEmailFormField,
};
pub use self::upstream::{
    UpstreamExistingLinkContext, UpstreamRegister, UpstreamRegisterFormField, UpstreamSuggestLink,
};
pub use self::wrappers::{
    EmptyContext, SampleIdentifier, TemplateContext, WithCsrf, WithLanguage, WithOptionalSession,
    WithSession,
};
