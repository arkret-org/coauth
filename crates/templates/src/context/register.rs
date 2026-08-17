//! Registration strand template contexts, including multi-step registration
//! (email verification, display name, registration token).

use std::collections::BTreeMap;

use coauth_account_types::PostAuthAction;
use coauth_data::{UpstreamOAuthProvider, UserEmailAuthentication};
use rand_core::RngCore as Rng;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::login::PostAuthContext;
use super::wrappers::{SampleIdentifier, TemplateContext, sample_list};
use crate::{FormField, FormState};

// -- Registration form fields -----------------------------------------------

/// Enumeration of registration form fields.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterFormField {
    /// Handle field
    Handle,
    /// Email field
    Email,
    /// Password field
    Password,
    /// Confirmation password field
    PasswordConfirm,
    /// Terms-of-service acceptance checkbox
    AcceptTerms,
}

impl FormField for RegisterFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Handle | Self::Email | Self::AcceptTerms => true,
            Self::Password | Self::PasswordConfirm => false,
        }
    }
}

// -- Registration page ------------------------------------------------------

/// Data passed to the `register.html` template.
#[derive(Serialize, Default)]
pub struct RegisterContext {
    providers: Vec<UpstreamOAuthProvider>,
    next: Option<PostAuthContext>,
}

impl RegisterContext {
    /// Build a registration context with the given upstream providers.
    #[must_use]
    pub fn new(providers: Vec<UpstreamOAuthProvider>) -> Self {
        Self {
            providers,
            next: None,
        }
    }

    /// Attach a post-authentication action.
    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }
}

impl TemplateContext for RegisterContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(vec![Self {
            providers: Vec::new(),
            next: None,
        }])
    }
}

// -- Password registration --------------------------------------------------

/// Data passed to the `password_register.html` template.
#[derive(Serialize, Default)]
pub struct PasswordRegisterContext {
    form: FormState<RegisterFormField>,
    next: Option<PostAuthContext>,
}

impl PasswordRegisterContext {
    /// Replace the form state for the password registration form.
    #[must_use]
    pub fn with_form_state(self, form: FormState<RegisterFormField>) -> Self {
        Self { form, ..self }
    }

    /// Attach a post-authentication action.
    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }
}

impl TemplateContext for PasswordRegisterContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(vec![Self {
            form: FormState::default(),
            next: None,
        }])
    }
}

// -- Email verification step ------------------------------------------------

/// Fields on the email-verification step form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterStepsVerifyEmailFormField {
    /// Verification code
    Code,
}

impl FormField for RegisterStepsVerifyEmailFormField {
    fn keep(&self) -> bool {
        true
    }
}

/// Data for the `pages/register/steps/verify_email.html` template.
#[derive(Serialize)]
pub struct RegisterStepsVerifyEmailContext {
    form: FormState<RegisterStepsVerifyEmailFormField>,
    authentication: UserEmailAuthentication,
}

impl RegisterStepsVerifyEmailContext {
    /// Create a context for the email verification step.
    #[must_use]
    pub fn new(authentication: UserEmailAuthentication) -> Self {
        Self {
            form: FormState::default(),
            authentication,
        }
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(self, form: FormState<RegisterStepsVerifyEmailFormField>) -> Self {
        Self { form, ..self }
    }
}

impl TemplateContext for RegisterStepsVerifyEmailContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        let auth = UserEmailAuthentication {
            id: coauth_data::new_id(now, rng),
            user_session_id: None,
            user_registration_id: None,
            email: "foobar@example.com".to_owned(),
            created_at: now,
            completed_at: None,
        };
        sample_list(vec![Self {
            form: FormState::default(),
            authentication: auth,
        }])
    }
}

// -- Email in use step ------------------------------------------------------

/// Data for the `pages/register/steps/email_in_use.html` template.
#[derive(Serialize)]
pub struct RegisterStepsEmailInUseContext {
    email: String,
    action: Option<PostAuthAction>,
}

impl RegisterStepsEmailInUseContext {
    /// Create a context for the email-in-use page.
    #[must_use]
    pub fn new(email: String, action: Option<PostAuthAction>) -> Self {
        Self { email, action }
    }
}

impl TemplateContext for RegisterStepsEmailInUseContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        let addr = "hello@example.com".to_owned();
        let action = PostAuthAction::continue_grant(Ulid::nil());
        sample_list(vec![Self::new(addr, Some(action))])
    }
}

// -- Display name step ------------------------------------------------------

/// Fields on the display-name step form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterStepsDisplayNameFormField {
    /// Display name
    DisplayName,
}

impl FormField for RegisterStepsDisplayNameFormField {
    fn keep(&self) -> bool {
        true
    }
}

/// Data for the `display_name.html` template.
#[derive(Serialize, Default)]
pub struct RegisterStepsDisplayNameContext {
    form: FormState<RegisterStepsDisplayNameFormField>,
}

impl RegisterStepsDisplayNameContext {
    /// Build the display-name page context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(
        mut self,
        form_state: FormState<RegisterStepsDisplayNameFormField>,
    ) -> Self {
        self.form = form_state;
        self
    }
}

impl TemplateContext for RegisterStepsDisplayNameContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(vec![Self::default()])
    }
}

// -- Registration token step ------------------------------------------------

/// Fields on the registration-token step form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterStepsRegistrationTokenFormField {
    /// Registration token
    Token,
}

impl FormField for RegisterStepsRegistrationTokenFormField {
    fn keep(&self) -> bool {
        true
    }
}

/// Data for the registration-token step page.
#[derive(Serialize, Default)]
pub struct RegisterStepsRegistrationTokenContext {
    form: FormState<RegisterStepsRegistrationTokenFormField>,
}

impl RegisterStepsRegistrationTokenContext {
    /// Build the registration-token page context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(
        mut self,
        form_state: FormState<RegisterStepsRegistrationTokenFormField>,
    ) -> Self {
        self.form = form_state;
        self
    }
}

impl TemplateContext for RegisterStepsRegistrationTokenContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(vec![Self::default()])
    }
}
