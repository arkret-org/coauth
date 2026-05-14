//! Login-related template contexts.

use std::collections::BTreeMap;

use coauth_data::{
    AuthorizationGrant, DeviceCodeGrant, PostAuthAction, UpstreamOAuthLink, UpstreamOAuthProvider,
};
use rand_core::RngCore as Rng;
use serde::{Deserialize, Serialize};

use super::wrappers::{SampleIdentifier, TemplateContext, sample_list};
use crate::{FieldError, FormField, FormState};

/// Enumeration of login form fields.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoginFormField {
    /// Username field
    Username,
    /// Password field
    Password,
}

impl FormField for LoginFormField {
    fn keep(&self) -> bool {
        matches!(self, Self::Username)
    }
}

/// Discriminated union describing the post-authentication action variant.
/// See [`PostAuthContext`].
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PostAuthContextInner {
    /// Resume an in-progress authorization grant.
    ContinueAuthorizationGrant {
        /// The authorization grant that will be continued after authentication
        grant: Box<AuthorizationGrant>,
    },

    /// Resume an in-progress device code grant.
    ContinueDeviceCodeGrant {
        /// The device code grant that will be continued after authentication
        grant: Box<DeviceCodeGrant>,
    },

    /// Proceed to password change flow.
    ChangePassword,

    /// Link an upstream OAuth provider account.
    LinkUpstream {
        /// The upstream provider
        provider: Box<UpstreamOAuthProvider>,
        /// The link
        link: Box<UpstreamOAuthLink>,
    },

    /// Navigate to account management.
    ManageAccount,
}

/// Resolved post-authentication action presented on the login screen.
#[derive(Serialize)]
pub struct PostAuthContext {
    /// URL-level action parameters.
    pub params: PostAuthAction,
    /// Loaded context details for the action.
    #[serde(flatten)]
    pub ctx: PostAuthContextInner,
}

/// Data passed to the `login.html` template.
#[derive(Serialize, Default)]
pub struct LoginContext {
    form: FormState<LoginFormField>,
    next: Option<PostAuthContext>,
    providers: Vec<UpstreamOAuthProvider>,
}

impl LoginContext {
    /// Replace the current form state.
    #[must_use]
    pub fn with_form_state(self, form: FormState<LoginFormField>) -> Self {
        Self { form, ..self }
    }

    /// Obtain a mutable reference to the form state.
    pub fn form_state_mut(&mut self) -> &mut FormState<LoginFormField> {
        &mut self.form
    }

    /// Attach upstream OAuth providers to the context.
    #[must_use]
    pub fn with_upstream_providers(self, providers: Vec<UpstreamOAuthProvider>) -> Self {
        Self { providers, ..self }
    }

    /// Set the post-authentication action.
    #[must_use]
    pub fn with_post_action(self, context: PostAuthContext) -> Self {
        Self {
            next: Some(context),
            ..self
        }
    }
}

impl TemplateContext for LoginContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(vec![
            Self::default(),
            Self {
                form: FormState::default(),
                next: None,
                providers: Vec::new(),
            },
            Self {
                form: FormState::default()
                    .with_error_on_field(LoginFormField::Username, FieldError::Required)
                    .with_error_on_field(
                        LoginFormField::Password,
                        FieldError::Policy {
                            code: None,
                            message: "password too short".to_owned(),
                        },
                    ),
                next: None,
                providers: Vec::new(),
            },
            Self {
                form: FormState::default()
                    .with_error_on_field(LoginFormField::Username, FieldError::Exists),
                next: None,
                providers: Vec::new(),
            },
        ])
    }
}
