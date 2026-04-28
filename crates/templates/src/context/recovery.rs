//! Account recovery flow template contexts.

use std::collections::BTreeMap;

use coauth_data::{User, UserRecoverySession};
use rand_core::RngCore as Rng;
use serde::{Deserialize, Serialize};

use super::wrappers::{SampleIdentifier, TemplateContext, sample_list};
use crate::{FieldError, FormField, FormState};

// -- Start ------------------------------------------------------------------

/// Fields on the recovery start form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStartFormField {
    /// Email address
    Email,
}

impl FormField for RecoveryStartFormField {
    fn keep(&self) -> bool {
        true
    }
}

/// Data for the `pages/recovery/start.html` template.
#[derive(Serialize, Default)]
pub struct RecoveryStartContext {
    form: FormState<RecoveryStartFormField>,
}

impl RecoveryStartContext {
    /// Build the recovery-start page context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(self, form: FormState<RecoveryStartFormField>) -> Self {
        Self { form }
    }
}

impl TemplateContext for RecoveryStartContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(vec![
            Self::new(),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(RecoveryStartFormField::Email, FieldError::Required),
            ),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(RecoveryStartFormField::Email, FieldError::Invalid),
            ),
        ])
    }
}

// -- Progress ---------------------------------------------------------------

/// Data for the `pages/recovery/progress.html` template.
#[derive(Serialize)]
pub struct RecoveryProgressContext {
    session: UserRecoverySession,
    /// True when a resend attempt was blocked by the rate limiter.
    resend_failed_due_to_rate_limit: bool,
}

impl RecoveryProgressContext {
    /// Build the recovery-progress page context.
    #[must_use]
    pub fn new(session: UserRecoverySession, resend_failed_due_to_rate_limit: bool) -> Self {
        Self {
            session,
            resend_failed_due_to_rate_limit,
        }
    }
}

impl TemplateContext for RecoveryProgressContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        let sess = UserRecoverySession {
            id: coauth_data::new_id(now, rng),
            email: "name@mail.com".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            ip_address: None,
            locale: "en".to_owned(),
            created_at: now,
            consumed_at: None,
        };

        sample_list(vec![
            Self {
                session: sess.clone(),
                resend_failed_due_to_rate_limit: false,
            },
            Self {
                session: sess,
                resend_failed_due_to_rate_limit: true,
            },
        ])
    }
}

// -- Expired ----------------------------------------------------------------

/// Data for the `pages/recovery/expired.html` template.
#[derive(Serialize)]
pub struct RecoveryExpiredContext {
    session: UserRecoverySession,
}

impl RecoveryExpiredContext {
    /// Build the recovery-expired page context.
    #[must_use]
    pub fn new(session: UserRecoverySession) -> Self {
        Self { session }
    }
}

impl TemplateContext for RecoveryExpiredContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        let sess = UserRecoverySession {
            id: coauth_data::new_id(now, rng),
            email: "name@mail.com".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            ip_address: None,
            locale: "en".to_owned(),
            created_at: now,
            consumed_at: None,
        };
        sample_list(vec![Self { session: sess }])
    }
}

// -- Finish -----------------------------------------------------------------

/// Fields on the recovery-finish form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFinishFormField {
    /// New password
    NewPassword,
    /// New password confirmation
    NewPasswordConfirm,
}

impl FormField for RecoveryFinishFormField {
    fn keep(&self) -> bool {
        false
    }
}

/// Data for the `pages/recovery/finish.html` template.
#[derive(Serialize)]
pub struct RecoveryFinishContext {
    user: User,
    form: FormState<RecoveryFinishFormField>,
}

impl RecoveryFinishContext {
    /// Build the recovery-finish page context.
    #[must_use]
    pub fn new(user: User) -> Self {
        Self {
            user,
            form: FormState::default(),
        }
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(mut self, form: FormState<RecoveryFinishFormField>) -> Self {
        self.form = form;
        self
    }
}

impl TemplateContext for RecoveryFinishContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(
            User::samples(now, rng)
                .into_iter()
                .flat_map(|u| {
                    vec![
                        Self::new(u.clone()),
                        Self::new(u.clone()).with_form_state(
                            FormState::default().with_error_on_field(
                                RecoveryFinishFormField::NewPassword,
                                FieldError::Invalid,
                            ),
                        ),
                        Self::new(u).with_form_state(FormState::default().with_error_on_field(
                            RecoveryFinishFormField::NewPasswordConfirm,
                            FieldError::Invalid,
                        )),
                    ]
                })
                .collect(),
        )
    }
}
