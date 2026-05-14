//! Email template contexts (recovery and verification emails).

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
};

use chrono::Duration;
use coauth_data::{
    BrowserSession, User, UserEmailAuthenticationCode, UserRecoverySession, UserRegistration,
};
use rand_core::RngCore as Rng;
use serde::Serialize;

use super::wrappers::{SampleIdentifier, TemplateContext, sample_list};

// -- Recovery email ---------------------------------------------------------

/// Data passed to the `emails/recovery.{txt,html,subject}` templates.
#[derive(Serialize)]
pub struct EmailRecoveryContext {
    user: User,
    session: UserRecoverySession,
    recovery_link: url::Url,
}

impl EmailRecoveryContext {
    /// Build the recovery-email context.
    #[must_use]
    pub fn new(user: User, session: UserRecoverySession, recovery_link: url::Url) -> Self {
        Self {
            user,
            session,
            recovery_link,
        }
    }

    /// The user this recovery email is addressed to.
    #[must_use]
    pub fn user(&self) -> &User {
        &self.user
    }

    /// The recovery session associated with this email.
    #[must_use]
    pub fn session(&self) -> &UserRecoverySession {
        &self.session
    }
}

impl TemplateContext for EmailRecoveryContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(
            User::samples(now, rng)
                .into_iter()
                .map(|user| {
                    let session = UserRecoverySession {
                        id: coauth_data::new_id(now, rng),
                        email: "hello@example.com".to_owned(),
                        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/536.30.1 (KHTML, like Gecko) Version/6.0.5 Safari/536.30.1".to_owned(),
                        ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                        locale: "en".to_owned(),
                        created_at: now,
                        consumed_at: None,
                    };

                    let link = "https://example.com/recovery/complete?ticket=abcdefghijklmnopqrstuvwxyz0123456789"
                        .parse()
                        .unwrap();

                    Self::new(user, session, link)
                })
                .collect(),
        )
    }
}

// -- Verification email -----------------------------------------------------

/// Data passed to the `emails/verification.{txt,html,subject}` templates.
#[derive(Serialize)]
pub struct EmailVerificationContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    browser_session: Option<BrowserSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_registration: Option<UserRegistration>,
    authentication_code: UserEmailAuthenticationCode,
}

impl EmailVerificationContext {
    /// Build the verification-email context.
    #[must_use]
    pub fn new(
        authentication_code: UserEmailAuthenticationCode,
        browser_session: Option<BrowserSession>,
        user_registration: Option<UserRegistration>,
    ) -> Self {
        Self {
            browser_session,
            user_registration,
            authentication_code,
        }
    }

    /// The user this verification email is addressed to, if available.
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.browser_session.as_ref().map(|s| &s.user)
    }

    /// The verification code carried by this email.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.authentication_code.code
    }
}

impl TemplateContext for EmailVerificationContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(
            BrowserSession::samples(now, rng)
                .into_iter()
                .map(|session| {
                    let code = UserEmailAuthenticationCode {
                        id: coauth_data::new_id(now, rng),
                        user_email_authentication_id: coauth_data::new_id(now, rng),
                        code: "123456".to_owned(),
                        created_at: now - Duration::try_minutes(5).unwrap(),
                        expires_at: now + Duration::try_minutes(25).unwrap(),
                    };

                    Self {
                        browser_session: Some(session),
                        user_registration: None,
                        authentication_code: code,
                    }
                })
                .collect(),
        )
    }
}
