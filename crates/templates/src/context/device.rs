//! Device code flow and device naming template contexts.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use chrono::Duration;
use coauth_data::{Client, DeviceCodeGrant, PrincipalUser};
use oauth_types::scope::OPENID;
use rand_core::RngCore as Rng;
use serde::{Deserialize, Serialize};

use super::wrappers::{SampleIdentifier, TemplateContext, sample_list};
use crate::{FieldError, FormField, FormState};

/// Generate a random alphanumeric string of the given length.
fn rand_alphanumeric_string(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf.iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect()
}

// -- Device link form -------------------------------------------------------

/// Fields on the device-link page form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLinkFormField {
    /// Device code
    Code,
}

impl FormField for DeviceLinkFormField {
    fn keep(&self) -> bool {
        true
    }
}

/// Data for the `device_link.html` template.
#[derive(Serialize, Default, Debug)]
pub struct DeviceLinkContext {
    form_state: FormState<DeviceLinkFormField>,
}

impl DeviceLinkContext {
    /// Build the device-link page context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the form state.
    #[must_use]
    pub fn with_form_state(mut self, form_state: FormState<DeviceLinkFormField>) -> Self {
        self.form_state = form_state;
        self
    }
}

impl TemplateContext for DeviceLinkContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(vec![
            Self::new(),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(DeviceLinkFormField::Code, FieldError::Required),
            ),
        ])
    }
}

// -- Device approval --------------------------------------------------------

/// Data for the device approval template.
#[derive(Serialize, Debug)]
pub struct DeviceApprovalContext {
    grant: DeviceCodeGrant,
    client: Client,
    principal_user: PrincipalUser,
}

impl DeviceApprovalContext {
    /// Build the device approval page context.
    #[must_use]
    pub fn new(grant: DeviceCodeGrant, client: Client, principal_user: PrincipalUser) -> Self {
        Self {
            grant,
            client,
            principal_user,
        }
    }
}

impl TemplateContext for DeviceApprovalContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(
            Client::samples(now, rng)
                .into_iter()
                .map(|client| {
                    let grant = DeviceCodeGrant {
                        id: coauth_data::new_id(now, rng),
                        state: coauth_data::DeviceCodeGrantState::Pending,
                        client_id: client.id,
                        scope: [OPENID].into_iter().collect(),
                        user_code: rand_alphanumeric_string(rng, 6).to_uppercase(),
                        device_code: rand_alphanumeric_string(rng, 32),
                        created_at: now - Duration::try_minutes(5).unwrap(),
                        expires_at: now + Duration::try_minutes(25).unwrap(),
                        ip_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36".to_owned()),
                    };
                    Self {
                        grant,
                        client,
                        principal_user: PrincipalUser {
                            principal_id: "alice@example.com".to_owned(),
                            display_name: Some("Alice".to_owned()),
                        },
                    }
                })
                .collect(),
        )
    }
}

// -- Device naming ----------------------------------------------------------

/// Data for the `device_name.txt` template.
#[derive(Serialize)]
pub struct DeviceNameContext {
    client: Client,
    raw_user_agent: String,
}

impl DeviceNameContext {
    /// Build the context from a client and an optional User-Agent string.
    #[must_use]
    pub fn new(client: Client, user_agent: Option<String>) -> Self {
        Self {
            client,
            raw_user_agent: user_agent.unwrap_or_default(),
        }
    }
}

impl TemplateContext for DeviceNameContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(
            Client::samples(now, rng)
                .into_iter()
                .map(|client| Self {
                    client,
                    raw_user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36".to_owned(),
                })
                .collect(),
        )
    }
}
