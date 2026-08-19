//! Device naming template context.

use std::collections::BTreeMap;

use coauth_data::Client;
use rand_core::RngCore as Rng;
use serde::Serialize;

use super::wrappers::{SampleIdentifier, TemplateContext, sample_list};

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
