// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::Context;
use async_trait::async_trait;
use convert_case::{Case, Casing};
use serde::de::DeserializeOwned;

use super::Client;

/// Describes a named section within an IANA registry, including
/// the lookup key, human-readable documentation text, and an
/// optional reference URL pointing to the source specification.
#[derive(Debug, Clone)]
pub struct Section {
    /// Lookup key used to identify this section in generated code
    pub key: &'static str,

    /// Human-readable documentation for this section
    pub doc: &'static str,

    /// Optional URL to the source specification
    pub url: Option<&'static str>,
}

/// Convenience constructor for creating a [`Section`] without a URL.
#[must_use]
pub const fn s(key: &'static str, doc: &'static str) -> Section {
    Section {
        key,
        doc,
        url: None,
    }
}

/// Represents a single member within an IANA-defined enumeration,
/// capturing the raw value, optional description text, and the
/// Rust-friendly identifier to use in generated code.
#[derive(Debug)]
pub struct EnumMember {
    /// The raw string value from the IANA registry
    pub value: String,

    /// Optional description text from the registry
    pub description: Option<String>,

    /// The PascalCase identifier to use in generated Rust code
    pub enum_name: String,
}

/// Trait for types that can be deserialized from an IANA CSV registry
/// and converted into Rust enum members for code generation.
#[async_trait]
pub trait EnumEntry: DeserializeOwned + Send + Sync {
    /// URL of the IANA CSV registry for this entry type
    const URL: &'static str;

    /// Static list of sections that partition the registry
    const SECTIONS: &'static [Section];

    /// Build the full section list by attaching the registry URL
    /// to each statically-defined section.
    #[must_use]
    fn sections() -> Vec<Section> {
        Self::SECTIONS
            .iter()
            .map(|section| Section {
                url: Some(Self::URL),
                ..*section
            })
            .collect()
    }

    /// Returns the section key this entry belongs to, or `None`
    /// if the entry should be skipped during code generation.
    fn key(&self) -> Option<&'static str>;

    /// The raw name/value of this entry as it appears in the registry.
    fn name(&self) -> &str;

    /// Optional human-readable description of this entry.
    fn description(&self) -> Option<&str> {
        None
    }

    /// Derive a PascalCase Rust identifier from the entry name.
    /// Applies the conversion twice so that names like "N_A"
    /// become "Na" rather than "NA".
    fn enum_name(&self) -> String {
        let sanitized = self.name().replace('+', "_");
        // Double-convert to normalize edge cases in casing
        sanitized.to_case(Case::Pascal).to_case(Case::Pascal)
    }

    /// Fetch the CSV registry from the IANA website and parse it
    /// into a list of section-key / enum-member pairs.
    ///
    /// Entries whose description contains "TEMPORARY" are filtered out.
    async fn fetch(client: &Client) -> anyhow::Result<Vec<(&'static str, EnumMember)>> {
        tracing::info!("Fetching CSV");

        let csv_url = Self::URL;
        let user_agent_header = "coauth-iana-codegen/0.1";

        #[expect(
            clippy::disallowed_methods,
            reason = "we don't use send_traced in the codegen"
        )]
        let response = client
            .get(csv_url)
            .header("User-Agent", user_agent_header)
            .send()
            .await
            .context(format!("can't the CSV at {csv_url}"))?;

        let status_code = response.status();
        anyhow::ensure!(
            status_code.is_success(),
            "HTTP status code is not 200: {status_code}"
        );

        let body_text = response
            .text()
            .await
            .context(format!("can't the CSV body at {csv_url}"))?;

        let parsed_entries: Result<Vec<_>, _> =
            csv::Reader::from_reader(body_text.as_bytes())
                .into_deserialize()
                .filter_map(|record: Result<Self, _>| {
                    record
                        .map(|entry| {
                            // Skip entries marked as TEMPORARY
                            let is_temporary = entry
                                .description()
                                .is_some_and(|desc| desc.contains("TEMPORARY"));

                            if is_temporary {
                                return None;
                            }

                            entry.key().map(|section_key| {
                                let member = EnumMember {
                                    value: entry.name().to_owned(),
                                    description: entry.description().map(ToOwned::to_owned),
                                    enum_name: entry.enum_name(),
                                };
                                (section_key, member)
                            })
                        })
                        .transpose()
                })
                .collect();

        Ok(parsed_entries.context(format!("can't parse the CSV at {csv_url}"))?)
    }
}
