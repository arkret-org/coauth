// Copyright (c) 2026 Arkret Authors. Licensed under the Apache License,
// Version 2.0; see LICENSE-APACHE for details.

//! Admin-curated OAuth client display name + description, indexed by
//! BCP-47 locale tag.
//!
//! This is intentionally separate from the OIDC-spec-shaped
//! [`super::LocalizedClientMetadata`] (which covers `client_name`,
//! `logo_uri`, `client_uri`, `policy_uri`, `tos_uri`). The i18n payload
//! captured here is what the consent screen renders to the end user, and
//! it includes a free-form `description` field that has no place in the
//! OIDC dynamic-registration metadata vocabulary.
//!
//! Persisted as a JSONB column (`oauth_clients.i18n`); see migration
//! `20260510000100_oauth_clients_i18n`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One locale's worth of admin-edited client display strings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthClientI18nEntry {
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Map of BCP-47 locale tag → entry. `BTreeMap` gives deterministic
/// iteration order which the admin UI and snapshot tests both rely on.
pub type OAuthClientI18n = BTreeMap<String, OAuthClientI18nEntry>;
