// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Admin endpoints for managing OAuth client metadata.
//!
//! This module currently exposes the **localised** metadata side of the
//! house — the per-locale variants of `client_name`, `logo_uri`,
//! `client_uri`, `policy_uri`, and `tos_uri` — because the non-localised
//! defaults are already stored on the `oauth_clients` row at registration
//! time. The companion table `oauth_client_localized_metadata` (see
//! migration `00000000000000_initial`) stores one row per (`client_id`,
//! `locale`, `field`) triple, and this handler is the only public surface
//! that lets an operator edit them after the fact.

use std::collections::BTreeMap;

use coauth_data::{
    LocalizableField, LocalizedClientMetadata, audit::AdminOperation, oauth::OAuthClientRepository,
};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    AppError, JsonResult,
    handlers::admin::{call_context::extract_call_context, params::extract_ulid_param},
};

/// JSON shape for the localised metadata of a single OAuth client.
///
/// Field naming mirrors the column names on
/// `oauth_client_localized_metadata`. Each map is keyed by BCP-47 locale
/// tag (e.g. `"ja"`, `"zh-Hans"`, `"en-GB"`) and the values are plain
/// strings — URL fields are validated server-side at write time so the
/// admin UI can stay schema-free.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "OAuthClientLocalizedMetadata")]
pub struct LocalizedMetadataPayload {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub client_name: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub logo_uri: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub client_uri: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub policy_uri: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tos_uri: BTreeMap<String, String>,
}

impl LocalizedMetadataPayload {
    fn from_domain(meta: LocalizedClientMetadata) -> Self {
        Self {
            client_name: meta.client_name,
            logo_uri: stringify_url_map(meta.logo_uri),
            client_uri: stringify_url_map(meta.client_uri),
            policy_uri: stringify_url_map(meta.policy_uri),
            tos_uri: stringify_url_map(meta.tos_uri),
        }
    }

    /// Convert the wire payload into the typed domain struct, parsing all
    /// URL-typed values along the way. Returns the offending field/locale
    /// pair on the first parse failure so the admin gets a usable error.
    fn into_domain(self) -> Result<LocalizedClientMetadata, BadLocalizedMetadata> {
        let mut out = LocalizedClientMetadata {
            client_name: self.client_name,
            ..LocalizedClientMetadata::default()
        };

        for (locale, value) in self.logo_uri {
            let url = parse_url(LocalizableField::LogoUri, &locale, &value)?;
            out.logo_uri.insert(locale, url);
        }
        for (locale, value) in self.client_uri {
            let url = parse_url(LocalizableField::ClientUri, &locale, &value)?;
            out.client_uri.insert(locale, url);
        }
        for (locale, value) in self.policy_uri {
            let url = parse_url(LocalizableField::PolicyUri, &locale, &value)?;
            out.policy_uri.insert(locale, url);
        }
        for (locale, value) in self.tos_uri {
            let url = parse_url(LocalizableField::TosUri, &locale, &value)?;
            out.tos_uri.insert(locale, url);
        }

        Ok(out)
    }
}

fn stringify_url_map(map: BTreeMap<String, Url>) -> BTreeMap<String, String> {
    map.into_iter().map(|(k, v)| (k, v.to_string())).collect()
}

#[derive(Debug)]
struct BadLocalizedMetadata {
    field: LocalizableField,
    locale: String,
    raw: String,
}

fn parse_url(
    field: LocalizableField,
    locale: &str,
    value: &str,
) -> Result<Url, BadLocalizedMetadata> {
    Url::parse(value).map_err(|_| BadLocalizedMetadata {
        field,
        locale: locale.to_owned(),
        raw: value.to_owned(),
    })
}

/// JSON envelope returned by both endpoints. We do not use the standard
/// [`super::super::response::SingleOutcome`] wrapper because that wrapper
/// requires the payload to implement
/// [`super::super::model::Resource`], which expects a stable canonical
/// path *per resource instance*. The localised metadata is a sub-resource
/// of an OAuth client and has no independent identity, so a flat
/// `{ data: ... }` envelope is a better fit.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct LocalizedMetadataOutcome {
    pub data: LocalizedMetadataPayload,
}

/// `GET /_coauth/admin/oauth-clients/{id}/localized-metadata`
///
/// Returns the full set of localised metadata for the given client. The
/// response is the same shape accepted by `PUT`, so admin UIs can
/// round-trip an edit without normalising on the client side.
#[endpoint]
#[tracing::instrument(
    name = "handler.admin.v1.oauth_clients.get_localized_metadata",
    skip_all
)]
pub async fn get_localized_metadata(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<LocalizedMetadataOutcome> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let client_id = extract_ulid_param(req)?;

    // Confirm the client actually exists; without this the admin UI
    // would happily round-trip an empty payload for a typo'd ID.
    let exists = repo.oauth_client().lookup(client_id).await?.is_some();
    if !exists {
        return Err(AppError::not_found(format!(
            "OAuth client {client_id} not found"
        )));
    }

    let metadata = repo
        .oauth_client()
        .load_localized_metadata(client_id)
        .await?;

    Ok(Json(LocalizedMetadataOutcome {
        data: LocalizedMetadataPayload::from_domain(metadata),
    }))
}

/// `PUT /_coauth/admin/oauth-clients/{id}/localized-metadata`
///
/// Replaces the entire set of localised metadata for the given client. An
/// empty payload clears all locales. URL-typed values are parsed
/// server-side; an invalid URL produces a `400` with the offending
/// `field` and `locale` so the UI can highlight the right input.
#[endpoint]
#[tracing::instrument(
    name = "handler.admin.v1.oauth_clients.replace_localized_metadata",
    skip_all
)]
pub async fn replace_localized_metadata(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<LocalizedMetadataOutcome> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let client_id = extract_ulid_param(req)?;

    // Confirm the client exists before mutating any rows.
    let exists = repo.oauth_client().lookup(client_id).await?.is_some();
    if !exists {
        return Err(AppError::not_found(format!(
            "OAuth client {client_id} not found"
        )));
    }

    let body: LocalizedMetadataPayload = req.parse_json().await.map_err(AppError::internal)?;

    let metadata = body.into_domain().map_err(|err| {
        AppError::bad_request(format!(
            "Invalid {field} URL for locale {locale:?}: {raw}",
            field = err.field.as_str(),
            locale = err.locale,
            raw = err.raw,
        ))
    })?;

    repo.oauth_client()
        .replace_localized_metadata(client_id, &metadata)
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::OAuthClientLocalizedMetadataUpdated,
        "oauth_client",
        Some(client_id),
        serde_json::json!({
            "locale_count":
                metadata.client_name.len()
                    + metadata.logo_uri.len()
                    + metadata.client_uri.len()
                    + metadata.policy_uri.len()
                    + metadata.tos_uri.len(),
        }),
    )
    .await?;

    repo.save().await?;

    Ok(Json(LocalizedMetadataOutcome {
        data: LocalizedMetadataPayload::from_domain(metadata),
    }))
}
