// Copyright (c) 2026 Cokret Authors. Licensed under the Apache License,
// Version 2.0; see LICENSE-APACHE for details.

//! Admin endpoint for editing per-locale OAuth client display strings.
//!
//! `POST /api/admin/v1/oauth/clients/{id}/i18n`
//!
//! Body:
//!     { "locale": "zh-CN", "`display_name"`: "示例", "description": "..." }
//!
//! The handler upserts the entry into the `oauth_clients.i18n` JSONB
//! column (see migration `20260510000100_oauth_clients_i18n`). Other
//! locales are left untouched. Pass an empty `display_name` to delete
//! the entry for that locale.
//!
//! This is distinct from `/api/admin/v1/oauth-clients/{id}/localized-metadata`
//! which only covers the OIDC-spec-shaped fields (`client_name`,
//! `logo_uri`, `client_uri`, `policy_uri`, `tos_uri`). The i18n payload
//! covered here adds a free-form `description` that the consent screen
//! shows to end-users.

use std::collections::BTreeMap;

use coauth_data::{
    audit::AdminOperation,
    oauth::{OAuthClientI18n, OAuthClientI18nEntry, OAuthClientRepository},
};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AppError, JsonResult,
    handlers::admin::{call_context::extract_call_context, params::extract_ulid_param},
};

/// Wire-format entry for one locale's worth of admin-curated display
/// strings. `description` is optional (clear by sending `null`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "OAuthClientI18nEntry")]
pub struct I18nEntryDto {
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl From<OAuthClientI18nEntry> for I18nEntryDto {
    fn from(value: OAuthClientI18nEntry) -> Self {
        Self {
            display_name: value.display_name,
            description: value.description,
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "OAuthClientI18nUpsertRequest")]
pub struct UpsertRequest {
    pub locale: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename = "OAuthClientI18nResponse")]
pub struct I18nResponse {
    pub data: BTreeMap<String, I18nEntryDto>,
}

impl I18nResponse {
    fn from_domain(value: OAuthClientI18n) -> Self {
        let data = value.into_iter().map(|(k, v)| (k, v.into())).collect();
        Self { data }
    }
}

/// Lightweight RFC 5646 sanity check: locale tag must be 2..=35 chars and
/// only contain ASCII alphanumerics and `-`. We do not pull a full BCP-47
/// parser in here because the consent renderer only matches by string
/// equality — bad-but-not-malicious tags simply never match a request.
fn is_valid_locale(tag: &str) -> bool {
    let len = tag.len();
    if !(2..=35).contains(&len) {
        return false;
    }
    tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `GET /api/admin/v1/oauth/clients/{id}/i18n`
///
/// Returns the full set of locale → entry mappings for the client.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.oauth_clients_i18n.get", skip_all)]
pub async fn get_i18n(req: &mut Request, depot: &Depot) -> JsonResult<I18nResponse> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let client_id = extract_ulid_param(req)?;

    let exists = repo.oauth_client().lookup(client_id).await?.is_some();
    if !exists {
        return Err(AppError::not_found(format!(
            "OAuth client {client_id} not found"
        )));
    }

    let entries = repo.oauth_client().load_i18n(client_id).await?;
    Ok(Json(I18nResponse::from_domain(entries)))
}

/// `POST /api/admin/v1/oauth/clients/{id}/i18n`
///
/// Upserts a single locale entry. Returns the post-update map.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.oauth_clients_i18n.upsert", skip_all)]
pub async fn upsert_i18n(req: &mut Request, depot: &Depot) -> JsonResult<I18nResponse> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let client_id = extract_ulid_param(req)?;

    let exists = repo.oauth_client().lookup(client_id).await?.is_some();
    if !exists {
        return Err(AppError::not_found(format!(
            "OAuth client {client_id} not found"
        )));
    }

    let body: UpsertRequest = req.parse_json().await.map_err(AppError::internal)?;

    if !is_valid_locale(&body.locale) {
        return Err(AppError::bad_request(format!(
            "invalid BCP-47 locale tag: {:?}",
            body.locale
        )));
    }

    let updated = repo
        .oauth_client()
        .set_i18n_entry(
            client_id,
            body.locale.clone(),
            body.display_name.clone(),
            body.description.clone(),
        )
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
            "kind": "i18n_entry_upsert",
            "locale": body.locale,
            "cleared": body.display_name.trim().is_empty(),
            "locale_count": updated.len(),
        }),
    )
    .await?;

    repo.save().await?;

    Ok(Json(I18nResponse::from_domain(updated)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_validation_accepts_common_bcp47() {
        for tag in ["en", "en-US", "zh-CN", "zh-Hant-TW", "ja-Jpan-JP", "es-419"] {
            assert!(is_valid_locale(tag), "should accept {tag}");
        }
    }

    #[test]
    fn locale_validation_rejects_garbage() {
        for tag in ["", "x", "!!", "en US", "zh_CN", &"a".repeat(40)] {
            assert!(!is_valid_locale(tag), "should reject {tag:?}");
        }
    }
}
