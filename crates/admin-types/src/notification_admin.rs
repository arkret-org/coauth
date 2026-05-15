//! Admin DTOs for the coauth notification surfaces:
//!
//! - `GET  /api/admin/v1/notification-channels` — configured channel
//!   roster (currently `email` and `sms`) with a per-channel
//!   `configured` flag derived from `SiteConfig`.
//! - `GET  /api/admin/v1/notification-templates` — known template
//!   keys + human-readable descriptions.
//! - `POST /api/admin/v1/notification-templates/publish` — publish a
//!   new template version (request + response body).
//!
//! Round-32 (C32.7): lifted out of the inline definitions in
//! `coauth/crates/backend/src/handlers/admin/v1/notification_channels.rs`
//! and `…/notification_templates.rs`, plus the divergent inline
//! `CoauthNotificationChannel` / `CoauthNotificationTemplate` shims
//! that lived in `sodmin/src/api/coauth.rs`. The sodmin shims used
//! invented field names (`id` / `channel_type` / `is_healthy` /
//! `last_error` / `name` / `updated_at`) that did not match what the
//! backend actually serialized — sharing the wire shape via this
//! crate turns that drift into a compile error rather than a
//! silent serde-default empty UI.

use serde::{Deserialize, Serialize};

// ── notification channels ───────────────────────────────────────────

/// Per-channel configured-status row. `channel` is the literal channel
/// name the dispatch pipeline routes on (today: `"email"` / `"sms"`).
/// `configured` reflects whether the operator's `SiteConfig` has the
/// flags that imply this channel can be delivered.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct NotificationChannelStatus {
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub configured: bool,
}

/// Top-level response for `GET /api/admin/v1/notification-channels`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct NotificationChannelsResponse {
    #[serde(default)]
    pub channels: Vec<NotificationChannelStatus>,
}

// ── notification template directory ──────────────────────────────────

/// One entry in the known-template-key catalog. `key` is what the
/// dispatcher looks up at send time (e.g. `"verification"`,
/// `"recovery"`); `description` is a one-line human gloss for the admin
/// UI catalog.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct NotificationTemplateEntry {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub description: String,
}

/// Top-level response for `GET /api/admin/v1/notification-templates`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct NotificationTemplatesResponse {
    #[serde(default)]
    pub templates: Vec<NotificationTemplateEntry>,
}

// ── publish-template request / response ──────────────────────────────

/// Request body for
/// `POST /api/admin/v1/notification-templates/publish`. The backend
/// accepts the body, persists a new template version row, and returns
/// the persisted row as [`PublishedTemplateResponse`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct PublishTemplateRequest {
    /// The template key to publish (e.g. `"verification"`).
    #[serde(default)]
    pub template_key: String,
    /// Delivery channel — `"email"` or `"sms"`.
    #[serde(default)]
    pub channel: String,
    /// Locale tag, e.g. `"en"` / `"zh-CN"`. Defaults to `"en"` when
    /// the field is absent on the wire.
    #[serde(default = "default_locale")]
    pub locale: String,
    /// Optional subject template — used by the email channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_template: Option<String>,
    /// Required body template (Minijinja syntax).
    #[serde(default)]
    pub body_template: String,
}

fn default_locale() -> String {
    "en".to_owned()
}

impl PublishTemplateRequest {
    /// Validate that the request is internally consistent. Returns the
    /// first invariant violation as a human-readable string.
    pub fn validate(&self) -> Result<(), String> {
        if self.template_key.is_empty() {
            return Err("template_key is required".into());
        }
        if self.body_template.is_empty() {
            return Err("body_template is required".into());
        }
        Ok(())
    }
}

/// Response body for the publish endpoint — the persisted row with
/// generated identity + timestamps.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct PublishedTemplateResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub template_key: String,
    /// Monotonically increasing version within `(template_key, channel)`.
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_template: Option<String>,
    #[serde(default)]
    pub body_template: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_request_validates_required_fields() {
        let r = PublishTemplateRequest::default();
        assert!(r.validate().is_err());

        let r = PublishTemplateRequest {
            template_key: "verification".into(),
            channel: "email".into(),
            locale: "en".into(),
            subject_template: None,
            body_template: String::new(),
        };
        let err = r.validate().unwrap_err();
        assert!(err.contains("body_template"));

        let r = PublishTemplateRequest {
            template_key: "verification".into(),
            channel: "email".into(),
            locale: "en".into(),
            subject_template: Some("Verify".into()),
            body_template: "code: {{code}}".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn publish_request_locale_defaults_to_en() {
        let json = r#"{"template_key":"v","channel":"email","body_template":"x"}"#;
        let r: PublishTemplateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(r.locale, "en");
    }

    #[test]
    fn publish_request_omits_subject_when_none() {
        let r = PublishTemplateRequest {
            template_key: "v".into(),
            channel: "email".into(),
            locale: "en".into(),
            subject_template: None,
            body_template: "x".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("subject_template"), "got: {s}");
    }

    #[test]
    fn channels_response_round_trips() {
        let resp = NotificationChannelsResponse {
            channels: vec![
                NotificationChannelStatus {
                    channel: "email".into(),
                    configured: true,
                },
                NotificationChannelStatus {
                    channel: "sms".into(),
                    configured: false,
                },
            ],
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: NotificationChannelsResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.channels.len(), 2);
        assert!(back.channels[0].configured);
        assert!(!back.channels[1].configured);
    }

    #[test]
    fn templates_response_round_trips() {
        let resp = NotificationTemplatesResponse {
            templates: vec![NotificationTemplateEntry {
                key: "verification".into(),
                description: "Verification code".into(),
            }],
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: NotificationTemplatesResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.templates.len(), 1);
        assert_eq!(back.templates[0].key, "verification");
    }

    #[test]
    fn published_response_omits_published_at_when_unset() {
        let r = PublishedTemplateResponse {
            id: "tpl-1".into(),
            template_key: "verification".into(),
            version: 1,
            channel: "email".into(),
            locale: "en".into(),
            subject_template: None,
            body_template: "x".into(),
            created_at: "2026-05-10T00:00:00Z".into(),
            published_at: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("published_at"), "got: {s}");
    }
}
