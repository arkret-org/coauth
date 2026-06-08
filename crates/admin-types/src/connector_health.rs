//! Admin DTOs for the coauth connector-health probe surface.
//!
//! Mirrors `GET /_coauth/admin/connector-health` — per-provider principal
//! connector health bucket. The endpoint enumerates every registered
//! connector in the depot's `ConnectorRegistry`; if no registry is
//! present, the single principal connection is probed directly and
//! returned as a one-element list.
//!
//! Round-32 (C32.7): lifted out of the inline definition in
//! `coauth/crates/backend/src/handlers/admin/v1/connector_health.rs`
//! and out of the divergent inline `CoauthConnectorHealth` shim that
//! lived in `sodmin/src/api/coauth.rs` (the shim used `name`/`ok`/
//! `reason` whereas the wire actually carries `provider`/`principal_authority`/
//! `status`/`error`). Sharing the wire shape via this crate makes the
//! drift a compile-error rather than a runtime serde-default surprise.

use serde::{Deserialize, Serialize};

/// Health bucket for a single connector provider. Wire format is the
/// literal `"healthy"` / `"unhealthy"` strings the backend emits — kept
/// as a typed enum so the admin UI can drive its badge tone without
/// stringly-typed comparisons.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorHealthStatus {
    Healthy,
    Unhealthy,
}

impl ConnectorHealthStatus {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            ConnectorHealthStatus::Healthy => "Healthy",
            ConnectorHealthStatus::Unhealthy => "Unhealthy",
        }
    }

    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "healthy" | "ok" => Some(ConnectorHealthStatus::Healthy),
            "unhealthy" | "down" | "error" => Some(ConnectorHealthStatus::Unhealthy),
            _ => None,
        }
    }

    /// True when the provider passed its last probe.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, ConnectorHealthStatus::Healthy)
    }
}

/// Single connector-provider health row.
///
/// `provider` is the connector name registered in the
/// `ConnectorRegistry` (e.g. `"soland"`); `principal_authority` is the
/// authority the provider is pointed at; `status` is the wire
/// string — use [`ConnectorHealthRow::status_typed`] for the typed
/// bucket. `error` carries the probe failure message when the provider
/// is unhealthy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct ConnectorHealthRow {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub principal_authority: String,
    /// `"healthy"` or `"unhealthy"`. Use [`Self::status_typed`].
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ConnectorHealthRow {
    #[must_use]
    pub fn status_typed(&self) -> ConnectorHealthStatus {
        // Default to Unhealthy on unknown so an unrecognized status code
        // does not look green to the operator.
        ConnectorHealthStatus::from_wire(&self.status).unwrap_or(ConnectorHealthStatus::Unhealthy)
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status_typed().is_healthy()
    }
}

/// Top-level response for `GET /_coauth/admin/connector-health`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct ConnectorHealthOutcome {
    #[serde(default)]
    pub providers: Vec<ConnectorHealthRow>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_wire_round_trip() {
        for (wire, label) in [("healthy", "Healthy"), ("unhealthy", "Unhealthy")] {
            let s = ConnectorHealthStatus::from_wire(wire).expect("variant");
            assert_eq!(s.label(), label);
        }
        assert!(ConnectorHealthStatus::from_wire("nope").is_none());
        assert_eq!(
            ConnectorHealthStatus::from_wire("ok"),
            Some(ConnectorHealthStatus::Healthy)
        );
        assert_eq!(
            ConnectorHealthStatus::from_wire("down"),
            Some(ConnectorHealthStatus::Unhealthy)
        );
    }

    #[test]
    fn unknown_status_falls_back_to_unhealthy() {
        let row = ConnectorHealthRow {
            provider: "soland".into(),
            principal_authority: "soland.example".into(),
            status: "garbage".into(),
            error: None,
        };
        assert_eq!(row.status_typed(), ConnectorHealthStatus::Unhealthy);
        assert!(!row.is_healthy());
    }

    #[test]
    fn healthy_omits_error_on_serialize() {
        let row = ConnectorHealthRow {
            provider: "soland".into(),
            principal_authority: "soland.example".into(),
            status: "healthy".into(),
            error: None,
        };
        let s = serde_json::to_string(&row).unwrap();
        assert!(!s.contains("\"error\""), "got: {s}");
        assert!(s.contains("\"status\":\"healthy\""));
    }

    #[test]
    fn unhealthy_carries_error_field() {
        let row = ConnectorHealthRow {
            provider: "soland".into(),
            principal_authority: "soland.example".into(),
            status: "unhealthy".into(),
            error: Some("probe timed out".into()),
        };
        let s = serde_json::to_string(&row).unwrap();
        assert!(s.contains("\"error\":\"probe timed out\""));
    }

    #[test]
    fn response_round_trips_through_serde_json() {
        let resp = ConnectorHealthOutcome {
            providers: vec![
                ConnectorHealthRow {
                    provider: "soland".into(),
                    principal_authority: "soland-a.example".into(),
                    status: "healthy".into(),
                    error: None,
                },
                ConnectorHealthRow {
                    provider: "secondary".into(),
                    principal_authority: "soland-b.example".into(),
                    status: "unhealthy".into(),
                    error: Some("connection refused".into()),
                },
            ],
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: ConnectorHealthOutcome = serde_json::from_str(&s).unwrap();
        assert_eq!(back.providers.len(), 2);
        assert!(back.providers[0].is_healthy());
        assert!(!back.providers[1].is_healthy());
        assert_eq!(
            back.providers[1].error.as_deref(),
            Some("connection refused")
        );
    }
}
