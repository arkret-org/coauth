//! Admin DTOs for the soland federation status surface.
//!
//! Mirrors `GET /api/admin/v1/federation/status` — per-Space federation
//! peers + last-anchor-pulled-at + outbound queue depth. The endpoint is
//! 404-tolerant on the client side; soland may not have the route wired
//! yet for every deployment.
//!
//! Round-27 migrated these out of `sodmin/src/types/federation_status.rs`
//! (where they were flagged `TODO(a0-shared-crate)`). The sodmin inline
//! copies stay in place this round; sodmin's next round will switch.

use serde::{Deserialize, Serialize};

/// Health bucket for a single federation peer. Drives the badge tone
/// in the admin UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum FederationPeerHealth {
    Healthy,
    Degraded,
    Unreachable,
}

impl FederationPeerHealth {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            FederationPeerHealth::Healthy => "Healthy",
            FederationPeerHealth::Degraded => "Degraded",
            FederationPeerHealth::Unreachable => "Unreachable",
        }
    }

    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "healthy" | "ok" => Some(FederationPeerHealth::Healthy),
            "degraded" | "lagging" => Some(FederationPeerHealth::Degraded),
            "unreachable" | "down" => Some(FederationPeerHealth::Unreachable),
            _ => None,
        }
    }
}

/// Summary row per (Space, peer) federation pair.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct FederationStatusRow {
    #[serde(default)]
    pub space_id: String,
    #[serde(default)]
    pub peer_did: String,
    #[serde(default)]
    pub peer_label: Option<String>,
    /// Peer health bucket — wire format is one of:
    /// `healthy` / `degraded` / `unreachable`.
    #[serde(default)]
    pub health: String,
    /// Last successful anchor pull time (RFC3339).
    #[serde(default)]
    pub last_anchor_pulled_at: Option<String>,
    /// Last outbound replication push time (RFC3339).
    #[serde(default)]
    pub last_pushed_at: Option<String>,
    /// Pending Move/Anchor messages waiting to push to this peer.
    #[serde(default)]
    pub outbound_queue_depth: u64,
}

impl FederationStatusRow {
    #[must_use]
    pub fn health_typed(&self) -> FederationPeerHealth {
        FederationPeerHealth::from_wire(&self.health).unwrap_or(FederationPeerHealth::Healthy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_wire_round_trip() {
        for (wire, label) in [
            ("healthy", "Healthy"),
            ("degraded", "Degraded"),
            ("unreachable", "Unreachable"),
        ] {
            let h = FederationPeerHealth::from_wire(wire).expect("variant");
            assert_eq!(h.label(), label);
        }
        assert!(FederationPeerHealth::from_wire("nope").is_none());
        assert_eq!(
            FederationPeerHealth::from_wire("ok"),
            Some(FederationPeerHealth::Healthy)
        );
        assert_eq!(
            FederationPeerHealth::from_wire("lagging"),
            Some(FederationPeerHealth::Degraded)
        );
        assert_eq!(
            FederationPeerHealth::from_wire("down"),
            Some(FederationPeerHealth::Unreachable)
        );
    }

    #[test]
    fn row_health_falls_back_to_healthy_on_unknown() {
        let r = FederationStatusRow {
            health: "garbage".into(),
            ..Default::default()
        };
        assert_eq!(r.health_typed(), FederationPeerHealth::Healthy);

        let r = FederationStatusRow {
            health: "unreachable".into(),
            ..Default::default()
        };
        assert_eq!(r.health_typed(), FederationPeerHealth::Unreachable);
    }
}
