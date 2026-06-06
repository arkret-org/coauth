//! Admin DTOs for the coauth account administration surface.
//!
//! Mirrors the JSON:API attributes block emitted by:
//!
//! - `GET /_coauth/admin/accounts` — paginated account list.
//! - `GET /_coauth/admin/accounts/{account_id}` — single-account detail.
//! - `POST /_coauth/admin/accounts/{account_id}/
//!   {lock|disable|erase|reset-recovery}` — mutation endpoints that return the
//!   same `AccountRecord` envelope.
//!
//! Round-33 (C33.3): lifted out of the inline `AccountRecord`/`AccountStatus`
//! definitions in
//! `coauth/crates/backend/src/handlers/admin/v1/accounts.rs` and the
//! divergent inline `CoauthAdminAccountRecord` decoder shim in
//! `sodmin/src/api/coauth.rs`. The sodmin shim hard-coded `String`
//! comparisons against `"locked"` / `"disabled"` to recover the typed
//! status — the wire enum now decodes directly to a typed bucket so the
//! comparison is a `match` on a Rust enum and any new server-side
//! lifecycle state surfaces as a compile error rather than a silent
//! `is_locked = false` UI fallback.
//!
//! The sodmin shim was also missing `locked_at`, `deactivated_at`,
//! `principal_id_bindings`, and `primary_principal_binding` — fields
//! the backend has been emitting since the DID binding preview landed.
//! The shared shape now carries them explicitly.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::did_binding_admin::AccountDidBindingPreview;

/// Lifecycle bucket for a coauth account. Wire format is the canonical
/// account-lifecycle `status` axis from
/// `cokret-spec/spec/v1/zh/identity/account-lifecycle.md`:
/// `active` / `soft_logged_out` / `locked` / `suspended` / `deactivated` /
/// `erasure_pending`.
///
/// Kept as a typed enum so the admin UI can drive its badge tone /
/// gating off a `match` rather than stringly-typed comparisons. The backend
/// currently only derives `active` / `locked` / `deactivated` from the user
/// row, but the full closed enum decodes here so a governance/erasure state
/// added server-side surfaces as a new variant rather than a decode failure.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum AdminAccountStatus {
    #[default]
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    ErasurePending,
}

impl AdminAccountStatus {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            AdminAccountStatus::Active => "Active",
            AdminAccountStatus::SoftLoggedOut => "Soft logged out",
            AdminAccountStatus::Locked => "Locked",
            AdminAccountStatus::Suspended => "Suspended",
            AdminAccountStatus::Deactivated => "Deactivated",
            AdminAccountStatus::ErasurePending => "Erasure pending",
        }
    }

    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "active" => Some(AdminAccountStatus::Active),
            "soft_logged_out" => Some(AdminAccountStatus::SoftLoggedOut),
            "locked" => Some(AdminAccountStatus::Locked),
            "suspended" => Some(AdminAccountStatus::Suspended),
            "deactivated" => Some(AdminAccountStatus::Deactivated),
            "erasure_pending" => Some(AdminAccountStatus::ErasurePending),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_locked(&self) -> bool {
        matches!(self, AdminAccountStatus::Locked)
    }

    #[must_use]
    pub fn is_deactivated(&self) -> bool {
        matches!(self, AdminAccountStatus::Deactivated)
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, AdminAccountStatus::Active)
    }
}

impl std::fmt::Display for AdminAccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminAccountStatus::Active => f.write_str("active"),
            AdminAccountStatus::SoftLoggedOut => f.write_str("soft_logged_out"),
            AdminAccountStatus::Locked => f.write_str("locked"),
            AdminAccountStatus::Suspended => f.write_str("suspended"),
            AdminAccountStatus::Deactivated => f.write_str("deactivated"),
            AdminAccountStatus::ErasurePending => f.write_str("erasure_pending"),
        }
    }
}

/// JSON:API `attributes` payload for one account.
///
/// Field order mirrors `AccountRecord` in
/// `coauth/crates/backend/src/handlers/admin/v1/accounts.rs` so the
/// generated `OpenAPI` document and the sodmin client decoder stay in
/// lock-step. The `id` is intentionally NOT here — it lives on the
/// JSON:API envelope (`SingleResource::id`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminAccountAttributes {
    /// Stable account handle.
    #[serde(default)]
    pub handle: String,

    /// Cokret account lifecycle state.
    #[serde(default)]
    pub status: AdminAccountStatus,

    /// When the account was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,

    /// When the account was last updated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,

    /// When the account was locked, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_at: Option<DateTime<Utc>>,

    /// When the account was deactivated, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<DateTime<Utc>>,

    /// Whether the account can request coauth admin privileges.
    #[serde(default)]
    pub admin: bool,

    /// Human-facing display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Optional avatar URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,

    /// Preferred locale for account-facing UX.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_locale: Option<String>,

    /// Primary principal identifier once DID binding storage is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_principal_id: Option<String>,

    /// Bound principal identifiers.
    #[serde(default)]
    pub principal_ids: Vec<String>,

    /// Richer placeholder contract for the primary DID binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_principal_binding: Option<AccountDidBindingPreview>,

    /// Richer placeholder contract for downstream admin/OpenAPI integrations.
    #[serde(default)]
    pub principal_id_bindings: Vec<AccountDidBindingPreview>,
}

impl AdminAccountAttributes {
    /// Convenience: pick the best available primary DID. Prefers the
    /// explicit `primary_principal_id` and falls back to the first
    /// entry in `principal_ids` so callers do not have to repeat that
    /// fallback at every call site.
    #[must_use]
    pub fn effective_primary_did(&self) -> Option<&str> {
        self.primary_principal_id
            .as_deref()
            .or_else(|| self.principal_ids.first().map(String::as_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_wire_round_trip() {
        for (wire, label) in [
            ("active", "Active"),
            ("soft_logged_out", "Soft logged out"),
            ("locked", "Locked"),
            ("suspended", "Suspended"),
            ("deactivated", "Deactivated"),
            ("erasure_pending", "Erasure pending"),
        ] {
            let s = AdminAccountStatus::from_wire(wire).expect("variant");
            assert_eq!(s.label(), label);
            // Round-trip through serde so the lowercase wire form holds.
            let json = serde_json::to_string(&s).unwrap();
            let back: AdminAccountStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
        assert!(AdminAccountStatus::from_wire("nope").is_none());
        // The legacy non-spec `disabled` value is no longer accepted.
        assert!(AdminAccountStatus::from_wire("disabled").is_none());
    }

    #[test]
    fn admin_account_attributes_default_is_active() {
        let a = AdminAccountAttributes::default();
        assert_eq!(a.status, AdminAccountStatus::Active);
        assert!(a.principal_ids.is_empty());
        assert!(a.principal_id_bindings.is_empty());
        assert!(a.primary_principal_binding.is_none());
    }

    #[test]
    fn effective_primary_did_falls_back_to_principal_list() {
        let mut a = AdminAccountAttributes::default();
        assert_eq!(a.effective_primary_did(), None);

        a.principal_ids.push("did:web:fallback.example".into());
        assert_eq!(a.effective_primary_did(), Some("did:web:fallback.example"));

        a.primary_principal_id = Some("did:web:explicit.example".into());
        assert_eq!(a.effective_primary_did(), Some("did:web:explicit.example"));
    }

    #[test]
    fn omit_unset_optional_timestamp_fields_on_serialize() {
        let a = AdminAccountAttributes {
            handle: "alice".into(),
            ..AdminAccountAttributes::default()
        };
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("\"handle\":\"alice\""));
        assert!(s.contains("\"status\":\"active\""));
        assert!(!s.contains("\"locked_at\""));
        assert!(!s.contains("\"deactivated_at\""));
        assert!(!s.contains("\"created_at\""));
        assert!(!s.contains("\"updated_at\""));
        assert!(!s.contains("\"display_name\""));
        assert!(!s.contains("\"primary_principal_binding\""));
    }

    #[test]
    fn deserialize_matches_backend_wire_with_locked_and_deactivated_at() {
        // Mirrors what the coauth backend emits for a locked account.
        let wire = r#"{
            "handle": "alice",
            "status": "locked",
            "created_at": "2026-05-01T00:00:00Z",
            "updated_at": "2026-05-02T00:00:00Z",
            "locked_at": "2026-05-02T00:00:00Z",
            "deactivated_at": null,
            "admin": false,
            "display_name": null,
            "avatar_url": null,
            "preferred_locale": null,
            "primary_principal_id": null,
            "principal_ids": [],
            "primary_principal_binding": null,
            "principal_id_bindings": []
        }"#;
        let a: AdminAccountAttributes = serde_json::from_str(wire).unwrap();
        assert_eq!(a.status, AdminAccountStatus::Locked);
        assert!(a.locked_at.is_some());
        assert!(a.deactivated_at.is_none());
        assert!(!a.admin);
    }

    #[test]
    fn status_helpers_classify_lifecycle() {
        assert!(AdminAccountStatus::Active.is_active());
        assert!(!AdminAccountStatus::Active.is_locked());
        assert!(AdminAccountStatus::Locked.is_locked());
        assert!(!AdminAccountStatus::Locked.is_active());
        assert!(AdminAccountStatus::Deactivated.is_deactivated());
        assert!(!AdminAccountStatus::Deactivated.is_active());
    }
}
