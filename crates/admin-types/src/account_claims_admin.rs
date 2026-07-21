//! Admin DTOs for the per-account claim inventory surface.
//!
//! Mirrors the wire shape emitted by:
//!
//! - `GET /_coauth/admin/accounts/{account_id}/claims` — `AccountClaimsOutcome { data:
//!   [AccountClaimRecord, ...] }` from `coauth/crates/backend/src/handlers/admin/v1/accounts.rs`.
//!
//! The claim issuance / revocation request bodies and the
//! richer `ClaimRecord` returned by `POST /admin/v1/claims` and
//! `POST /admin/v1/claims/{id}/revoke` live in
//! `coauth/crates/backend/src/handlers/admin/v1/claims.rs`. They use a
//! `status` enum (active/revoked/expired) on the wire whereas the
//! per-account inventory endpoint emits a free-form `state` string the
//! UI displays as-is. Sharing the inventory shape is the priority
//! because that's what the account-detail page consumes; the issuance
//! path is sodmin-server-only and can lift in a later round.
//!
//! Round-33 (C33.3): lifted out of the inline `AccountClaimRecord` /
//! `AccountClaimsOutcome` definitions on the backend and the
//! divergent `CoauthAccountClaim` / `CoauthAccountClaimsEnvelope`
//! decoder shims in `sodmin/src/api/coauth.rs`. The sodmin shim was
//! decoding only `claim_kind` / `value` / `state` / `source` and
//! silently dropping every other field — including the `id` the UI
//! needs to address a claim by record ULID, the `subject`/`issuer`
//! pair the audit panel renders, the `verifier_did` and
//! `represented_org` that gate progressive-disclosure verification,
//! and the `expires_at`/`revoked_at`/`revoked_reason` lifecycle
//! triplet. The shared shape now carries every field the backend
//! emits, with chrono-typed timestamps so a malformed / missing
//! datetime fails to decode rather than silently rendering as an
//! empty cell.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One row in the per-account claim inventory.
///
/// Field order mirrors the `AccountClaimRecord` struct in
/// `coauth/crates/backend/src/handlers/admin/v1/accounts.rs` exactly
/// — when the backend struct is renamed / reordered the rename should
/// land in this file in the same commit so rustc enforces the move.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminAccountClaimRecord {
    /// Claim record ULID.
    #[serde(default)]
    pub id: String,

    /// Account ULID, when the claim resolves to a local coauth account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,

    /// Claim kind, for example `verified_email_domain`, `org_role`,
    /// `handle`, `principal_id`.
    #[serde(default)]
    pub claim_kind: String,

    /// Compact display value extracted from `payload` for the admin UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    /// Free-form lifecycle state string. This is intentionally not
    /// typed because the per-account inventory endpoint pipes
    /// service-layer enum names through verbatim (e.g. `"active"`,
    /// `"revoked"`, `"expired"`). Use the dedicated `ClaimStatus` enum
    /// on the issue/revoke admin endpoints when typing matters.
    #[serde(default)]
    pub state: String,

    /// Source provenance — the inventory endpoint emits the literal
    /// `"coauth_claim_repository"` so the UI can distinguish persisted records.
    #[serde(default)]
    pub source: String,

    /// Subject account, local DID, username, or external DID the claim
    /// was issued against.
    #[serde(default)]
    pub subject: String,

    /// Issuer DID or trusted issuer identifier.
    #[serde(default)]
    pub issuer: String,

    /// DID of the verifier that checked the progressive-disclosure claim.
    #[serde(default)]
    pub verifier_did: String,

    /// Organization represented by the verifier.
    #[serde(default)]
    pub represented_org: String,

    /// Raw claim payload — kept untyped so the verifier-supplied JSON
    /// schema can vary per claim kind.
    #[serde(default)]
    pub payload: serde_json::Value,

    /// When the claim was issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,

    /// When the claim expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// When the claim was revoked, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,

    /// Operator-supplied revocation reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
}

impl AdminAccountClaimRecord {
    /// True when the inventory record's `state` reads as a revoked
    /// variant. Helpers use this to gate the "Revoke" button in the
    /// UI so admins do not double-revoke.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.state == "revoked" || self.revoked_at.is_some()
    }
}

/// Top-level response for `GET .../accounts/{id}/claims`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminAccountClaimsOutcome {
    #[serde(default)]
    pub data: Vec<AdminAccountClaimRecord>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use super::*;

    #[test]
    fn claim_record_default_round_trips() {
        let r = AdminAccountClaimRecord::default();
        let s = serde_json::to_string(&r).unwrap();
        let back: AdminAccountClaimRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn unset_optional_fields_omitted_on_serialize() {
        let r = AdminAccountClaimRecord {
            id: "01H...".into(),
            claim_kind: "handle".into(),
            value: Some("alice".into()),
            state: "active".into(),
            source: "coauth_claim_repository".into(),
            subject: "01H...".into(),
            issuer: "did:web:issuer.example".into(),
            verifier_did: "did:web:verifier.example".into(),
            represented_org: "Example Org".into(),
            payload: serde_json::json!({"value": "alice"}),
            ..AdminAccountClaimRecord::default()
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("\"account_id\""));
        assert!(!s.contains("\"expires_at\""));
        assert!(!s.contains("\"revoked_at\""));
        assert!(!s.contains("\"revoked_reason\""));
        assert!(!s.contains("\"issued_at\""));
        assert!(s.contains("\"value\":\"alice\""));
        assert!(s.contains("\"source\":\"coauth_claim_repository\""));
    }

    #[test]
    fn deserialize_matches_backend_inventory_wire() {
        // Mirrors the JSON the per-account claims endpoint emits.
        let wire = r#"{
            "data": [{
                "id": "01HXYZ...",
                "account_id": "01HACC...",
                "claim_kind": "org_role",
                "value": "admin",
                "state": "active",
                "source": "coauth_claim_repository",
                "subject": "01HACC...",
                "issuer": "did:web:issuer.example",
                "verifier_did": "did:web:verifier.example",
                "represented_org": "Example Org",
                "payload": {"value": "admin"},
                "issued_at": "2026-05-01T00:00:00.000Z",
                "expires_at": null,
                "revoked_at": null,
                "revoked_reason": null
            }]
        }"#;
        let resp: AdminAccountClaimsOutcome = serde_json::from_str(wire).unwrap();
        assert_eq!(resp.data.len(), 1);
        let row = &resp.data[0];
        assert_eq!(row.claim_kind, "org_role");
        assert_eq!(row.state, "active");
        assert_eq!(row.source, "coauth_claim_repository");
        assert_eq!(row.value.as_deref(), Some("admin"));
        assert_eq!(row.represented_org, "Example Org");
        assert!(!row.is_revoked());
        assert!(row.issued_at.is_some());
    }

    #[test]
    fn revoked_flag_uses_state_or_revoked_at() {
        let mut r = AdminAccountClaimRecord {
            state: "revoked".into(),
            ..AdminAccountClaimRecord::default()
        };
        assert!(r.is_revoked());

        r.state = "active".into();
        r.revoked_at = Some(Utc::now());
        assert!(r.is_revoked());

        r.revoked_at = None;
        assert!(!r.is_revoked());
    }
}
