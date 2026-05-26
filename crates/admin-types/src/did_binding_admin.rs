//! Admin DTOs for the coauth account DID-binding surface.
//!
//! Mirrors the wire contracts spoken by coauth's
//! `coauth/crates/backend/src/handlers/admin/v1/account_dids.rs`:
//!
//! - `GET    /api/admin/v1/accounts/{account_id}/dids` — full per-binding
//!   inventory (`AccountDidBinding`) plus a meta block describing the
//!   resolver mode and which proof shapes the deployment accepts.
//! - `POST   /api/admin/v1/accounts/{account_id}/dids` — request body
//!   used to add a binding (`AddAccountDidBindingRequest`).
//! - `DELETE /api/admin/v1/accounts/{account_id}/dids/{did}` — request
//!   body for revoke (`RemoveAccountDidBindingRequest`).
//!
//! Round-33 (C33.3): lifted out of the inline definitions in the
//! backend handler and the divergent `CoauthAdminDidBindingRecord`
//! / `CoauthAdminDidBindingsEnvelope` decoders in
//! `sodmin/src/api/coauth.rs`. The sodmin shim was only inspecting
//! `did`, `kind`, `state`, `verification_status`, `primary`, `active`,
//! and `last_verified_at` — silently dropping `id`, `account_id`,
//! `resolver`, `created_at`, `last_resolver_receipt_id`, and
//! `revoked_at`. The shared shape now carries every field the backend
//! emits, and the typed enums make any drift in the lifecycle vocab a
//! compile error rather than a stringly-typed `format!` collapse on
//! the UI side.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Binding purpose. Wire format is `"primary"` / `"recovery"` /
/// `"pairwise"`. Pairwise bindings are per-counterparty so the backend
/// can differentiate them from the long-lived primary identity.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DidBindingKind {
    #[default]
    Primary,
    Recovery,
    Pairwise,
}

impl DidBindingKind {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            DidBindingKind::Primary => "Primary",
            DidBindingKind::Recovery => "Recovery",
            DidBindingKind::Pairwise => "Pairwise",
        }
    }

    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "primary" => Some(DidBindingKind::Primary),
            "recovery" => Some(DidBindingKind::Recovery),
            "pairwise" => Some(DidBindingKind::Pairwise),
            _ => None,
        }
    }
}

/// Lifecycle bucket for a DID binding. A binding starts in
/// `PendingProof` until the resolver / control proof is verified, then
/// transitions to `Active` (or `Rejected` if the proof failed).
/// `Revoked` is the terminal explicit-removal state.
///
/// **alsoKnownAs / `binding_state` is a HINT, not authoritative.**
/// Per spec `identity/identity-handles.md` §6.0 (verifier authority
/// vs. cache split), the `binding_state` field — and any
/// `alsoKnownAs`-derived hint embedded in admin / API responses — is
/// a cache hint only. A verifier MUST first-party verify the DID
/// Document (and `alsoKnownAs` proof) for any trust decision (wallet
/// disclosure, accept-invite, join-official-realm, cross-org
/// federation, audit-trail). Cache-allowed UI surfaces (verified
/// badge, mention autocomplete, contact card) MAY use a bounded
/// cache, but MUST degrade to unverified on cache miss or §6.1.2
/// invalidation. coauth (and any teabay / soland mirror) is NOT a
/// trust authority — it MUST NOT be treated as a wire-normative
/// source of binding state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DidBindingState {
    #[default]
    PendingProof,
    Active,
    Revoked,
    Rejected,
}

impl DidBindingState {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            DidBindingState::PendingProof => "Pending proof",
            DidBindingState::Active => "Active",
            DidBindingState::Revoked => "Revoked",
            DidBindingState::Rejected => "Rejected",
        }
    }

    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "pending_proof" => Some(DidBindingState::PendingProof),
            "active" => Some(DidBindingState::Active),
            "revoked" => Some(DidBindingState::Revoked),
            "rejected" => Some(DidBindingState::Rejected),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, DidBindingState::Active)
    }
}

/// Verification status for the resolver-side / control-proof check.
///
/// `NotRequested` is the wire value the backend uses when the
/// deployment's resolver does not require a proof for this binding kind
/// (e.g. local-only DIDs).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DidBindingVerificationStatus {
    #[default]
    Pending,
    Verified,
    Rejected,
    NotRequested,
}

impl DidBindingVerificationStatus {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            DidBindingVerificationStatus::Pending => "Pending",
            DidBindingVerificationStatus::Verified => "Verified",
            DidBindingVerificationStatus::Rejected => "Rejected",
            DidBindingVerificationStatus::NotRequested => "Not requested",
        }
    }

    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(DidBindingVerificationStatus::Pending),
            "verified" => Some(DidBindingVerificationStatus::Verified),
            "rejected" => Some(DidBindingVerificationStatus::Rejected),
            "not_requested" => Some(DidBindingVerificationStatus::NotRequested),
            _ => None,
        }
    }
}

/// Whether the deployment resolves DIDs locally or delegates to a
/// public DID resolver.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DidBindingResolverMode {
    #[default]
    LocalBindings,
    DelegatedResolver,
}

impl DidBindingResolverMode {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            DidBindingResolverMode::LocalBindings => "Local bindings",
            DidBindingResolverMode::DelegatedResolver => "Delegated resolver",
        }
    }

    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "local_bindings" => Some(DidBindingResolverMode::LocalBindings),
            "delegated_resolver" => Some(DidBindingResolverMode::DelegatedResolver),
            _ => None,
        }
    }
}

/// Resolver/delegation metadata for one binding (or for the meta block
/// at the top of the response).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct DidBindingResolverDescriptor {
    /// Whether coauth resolves locally or delegates to a public DID service.
    #[serde(default)]
    pub mode: DidBindingResolverMode,

    /// Delegated/public DID resolver endpoint when coauth is not authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,

    /// Whether pairwise bindings require resolver-side proof validation.
    #[serde(default)]
    pub proof_required_for_pairwise: bool,
}

/// Compact DID binding preview embedded in `AdminAccountAttributes`
/// (`primary_principal_binding` / `principal_did_bindings`).
///
/// Carries just enough state for an account-list row to render a
/// primary-DID badge without fetching the full per-binding inventory.
/// Schema derives are enabled via the `schema` feature so the backend
/// can plumb this type into `#[salvo::endpoint]` annotations.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AccountDidBindingPreview {
    /// Bound principal DID.
    #[serde(default)]
    pub did: String,

    /// Binding purpose.
    #[serde(default)]
    pub kind: DidBindingKind,

    /// High-level lifecycle state for downstream admin/UI surfaces.
    ///
    /// HINT ONLY, NOT AUTHORITATIVE — verifier MUST first-party verify
    /// the DID Document for trust decisions. See [`DidBindingState`]
    /// docs for the full cache-vs-authority split (spec
    /// `identity/identity-handles.md` §6.0).
    #[serde(default)]
    pub state: DidBindingState,

    /// Whether this binding is the account's current primary DID.
    #[serde(default)]
    pub primary: bool,

    /// Whether this binding is currently active.
    #[serde(default)]
    pub active: bool,
}

/// Full DID binding row returned by `GET .../accounts/{id}/dids`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminAccountDidBinding {
    /// Binding identifier.
    #[serde(default)]
    pub id: String,

    /// Account ULID.
    #[serde(default)]
    pub account_id: String,

    /// Bound principal DID.
    #[serde(default)]
    pub did: String,

    /// Binding purpose.
    #[serde(default)]
    pub kind: DidBindingKind,

    /// High-level lifecycle state.
    ///
    /// HINT ONLY, NOT AUTHORITATIVE — verifier MUST first-party verify
    /// the DID Document for trust decisions. coauth's `binding_state`
    /// is a cache hint for UI surfaces (badge / autocomplete / contact
    /// card); the authority is the resolved DID Document. See
    /// [`DidBindingState`] docs for the full cache-vs-authority split
    /// (spec `identity/identity-handles.md` §6.0).
    #[serde(default)]
    pub state: DidBindingState,

    /// Whether this binding is the account's primary DID.
    #[serde(default)]
    pub primary: bool,

    /// Whether this binding is currently active.
    #[serde(default)]
    pub active: bool,

    /// Verification status of the delegated/public DID control proof.
    #[serde(default)]
    pub verification_status: DidBindingVerificationStatus,

    /// Resolver/delegation metadata for this binding.
    #[serde(default)]
    pub resolver: DidBindingResolverDescriptor,

    /// When the binding was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,

    /// When the resolver/control proof was last verified, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<DateTime<Utc>>,

    /// Resolver receipt or operation identifier, when delegated publication exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resolver_receipt_id: Option<String>,

    /// When the binding was revoked, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Top-of-response meta block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminAccountDidBindingsMeta {
    /// Resolver/delegation mode for this deployment.
    #[serde(default)]
    pub resolver: DidBindingResolverDescriptor,

    /// Supported proof shapes that coauth intends to accept for DID binding.
    #[serde(default)]
    pub supported_verification_methods: Vec<String>,

    /// Stable signal that the surface exists but write logic is not complete yet.
    #[serde(default)]
    pub supports_write_operations: bool,
}

/// Top-level response for `GET .../accounts/{id}/dids`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminAccountDidBindingsResponse {
    #[serde(default)]
    pub data: Vec<AdminAccountDidBinding>,
    #[serde(default)]
    pub meta: AdminAccountDidBindingsMeta,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_state_verification_resolver_round_trip() {
        for k in [
            DidBindingKind::Primary,
            DidBindingKind::Recovery,
            DidBindingKind::Pairwise,
        ] {
            let s = serde_json::to_string(&k).unwrap();
            let back: DidBindingKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, back);
            // from_wire mirror
            let raw = s.trim_matches('"');
            assert_eq!(DidBindingKind::from_wire(raw), Some(k));
        }
        for st in [
            DidBindingState::PendingProof,
            DidBindingState::Active,
            DidBindingState::Revoked,
            DidBindingState::Rejected,
        ] {
            let s = serde_json::to_string(&st).unwrap();
            let back: DidBindingState = serde_json::from_str(&s).unwrap();
            assert_eq!(st, back);
            let raw = s.trim_matches('"');
            assert_eq!(DidBindingState::from_wire(raw), Some(st));
        }
        for v in [
            DidBindingVerificationStatus::Pending,
            DidBindingVerificationStatus::Verified,
            DidBindingVerificationStatus::Rejected,
            DidBindingVerificationStatus::NotRequested,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: DidBindingVerificationStatus = serde_json::from_str(&s).unwrap();
            assert_eq!(v, back);
            let raw = s.trim_matches('"');
            assert_eq!(DidBindingVerificationStatus::from_wire(raw), Some(v));
        }
        for m in [
            DidBindingResolverMode::LocalBindings,
            DidBindingResolverMode::DelegatedResolver,
        ] {
            let s = serde_json::to_string(&m).unwrap();
            let back: DidBindingResolverMode = serde_json::from_str(&s).unwrap();
            assert_eq!(m, back);
            let raw = s.trim_matches('"');
            assert_eq!(DidBindingResolverMode::from_wire(raw), Some(m));
        }
    }

    #[test]
    fn state_active_helper() {
        assert!(DidBindingState::Active.is_active());
        assert!(!DidBindingState::Revoked.is_active());
        assert!(!DidBindingState::PendingProof.is_active());
    }

    #[test]
    fn unknown_enum_wires_are_rejected_at_decode() {
        // Catching new server-side variants at decode time is exactly
        // why these are typed enums — the previous `String` shim
        // collapsed unknown values into "garbage" UI text.
        assert!(serde_json::from_str::<DidBindingKind>("\"alien\"").is_err());
        assert!(serde_json::from_str::<DidBindingState>("\"unknown\"").is_err());
        assert!(serde_json::from_str::<DidBindingVerificationStatus>("\"???\"").is_err());
        assert!(serde_json::from_str::<DidBindingResolverMode>("\"hybrid\"").is_err());
    }

    #[test]
    fn resolver_descriptor_omits_resolver_url_when_none() {
        let d = DidBindingResolverDescriptor {
            mode: DidBindingResolverMode::LocalBindings,
            resolver: None,
            proof_required_for_pairwise: false,
        };
        let s = serde_json::to_string(&d).unwrap();
        assert!(!s.contains("\"resolver\""));
        assert!(s.contains("\"mode\":\"local_bindings\""));
    }

    #[test]
    fn binding_response_round_trips_through_serde_json() {
        let resp = AdminAccountDidBindingsResponse {
            data: vec![AdminAccountDidBinding {
                id: "acctdid-abc".into(),
                account_id: "01H...".into(),
                did: "did:web:alice.example".into(),
                kind: DidBindingKind::Primary,
                state: DidBindingState::Active,
                primary: true,
                active: true,
                verification_status: DidBindingVerificationStatus::Verified,
                resolver: DidBindingResolverDescriptor::default(),
                created_at: None,
                last_verified_at: None,
                last_resolver_receipt_id: Some("resolver-preview-abc".into()),
                revoked_at: None,
            }],
            meta: AdminAccountDidBindingsMeta {
                resolver: DidBindingResolverDescriptor::default(),
                supported_verification_methods: vec!["did_controller_key".into(), "passkey".into()],
                supports_write_operations: false,
            },
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: AdminAccountDidBindingsResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.data.len(), 1);
        assert_eq!(back.data[0].kind, DidBindingKind::Primary);
        assert_eq!(back.data[0].state, DidBindingState::Active);
        assert!(back.data[0].primary);
        assert!(!back.meta.supports_write_operations);
        assert_eq!(back.meta.supported_verification_methods.len(), 2);
    }

    #[test]
    fn account_did_binding_preview_round_trip() {
        let p = AccountDidBindingPreview {
            did: "did:web:bob.example".into(),
            kind: DidBindingKind::Recovery,
            state: DidBindingState::PendingProof,
            primary: false,
            active: false,
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: AccountDidBindingPreview = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
        assert!(s.contains("\"kind\":\"recovery\""));
        assert!(s.contains("\"state\":\"pending_proof\""));
    }
}
