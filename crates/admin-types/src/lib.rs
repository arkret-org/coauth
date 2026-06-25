//! Shared serde types for the coauth admin API surface.
//!
//! Why this crate exists: previously every admin response was either an
//! inline `#[derive(Serialize)]` struct in
//! `coauth/crates/backend/src/handlers/` or a `serde_json::json!({…})` literal,
//! with `sodmin` re-implementing a mirror struct on the client side. Any field
//! rename, addition, or removal silently broke the admin SPA at runtime.
//! Putting the wire shape in a single shared crate lets `rustc` enforce drift:
//! a backend handler and a sodmin page that disagree on a field will not
//! compile together.
//!
//! Scope: **operator-facing** admin API only. Protocol-level event /
//! grant types live in `cokret-rust-sdk` and are not duplicated here.
//!
//! Schema derives (`schemars::JsonSchema`, `salvo::oapi::ToSchema`) are
//! gated behind the `schema` feature so that pure clients like `sodmin`
//! do not transitively pull salvo + schemars.

pub mod account_admin;
pub mod account_claims_admin;
pub mod applets_admin;
pub mod bridge_admin;
pub mod circle_capability_admin;
pub mod collaboration_capability_admin;
pub mod connector_health;
pub mod did_binding_admin;
pub mod envelope;
pub mod federation_admin;
pub mod integration_manifest_admin;
pub mod notification_admin;
pub mod organization_admin;
pub mod risk_action;

pub use account_admin::*;
pub use account_claims_admin::*;
pub use applets_admin::*;
pub use bridge_admin::*;
pub use circle_capability_admin::*;
pub use collaboration_capability_admin::*;
pub use connector_health::*;
pub use did_binding_admin::*;
pub use envelope::*;
pub use federation_admin::*;
pub use integration_manifest_admin::*;
pub use notification_admin::*;
pub use organization_admin::*;
pub use risk_action::*;
