//! Shared serde types for the coauth admin API surface.
//!
//! Why this crate exists: previously every admin response was either an
//! inline `#[derive(Serialize)]` struct in `coauth/crates/backend/src/handlers/`
//! or a `serde_json::json!({…})` literal, with `sodmin` re-implementing a
//! mirror struct on the client side. Any field rename, addition, or
//! removal silently broke the admin SPA at runtime. Putting the wire shape
//! in a single shared crate lets `rustc` enforce drift: a backend handler
//! and a sodmin page that disagree on a field will not compile together.
//!
//! Scope: **operator-facing** admin API only. Protocol-level event /
//! grant types live in `contrix-rust-sdk` and are not duplicated here.
//!
//! Schema derives (`schemars::JsonSchema`, `salvo::oapi::ToSchema`) are
//! gated behind the `schema` feature so that pure clients like `sodmin`
//! do not transitively pull salvo + schemars.

pub mod risk_action;

pub use risk_action::*;
