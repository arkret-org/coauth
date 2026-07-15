//! Shared serde wire types for the self-serve passkey ceremony endpoints
//! under `/_coauth/account/auth/passkey/*`.
//!
//! The inner WebAuthn payloads (`challenge` / `attestation` / `assertion`) stay
//! as `serde_json::Value` because they are passed through verbatim to and from
//! the browser's `navigator.credentials` API; the backend decodes them into
//! `webauthn-rs` types locally, so clients depending on this crate never need
//! `webauthn-rs`.

use serde::{Deserialize, Serialize};

/// Account-selection hint accepted by the passkey ceremony start endpoints and
/// flattened into the finish request bodies. All fields are optional; the
/// backend resolves the target account from whichever hint is present.
#[derive(Default, Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename = "AuthPasskeyAccountHint")]
pub struct PasskeyAccountHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Body for `passkey/register/finish`: the account hint plus the browser
/// attestation produced by `navigator.credentials.create`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename = "AuthPasskeyRegisterFinishRequest")]
pub struct PasskeyRegisterFinishRequestBody {
    #[serde(flatten)]
    pub hint: PasskeyAccountHint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub attestation: serde_json::Value,
}

/// Body for `passkey/auth/finish`: the account hint plus the browser assertion
/// produced by `navigator.credentials.get`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename = "AuthPasskeyAuthFinishRequest")]
pub struct PasskeyAuthFinishRequestBody {
    #[serde(flatten)]
    pub hint: PasskeyAccountHint,
    pub assertion: serde_json::Value,
}

/// Outcome of `passkey/register/start`: the resolved account plus the
/// `CreationChallengeResponse` JSON the browser feeds into
/// `navigator.credentials.create({ publicKey: ... })`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyRegisterStartOutcome {
    pub account_id: String,
    pub handle: String,
    pub challenge: serde_json::Value,
}

/// Outcome of `passkey/register/finish`: the persisted credential.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyRegisterFinishOutcome {
    pub account_id: String,
    pub id: String,
    pub credential_id_b64: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// Outcome of `passkey/auth/start`: the resolved account plus the
/// `RequestChallengeResponse` JSON the browser feeds into
/// `navigator.credentials.get({ publicKey: ... })`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyAuthStartOutcome {
    pub account_id: String,
    pub handle: String,
    pub challenge: serde_json::Value,
}

/// Outcome of `passkey/auth/finish`: the credential id that satisfied the
/// assertion.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyAuthFinishOutcome {
    pub account_id: String,
    pub credential_id_b64: String,
}
