//! Shared serde wire types for the self-serve passkey ceremony endpoints
//! under `/_coauth/account/auth/passkey/*`.
//!
//! The inner WebAuthn payloads (`challenge` / `attestation` / `assertion`) stay
//! as `serde_json::Value` because they are passed through verbatim to and from
//! the browser's `navigator.credentials` API; the backend decodes them into
//! `webauthn-rs` types locally, so clients depending on this crate never need
//! `webauthn-rs`.

use serde::{Deserialize, Serialize};

/// Account-selection hint accepted by the passkey authentication start
/// endpoint. The backend accepts `account_id`, `handle`, or `login_hint`.
/// Finish endpoints derive the account from server-side ceremony state
/// instead of trusting another caller-supplied hint.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename = "AuthPasskeyAccountHint")]
pub struct PasskeyAccountHint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
}

/// Body for `passkey/register/start`.
///
/// The account is never caller-selected: the backend derives it from the
/// authenticated browser session. `display_name` only controls the
/// human-readable name shown by the authenticator.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename = "AuthPasskeyRegisterStartRequest")]
pub struct PasskeyRegisterStartRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Body for `passkey/register/finish`: the opaque ceremony id plus the browser
/// attestation produced by `navigator.credentials.create`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename = "AuthPasskeyRegisterFinishRequest")]
pub struct PasskeyRegisterFinishRequestBody {
    pub ceremony_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub attestation: serde_json::Value,
}

/// Body for `passkey/auth/finish`: the opaque ceremony id plus the browser
/// assertion produced by `navigator.credentials.get`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
#[serde(rename = "AuthPasskeyAuthFinishRequest")]
pub struct PasskeyAuthFinishRequestBody {
    pub ceremony_id: String,
    pub assertion: serde_json::Value,
}

/// Outcome of `passkey/register/start`: the resolved account plus the
/// `CreationChallengeResponse` JSON the browser feeds into
/// `navigator.credentials.create({ publicKey: ... })`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyRegisterStartOutcome {
    pub ceremony_id: String,
    pub account_id: String,
    pub handle: String,
    pub challenge: serde_json::Value,
}

/// Outcome of `passkey/register/finish`: the persisted credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyRegisterFinishOutcome {
    pub account_id: String,
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// Outcome of `passkey/auth/start`: the resolved account plus the
/// `RequestChallengeResponse` JSON the browser feeds into
/// `navigator.credentials.get({ publicKey: ... })`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyAuthStartOutcome {
    pub ceremony_id: String,
    pub account_id: String,
    pub handle: String,
    pub challenge: serde_json::Value,
}

/// Outcome of `passkey/auth/finish`: the credential id that satisfied the
/// assertion.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyAuthFinishOutcome {
    pub status: String,
    pub account_id: String,
    pub passkey_id: String,
}

/// User-facing credential metadata. Credential public keys and full credential
/// ids are deliberately not exposed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeySummary {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyListOutcome {
    pub passkeys: Vec<PasskeySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyRenameRequestBody {
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(salvo::oapi::ToSchema))]
pub struct PasskeyMutationOutcome {
    pub status: String,
    pub id: String,
}
