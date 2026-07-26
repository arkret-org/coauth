//! Browser WebAuthn bridge.
//!
//! `webauthn-rs-proto` owns the binary/base64url conversion so the UI never
//! relies on browser-private JSON serialisation of `PublicKeyCredential`.

use coauth_account_types::passkey::{PasskeyAuthFinishOutcome, PasskeyRegisterFinishOutcome};
#[cfg(target_arch = "wasm32")]
use coauth_account_types::passkey::{PasskeyAuthStartOutcome, PasskeyRegisterStartOutcome};

#[cfg(target_arch = "wasm32")]
fn js_error(value: wasm_bindgen::JsValue) -> String {
    let raw = value.as_string();
    let name = js_sys::Reflect::get(&value, &"name".into())
        .ok()
        .and_then(|value| value.as_string());
    name.as_deref()
        .or(raw.as_deref())
        .map(authenticator_error_message)
        .unwrap_or_else(|| authenticator_error_message(""))
}

#[cfg(any(target_arch = "wasm32", test))]
fn authenticator_error_message(name: &str) -> String {
    match name {
        "NotAllowedError" | "AbortError" => {
            "The passkey request was cancelled or timed out. Please try again.".to_owned()
        }
        "InvalidStateError" => "This passkey is already registered for this account.".to_owned(),
        "NotSupportedError" => {
            "This browser or authenticator does not support the requested passkey operation."
                .to_owned()
        }
        "SecurityError" => {
            "Passkeys require HTTPS (or localhost) and a matching site origin.".to_owned()
        }
        _ => "The authenticator request could not be completed. Please try again.".to_owned(),
    }
}

#[cfg(target_arch = "wasm32")]
fn ensure_webauthn_available() -> Result<web_sys::Window, String> {
    let window =
        web_sys::window().ok_or_else(|| "Passkeys require a browser window.".to_owned())?;
    let secure_context = js_sys::Reflect::get(&window, &"isSecureContext".into())
        .ok()
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !secure_context {
        return Err("Passkeys require HTTPS (or localhost).".to_owned());
    }
    let public_key_credential =
        js_sys::Reflect::get(&window, &"PublicKeyCredential".into()).unwrap_or_default();
    if public_key_credential.is_null() || public_key_credential.is_undefined() {
        return Err("This browser does not support passkeys.".to_owned());
    }
    Ok(window)
}

#[cfg(target_arch = "wasm32")]
fn registration_transports(
    credential: &web_sys::PublicKeyCredential,
) -> Option<Vec<webauthn_rs_proto::AuthenticatorTransport>> {
    use std::str::FromStr as _;

    use wasm_bindgen::JsCast as _;

    let response = js_sys::Reflect::get(credential, &"response".into()).ok()?;
    let get_transports = js_sys::Reflect::get(&response, &"getTransports".into())
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?;
    let values = js_sys::Array::from(&get_transports.call0(&response).ok()?);
    let transports = values
        .iter()
        .filter_map(|value| value.as_string())
        .filter_map(|value| webauthn_rs_proto::AuthenticatorTransport::from_str(&value).ok())
        .collect::<Vec<_>>();
    (!transports.is_empty()).then_some(transports)
}

#[cfg(target_arch = "wasm32")]
pub async fn authenticate(handle: String) -> Result<PasskeyAuthFinishOutcome, String> {
    use wasm_bindgen::JsCast as _;
    use wasm_bindgen_futures::JsFuture;
    use webauthn_rs_proto::{PublicKeyCredential, RequestChallengeResponse};

    let window = ensure_webauthn_available()?;
    let start = crate::api::api_post::<PasskeyAuthStartOutcome>(
        "/account/auth/passkey/auth/start",
        serde_json::json!({ "handle": handle }),
    )
    .await?;
    let challenge: RequestChallengeResponse = serde_json::from_value(start.challenge)
        .map_err(|error| format!("Invalid WebAuthn challenge: {error}"))?;
    let options: web_sys::CredentialRequestOptions = challenge.into();
    let credential = window
        .navigator()
        .credentials()
        .get_with_options(&options)
        .map(JsFuture::from)
        .map_err(js_error)?
        .await
        .map_err(js_error)?
        .dyn_into::<web_sys::PublicKeyCredential>()
        .map_err(|_| "The authenticator returned an unsupported credential.".to_owned())?;
    let assertion = serde_json::to_value(PublicKeyCredential::from(credential))
        .map_err(|error| format!("Could not encode the authenticator response: {error}"))?;

    crate::api::api_post(
        "/account/auth/passkey/auth/finish",
        serde_json::json!({
            "ceremony_id": start.ceremony_id,
            "assertion": assertion,
        }),
    )
    .await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn authenticate(_handle: String) -> Result<PasskeyAuthFinishOutcome, String> {
    Err("Passkeys are only available in a secure browser context.".to_owned())
}

#[cfg(target_arch = "wasm32")]
pub async fn register(
    display_name: Option<String>,
    label: Option<String>,
) -> Result<PasskeyRegisterFinishOutcome, String> {
    use wasm_bindgen::JsCast as _;
    use wasm_bindgen_futures::JsFuture;
    use webauthn_rs_proto::{CreationChallengeResponse, RegisterPublicKeyCredential};

    let window = ensure_webauthn_available()?;
    let start = crate::api::api_post::<PasskeyRegisterStartOutcome>(
        "/account/auth/passkey/register/start",
        serde_json::json!({ "display_name": display_name }),
    )
    .await?;
    let challenge: CreationChallengeResponse = serde_json::from_value(start.challenge)
        .map_err(|error| format!("Invalid WebAuthn challenge: {error}"))?;
    let options: web_sys::CredentialCreationOptions = challenge.into();
    let credential = window
        .navigator()
        .credentials()
        .create_with_options(&options)
        .map(JsFuture::from)
        .map_err(js_error)?
        .await
        .map_err(js_error)?
        .dyn_into::<web_sys::PublicKeyCredential>()
        .map_err(|_| "The authenticator returned an unsupported credential.".to_owned())?;
    let transports = registration_transports(&credential);
    let mut attestation = RegisterPublicKeyCredential::from(credential);
    attestation.response.transports = transports;
    let attestation = serde_json::to_value(attestation)
        .map_err(|error| format!("Could not encode the authenticator response: {error}"))?;

    crate::api::api_post(
        "/account/auth/passkey/register/finish",
        serde_json::json!({
            "ceremony_id": start.ceremony_id,
            "label": label,
            "attestation": attestation,
        }),
    )
    .await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn register(
    _display_name: Option<String>,
    _label: Option<String>,
) -> Result<PasskeyRegisterFinishOutcome, String> {
    Err("Passkeys are only available in a secure browser context.".to_owned())
}

#[cfg(test)]
mod tests {
    use super::authenticator_error_message;

    #[test]
    fn authenticator_errors_are_actionable_without_exposing_browser_details() {
        assert!(authenticator_error_message("NotAllowedError").contains("cancelled or timed out"));
        assert!(authenticator_error_message("InvalidStateError").contains("already registered"));
        assert!(authenticator_error_message("NotSupportedError").contains("does not support"));
        assert!(authenticator_error_message("SecurityError").contains("HTTPS"));
        assert!(!authenticator_error_message("UnknownError").contains("UnknownError"));
    }
}
