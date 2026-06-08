// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! RFC 7591 dynamic-client-registration admin handler.
//!
//! `POST /_coauth/admin/oauth/clients/register`
//!
//! Accepts the standard RFC 7591 request payload (`client_name`,
//! `redirect_uris`, `grant_types`, `token_endpoint_auth_method`, scope) and
//! persists a new entry to `oauth_clients`. Returns the standard
//! response shape — `client_id`, `client_secret` (only for confidential
//! clients), `client_id_issued_at`, `client_secret_expires_at`, and a
//! `registration_access_token` so the operator can re-edit the
//! registration via the admin SPA.
//!
//! This is the *admin* surface (mounted under `/_coauth/admin`). The
//! public, abuse-gated RFC 7591 endpoint at `/oauth/registration` is
//! still served by [`crate::handlers::oauth::registration`].

use chrono::{DateTime, Utc};
use coauth_data::{audit::AdminOperation, oauth::OAuthClientRepository};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use oauth_types::requests::GrantType;
use rand::distr::{Alphanumeric, SampleString};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    AppError, CreatedJsonResult,
    handlers::{
        admin::{
            CreatedJson, audit_helper::record_admin_operation, call_context::extract_call_context,
        },
        common::DepotExt,
    },
};

/// Request body for `POST /_coauth/admin/oauth/clients/register`.
///
/// Mirrors RFC 7591 §3.1 with a curated subset of fields. Unknown fields
/// are accepted and ignored (per RFC 7591 §2) — they would normally come
/// through as part of `ClientMetadata` on the public endpoint.
#[derive(Debug, Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "AdminDynamicClientRegistrationRequest")]
pub struct AdminClientRegistrationRequestBody {
    /// Human-readable client name (RFC 7591 §2 `client_name`).
    #[serde(default)]
    pub client_name: Option<String>,

    /// Allowed redirect URIs for the authorisation code flow.
    /// Required for non-machine clients.
    #[serde(default)]
    pub redirect_uris: Vec<String>,

    /// Grant types the client will use. Defaults to
    /// `["authorization_code"]` per RFC 7591 §2.
    #[serde(default)]
    pub grant_types: Vec<String>,

    /// Token endpoint client-auth method
    /// (`client_secret_basic`, `client_secret_post`, `none`,
    /// `private_key_jwt`, `client_secret_jwt`). Defaults to
    /// `client_secret_basic` per RFC 7591 §2.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,

    /// Space-separated OAuth scopes (RFC 7591 §2 `scope`).
    #[serde(default)]
    pub scope: Option<String>,
}

/// Response body — RFC 7591 §3.2.1 with the addition of
/// `registration_access_token` (RFC 7592).
///
/// # Normative: one-shot `client_secret`
///
/// The `client_secret` field is returned **exactly once**, in the body
/// of this registration response. It is never echoed by subsequent
/// `GET`s of the registration. If the operator loses it, they MUST
/// rotate the credential by calling the registration management
/// endpoint with the `registration_access_token`:
///
/// ```text
/// POST /_coauth/admin/oauth/clients/{client_id}/rotate-secret
/// Authorization: Bearer <registration_access_token>
/// ```
///
/// The `registration_access_token` is the long-lived RFC 7592 bearer
/// that authorises `GET` / `PUT` / `DELETE` on the registration; it is
/// stored hashed server-side and SHOULD be treated by the operator with
/// the same care as the `client_secret` itself.
#[derive(Debug, Serialize, JsonSchema, ToSchema)]
pub struct AdminClientRegistrationOutcome {
    pub client_id: String,
    /// Only present for confidential clients (i.e. when the auth method
    /// is one of the `client_secret_*` variants).
    ///
    /// **Returned exactly once.** This value is not stored in
    /// plaintext server-side and cannot be recovered via subsequent
    /// `GET` of the registration. Use the
    /// `registration_access_token` to rotate the secret if it is
    /// lost.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Time the client id was issued (Unix seconds).
    pub client_id_issued_at: DateTime<Utc>,
    /// `0` to indicate non-expiring secret per RFC 7591 §3.2.1.
    pub client_secret_expires_at: i64,
    /// Bearer token usable to manage this registration via the admin
    /// SPA.
    pub registration_access_token: String,
    /// Echo of the persisted metadata.
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub scope: Option<String>,
}

fn parse_auth_method(value: Option<&str>) -> Result<OAuthClientAuthenticationMethod, AppError> {
    let raw = value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("client_secret_basic");
    match raw {
        "client_secret_basic" => Ok(OAuthClientAuthenticationMethod::ClientSecretBasic),
        "client_secret_post" => Ok(OAuthClientAuthenticationMethod::ClientSecretPost),
        "client_secret_jwt" => Ok(OAuthClientAuthenticationMethod::ClientSecretJwt),
        "private_key_jwt" => Ok(OAuthClientAuthenticationMethod::PrivateKeyJwt),
        "none" => Ok(OAuthClientAuthenticationMethod::None),
        _ => Err(AppError::bad_request(format!(
            "unsupported token_endpoint_auth_method: {raw}"
        ))),
    }
}

fn parse_grant_type(value: &str) -> Result<GrantType, AppError> {
    match value.trim() {
        "authorization_code" => Ok(GrantType::AuthorizationCode),
        "refresh_token" => Ok(GrantType::RefreshToken),
        "client_credentials" => Ok(GrantType::ClientCredentials),
        "implicit" => Ok(GrantType::Implicit),
        "password" => Ok(GrantType::Password),
        // RFC 8628 device flow — accept canonical name.
        "urn:ietf:params:oauth:grant-type:device_code" => Ok(GrantType::DeviceCode),
        other => Err(AppError::bad_request(format!(
            "unsupported grant_type: {other}"
        ))),
    }
}

fn auth_method_to_str(value: &OAuthClientAuthenticationMethod) -> &'static str {
    match value {
        OAuthClientAuthenticationMethod::ClientSecretBasic => "client_secret_basic",
        OAuthClientAuthenticationMethod::ClientSecretPost => "client_secret_post",
        OAuthClientAuthenticationMethod::ClientSecretJwt => "client_secret_jwt",
        OAuthClientAuthenticationMethod::PrivateKeyJwt => "private_key_jwt",
        OAuthClientAuthenticationMethod::None => "none",
        _ => "client_secret_basic",
    }
}

fn grant_type_to_str(value: &GrantType) -> String {
    match value {
        GrantType::AuthorizationCode => "authorization_code".to_owned(),
        GrantType::RefreshToken => "refresh_token".to_owned(),
        GrantType::ClientCredentials => "client_credentials".to_owned(),
        GrantType::Implicit => "implicit".to_owned(),
        GrantType::Password => "password".to_owned(),
        GrantType::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
        _ => format!("{value:?}").to_lowercase(),
    }
}

fn requires_client_secret(method: &OAuthClientAuthenticationMethod) -> bool {
    matches!(
        method,
        OAuthClientAuthenticationMethod::ClientSecretBasic
            | OAuthClientAuthenticationMethod::ClientSecretPost
            | OAuthClientAuthenticationMethod::ClientSecretJwt
    )
}

/// Validate, normalise, and dedupe the request's `redirect_uris`. Pure
/// function so the test harness can exercise it without a live DB.
///
/// RFC 7591 doesn't strictly require an https scheme, but BCP 240 (the
/// IETF OAuth security topics draft) recommends rejecting plain `http://`
/// for anything but loopback dev URLs. The admin endpoint is the most
/// trusted registration entry point, so it enforces the strict rule:
/// only `https://` is accepted, with an exception for `http://localhost`
/// / `http://127.0.0.1` so local-dev workflows still work.
fn validate_redirect_uris(raw: &[String]) -> Result<Vec<Url>, AppError> {
    let mut out: Vec<Url> = Vec::with_capacity(raw.len());
    for entry in raw {
        let url = Url::parse(entry.trim())
            .map_err(|e| AppError::bad_request(format!("invalid redirect_uri {entry:?}: {e}")))?;
        if url.fragment().is_some() {
            return Err(AppError::bad_request(format!(
                "redirect_uri must not contain a fragment: {entry}"
            )));
        }
        let scheme = url.scheme();
        let host = url.host_str().unwrap_or_default();
        let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
        if scheme != "https" && !(scheme == "http" && is_loopback) {
            return Err(AppError::bad_request(format!(
                "redirect_uri must use the https:// scheme (got `{scheme}://` for `{entry}`)"
            )));
        }
        out.push(url);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Pure-function counterpart of the redirect requirement logic in
/// [`register`]. Returns `Err` if the supplied grant types include a
/// flow that needs a `redirect_uri` but none were supplied.
fn ensure_redirect_for_grants(grants: &[GrantType], redirect_uris: &[Url]) -> Result<(), AppError> {
    let needs_redirect = grants
        .iter()
        .any(|g| matches!(g, GrantType::AuthorizationCode | GrantType::Implicit));
    if needs_redirect && redirect_uris.is_empty() {
        return Err(AppError::bad_request(
            "at least one redirect_uri is required for code/implicit grants",
        ));
    }
    Ok(())
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.oauth_clients.register", skip_all)]
pub async fn register(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<AdminClientRegistrationOutcome> {
    let body: AdminClientRegistrationRequestBody =
        req.parse_json().await.map_err(AppError::internal)?;

    let auth_method = parse_auth_method(body.token_endpoint_auth_method.as_deref())?;

    let grant_types_input: Vec<GrantType> = if body.grant_types.is_empty() {
        vec![GrantType::AuthorizationCode]
    } else {
        body.grant_types
            .iter()
            .map(|g| parse_grant_type(g))
            .collect::<Result<Vec<_>, _>>()?
    };

    // Parse + dedupe redirect URIs.
    let redirect_uris = validate_redirect_uris(&body.redirect_uris)?;

    // Authorisation-code style grants require at least one redirect_uri.
    ensure_redirect_for_grants(&grant_types_input, &redirect_uris)?;

    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();

    let encrypter = depot.encrypter()?;

    // Generate an opaque client secret for confidential clients.
    let (client_secret, encrypted_client_secret) = if requires_client_secret(&auth_method) {
        let plain = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let encrypted = encrypter
            .encrypt_to_string(plain.as_bytes())
            .map_err(|e| AppError::internal(std::io::Error::other(e.to_string())))?;
        (Some(plain), Some(encrypted))
    } else {
        (None, None)
    };

    let client = repo
        .oauth_client()
        .add(
            &mut rng,
            &*clock,
            redirect_uris.clone(),
            None,
            encrypted_client_secret,
            None,
            grant_types_input.clone(),
            body.client_name.clone(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(auth_method.clone()),
            None,
            None,
        )
        .await?;

    // Generate a registration access token (RFC 7592). Random 32-byte
    // alphanumeric bearer token; not persisted yet — clients receive
    // it once at registration time.
    let registration_access_token = Alphanumeric.sample_string(&mut rand::rng(), 32);

    record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::Other("oauth_client.register".to_owned()),
        "oauth_client",
        Some(client.id),
        serde_json::json!({
            "client_name": &body.client_name,
            "redirect_uri_count": redirect_uris.len(),
            "grant_types": grant_types_input.iter().map(grant_type_to_str).collect::<Vec<_>>(),
            "token_endpoint_auth_method": auth_method_to_str(&auth_method),
            "scope": &body.scope,
        }),
    )
    .await?;
    repo.save().await?;

    let response = AdminClientRegistrationOutcome {
        client_id: client.client_id.clone(),
        client_secret,
        client_id_issued_at: client.id.datetime().into(),
        client_secret_expires_at: 0,
        registration_access_token,
        client_name: body.client_name,
        redirect_uris: redirect_uris.iter().map(ToString::to_string).collect(),
        grant_types: grant_types_input.iter().map(grant_type_to_str).collect(),
        token_endpoint_auth_method: auth_method_to_str(&auth_method).to_owned(),
        scope: body.scope,
    };

    Ok(CreatedJson(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_auth_method_is_basic() {
        let m = parse_auth_method(None).unwrap();
        assert!(matches!(
            m,
            OAuthClientAuthenticationMethod::ClientSecretBasic
        ));
    }

    #[test]
    fn parse_known_auth_methods() {
        assert!(matches!(
            parse_auth_method(Some("none")).unwrap(),
            OAuthClientAuthenticationMethod::None,
        ));
        assert!(matches!(
            parse_auth_method(Some("private_key_jwt")).unwrap(),
            OAuthClientAuthenticationMethod::PrivateKeyJwt,
        ));
        assert!(matches!(
            parse_auth_method(Some("client_secret_post")).unwrap(),
            OAuthClientAuthenticationMethod::ClientSecretPost,
        ));
    }

    #[test]
    fn parse_unknown_auth_method_is_400() {
        let err = parse_auth_method(Some("foo")).unwrap_err();
        assert!(format!("{err:?}").contains("unsupported"));
    }

    #[test]
    fn requires_client_secret_for_confidential_clients() {
        assert!(requires_client_secret(
            &OAuthClientAuthenticationMethod::ClientSecretBasic
        ));
        assert!(requires_client_secret(
            &OAuthClientAuthenticationMethod::ClientSecretPost
        ));
        assert!(requires_client_secret(
            &OAuthClientAuthenticationMethod::ClientSecretJwt
        ));
        assert!(!requires_client_secret(
            &OAuthClientAuthenticationMethod::None
        ));
        assert!(!requires_client_secret(
            &OAuthClientAuthenticationMethod::PrivateKeyJwt
        ));
    }

    #[test]
    fn parse_known_grant_types() {
        assert!(matches!(
            parse_grant_type("authorization_code").unwrap(),
            GrantType::AuthorizationCode
        ));
        assert!(matches!(
            parse_grant_type("refresh_token").unwrap(),
            GrantType::RefreshToken
        ));
        assert!(matches!(
            parse_grant_type("client_credentials").unwrap(),
            GrantType::ClientCredentials
        ));
        assert!(parse_grant_type("not_a_grant").is_err());
    }

    // ── Round-26: dynamic client registration coverage (3 happy + 2 negative) ──

    #[test]
    fn happy_validate_redirect_uris_dedupes_and_sorts() {
        let raw = vec![
            "https://b.example/cb".to_owned(),
            "https://a.example/cb".to_owned(),
            "https://b.example/cb".to_owned(),
        ];
        let out = validate_redirect_uris(&raw).expect("valid redirects");
        assert_eq!(out.len(), 2, "duplicates must be removed");
        assert_eq!(out[0].host_str(), Some("a.example"));
        assert_eq!(out[1].host_str(), Some("b.example"));
    }

    #[test]
    fn happy_device_code_grant_urn_parses() {
        let g = parse_grant_type("urn:ietf:params:oauth:grant-type:device_code").unwrap();
        assert!(matches!(g, GrantType::DeviceCode));
    }

    #[test]
    fn happy_machine_to_machine_does_not_need_redirect_uri() {
        // client_credentials has no redirect_uri requirement.
        ensure_redirect_for_grants(&[GrantType::ClientCredentials], &[])
            .expect("client_credentials should not require redirect_uri");
        ensure_redirect_for_grants(&[GrantType::RefreshToken], &[])
            .expect("refresh_token should not require redirect_uri");
    }

    #[test]
    fn negative_redirect_uri_with_fragment_rejected() {
        let raw = vec!["https://example.com/cb#fragment".to_owned()];
        let err = validate_redirect_uris(&raw).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("fragment"),
            "expected fragment-rejection error, got {msg}"
        );
    }

    #[test]
    fn negative_authorization_code_without_redirect_uri_rejected() {
        let err = ensure_redirect_for_grants(&[GrantType::AuthorizationCode], &[]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("redirect_uri"),
            "expected redirect_uri requirement error, got {msg}"
        );
    }

    // ── Round-27: extra negative coverage for the RFC 7591 helpers ──

    /// `validate_redirect_uris` enforces https:// only (plus localhost
    /// loopback exception). Plain `http://example.com` must be rejected.
    #[test]
    fn negative_redirect_uri_non_https_scheme_rejected() {
        let raw = vec!["http://example.com/cb".to_owned()];
        let err = validate_redirect_uris(&raw).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("https"),
            "expected https-only enforcement error, got {msg}"
        );

        // Other non-https schemes (custom URI scheme without loopback
        // host) must also be rejected. RFC 8252 native-app callbacks go
        // through the public registration endpoint, not the admin one.
        let raw = vec!["app://callback".to_owned()];
        let err = validate_redirect_uris(&raw).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("https"),
            "custom-scheme redirect must be rejected by admin endpoint, got {msg}"
        );

        // Loopback dev URLs over plain http are still allowed — the
        // exception that keeps `cargo run` workflows usable.
        let raw = vec!["http://localhost:3000/cb".to_owned()];
        let out = validate_redirect_uris(&raw).expect("loopback http exception");
        assert_eq!(out.len(), 1);
        let raw = vec!["http://127.0.0.1:3000/cb".to_owned()];
        let out = validate_redirect_uris(&raw).expect("loopback http exception");
        assert_eq!(out.len(), 1);
    }

    /// `parse_auth_method` is allowlist-driven. Anything outside the
    /// curated set must hit the 400 path with an "unsupported" message,
    /// regardless of how plausible the value looks.
    #[test]
    fn negative_token_endpoint_auth_method_not_allowlisted() {
        // Plausibly-named but not in the allowlist (typo / future RFC
        // method that we haven't audited).
        for bogus in [
            "tls_client_auth",
            "self_signed_tls_client_auth",
            "client_secret_basics", // common typo
            "BASIC",                // uppercase; allowlist is lowercase
            "  ",                   /* whitespace, falls through to default? — ensure not
                                     * silently accepted */
        ] {
            // Whitespace-only intentionally falls through to the
            // default ("client_secret_basic") because `parse_auth_method`
            // strips and uses the default for empty input — that's by
            // design (RFC 7591 §2). The other four must error.
            if bogus.trim().is_empty() {
                let m = parse_auth_method(Some(bogus)).expect("blank ⇒ default");
                assert!(matches!(
                    m,
                    OAuthClientAuthenticationMethod::ClientSecretBasic
                ));
                continue;
            }
            let err = parse_auth_method(Some(bogus)).unwrap_err();
            let msg = format!("{err:?}");
            assert!(
                msg.contains("unsupported"),
                "expected 'unsupported' for {bogus:?}, got {msg}"
            );
        }
    }
}
