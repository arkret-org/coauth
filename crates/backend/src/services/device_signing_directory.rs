//! Resolve an authorized device signing key from the Principal Server's
//! device directory (`POST /_soland/gate/account/device-signing-keys/query`).
//!
//! A device holder proof (session-grant refresh / soft-logout restore) is
//! signed by the device's `ck.device.authorize`-authorized signing key. That
//! key is NOT a verificationMethod in the principal's DID document — the DID
//! document only carries the inception / control keys. The source of truth for
//! per-device signing keys is the Principal Server's device directory, written
//! by the `ck.device.authorize` projector and masked by `ck.device.revoke`.
//!
//! This module is the Auth Server's read into that directory: given the
//! principal DID (the session-grant subject) and the bound `device_id`, it
//! returns the authorized, non-revoked device signing key as an Ed25519
//! `did:key` multibase. The Principal Server is selected from the configured
//! `principal_servers` by the session-grant audience, and the request rides the
//! same static bearer coauth already holds for that server's embedded
//! `did:webvh` registration surface.

use coauth_config::CokretConfig;
use cokret_core::DeviceSigningKeyDirectoryQueryRequestBody;
use thiserror::Error;

use crate::outbound_http;

// TODO(_fix_plan.md decision 4 / COA-ARCH-01): the protocol read face for the
// device signing-key directory facet is `POST /_cokret/self/keys/query`
// (`ck.self.keys.query.lookup`), whose response `query_device_record` carries
// `device_signing_key` / `device_status`. coauth CANNOT switch to it
// single-sidedly: that protocol path authenticates a *principal session grant*
// (`authenticated_session`) and gates cross-principal reads behind a
// realm-co-membership visibility predicate. While verifying a device holder
// proof during session-grant refresh / soft-logout restore, coauth acts as the
// Auth Server — it holds no session grant for the target principal and is not a
// realm co-member, so it cannot authenticate as the subject nor pass the
// visibility check. soland exposes this dedicated server-to-server bearer-gated
// read (`/_soland/gate/account/device-signing-keys/query`, op
// `org.cokret.soland.gate.account.device_signing_keys.query`) precisely for the
// Auth-Server role; it is documented soland-side as a deployment-local
// integration read, not a spec operation. Migrating onto `/_cokret/self/...`
// needs coauth+soland coordination (soland accepting an S2S auth mode with a
// cross-principal exemption on the protocol path). Keep the working S2S edge
// until that coordinated change lands.
const DEVICE_SIGNING_KEY_DIRECTORY_PATH: &str =
    "/_soland/gate/account/device-signing-keys/query";

/// Errors raised while resolving an authorized device signing key.
#[derive(Debug, Error)]
pub enum DeviceSigningDirectoryError {
    /// No `principal_servers` entry matched the session-grant audience, so the
    /// Principal Server base URL / bearer cannot be resolved.
    #[error("no configured principal server matches audience {audience:?}")]
    PrincipalServerUnknown { audience: String },
    /// The matched principal server has no static bearer configured for the
    /// server-to-server directory read.
    #[error("principal server {audience:?} has no embedded_webvh_registration_bearer configured")]
    DirectoryBearerMissing { audience: String },
    /// The configured endpoint could not be joined with the directory path.
    #[error("principal server endpoint is not a valid URL: {0}")]
    InvalidEndpoint(#[from] url::ParseError),
    /// Transport failure talking to the Principal Server.
    #[error("device signing-key directory request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Non-2xx response from the Principal Server.
    #[error("device signing-key directory returned status {status}: {body}")]
    DirectoryRejected { status: u16, body: String },
    /// The directory accepted the request but the device is not present
    /// (unknown / unverified / revoked), so no authorized key exists.
    #[error("no authorized device signing key for device {device_id:?}")]
    DeviceNotAuthorized { device_id: String },
}

/// The single authorized device signing key resolved for `(principal, device)`.
#[derive(Debug, Clone)]
pub struct ResolvedDeviceSigningKey {
    /// Ed25519 `did:key` multibase rendering returned by the directory
    /// (`did:key:z…`).
    pub device_signing_key_did: String,
    /// The bare `z…` multibase Ed25519 key, suitable for
    /// `cokret_signatures::PublicKeyMaterial::Ed25519Multibase`.
    pub multibase: String,
}

/// Resolve `(principal_id, device_id)` → authorized device signing key against
/// the Principal Server selected by `audience`.
///
/// The Principal Server endpoint + bearer come from
/// [`CokretConfig::principal_servers`]; the session-grant `audience` selects the
/// row (its `audience` field). Only verified, non-revoked devices are returned,
/// so a present result is itself proof the key is currently authorized; an
/// absent device yields [`DeviceSigningDirectoryError::DeviceNotAuthorized`].
pub async fn resolve_authorized_device_signing_key(
    http_client: &reqwest::Client,
    cokret_config: &CokretConfig,
    audience: &str,
    principal_id: &str,
    device_id: &str,
) -> Result<ResolvedDeviceSigningKey, DeviceSigningDirectoryError> {
    let server = cokret_config
        .principal_servers
        .iter()
        .find(|server| server.audience == audience)
        .ok_or_else(|| DeviceSigningDirectoryError::PrincipalServerUnknown {
            audience: audience.to_owned(),
        })?;
    let bearer = server
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DeviceSigningDirectoryError::DirectoryBearerMissing {
            audience: audience.to_owned(),
        })?;

    let endpoint = server.endpoint.join(DEVICE_SIGNING_KEY_DIRECTORY_PATH)?;

    let typed_principal = cokret_core::Did::new(principal_id.to_owned()).map_err(|_| {
        DeviceSigningDirectoryError::DeviceNotAuthorized {
            device_id: device_id.to_owned(),
        }
    })?;
    let typed_device = cokret_core::DeviceId::new(device_id.to_owned()).map_err(|_| {
        DeviceSigningDirectoryError::DeviceNotAuthorized {
            device_id: device_id.to_owned(),
        }
    })?;
    let body = DeviceSigningKeyDirectoryQueryRequestBody {
        principal_id: typed_principal,
        device_ids: vec![typed_device],
    };

    let response = outbound_http::send_with_policy(
        outbound_http::soland_policy("device_signing_keys_query"),
        || {
            http_client
                .post(endpoint.clone())
                .bearer_auth(bearer)
                .json(&body)
        },
    )
    .await?;

    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(DeviceSigningDirectoryError::DirectoryRejected {
            status: status.as_u16(),
            body: text.chars().take(512).collect(),
        });
    }

    let outcome: cokret_core::DeviceSigningKeyDirectoryOutcome = serde_json::from_str(&text)
        .map_err(|error| DeviceSigningDirectoryError::DirectoryRejected {
            status: status.as_u16(),
            body: format!("invalid response body: {error}"),
        })?;

    let entry = outcome
        .devices
        .into_iter()
        .find(|entry| entry.device_id.as_str() == device_id)
        .ok_or_else(|| DeviceSigningDirectoryError::DeviceNotAuthorized {
            device_id: device_id.to_owned(),
        })?;

    let multibase = entry
        .device_signing_key
        .strip_prefix("did:key:")
        .unwrap_or(entry.device_signing_key.as_str())
        .to_owned();

    Ok(ResolvedDeviceSigningKey {
        device_signing_key_did: entry.device_signing_key,
        multibase,
    })
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    #[test]
    fn directory_url_joins_product_surface_path() {
        let endpoint = Url::parse("https://soland.example:8443/").unwrap();
        let url = endpoint.join(DEVICE_SIGNING_KEY_DIRECTORY_PATH).unwrap();
        assert_eq!(
            url.as_str(),
            "https://soland.example:8443/_soland/gate/account/device-signing-keys/query"
        );
    }
}
