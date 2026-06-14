//! HTTP adapter for the `starid` `did:webvh` registry.
//!
//! Onboarding and recovery strands in coauth call into this adapter to mint
//! and re-mint a managed `did:webvh` for the principal account, and to
//! verify control-proofs supplied by the device on subsequent privileged
//! operations. It is a thin wrapper over starid's private WebVH DID
//! operations exposed under `/_starid/root/webvh/*`.
//!
//! The architectural intent is that **coauth never holds the principal's
//! signing key** — it only ferries the device's update-key (multibase
//! `z6Mk…`) into starid at create-time, and verifies signed challenges
//! at subsequent operation-time. starid stores the DID log; coauth keeps
//! the binding between `account_id` and `did:webvh:…` in its own
//! `account_identity_binding` table.
//!
//! The adapter lives in the `backend/services` layer (alongside
//! [`crate::services::did_resolver`] and
//! [`crate::services::principal_cache`]) rather than `coauth-data`
//! because it carries an HTTP dependency. `coauth-data` is intentionally
//! transport-free; placing an HTTP client there would mix layers.

use async_trait::async_trait;
use coauth_config::StaridConfig;
use cokret_core::ErrorEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

use crate::outbound_http;

/// Error returned by [`StaridResolver`] HTTP calls.
///
/// The variants mirror starid's `ApiFault` shape so callers can map
/// failures back to onboarding-strand error codes without having to parse
/// raw JSON.
#[derive(Debug, Error)]
pub enum StaridError {
    #[error("starid HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("starid returned malformed JSON: {0}")]
    BadResponse(#[from] serde_json::Error),

    #[error("starid base URL invalid: {0}")]
    Url(#[from] url::ParseError),

    /// 4xx with the `error.code` from the response envelope and the human
    /// `message` string. `code == "not_found"` means the DID isn't
    /// hosted by this starid; everything else is a programmer or
    /// signature failure.
    #[error("starid request failed ({status}, code={code}): {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },

    /// starid accepted the request but the response was missing the
    /// expected `did` / `verified` field. Should never happen in
    /// production — surfaces as an integration bug.
    #[error("starid response missing field: {0}")]
    MissingField(&'static str),
}

/// Wire-shape of starid's `POST /_starid/root/webvh/dids` request body. Mirrors
/// `starid::wire::CreateWebvhDidRequestBody`. Only the fields the adapter
/// actually exercises are serialised.
#[derive(Debug, Serialize)]
struct CreateWebvhDidRequestBody<'a> {
    host: &'a str,
    path: String,
    update_keys: Vec<String>,
    document_patch: Value,
}

/// Wire-shape of starid's `POST /_starid/root/webvh/dids` response body.
#[derive(Debug, Deserialize)]
struct CreateWebvhDidOutcome {
    did: String,
    #[allow(dead_code)]
    scid: String,
    version_id: String,
}

/// Wire-shape of starid's `POST /_starid/root/webvh/dids/{did}/verify`
/// response body.
#[derive(Debug, Deserialize)]
struct WebvhVerifyOutcome {
    verified: bool,
    #[serde(default)]
    head_version_id: Option<String>,
}

/// Wire-shape of starid's `POST /_starid/root/webvh/dids/{did}/update`
/// request body. Mirrors `starid::wire::UpdateWebvhDidRequestBody`.
#[derive(Debug, Serialize)]
struct UpdateWebvhDidRequestBody<'a> {
    prev_version_id: &'a str,
    update_keys: Vec<String>,
    document_patch: Value,
}

/// Wire-shape of starid's `POST /_starid/root/webvh/dids/{did}/update`
/// response body. Same envelope as `CreateWebvhDidOutcome`.
#[derive(Debug, Deserialize)]
struct UpdateWebvhDidOutcome {
    did: String,
    version_id: String,
}

/// The minted `did:webvh` and its current head version, returned from
/// [`StaridResolver::create_principal_did`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaridMintResult {
    pub did: String,
    pub version_id: String,
}

/// Verified-control-proof outcome from
/// [`StaridResolver::verify_control_proof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaridVerifyResult {
    pub verified: bool,
    pub head_version_id: Option<String>,
}

/// Shared handle around a [`StaridRegistry`] implementation. Wrapped in
/// an `Arc` so it can be cloned cheaply into the Salvo depot once per
/// request and shared across handlers.
pub type StaridRegistryHandle = std::sync::Arc<dyn StaridRegistry>;

/// Trait alias for objects that can act as a starid registry. Lets us
/// inject a fake in tests without hitting the network.
#[async_trait]
pub trait StaridRegistry: Send + Sync {
    /// Mint a managed `did:webvh` rooted at `account_id`, controlled by
    /// `update_key` (a multibase Ed25519 update key, typically `z6Mk…`).
    ///
    /// Returns the canonical `did:webvh:…` and its `version_id` (`1-…`).
    /// The caller is expected to persist `(account_id → did)` in the
    /// `account_identity_binding` table so subsequent operations can
    /// look it up.
    async fn create_principal_did(
        &self,
        account_id: &str,
        update_key: &str,
    ) -> Result<StaridMintResult, StaridError>;

    /// Re-mint the principal DID during account recovery. Today this is
    /// implemented as a fresh inception under a new SCID — the device's
    /// new update-key replaces the old one and the previous DID is
    /// deactivated upstream by the recovery strand.
    ///
    /// The recovery contract is captured separately in coauth's
    /// `_todos.md`; this method exists so onboarding and recovery share
    /// the same `StaridResolver` entry point.
    async fn recover_principal_did(
        &self,
        account_id: &str,
        update_key: &str,
    ) -> Result<StaridMintResult, StaridError>;

    /// Verify a signed control-proof against a hosted DID. The `entry`
    /// is a webvh log-entry-shaped JSON value with a `proof[0]`
    /// `DataIntegrityProof` block; starid checks that the proof's
    /// `verificationMethod` references one of the DID's current
    /// `updateKeys` and that the signature is a valid `eddsa-jcs-2022`
    /// signature over the entry minus `proof[]`.
    async fn verify_control_proof(
        &self,
        did: &str,
        entry: &Value,
    ) -> Result<StaridVerifyResult, StaridError>;

    /// Rotate the DID's `update_keys` slot to a new device-bound key.
    /// Posts to `POST /_starid/root/webvh/dids/{did}/update` with the next
    /// `version_id` (computed from the supplied `prev_version_id`) and a
    /// document patch that replaces `verificationMethod.key-1` with
    /// `new_update_key`.
    ///
    /// Onboarding strand: when a new passkey is enrolled on an account
    /// that already has a starid-minted DID, coauth calls this to swap
    /// the device key. starid validates that the request is signed by
    /// (or carries proof of) the *previous* `update_key`, so the rotation
    /// is itself authenticated by the outgoing key.
    async fn rotate_update_key(
        &self,
        did: &str,
        prev_version_id: &str,
        new_update_key: &str,
    ) -> Result<StaridMintResult, StaridError>;
}

/// Production HTTP-backed implementation of [`StaridRegistry`].
#[derive(Debug, Clone)]
pub struct StaridResolver {
    base_url: Url,
    did_host: String,
    path_prefix: String,
    admin_token: Option<String>,
    http: reqwest::Client,
}

impl StaridResolver {
    /// Build a resolver from a [`StaridConfig`]. Uses a default `reqwest`
    /// client tuned for short-lived API calls (10s timeout). Production
    /// callers should pass their own `reqwest::Client` via
    /// [`Self::with_http_client`] so they share connection pools.
    pub fn from_config(config: &StaridConfig) -> Result<Self, StaridError> {
        let http = crate::reqwest_client();
        Self::with_http_client(config, http)
    }

    /// Build a resolver from a [`StaridConfig`] and an existing
    /// `reqwest::Client`. Tests use this to inject a `wiremock`-pointed
    /// client without spinning up the full TLS stack.
    pub fn with_http_client(
        config: &StaridConfig,
        http: reqwest::Client,
    ) -> Result<Self, StaridError> {
        let did_host = config
            .did_host
            .clone()
            .or_else(|| config.base_url.host_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "starid.local".to_owned());
        Ok(Self {
            base_url: config.base_url.clone(),
            did_host,
            path_prefix: config.path_prefix.trim_matches('/').to_owned(),
            admin_token: config.admin_token.clone(),
            http,
        })
    }

    /// Compose the path coauth wants starid to mint the DID at:
    /// `<path_prefix>/<account_id>` with the `account_id` sanitised to
    /// the `[a-z0-9-]` alphabet starid allows in webvh paths.
    fn principal_path(&self, account_id: &str) -> String {
        let slug = account_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect::<String>();
        let slug = slug.trim_matches('-').to_owned();
        if self.path_prefix.is_empty() {
            slug
        } else {
            format!("{}/{}", self.path_prefix, slug)
        }
    }

    fn create_url(&self) -> Result<Url, StaridError> {
        let path = if self.admin_token.is_some() {
            "_starid/local/admin/dids"
        } else {
            "_starid/root/webvh/dids"
        };
        Ok(self.base_url.join(path)?)
    }

    fn update_url(&self, did: &str) -> Result<Url, StaridError> {
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| url::ParseError::SetHostOnCannotBeABaseUrl)?;
            segments.pop_if_empty();
            segments.extend(["_starid", "root", "webvh", "dids", did, "update"]);
        }
        Ok(url)
    }

    fn verify_url(&self, did: &str) -> Result<Url, StaridError> {
        // url::Url::join would treat `:` in `did:webvh:…` as a scheme
        // separator. Build the URL via path-segment append so the DID
        // gets percent-encoded correctly.
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| url::ParseError::SetHostOnCannotBeABaseUrl)?;
            // Strip any trailing empty segment from the base path so we
            // don't end up with `…//api/v1/…`.
            segments.pop_if_empty();
            segments.extend(["_starid", "root", "webvh", "dids", did, "verify"]);
        }
        Ok(url)
    }

    async fn post_create(
        &self,
        body: &CreateWebvhDidRequestBody<'_>,
    ) -> Result<CreateWebvhDidOutcome, StaridError> {
        let url = self.create_url()?;
        let response = outbound_http::send_with_policy(
            outbound_http::starid_mutation_policy("create_principal_did"),
            || {
                let mut request = self.http.post(url.clone()).json(body);
                if let Some(token) = &self.admin_token {
                    request = request.bearer_auth(token);
                }
                request
            },
        )
        .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(parse_api_fault(status.as_u16(), &bytes));
        }
        let parsed: CreateWebvhDidOutcome = serde_json::from_slice(&bytes)?;
        Ok(parsed)
    }
}

#[async_trait]
impl StaridRegistry for StaridResolver {
    async fn create_principal_did(
        &self,
        account_id: &str,
        update_key: &str,
    ) -> Result<StaridMintResult, StaridError> {
        let body = CreateWebvhDidRequestBody {
            host: &self.did_host,
            path: self.principal_path(account_id),
            update_keys: vec![update_key.to_owned()],
            document_patch: json!({
                "verificationMethod": {"key-1": update_key},
            }),
        };
        let parsed = self.post_create(&body).await?;
        Ok(StaridMintResult {
            did: parsed.did,
            version_id: parsed.version_id,
        })
    }

    async fn recover_principal_did(
        &self,
        account_id: &str,
        update_key: &str,
    ) -> Result<StaridMintResult, StaridError> {
        // Recovery currently mints a fresh inception. The prior DID is
        // deactivated by the recovery strand's caller via
        // `POST /_starid/root/webvh/dids/{did}/deactivate` (out of scope for
        // this adapter — recovery owns the prior-DID lookup).
        //
        // Path is suffixed with `/recovered/<n>` so a recovered account
        // doesn't collide with its prior `accounts/<id>` path. The `n`
        // counter is supplied by the caller via `account_id` itself
        // when needed (e.g., `01ARYZ.../recovered-2`); we don't fabric
        // a counter here.
        let body = CreateWebvhDidRequestBody {
            host: &self.did_host,
            path: self.principal_path(account_id),
            update_keys: vec![update_key.to_owned()],
            document_patch: json!({
                "verificationMethod": {"key-1": update_key},
                "recovered": true,
            }),
        };
        let parsed = self.post_create(&body).await?;
        Ok(StaridMintResult {
            did: parsed.did,
            version_id: parsed.version_id,
        })
    }

    async fn rotate_update_key(
        &self,
        did: &str,
        prev_version_id: &str,
        new_update_key: &str,
    ) -> Result<StaridMintResult, StaridError> {
        let body = UpdateWebvhDidRequestBody {
            prev_version_id,
            update_keys: vec![new_update_key.to_owned()],
            document_patch: json!({
                "verificationMethod": {"key-1": new_update_key},
            }),
        };
        let url = self.update_url(did)?;
        let response = outbound_http::send_with_policy(
            outbound_http::starid_mutation_policy("rotate_update_key"),
            || {
                let mut request = self.http.post(url.clone()).json(&body);
                if let Some(token) = &self.admin_token {
                    request = request.bearer_auth(token);
                }
                request
            },
        )
        .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(parse_api_fault(status.as_u16(), &bytes));
        }
        let parsed: UpdateWebvhDidOutcome = serde_json::from_slice(&bytes)?;
        Ok(StaridMintResult {
            did: parsed.did,
            version_id: parsed.version_id,
        })
    }

    async fn verify_control_proof(
        &self,
        did: &str,
        entry: &Value,
    ) -> Result<StaridVerifyResult, StaridError> {
        let url = self.verify_url(did)?;
        let response = outbound_http::send_with_policy(
            outbound_http::starid_verification_policy("verify_control_proof"),
            || {
                let mut request = self.http.post(url.clone()).json(&json!({"entry": entry}));
                if let Some(token) = &self.admin_token {
                    request = request.bearer_auth(token);
                }
                request
            },
        )
        .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            // 401 → invalid signature. Caller may want to surface that
            // distinctly; today we collapse it into the `Api` variant
            // and let the caller match on `error.code`.
            return Err(parse_api_fault(status.as_u16(), &bytes));
        }
        let parsed: WebvhVerifyOutcome = serde_json::from_slice(&bytes)?;
        if !parsed.verified {
            return Err(StaridError::MissingField("verified=true"));
        }
        Ok(StaridVerifyResult {
            verified: true,
            head_version_id: parsed.head_version_id,
        })
    }
}

fn parse_api_fault(status: u16, bytes: &[u8]) -> StaridError {
    match serde_json::from_slice::<ErrorEnvelope>(bytes) {
        Ok(env) => StaridError::Api {
            status,
            code: env.error.code,
            message: env.error.message,
        },
        Err(_) => StaridError::Api {
            status,
            code: "unparseable".to_owned(),
            message: String::from_utf8_lossy(bytes).into_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// `reqwest`'s rustls feature requires a default crypto provider.
    /// Install it once per test process.
    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn config_for(server: &MockServer) -> StaridConfig {
        StaridConfig {
            base_url: Url::parse(&server.uri()).unwrap(),
            did_host: Some("starid.local".to_owned()),
            path_prefix: "accounts".to_owned(),
            admin_token: None,
        }
    }

    fn admin_config_for(server: &MockServer, token: &str) -> StaridConfig {
        StaridConfig {
            base_url: Url::parse(&server.uri()).unwrap(),
            did_host: Some("starid.local".to_owned()),
            path_prefix: "accounts".to_owned(),
            admin_token: Some(token.to_owned()),
        }
    }

    #[test]
    fn principal_path_sanitises_account_id() {
        install_crypto_provider();
        let config = StaridConfig {
            base_url: Url::parse("https://starid.example").unwrap(),
            did_host: None,
            path_prefix: "accounts".to_owned(),
            admin_token: None,
        };
        let resolver = StaridResolver::from_config(&config).unwrap();
        assert_eq!(
            resolver.principal_path("01ARYZ_6S41TSV4RRFFQ69G5FAV"),
            "accounts/01aryz-6s41tsv4rrffq69g5fav"
        );
    }

    #[tokio::test]
    async fn create_principal_did_posts_to_public_endpoint() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let config = config_for(&server);
        Mock::given(method("POST"))
            .and(path("/_starid/root/webvh/dids"))
            .and(body_partial_json(json!({
                "host": "starid.local",
                "path": "accounts/01aryz",
                "update_keys": ["z6Mkdevicekey"],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "did": "did:webvh:zminted:starid.local:accounts:01aryz",
                "scid": "zminted",
                "version_id": "1-zhead",
                "raw_document_digest": "zhash",
                "host": "starid.local",
                "path": "accounts/01aryz",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let resolver = StaridResolver::from_config(&config).unwrap();
        let result = resolver
            .create_principal_did("01ARYZ", "z6Mkdevicekey")
            .await
            .expect("create succeeds");
        assert_eq!(result.did, "did:webvh:zminted:starid.local:accounts:01aryz");
        assert_eq!(result.version_id, "1-zhead");
    }

    #[tokio::test]
    async fn create_principal_did_uses_admin_endpoint_when_token_set() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let config = admin_config_for(&server, "super-secret");
        Mock::given(method("POST"))
            .and(path("/_starid/local/admin/dids"))
            .and(header("Authorization", "Bearer super-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "did": "did:webvh:zadmin:starid.local:accounts:01aryz",
                "scid": "zadmin",
                "version_id": "1-zheadadmin",
                "raw_document_digest": "zhash",
                "host": "starid.local",
                "path": "accounts/01aryz",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let resolver = StaridResolver::from_config(&config).unwrap();
        let result = resolver
            .create_principal_did("01ARYZ", "z6Mkdevicekey")
            .await
            .expect("admin-mode create succeeds");
        assert_eq!(result.did, "did:webvh:zadmin:starid.local:accounts:01aryz");
    }

    #[tokio::test]
    async fn create_principal_did_maps_starid_fault_to_api_error() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let config = config_for(&server);
        Mock::given(method("POST"))
            .and(path("/_starid/root/webvh/dids"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "ok": false,
                "error": {
                    "code": cokret_core::error::ERROR_CODE_CAS_CONFLICT,
                    "message": "stale write"
                },
                "request_id": "ck:request:01964137-0000-7000-8000-000000000001"
            })))
            .mount(&server)
            .await;

        let resolver = StaridResolver::from_config(&config).unwrap();
        let err = resolver
            .create_principal_did("01ARYZ", "z6Mkdevicekey")
            .await
            .unwrap_err();
        match err {
            StaridError::Api { status, code, .. } => {
                assert_eq!(status, 409);
                assert_eq!(code, cokret_core::error::ERROR_CODE_CAS_CONFLICT);
            }
            other => panic!("expected Api fault, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recover_principal_did_marks_recovered_in_document_patch() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let config = config_for(&server);
        Mock::given(method("POST"))
            .and(path("/_starid/root/webvh/dids"))
            .and(body_partial_json(json!({
                "document_patch": {"recovered": true},
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "did": "did:webvh:zrecovered:starid.local:accounts:01aryz-recovered-2",
                "scid": "zrecovered",
                "version_id": "1-zhead",
                "raw_document_digest": "zhash",
                "host": "starid.local",
                "path": "accounts/01aryz-recovered-2",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let resolver = StaridResolver::from_config(&config).unwrap();
        let result = resolver
            .recover_principal_did("01ARYZ-recovered-2", "z6Mknewkey")
            .await
            .expect("recover succeeds");
        assert!(result.did.contains("recovered"));
    }

    #[tokio::test]
    async fn rotate_update_key_posts_to_update_endpoint_with_new_key() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let config = config_for(&server);
        Mock::given(method("POST"))
            .and(path_regex(r"^/_starid/root/webvh/dids/.+/update$"))
            .and(body_partial_json(json!({
                "prev_version_id": "1-zhead",
                "update_keys": ["z6Mknewdevicekey"],
                "document_patch": {"verificationMethod": {"key-1": "z6Mknewdevicekey"}},
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "did": "did:webvh:zminted:starid.local:accounts:01aryz",
                "scid": "zminted",
                "version_id": "2-znext",
                "raw_document_digest": "zhash",
                "host": "starid.local",
                "path": "accounts/01aryz",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let resolver = StaridResolver::from_config(&config).unwrap();
        let result = resolver
            .rotate_update_key(
                "did:webvh:zminted:starid.local:accounts:01aryz",
                "1-zhead",
                "z6Mknewdevicekey",
            )
            .await
            .expect("rotate succeeds");
        assert_eq!(result.version_id, "2-znext");
        assert_eq!(result.did, "did:webvh:zminted:starid.local:accounts:01aryz");
    }

    #[tokio::test]
    async fn rotate_update_key_maps_409_to_api_error() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let config = config_for(&server);
        Mock::given(method("POST"))
            .and(path_regex(r"^/_starid/root/webvh/dids/.+/update$"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "ok": false,
                "error": {
                    "code": "stale_prev_version",
                    "message": "prev_version_id no longer matches head"
                },
                "request_id": "ck:request:01964137-0000-7000-8000-000000000002"
            })))
            .mount(&server)
            .await;

        let resolver = StaridResolver::from_config(&config).unwrap();
        let err = resolver
            .rotate_update_key(
                "did:webvh:zminted:starid.local:accounts:01aryz",
                "1-zstale",
                "z6Mknext",
            )
            .await
            .unwrap_err();
        match err {
            StaridError::Api { status, code, .. } => {
                assert_eq!(status, 409);
                assert_eq!(code, "stale_prev_version");
            }
            other => panic!("expected Api fault, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_control_proof_round_trips_did_in_path() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let config = config_for(&server);
        Mock::given(method("POST"))
            .and(path_regex(r"^/_starid/root/webvh/dids/.+/verify$"))
            .and(body_partial_json(json!({
                "entry": {"proof": [{"type": "DataIntegrityProof"}]},
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "verified": true,
                "did": "did:webvh:zminted:starid.local:accounts:01aryz",
                "head_version_id": "1-zhead",
                "verified_at": "2026-05-10T00:00:00Z",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let resolver = StaridResolver::from_config(&config).unwrap();
        let result = resolver
            .verify_control_proof(
                "did:webvh:zminted:starid.local:accounts:01aryz",
                &json!({
                    "parameters": {},
                    "state": {"challenge": "x"},
                    "proof": [{"type": "DataIntegrityProof"}],
                }),
            )
            .await
            .expect("verify succeeds");
        assert!(result.verified);
        assert_eq!(result.head_version_id.as_deref(), Some("1-zhead"));
    }

    #[tokio::test]
    async fn verify_control_proof_maps_unauthorized_to_api_error() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let config = config_for(&server);
        Mock::given(method("POST"))
            .and(path_regex(r"^/_starid/root/webvh/dids/.+/verify$"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "ok": false,
                "error": {
                    "code": "invalid_signature",
                    "message": "ed25519 signature is invalid"
                },
                "request_id": "ck:request:01964137-0000-7000-8000-000000000003"
            })))
            .mount(&server)
            .await;

        let resolver = StaridResolver::from_config(&config).unwrap();
        let err = resolver
            .verify_control_proof(
                "did:webvh:zminted:starid.local:accounts:01aryz",
                &json!({"proof": [{}]}),
            )
            .await
            .unwrap_err();
        match err {
            StaridError::Api { status, code, .. } => {
                assert_eq!(status, 401);
                assert_eq!(code, "invalid_signature");
            }
            other => panic!("expected Api fault, got {other:?}"),
        }
    }
}
