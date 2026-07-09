// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed client helpers for the Arkret `/_cokret/peer/*` protocol surface.

use std::time::Duration;

use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::constraints::Constrainable;
use coauth_keystore::Keystore;
use cokret_core::canonical::{canonical_json_bytes, sha256_digest};
use cokret_core::{
    HEADER_DESTINATION_TRUST_DOMAIN, HEADER_REQUEST_CANONICAL_DIGEST, HEADER_SOURCE_TRUST_DOMAIN,
    InviteDeliveryOutcome, InviteDeliveryRequest, SnapshotManifest,
};
use cokret_signatures::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, SignedRequestParts, canonical_message,
    format_signature_header, parse_signature_input,
};
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::outbound_http;

const SIGNATURE_LABEL: &str = "sig1";
const SIGNATURE_WINDOW_SECONDS: i64 = 300;
const SOURCE_SERVICE_DID_HEADER: &str = "Source-Service-DID";
const DESTINATION_SERVICE_DID_HEADER: &str = "Destination-Service-DID";

#[derive(Debug, Error)]
pub enum PeerProtocolClientError {
    #[error("peer protocol base URL is not configured")]
    BaseUrlNotConfigured,
    #[error("invalid peer protocol URL: {0}")]
    InvalidUrl(String),
    #[error("canonical JSON encoding failed: {0}")]
    Canonical(String),
    #[error("service signing key unavailable")]
    NoSigningKey,
    #[error("service signing failed")]
    Sign,
    #[error("HTTP send failed: {0}")]
    Http(String),
    #[error("peer protocol server returned status {0}")]
    Status(u16),
    #[error("peer protocol response body invalid: {0}")]
    Response(String),
}

#[derive(Debug, Clone)]
pub struct PeerProtocolIdentity {
    pub source_service_did: String,
    pub destination_service_did: String,
    pub source_trust_domain: String,
    pub destination_trust_domain: String,
}

impl PeerProtocolIdentity {
    #[must_use]
    pub fn same_destination(
        source_service_did: impl Into<String>,
        source_trust_domain: impl Into<String>,
    ) -> Self {
        let source_service_did = source_service_did.into();
        let source_trust_domain = source_trust_domain.into();
        Self {
            destination_service_did: source_service_did.clone(),
            destination_trust_domain: source_trust_domain.clone(),
            source_service_did,
            source_trust_domain,
        }
    }
}

pub struct PeerProtocolClient<'a> {
    base_url: &'a Url,
    http_client: &'a reqwest::Client,
    keystore: &'a Keystore,
    identity: PeerProtocolIdentity,
}

impl<'a> PeerProtocolClient<'a> {
    pub fn new(
        base_url: Option<&'a Url>,
        http_client: &'a reqwest::Client,
        keystore: &'a Keystore,
        identity: PeerProtocolIdentity,
    ) -> Result<Self, PeerProtocolClientError> {
        let Some(base_url) = base_url else {
            return Err(PeerProtocolClientError::BaseUrlNotConfigured);
        };
        Ok(Self {
            base_url,
            http_client,
            keystore,
            identity,
        })
    }

    pub async fn post_invite_delivery(
        &self,
        request: &InviteDeliveryRequest,
    ) -> Result<InviteDeliveryOutcome, PeerProtocolClientError> {
        let url = self.join_absolute("/_cokret/peer/invites")?;
        self.post_json(
            "peer_invites_submit",
            url,
            request,
            Some(&request.idempotency_key),
        )
        .await
    }

    pub async fn get_snapshot_head(
        &self,
        realm_id: &str,
    ) -> Result<SnapshotManifest, PeerProtocolClientError> {
        let mut url = self.join_absolute("/_cokret/peer/snapshot/head")?;
        url.query_pairs_mut().append_pair("realm_id", realm_id);
        let signed = self.signed_request("GET", &url, None, None)?;
        let response = outbound_http::send_with_policy(
            outbound_http::soland_policy("peer_snapshot_head").with_timeout(Duration::from_secs(5)),
            || {
                let mut request = self.http_client.get(url.clone());
                for (name, value) in &signed.headers {
                    request = request.header(name.as_str(), value.as_str());
                }
                request
            },
        )
        .await
        .map_err(|error| PeerProtocolClientError::Http(error.to_string()))?;

        parse_json_response(response).await
    }

    fn join_absolute(&self, path: &str) -> Result<Url, PeerProtocolClientError> {
        self.base_url
            .join(path)
            .map_err(|error| PeerProtocolClientError::InvalidUrl(error.to_string()))
    }

    async fn post_json<T, R>(
        &self,
        policy_name: &'static str,
        url: Url,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, PeerProtocolClientError>
    where
        T: Serialize,
        R: serde::de::DeserializeOwned,
    {
        let body_bytes = canonical_json_bytes(body)
            .map_err(|error| PeerProtocolClientError::Canonical(error.to_string()))?;
        let signed = self.signed_request("POST", &url, Some(&body_bytes), idempotency_key)?;

        let response = outbound_http::send_with_policy(
            outbound_http::soland_policy(policy_name).with_timeout(Duration::from_secs(5)),
            || {
                let mut request = self
                    .http_client
                    .post(url.clone())
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body_bytes.clone());
                for (name, value) in &signed.headers {
                    request = request.header(name.as_str(), value.as_str());
                }
                request
            },
        )
        .await
        .map_err(|error| PeerProtocolClientError::Http(error.to_string()))?;

        parse_json_response(response).await
    }

    fn signed_request(
        &self,
        method: &str,
        url: &Url,
        body: Option<&[u8]>,
        idempotency_key: Option<&str>,
    ) -> Result<SignedPeerRequest, PeerProtocolClientError> {
        let mut headers = vec![
            (
                SOURCE_SERVICE_DID_HEADER.to_owned(),
                self.identity.source_service_did.clone(),
            ),
            (
                DESTINATION_SERVICE_DID_HEADER.to_owned(),
                self.identity.destination_service_did.clone(),
            ),
            (
                HEADER_SOURCE_TRUST_DOMAIN.to_owned(),
                self.identity.source_trust_domain.clone(),
            ),
            (
                HEADER_DESTINATION_TRUST_DOMAIN.to_owned(),
                self.identity.destination_trust_domain.clone(),
            ),
        ];

        let mut covered = vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header(SOURCE_SERVICE_DID_HEADER.to_ascii_lowercase()),
            Component::Header(DESTINATION_SERVICE_DID_HEADER.to_ascii_lowercase()),
            Component::Header(HEADER_SOURCE_TRUST_DOMAIN.to_ascii_lowercase()),
            Component::Header(HEADER_DESTINATION_TRUST_DOMAIN.to_ascii_lowercase()),
        ];

        let body_digest =
            body.map(|bytes| ContentDigest::compute(bytes, ContentDigestAlgorithm::Sha256));
        if let Some(digest) = &body_digest {
            headers.push(("Content-Digest".to_owned(), digest.wire_value.clone()));
            headers.push((
                HEADER_REQUEST_CANONICAL_DIGEST.to_owned(),
                sha256_digest(body.expect("body exists when digest exists")),
            ));
            covered.push(Component::Header("content-digest".to_owned()));
            covered.push(Component::Header(
                HEADER_REQUEST_CANONICAL_DIGEST.to_ascii_lowercase(),
            ));
        }

        if let Some(key) = idempotency_key.filter(|key| !key.trim().is_empty()) {
            headers.push(("Idempotency-Key".to_owned(), key.to_owned()));
            covered.push(Component::Header("idempotency-key".to_owned()));
        }

        let (kid, signer) = eddsa_signer(self.keystore)?;
        let created = chrono::Utc::now().timestamp();
        let expires = created.saturating_add(SIGNATURE_WINDOW_SECONDS);
        let covered_wire = covered
            .iter()
            .map(|component| format!("\"{}\"", component.canonical_name()))
            .collect::<Vec<_>>()
            .join(" ");
        let signature_input_header = format!(
            "{SIGNATURE_LABEL}=({covered_wire});created={created};expires={expires};keyid=\"{}#{}\";alg=\"ed25519\"",
            self.identity.source_service_did, kid
        );
        let signature_input = parse_signature_input(&signature_input_header)
            .map_err(|_| PeerProtocolClientError::Sign)?;
        let request_parts = request_parts(method, url, &headers, body_digest.as_ref());
        let message = canonical_message(&request_parts, &signature_input)
            .map_err(|_| PeerProtocolClientError::Sign)?;

        use rand_core::SeedableRng as _;
        use signature::RandomizedSigner as _;
        let mut rng = rand_chacha::ChaChaRng::from_rng(rand_core::OsRng)
            .map_err(|_| PeerProtocolClientError::Sign)?;
        let raw = signer
            .try_sign_with_rng(&mut rng, &message)
            .map_err(|_| PeerProtocolClientError::Sign)?;
        let sig_bytes: Box<[u8]> = raw.into();
        let signature = cokret_core::base64_standard_encode(&sig_bytes);
        let signature_header = format_signature_header(SIGNATURE_LABEL, &signature)
            .map_err(|_| PeerProtocolClientError::Sign)?;

        headers.push(("Signature-Input".to_owned(), signature_input_header));
        headers.push(("Signature".to_owned(), signature_header));

        Ok(SignedPeerRequest { headers })
    }
}

#[derive(Debug, Clone)]
struct SignedPeerRequest {
    headers: Vec<(String, String)>,
}

fn request_parts(
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body_digest: Option<&ContentDigest>,
) -> SignedRequestParts {
    SignedRequestParts {
        method: method.to_owned(),
        target_uri: url.as_str().to_owned(),
        authority: url
            .host_str()
            .map(|host| match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            })
            .unwrap_or_default(),
        path: url.path().to_owned(),
        headers: headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect(),
        body_digest: body_digest.map(|digest| digest.wire_value.clone()),
    }
}

fn eddsa_signer(
    keystore: &Keystore,
) -> Result<
    (
        String,
        std::sync::Arc<coauth_jose::jwa::AsymmetricSigningKey>,
    ),
    PeerProtocolClientError,
> {
    let key = keystore
        .signing_key_for_algorithm(&JsonWebSignatureAlg::EdDsa)
        .ok_or(PeerProtocolClientError::NoSigningKey)?;
    let kid = key
        .kid()
        .filter(|kid| !kid.trim().is_empty())
        .ok_or(PeerProtocolClientError::NoSigningKey)?
        .to_owned();
    let signer = keystore
        .signer_for_algorithm(&JsonWebSignatureAlg::EdDsa)
        .map_err(|_| PeerProtocolClientError::NoSigningKey)?;
    Ok((kid, signer))
}

async fn parse_json_response<R>(response: reqwest::Response) -> Result<R, PeerProtocolClientError>
where
    R: serde::de::DeserializeOwned,
{
    let status = response.status();
    if !status.is_success() {
        return Err(PeerProtocolClientError::Status(status.as_u16()));
    }
    response
        .json()
        .await
        .map_err(|error| PeerProtocolClientError::Response(error.to_string()))
}

#[cfg(test)]
mod tests {
    use coauth_keystore::{JsonWebKey, JsonWebKeySet, PrivateKey};
    use rand_chacha::rand_core::SeedableRng;

    use super::*;

    fn test_keystore() -> Keystore {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(7);
        let key = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng)).with_kid("svc-key");
        Keystore::new(JsonWebKeySet::new(vec![key]))
    }

    #[test]
    fn signed_post_covers_peer_service_headers_and_body_digests() {
        let base = Url::parse("https://server.example/").unwrap();
        let client = reqwest::Client::new();
        let keystore = test_keystore();
        let identity = PeerProtocolIdentity::same_destination(
            "did:web:auth.example",
            "ak:trust_domain:auth.example",
        );
        let peer = PeerProtocolClient::new(Some(&base), &client, &keystore, identity).unwrap();
        let body = br#"{"a":1}"#;
        let url = base.join("/_cokret/peer/invites").unwrap();

        let signed = peer
            .signed_request("POST", &url, Some(body), Some("idem-1"))
            .unwrap();
        let header = |name: &str| {
            signed
                .headers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };

        assert_eq!(header("Source-Service-DID"), Some("did:web:auth.example"));
        let expected_digest = sha256_digest(body);
        assert_eq!(
            header(HEADER_REQUEST_CANONICAL_DIGEST),
            Some(expected_digest.as_str())
        );
        assert!(header("Content-Digest").is_some());
        assert!(
            header("Signature-Input")
                .unwrap()
                .contains("content-digest")
        );
        assert!(
            header("Signature-Input")
                .unwrap()
                .contains("request-canonical-digest")
        );
        assert!(header("Signature").unwrap().starts_with("sig1=:"));
    }

    #[test]
    fn signed_get_omits_body_digests() {
        let base = Url::parse("https://server.example/").unwrap();
        let client = reqwest::Client::new();
        let keystore = test_keystore();
        let identity = PeerProtocolIdentity::same_destination(
            "did:web:auth.example",
            "ak:trust_domain:auth.example",
        );
        let peer = PeerProtocolClient::new(Some(&base), &client, &keystore, identity).unwrap();
        let url = base
            .join("/_cokret/peer/snapshot/head?realm_id=ck:realm:test")
            .unwrap();

        let signed = peer.signed_request("GET", &url, None, None).unwrap();

        assert!(
            signed
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("Content-Digest"))
        );
        assert!(
            signed
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case(HEADER_REQUEST_CANONICAL_DIGEST))
        );
    }
}
