// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed client helpers for the Arkret `/_arkret/peer/*` protocol surface.

use std::time::Duration;

use arkret_canonical::canonical_json_bytes;
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusPublicationOutcome, AccountStatusPublicationRequestBody,
};
use arkret_models_collaboration::event_query::PeerEventsFrontierRequestBody;
use arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState;
use arkret_models_collaboration::governance::invite_addressing::{
    InviteDeliveryOutcome, InviteDeliveryRequestBodyBody,
};
use arkret_models_collaboration::principal_operations::{
    PcrGenesisSubmitOutcome, PcrGenesisSubmitRequestBody,
};
use arkret_models_crypto::http_bodies::PeerKeyPackagesClaimTransportBinding;
use arkret_signatures::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, SignedRequestParts, canonical_message,
    format_signature_header, parse_signature_input,
};
use arkret_state::SnapshotManifest;
use arkret_wire::{HEADER_DESTINATION_TRUST_DOMAIN, HEADER_SOURCE_TRUST_DOMAIN};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::constraints::Constrainable;
use coauth_keystore::Keystore;
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::outbound_http;

const SIGNATURE_LABEL: &str = "sig1";
const SIGNATURE_WINDOW_SECONDS: i64 = 300;
const SOURCE_SERVICE_ID_HEADER: &str = "Source-Service-ID";
const DESTINATION_SERVICE_ID_HEADER: &str = "Destination-Service-ID";

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

pub struct PeerProtocolClient<'a> {
    base_url: &'a Url,
    http_client: &'a reqwest::Client,
    keystore: &'a Keystore,
    identity: PeerKeyPackagesClaimTransportBinding,
}

impl<'a> PeerProtocolClient<'a> {
    pub fn new(
        base_url: Option<&'a Url>,
        http_client: &'a reqwest::Client,
        keystore: &'a Keystore,
        identity: PeerKeyPackagesClaimTransportBinding,
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
        request: &InviteDeliveryRequestBodyBody,
    ) -> Result<InviteDeliveryOutcome, PeerProtocolClientError> {
        let url = self.join_absolute("/_arkret/peer/invites")?;
        self.post_json(
            "peer_invites_submit",
            url,
            request,
            Some(&request.idempotency_key),
        )
        .await
    }

    /// Deliver one exact account-status publication through its dedicated
    /// peer operation. The idempotency key is a signed header and never part
    /// of the canonical body.
    pub async fn post_account_status_publication(
        &self,
        request: &AccountStatusPublicationRequestBody,
        idempotency_key: &str,
    ) -> Result<AccountStatusPublicationOutcome, PeerProtocolClientError> {
        let url = self.join_absolute("/_arkret/peer/account-status")?;
        self.post_json(
            "peer_account_status_submit",
            url,
            request,
            Some(idempotency_key),
        )
        .await
    }

    /// Relay the exact client-signed PCR genesis unit. The Account Authority
    /// authenticates the service transport but does not author or modify any
    /// principal Event.
    pub async fn post_principal_genesis(
        &self,
        request: &PcrGenesisSubmitRequestBody,
    ) -> Result<PcrGenesisSubmitOutcome, PeerProtocolClientError> {
        request
            .validate()
            .map_err(|error| PeerProtocolClientError::Canonical(error.to_string()))?;
        let url = self.join_absolute("/_arkret/peer/principal-genesis")?;
        let outcome: PcrGenesisSubmitOutcome = self
            .post_json(
                "peer_principal_genesis_submit",
                url,
                request,
                Some(request.idempotency_key.as_str()),
            )
            .await?;
        outcome
            .validate_against(request)
            .map_err(|error| PeerProtocolClientError::Response(error.to_string()))?;
        Ok(outcome)
    }

    pub async fn get_snapshot_head(
        &self,
        realm_id: &str,
    ) -> Result<SnapshotManifest, PeerProtocolClientError> {
        let mut url = self.join_absolute("/_arkret/peer/snapshot/head")?;
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

    /// Read the peer Event frontier through its registered HTTP QUERY binding.
    pub async fn read_events_frontier(
        &self,
        request: &PeerEventsFrontierRequestBody,
    ) -> Result<EventsFrontierFederationPeerState, PeerProtocolClientError> {
        let url = self.join_absolute("/_arkret/peer/events/frontier")?;
        let body_bytes = canonical_json_bytes(request)
            .map_err(|error| PeerProtocolClientError::Canonical(error.to_string()))?;
        let signed = self.signed_request("QUERY", &url, Some(&body_bytes), None)?;
        let query_method = reqwest::Method::from_bytes(b"QUERY")
            .map_err(|error| PeerProtocolClientError::InvalidUrl(error.to_string()))?;
        let response = outbound_http::send_with_policy(
            outbound_http::soland_policy("peer_events_read_frontier")
                .with_timeout(Duration::from_secs(5)),
            || {
                let mut builder = self
                    .http_client
                    .request(query_method.clone(), url.clone())
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body_bytes.clone());
                for (name, value) in &signed.headers {
                    builder = builder.header(name.as_str(), value.as_str());
                }
                builder
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
                SOURCE_SERVICE_ID_HEADER.to_owned(),
                self.identity.source_service_id.to_string(),
            ),
            (
                DESTINATION_SERVICE_ID_HEADER.to_owned(),
                self.identity.destination_service_id.to_string(),
            ),
            (
                HEADER_SOURCE_TRUST_DOMAIN.to_owned(),
                self.identity.source_trust_domain.to_string(),
            ),
            (
                HEADER_DESTINATION_TRUST_DOMAIN.to_owned(),
                self.identity.destination_trust_domain.to_string(),
            ),
        ];

        let mut covered = vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header(SOURCE_SERVICE_ID_HEADER.to_ascii_lowercase()),
            Component::Header(DESTINATION_SERVICE_ID_HEADER.to_ascii_lowercase()),
            Component::Header(HEADER_SOURCE_TRUST_DOMAIN.to_ascii_lowercase()),
            Component::Header(HEADER_DESTINATION_TRUST_DOMAIN.to_ascii_lowercase()),
        ];

        let body_digest =
            body.map(|bytes| ContentDigest::compute(bytes, ContentDigestAlgorithm::Sha256));
        if let Some(digest) = &body_digest {
            headers.push(("Content-Digest".to_owned(), digest.wire_value.clone()));
            covered.push(Component::Header("content-digest".to_owned()));
        }

        if let Some(key) = idempotency_key.filter(|key| !key.trim().is_empty()) {
            headers.push(("Idempotency-Key".to_owned(), key.to_owned()));
            covered.push(Component::Header("idempotency-key".to_owned()));
        }

        let signer = ed25519_signer(self.keystore)?;
        let created = chrono::Utc::now().timestamp();
        let expires = created.saturating_add(SIGNATURE_WINDOW_SECONDS);
        let covered_wire = covered
            .iter()
            .map(|component| format!("\"{}\"", component.canonical_name()))
            .collect::<Vec<_>>()
            .join(" ");
        let signature_input_header = format!(
            "{SIGNATURE_LABEL}=({covered_wire});created={created};expires={expires};keyid=\"{}#{}\";alg=\"ed25519\"",
            self.identity.source_service_id,
            super::service_identity::SERVICE_IDENTITY_VERIFICATION_METHOD_FRAGMENT
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
        let signature = arkret_canonical::base64url::base64_standard_encode(&sig_bytes);
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

fn ed25519_signer(
    keystore: &Keystore,
) -> Result<std::sync::Arc<coauth_jose::jwa::AsymmetricSigningKey>, PeerProtocolClientError> {
    let key = keystore
        .signing_key_for_algorithm(&JsonWebSignatureAlg::Ed25519)
        .ok_or(PeerProtocolClientError::NoSigningKey)?;
    key.kid()
        .filter(|kid| !kid.trim().is_empty())
        .ok_or(PeerProtocolClientError::NoSigningKey)?;
    keystore
        .signer_for_algorithm(&JsonWebSignatureAlg::Ed25519)
        .map_err(|_| PeerProtocolClientError::NoSigningKey)
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

    fn peer_identity() -> PeerKeyPackagesClaimTransportBinding {
        let service_id = arkret_identifiers::Did::new("did:web:auth.example").unwrap();
        let trust_domain =
            arkret_identifiers::TypedTrustDomainId::new("ak:trust_domain:auth.example").unwrap();
        PeerKeyPackagesClaimTransportBinding {
            source_service_id: service_id.clone(),
            destination_service_id: service_id,
            source_trust_domain: trust_domain.clone(),
            destination_trust_domain: trust_domain,
        }
    }

    #[test]
    fn signed_post_covers_peer_service_headers_and_content_digest() {
        let base = Url::parse("https://server.example/").unwrap();
        let client = reqwest::Client::new();
        let keystore = test_keystore();
        let identity = peer_identity();
        let peer = PeerProtocolClient::new(Some(&base), &client, &keystore, identity).unwrap();
        let body = br#"{"a":1}"#;
        let url = base.join("/_arkret/peer/invites").unwrap();

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

        assert_eq!(header("Source-Service-ID"), Some("did:web:auth.example"));
        assert!(header("Content-Digest").is_some());
        assert!(
            header("Signature-Input")
                .unwrap()
                .contains("content-digest")
        );
        assert!(
            !header("Signature-Input")
                .unwrap()
                .contains("request-canonical-digest")
        );
        assert!(
            header("Signature-Input")
                .unwrap()
                .contains("keyid=\"did:web:auth.example#service-key\"")
        );
        assert!(header("Signature").unwrap().starts_with("sig1=:"));
    }

    #[test]
    fn signed_get_omits_body_digests() {
        let base = Url::parse("https://server.example/").unwrap();
        let client = reqwest::Client::new();
        let keystore = test_keystore();
        let identity = peer_identity();
        let peer = PeerProtocolClient::new(Some(&base), &client, &keystore, identity).unwrap();
        let url = base
            .join("/_arkret/peer/snapshot/head?realm_id=ak:realm:test")
            .unwrap();

        let signed = peer.signed_request("GET", &url, None, None).unwrap();

        assert!(
            signed
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("Content-Digest"))
        );
    }

    #[test]
    fn signed_query_covers_actual_method_target_and_content_digest() {
        let base = Url::parse("https://server.example/").unwrap();
        let client = reqwest::Client::new();
        let keystore = test_keystore();
        let identity = peer_identity();
        let peer = PeerProtocolClient::new(Some(&base), &client, &keystore, identity).unwrap();
        let url = base.join("/_arkret/peer/events/frontier").unwrap();
        let body = br#"{"realm_id":"ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K"}"#;

        let signed = peer
            .signed_request("QUERY", &url, Some(body), None)
            .unwrap();
        let signature_input = signed
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Signature-Input"))
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert!(signature_input.contains("\"@method\""));
        assert!(signature_input.contains("\"@target-uri\""));
        assert!(signature_input.contains("\"content-digest\""));
        assert!(
            signed
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("Content-Digest"))
        );

        let query_parts = request_parts(
            "QUERY",
            &url,
            &signed.headers,
            Some(&ContentDigest::compute(
                body,
                ContentDigestAlgorithm::Sha256,
            )),
        );
        assert_eq!(query_parts.method, "QUERY");
        assert_eq!(query_parts.target_uri, url.as_str());
    }
}
