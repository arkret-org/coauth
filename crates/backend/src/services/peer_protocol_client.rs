// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed client helpers for the Arkret `/_arkret/peer/*` protocol surface.

use std::time::Duration;

use arkret_canonical::canonical_json_bytes;
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusPublicationOutcome, AccountStatusPublicationRequestBody,
};
use arkret_models_collaboration::governance::erasure::ErasureReceiptResource;
use arkret_models_collaboration::governance::invite_addressing::{
    InviteDeliveryOutcome, InviteDeliveryRequestBody,
};
use arkret_models_collaboration::principal_operations::{
    PcrGenesisSubmitOutcome, PcrGenesisSubmitRequestBody,
};
use arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding;
use arkret_signatures::http_signature::{
    Component, ContentDigest, ContentDigestAlgorithm, SignedRequestParts, canonical_message,
    format_signature_header, parse_signature_input,
};
use arkret_wire::{
    DeviceRevocationGateCheckOutcome, DeviceRevocationGateCheckRequestBody, Did,
    HEADER_DESTINATION_TRUST_DOMAIN, HEADER_SOURCE_TRUST_DOMAIN,
    PATH_PEER_DEVICE_REVOCATIONS_CHECK, ServiceOperationId,
};
use coauth_keystore::Keystore;
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::outbound_http;

const SIGNATURE_LABEL: &str = "sig1";
/// The fragment the owning Station authorizes this Account Authority under.
/// Every proof coauth issues as the Station names `{station_did}#<this>`;
/// the SDK owns the spelling so Station and Authority cannot drift.
pub(crate) const ACCOUNT_AUTHORITY_VERIFICATION_METHOD_FRAGMENT: &str =
    arkret_models_identity::service_identity::ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT;
const SIGNATURE_WINDOW_SECONDS: i64 = 300;
const SOURCE_SERVICE_ID_HEADER: &str = "Source-Service-ID";
const DESTINATION_SERVICE_ID_HEADER: &str = "Destination-Service-ID";
const ARKRET_OPERATION_HEADER: &str = "Arkret-Operation";

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
    #[error(
        "peer protocol server returned status {status}{problem_suffix}",
        problem_suffix = problem
            .as_ref()
            .map(|problem| format!(": {}: {}", problem.code(), problem.detail))
            .unwrap_or_default()
    )]
    Status {
        status: u16,
        // Boxed: `Problem` is by far the widest thing this enum carries, and
        // every peer call returns `Result<_, PeerProtocolClientError>`, so an
        // inline copy makes the whole federation path move it on the happy
        // path too.
        problem: Option<Box<arkret_wire::Problem>>,
    },
    #[error("peer protocol response body invalid: {0}")]
    Response(String),
}

pub struct PeerProtocolClient<'a> {
    base_url: &'a Url,
    http_client: &'a reqwest::Client,
    keystore: &'a Keystore,
    source_did: Did,
    identity: KeyPackagesClaimServiceBinding,
    source_trust_domain: arkret_identifiers::TrustDomainId,
    destination_trust_domain: arkret_identifiers::TrustDomainId,
}

impl<'a> PeerProtocolClient<'a> {
    pub fn new(
        base_url: Option<&'a Url>,
        http_client: &'a reqwest::Client,
        keystore: &'a Keystore,
        source_did: Did,
        identity: KeyPackagesClaimServiceBinding,
        source_trust_domain: arkret_identifiers::TrustDomainId,
        destination_trust_domain: arkret_identifiers::TrustDomainId,
    ) -> Result<Self, PeerProtocolClientError> {
        let Some(base_url) = base_url else {
            return Err(PeerProtocolClientError::BaseUrlNotConfigured);
        };
        let projected = arkret_identifiers::project_did_to_core_id(&source_did)
            .map_err(|error| PeerProtocolClientError::InvalidUrl(error.to_string()))?;
        if projected.as_str() != identity.source_id.as_str() {
            return Err(PeerProtocolClientError::InvalidUrl(
                "source service did does not project to Source-Service-ID".to_owned(),
            ));
        }
        Ok(Self {
            base_url,
            http_client,
            keystore,
            source_did,
            identity,
            source_trust_domain,
            destination_trust_domain,
        })
    }

    pub async fn post_invite_delivery(
        &self,
        request: &InviteDeliveryRequestBody,
    ) -> Result<InviteDeliveryOutcome, PeerProtocolClientError> {
        let url = self.join_absolute("/_arkret/peer/invites")?;
        self.post_json(
            "peer_invites_submit",
            url,
            ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT_V1,
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
            ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1,
            request,
            Some(idempotency_key),
        )
        .await
    }

    pub async fn get_erasure_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<ErasureReceiptResource, PeerProtocolClientError> {
        let url = self.join_absolute(&format!("/_arkret/peer/erasure-receipts/{receipt_id}"))?;
        self.get_json(
            "peer_erasure_receipt_get",
            url,
            ServiceOperationId::PEER_ERASURE_RECEIPT_RESOURCE_GET_V1,
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
                ServiceOperationId::PEER_PRINCIPAL_GENESIS_COMMAND_SUBMIT_V1,
                request,
                Some(request.idempotency_key.as_str()),
            )
            .await?;
        outcome
            .validate_against(request)
            .map_err(|error| PeerProtocolClientError::Response(error.to_string()))?;
        Ok(outcome)
    }

    /// Linearize one exact session-grant issue or refresh intent against the
    /// origin Station's durable device-revocation state.
    pub async fn post_device_revocation_gate_check(
        &self,
        request: &DeviceRevocationGateCheckRequestBody,
    ) -> Result<DeviceRevocationGateCheckOutcome, PeerProtocolClientError> {
        request
            .validate()
            .map_err(|error| PeerProtocolClientError::Canonical(error.to_string()))?;
        let url = self.join_absolute(PATH_PEER_DEVICE_REVOCATIONS_CHECK)?;
        let outcome: DeviceRevocationGateCheckOutcome = self
            .post_json(
                "peer_device_revocations_check",
                url,
                ServiceOperationId::PEER_DEVICE_REVOCATIONS_COMMAND_CHECK_V1,
                request,
                None,
            )
            .await?;
        outcome
            .validate_for_request(request)
            .map_err(|error| PeerProtocolClientError::Response(error.to_string()))?;
        Ok(outcome)
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
        operation_id: &str,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, PeerProtocolClientError>
    where
        T: Serialize,
        R: serde::de::DeserializeOwned,
    {
        let body_bytes = canonical_json_bytes(body)
            .map_err(|error| PeerProtocolClientError::Canonical(error.to_string()))?;
        let signed = self.signed_request(
            "POST",
            &url,
            operation_id,
            Some(&body_bytes),
            idempotency_key,
        )?;

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

    async fn get_json<R>(
        &self,
        policy_name: &'static str,
        url: Url,
        operation_id: &str,
    ) -> Result<R, PeerProtocolClientError>
    where
        R: serde::de::DeserializeOwned,
    {
        let signed = self.signed_request("GET", &url, operation_id, None, None)?;
        let response = outbound_http::send_with_policy(
            outbound_http::soland_policy(policy_name).with_timeout(Duration::from_secs(5)),
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

    fn signed_request(
        &self,
        method: &str,
        url: &Url,
        operation_id: &str,
        body: Option<&[u8]>,
        idempotency_key: Option<&str>,
    ) -> Result<SignedPeerRequest, PeerProtocolClientError> {
        let mut headers = vec![
            (
                SOURCE_SERVICE_ID_HEADER.to_owned(),
                self.identity.source_id.to_string(),
            ),
            (
                DESTINATION_SERVICE_ID_HEADER.to_owned(),
                self.identity.destination_id.to_string(),
            ),
            (
                HEADER_SOURCE_TRUST_DOMAIN.to_owned(),
                self.source_trust_domain.to_string(),
            ),
            (
                HEADER_DESTINATION_TRUST_DOMAIN.to_owned(),
                self.destination_trust_domain.to_string(),
            ),
            (ARKRET_OPERATION_HEADER.to_owned(), operation_id.to_owned()),
        ];

        let mut covered = vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header(SOURCE_SERVICE_ID_HEADER.to_ascii_lowercase()),
            Component::Header(DESTINATION_SERVICE_ID_HEADER.to_ascii_lowercase()),
            Component::Header(HEADER_SOURCE_TRUST_DOMAIN.to_ascii_lowercase()),
            Component::Header(HEADER_DESTINATION_TRUST_DOMAIN.to_ascii_lowercase()),
            Component::Header(ARKRET_OPERATION_HEADER.to_ascii_lowercase()),
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
            self.source_did, ACCOUNT_AUTHORITY_VERIFICATION_METHOD_FRAGMENT
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
    keystore
        .account_authority_signer()
        .map_err(|_| PeerProtocolClientError::NoSigningKey)
}

async fn parse_json_response<R>(response: reqwest::Response) -> Result<R, PeerProtocolClientError>
where
    R: serde::de::DeserializeOwned,
{
    let status = response.status();
    if !status.is_success() {
        let problem = response
            .json::<arkret_wire::Problem>()
            .await
            .ok()
            .filter(|problem| problem.status == status.as_u16())
            .map(Box::new);
        return Err(PeerProtocolClientError::Status {
            status: status.as_u16(),
            problem,
        });
    }
    response
        .json()
        .await
        .map_err(|error| PeerProtocolClientError::Response(error.to_string()))
}

#[cfg(test)]
mod tests {
    use coauth_keystore::{ACCOUNT_AUTHORITY_KEY_ID, JsonWebKey, JsonWebKeySet, PrivateKey};
    use rand_chacha::rand_core::SeedableRng;

    use super::*;

    fn test_keystore() -> Keystore {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(7);
        let service_key = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid(ACCOUNT_AUTHORITY_KEY_ID);
        let unrelated_device_key = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid("device-enrollment-key");
        Keystore::new(JsonWebKeySet::new(vec![service_key, unrelated_device_key]))
    }

    fn peer_identity() -> KeyPackagesClaimServiceBinding {
        let service_id =
            arkret_identifiers::DidCoreId::new("ak:did_core:web:auth.example".to_owned()).unwrap();
        KeyPackagesClaimServiceBinding {
            source_id: service_id.clone(),
            destination_id: service_id,
        }
    }

    fn source_did() -> arkret_identifiers::Did {
        arkret_identifiers::Did::new("did:web:auth.example".to_owned()).unwrap()
    }

    fn trust_domain() -> arkret_identifiers::TrustDomainId {
        arkret_identifiers::TrustDomainId::new("ak:trust_domain:auth.example".to_owned()).unwrap()
    }

    #[test]
    fn signed_post_covers_peer_service_headers_and_content_digest() {
        let base = Url::parse("https://server.example/").unwrap();
        let client = reqwest::Client::new();
        let keystore = test_keystore();
        let identity = peer_identity();
        let peer = PeerProtocolClient::new(
            Some(&base),
            &client,
            &keystore,
            source_did(),
            identity,
            trust_domain(),
            trust_domain(),
        )
        .unwrap();
        let body = br#"{"a":1}"#;
        let url = base.join("/_arkret/peer/invites").unwrap();

        let signed = peer
            .signed_request(
                "POST",
                &url,
                ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT_V1,
                Some(body),
                Some("idem-1"),
            )
            .unwrap();
        let header = |name: &str| {
            signed
                .headers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };

        assert_eq!(
            header("Source-Service-ID"),
            Some("ak:did_core:web:auth.example")
        );
        assert_eq!(
            header("Arkret-Operation"),
            Some(ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT_V1)
        );
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
                .contains("keyid=\"did:web:auth.example#account-authority\"")
        );
        assert!(header("Signature").unwrap().starts_with("sig1=:"));

        let service_key =
            ed25519_dalek_3::SigningKey::from_bytes(&keystore.account_authority_seed().unwrap());
        let policy = arkret_signatures::http_signature::SignatureVerificationPolicy::new(vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header("source-service-id".to_owned()),
            Component::Header("destination-service-id".to_owned()),
            Component::Header("source-trust-domain".to_owned()),
            Component::Header("destination-trust-domain".to_owned()),
            Component::Header("arkret-operation".to_owned()),
            Component::Header("content-digest".to_owned()),
            Component::Header("idempotency-key".to_owned()),
        ])
        .require_content_digest(true);
        arkret_signatures::http_signature::verify_signed_http_message(
            "POST",
            url.as_str(),
            "server.example",
            url.path(),
            signed
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            body,
            &service_key.verifying_key(),
            &policy,
            chrono::Utc::now().timestamp(),
        )
        .expect("peer HTTP signature must verify with the Account Authority key");
    }

    #[test]
    fn signed_query_covers_actual_method_target_and_content_digest() {
        let base = Url::parse("https://server.example/").unwrap();
        let client = reqwest::Client::new();
        let keystore = test_keystore();
        let identity = peer_identity();
        let peer = PeerProtocolClient::new(
            Some(&base),
            &client,
            &keystore,
            source_did(),
            identity,
            trust_domain(),
            trust_domain(),
        )
        .unwrap();
        let url = base.join("/_arkret/peer/events/frontier").unwrap();
        let body = br#"{"realm_id":"ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K"}"#;

        let signed = peer
            .signed_request(
                "QUERY",
                &url,
                ServiceOperationId::PEER_EVENTS_READ_FRONTIER_V1,
                Some(body),
                None,
            )
            .unwrap();
        let signature_input = signed
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Signature-Input"))
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert!(signature_input.contains("\"@method\""));
        assert!(signature_input.contains("\"@target-uri\""));
        assert!(signature_input.contains("\"arkret-operation\""));
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
