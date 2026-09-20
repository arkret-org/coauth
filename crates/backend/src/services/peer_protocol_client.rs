// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed client helpers for the Arkret `/_arkret/peer/*` protocol surface.

use std::time::Duration;

use arkret_canonical::canonical_json_bytes;
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusPublicationOutcome, AccountStatusPublicationRequestBody,
};
use arkret_models_collaboration::agent_operations::{
    AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentView,
};
use arkret_models_collaboration::governance::erasure::ErasureReceiptResource;
use arkret_models_collaboration::governance::invite_addressing::{
    InviteDeliveryOutcome, InviteDeliveryRequestBody,
};
use arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding;
use arkret_signatures::http_signature::{
    ContentDigest, ContentDigestAlgorithm, HTTP_SIGNATURE_MAX_LIFETIME_SECONDS,
    HttpSignatureScenario, SignedRequestParts, canonical_message, format_signature_header,
    http_signature_scenario_components, parse_signature_input,
};
use arkret_wire::{
    AuthorityBundleRequest, Did, HEADER_DESTINATION_TRUST_DOMAIN, HEADER_SOURCE_TRUST_DOMAIN,
    RealmAuthorityBundle, ServiceOperationId,
};
use coauth_keyring::Keyring;
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
    /// The implementation-private Station-TCB channel is not completely
    /// configured. Never a reason to guess the peer or call anonymously.
    #[error("deployment-internal authenticated channel is not configured: {0}")]
    InternalChannelNotConfigured(String),
}

pub struct PeerProtocolClient<'a> {
    base_url: &'a Url,
    http_client: &'a reqwest::Client,
    keyring: &'a Keyring,
    source_did: Did,
    identity: KeyPackagesClaimServiceBinding,
    source_trust_domain: arkret_identifiers::TrustDomainId,
    destination_trust_domain: arkret_identifiers::TrustDomainId,
}

impl<'a> PeerProtocolClient<'a> {
    pub fn new(
        base_url: Option<&'a Url>,
        http_client: &'a reqwest::Client,
        keyring: &'a Keyring,
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
            keyring,
            source_did,
            identity,
            source_trust_domain,
            destination_trust_domain,
        })
    }

    /// Build the signed service client for this Account Authority's one
    /// explicitly configured owning Station.
    ///
    /// A split Account Authority has no independent service identity: it
    /// signs as the owning Station with the Station DID's delegated
    /// `#account-authority` assertion method. Both service ids and both trust
    /// domains therefore come only from the verified runtime identity and
    /// explicit peer configuration. Missing or conflicting facts fail closed.
    pub fn new_for_owning_station(
        arkret_config: &'a coauth_config::ArkretConfig,
        http_client: &'a reqwest::Client,
        keyring: &'a Keyring,
    ) -> Result<Self, PeerProtocolClientError> {
        let target = arkret_config.owning_station().ok_or_else(|| {
            PeerProtocolClientError::InvalidUrl(
                "owning Station peer is not explicitly selected".to_owned(),
            )
        })?;
        let delegated = arkret_config
            .runtime_owning_station_identity
            .get()
            .ok_or_else(|| {
                PeerProtocolClientError::InvalidUrl(
                    "owning Station identity is not verified".to_owned(),
                )
            })?;
        let destination_id = delegated.station_id.clone();
        let source_trust_domain = arkret_identifiers::TrustDomainId::new(
            arkret_config
                .trust_domain
                .as_deref()
                .ok_or_else(|| {
                    PeerProtocolClientError::InvalidUrl(
                        "Account Authority trust_domain is not configured".to_owned(),
                    )
                })?
                .to_owned(),
        )
        .map_err(|error| PeerProtocolClientError::InvalidUrl(error.to_string()))?;
        let destination_trust_domain = arkret_identifiers::TrustDomainId::new(
            target
                .trust_domain
                .as_deref()
                .ok_or_else(|| {
                    PeerProtocolClientError::InvalidUrl(
                        "owning Station trust_domain is not configured".to_owned(),
                    )
                })?
                .to_owned(),
        )
        .map_err(|error| PeerProtocolClientError::InvalidUrl(error.to_string()))?;
        Self::new(
            Some(&target.endpoint),
            http_client,
            keyring,
            delegated.did,
            KeyPackagesClaimServiceBinding {
                source_id: delegated.station_id,
                destination_id,
            },
            source_trust_domain,
            destination_trust_domain,
        )
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

    /// Read the owning Station's exact Agent projection using the ordinary
    /// RFC 9421 service contract. This is not one of the four deployment
    /// bearer operations in §2.2.3.
    pub async fn get_agent_projection(
        &self,
        agent_id: &arkret_identifiers::DidCoreId,
    ) -> Result<AgentView, PeerProtocolClientError> {
        let mut url = self.join_absolute("/_arkret/self/agents/")?;
        url.path_segments_mut()
            .map_err(|_| {
                PeerProtocolClientError::InvalidUrl(
                    "owning Station endpoint cannot carry path segments".to_owned(),
                )
            })?
            .push(agent_id.as_str());
        self.get_json(
            "self_agent_resource_get",
            url,
            ServiceOperationId::SELF_AGENT_RESOURCE_GET_V1,
        )
        .await
    }

    /// Delegate the exact durable Agent pairing command to its authoritative
    /// owning Station using the ordinary RFC 9421 service contract.
    pub async fn post_agent_key_pair(
        &self,
        request: &AgentKeyPairRequestBody,
        idempotency_key: &str,
    ) -> Result<AgentKeyPairOutcome, PeerProtocolClientError> {
        let url = self.join_absolute("/_arkret/gate/account/agent-key-pair")?;
        self.post_json(
            "gate_account_pair_agent_key",
            url,
            ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
            request,
            Some(idempotency_key),
        )
        .await
    }

    /// Resolve the nonce-bound current authority chain from the exact owning
    /// Station before freezing an external-effect request. The response is
    /// only a carrier here; callers must run the SDK cryptographic verifier.
    pub async fn get_realm_authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
    ) -> Result<RealmAuthorityBundle, PeerProtocolClientError> {
        request
            .validate()
            .map_err(|error| PeerProtocolClientError::Canonical(error.to_string()))?;
        let url = self.join_absolute("/_arkret/open/realm-authority/bundle")?;
        let outcome: RealmAuthorityBundle = self
            .post_json(
                "open_realm_authority_bundle",
                url,
                ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1,
                request,
                None,
            )
            .await?;
        outcome
            .validate_for_request(request, chrono::Utc::now())
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

        let body_digest =
            body.map(|bytes| ContentDigest::compute(bytes, ContentDigestAlgorithm::Sha256));
        let mut applicable_components = vec!["source-trust-domain", "destination-trust-domain"];
        if let Some(digest) = &body_digest {
            headers.push(("Content-Digest".to_owned(), digest.wire_value.clone()));
            applicable_components.push("content-digest");
        }

        if let Some(key) = idempotency_key.filter(|key| !key.trim().is_empty()) {
            headers.push(("Idempotency-Key".to_owned(), key.to_owned()));
            applicable_components.push("idempotency-key");
        }
        let covered = http_signature_scenario_components(
            HttpSignatureScenario::ServiceToServiceV1,
            &applicable_components,
        )
        .map_err(|_| PeerProtocolClientError::Sign)?;

        let signer = ed25519_signer(self.keyring)?;
        let created = chrono::Utc::now().timestamp();
        let expires = created.saturating_add(HTTP_SIGNATURE_MAX_LIFETIME_SECONDS);
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

/// Implementation-private authenticated channel inside one Station TCB.
///
/// The configured Station origin and per-edge credential define this
/// deployment relationship. It has no Arkret operation identity and is never
/// advertised through Describe or protocol OpenAPI. Missing configuration
/// fails closed rather than falling back to discovery or an anonymous call.
pub struct InternalAuthorityChannel<'a> {
    base_url: &'a Url,
    http_client: &'a reqwest::Client,
    credential: &'a str,
    destination_service_id: arkret_identifiers::DidCoreId,
}

impl<'a> InternalAuthorityChannel<'a> {
    /// Build the channel from already-resolved configuration values.
    ///
    /// `credential` is the deployment credential configured for this exact
    /// Account Authority / Station edge. An absent or blank credential is a
    /// configuration gap, not a permission to call the peer unauthenticated.
    pub fn new(
        base_url: &'a Url,
        http_client: &'a reqwest::Client,
        credential: Option<&'a str>,
        destination_service_id: arkret_identifiers::DidCoreId,
    ) -> Result<Self, PeerProtocolClientError> {
        let credential = credential
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                PeerProtocolClientError::InternalChannelNotConfigured(format!(
                    "no channel credential is configured for {destination_service_id}"
                ))
            })?;
        Ok(Self {
            base_url,
            http_client,
            credential,
            destination_service_id,
        })
    }

    /// The configured target service identity of this channel.
    ///
    /// Consumers compare an authenticated outcome against this value; they
    /// never learn the peer's identity from the outcome itself.
    #[must_use]
    pub fn destination_service_id(&self) -> &arkret_identifiers::DidCoreId {
        &self.destination_service_id
    }

    /// POST one implementation-private Station-TCB intent. The configured
    /// origin and per-edge credential supply the boundary; no Arkret operation
    /// selector or service-signature scenario is involved.
    pub(crate) async fn post_private_json<T, R>(
        &self,
        policy_name: &'static str,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, PeerProtocolClientError>
    where
        T: Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = self
            .base_url
            .join(path)
            .map_err(|error| PeerProtocolClientError::InvalidUrl(error.to_string()))?;
        let body_bytes = canonical_json_bytes(body)
            .map_err(|error| PeerProtocolClientError::Canonical(error.to_string()))?;
        let response = outbound_http::send_with_policy(
            outbound_http::soland_policy(policy_name).with_timeout(Duration::from_secs(5)),
            || {
                let mut request = self
                    .http_client
                    .post(url.clone())
                    .bearer_auth(self.credential)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body_bytes.clone());
                if let Some(key) = idempotency_key {
                    request = request.header("Idempotency-Key", key);
                }
                request
            },
        )
        .await
        .map_err(|error| PeerProtocolClientError::Http(error.to_string()))?;

        parse_json_response(response).await
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
    keyring: &Keyring,
) -> Result<std::sync::Arc<coauth_jose::jwa::AsymmetricSigningKey>, PeerProtocolClientError> {
    keyring
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
    use coauth_keyring::{ACCOUNT_AUTHORITY_KEY_ID, JsonWebKey, JsonWebKeySet, PrivateKey};
    use rand_chacha::rand_core::SeedableRng;

    use super::*;

    fn test_keyring() -> Keyring {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(7);
        let service_key = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid(ACCOUNT_AUTHORITY_KEY_ID);
        let unrelated_device_key = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid("device-enrollment-key");
        Keyring::new(JsonWebKeySet::new(vec![service_key, unrelated_device_key]))
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
        let keyring = test_keyring();
        let identity = peer_identity();
        let peer = PeerProtocolClient::new(
            Some(&base),
            &client,
            &keyring,
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

        let service_key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(
            &keyring.account_authority_seed().unwrap(),
        );
        let policy = arkret_signatures::http_signature::SignatureVerificationPolicy::for_scenario(
            HttpSignatureScenario::ServiceToServiceV1,
            &[
                "content-digest",
                "source-trust-domain",
                "destination-trust-domain",
                "idempotency-key",
            ],
        )
        .expect("service-to-service signing components are registry-generated");
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
        let keyring = test_keyring();
        let identity = peer_identity();
        let peer = PeerProtocolClient::new(
            Some(&base),
            &client,
            &keyring,
            source_did(),
            identity,
            trust_domain(),
            trust_domain(),
        )
        .unwrap();
        let url = base.join("/_arkret/peer/streams/scan").unwrap();
        let body = br#"{"realm_id":"ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K"}"#;

        let signed = peer
            .signed_request(
                "QUERY",
                &url,
                ServiceOperationId::PEER_COMMITTED_EVENT_READ_SCAN_V1,
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
