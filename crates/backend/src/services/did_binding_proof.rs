//! Shared DID-signature verification and the canonical published-DID account
//! registration control proof.

use arkret_signatures::proof::verify_detached_ed25519_signature;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::{DateTime, Utc};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::jwt::JsonWebSignatureHeader;
use thiserror::Error;

use crate::services::did_resolver::DidResolution;

#[derive(Debug, Error)]
pub enum DidBindingProofError {
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    #[error("control proof shape is invalid: {0}")]
    InvalidShape(String),
    #[error("control proof does not match its durable challenge: {0}")]
    ChallengeMismatch(&'static str),
    #[error("control proof method-native resolution pins do not match")]
    ResolutionPinsMismatch,
    #[error("control proof verification method is absent from the resolved DID document")]
    VerificationMethodNotFound,
    #[error("control proof signature is invalid")]
    SignatureMismatch,
    #[error("control proof is expired")]
    Expired,
    #[error("DID authority binding failed: {0}")]
    Binding(#[from] crate::services::did_binding::DidBindingError),
}

pub fn normalize_did_for_binding(did: &str) -> Result<String, DidBindingProofError> {
    let parsed = arkret_identifiers::Did::new(did.trim().to_owned())
        .map_err(|error| DidBindingProofError::InvalidDid(error.to_string()))?;
    if parsed.as_str().starts_with("did:uuid:") {
        return Err(DidBindingProofError::InvalidDid(
            "did:uuid is not a resolvable controller DID".to_owned(),
        ));
    }
    Ok(parsed.to_string())
}

#[allow(clippy::too_many_arguments)]
pub fn validate_account_registration_control_proof(
    proof: &arkret_models_identity::AccountRegistrationControlProof,
    challenge: &coauth_data::DidBindingChallengeRecord,
    resolution: &DidResolution,
    expected_local_account_id: coauth_data::Ulid,
    expected_account_subject: &arkret_identifiers::Hash,
    expected_audience: &arkret_identifiers::DidCoreId,
    expected_origin: &str,
    expected_trust_domain: &arkret_identifiers::TrustDomainId,
    expected_dpop_jkt: &str,
    now: DateTime<Utc>,
) -> Result<(), DidBindingProofError> {
    proof
        .validate_shape()
        .map_err(|error| DidBindingProofError::InvalidShape(error.to_string()))?;
    let stored = &challenge.input;
    if stored.local_account_id != expected_local_account_id
        || &stored.account_subject != expected_account_subject
    {
        return Err(DidBindingProofError::ChallengeMismatch("account"));
    }
    if proof.challenge_id != stored.challenge_id
        || proof.challenge != stored.challenge
        || proof.purpose != arkret_models_identity::DidBindingPurpose::AccountBindingForPublishedDid
        || proof.request_canonical_digest != stored.request_digest
        || proof.account_subject != stored.account_subject
        || proof.principal_id != stored.principal_id
        || proof.did != stored.did
        || proof.did_version_id != stored.did_version_id
        || proof.log_head_digest != stored.log_head_digest
        || proof.control_key_digest != stored.control_key_digest
        || proof.dpop_jkt != stored.dpop_jkt
        || proof.audience_id != stored.audience_id
        || proof.origin != stored.origin
        || proof.trust_domain != stored.trust_domain
        || proof.issued_at != stored.issued_at
        || proof.expires_at != stored.expires_at
        || proof.witness_evidence != stored.witness_evidence
    {
        return Err(DidBindingProofError::ChallengeMismatch("transcript"));
    }
    if &proof.audience_id != expected_audience
        || proof.origin.as_str() != expected_origin
        || &proof.trust_domain != expected_trust_domain
        || proof.dpop_jkt != expected_dpop_jkt
    {
        return Err(DidBindingProofError::ChallengeMismatch("receiver binding"));
    }
    if now >= proof.expires_at {
        return Err(DidBindingProofError::Expired);
    }
    let Some(arkret_models_identity::IdentityMethodEvidence::DidWebvh {
        version_id,
        log_head_digest,
        control_key_digest,
    }) = resolution.closed_method_evidence.as_ref()
    else {
        return Err(DidBindingProofError::ResolutionPinsMismatch);
    };
    if version_id.as_str() != proof.did_version_id
        || log_head_digest != &proof.log_head_digest
        || control_key_digest != &proof.control_key_digest
        || resolution.document.id != proof.did.as_str()
    {
        return Err(DidBindingProofError::ResolutionPinsMismatch);
    }
    let method = resolution
        .document
        .verification_method
        .iter()
        .find(|method| method.id == proof.verification_method.as_str())
        .ok_or(DidBindingProofError::VerificationMethodNotFound)?;
    let material = method
        .public_key_material()
        .map_err(DidBindingProofError::InvalidShape)?;
    let raw_verification_key = material
        .ed25519_bytes()
        .map_err(|error| DidBindingProofError::InvalidShape(error.to_string()))?;
    let method_key_digest = arkret_identifiers::Hash::new(format!(
        "sha256:{}",
        arkret_canonical::sha256_hex(raw_verification_key)
    ))
    .map_err(|error| DidBindingProofError::InvalidShape(error.to_string()))?;
    if method_key_digest != proof.control_key_digest {
        return Err(DidBindingProofError::ResolutionPinsMismatch);
    }
    let signing_bytes = proof
        .canonical_signing_bytes()
        .map_err(|error| DidBindingProofError::InvalidShape(error.to_string()))?;
    if !verify_detached_ed25519_signature(&material, &signing_bytes, &proof.signature) {
        return Err(DidBindingProofError::SignatureMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum SdkJwsVerifyError {
    #[error("compact JWS shape is invalid: {0}")]
    InvalidShape(String),
    #[error("compact JWS alg must be Ed25519, got {0}")]
    UnsupportedAlgorithm(String),
    #[error("verification_method '{0}' not present in the resolved DID document")]
    MethodNotFound(String),
    #[error("resolved verification_method JWK is not a supported Ed25519 key: {0}")]
    UnsupportedJwk(String),
    #[error("Ed25519 signature did not verify")]
    SignatureMismatch,
    #[error("detached JWS verification failed: {0}")]
    VerificationFailed(String),
    #[error("detached JWS protected kid '{0}' does not match the outer verification_method")]
    KeyIdMismatch(String),
}

fn verify_compact_jws_with_sdk(
    proof_jws: &str,
    verification_methods: &[crate::handlers::arkret::VerificationMethod],
    verification_method_id: &str,
) -> Result<(), SdkJwsVerifyError> {
    let mut parts = proof_jws.split('.');
    let header_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing protected header".to_owned()))?;
    let payload_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing payload".to_owned()))?;
    let signature_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing signature".to_owned()))?;
    if parts.next().is_some() {
        return Err(SdkJwsVerifyError::InvalidShape(
            "too many segments".to_owned(),
        ));
    }
    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64u)
        .map_err(|error| SdkJwsVerifyError::InvalidShape(error.to_string()))?;
    let header: JsonWebSignatureHeader = serde_json::from_slice(&header_bytes)
        .map_err(|error| SdkJwsVerifyError::InvalidShape(error.to_string()))?;
    if header.alg() != &JsonWebSignatureAlg::Ed25519 {
        return Err(SdkJwsVerifyError::UnsupportedAlgorithm(
            header.alg().to_string(),
        ));
    }
    let method = verification_methods
        .iter()
        .find(|method| method.id == verification_method_id)
        .ok_or_else(|| SdkJwsVerifyError::MethodNotFound(verification_method_id.to_owned()))?;
    let material = method
        .public_key_material()
        .map_err(SdkJwsVerifyError::UnsupportedJwk)?;
    let signing_input = format!("{header_b64u}.{payload_b64u}");
    if verify_detached_ed25519_signature(&material, signing_input.as_bytes(), signature_b64u) {
        Ok(())
    } else {
        Err(SdkJwsVerifyError::SignatureMismatch)
    }
}

pub(crate) fn verify_detached_jws_with_sdk(
    detached_jws: &str,
    payload_bytes: &[u8],
    verification_methods: &[crate::handlers::arkret::VerificationMethod],
) -> Result<String, SdkJwsVerifyError> {
    let mut parts = detached_jws.split('.');
    let header_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing protected header".to_owned()))?;
    let payload_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing payload".to_owned()))?;
    let signature_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing signature".to_owned()))?;
    if parts.next().is_some() || !payload_b64u.is_empty() {
        return Err(SdkJwsVerifyError::InvalidShape(
            "detached JWS must contain exactly protected..signature".to_owned(),
        ));
    }
    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64u)
        .map_err(|error| SdkJwsVerifyError::InvalidShape(error.to_string()))?;
    let header: JsonWebSignatureHeader = serde_json::from_slice(&header_bytes)
        .map_err(|error| SdkJwsVerifyError::InvalidShape(error.to_string()))?;
    let verification_method = header
        .kid()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing kid".to_owned()))?
        .to_owned();
    let attached = format!(
        "{header_b64u}.{}.{signature_b64u}",
        Base64UrlUnpadded::encode_string(payload_bytes)
    );
    verify_compact_jws_with_sdk(&attached, verification_methods, &verification_method)?;
    Ok(verification_method)
}

/// Verify a detached Ed25519 JWS whose signing method is named by the outer
/// protocol field (`PayloadProof.verification_method`), not by a protected
/// `kid`. This is the spec profile for server-issued payload proofs such as
/// the device revocation gate decision receipt: the SDK signer
/// (`arkret_signatures::jws::sign_jws_ed25519`) emits the canonical
/// `{"alg":"Ed25519"}` header and the method id travels outside the JWS.
/// A protected `kid`, when present, MUST equal the outer verification_method.
pub(crate) fn verify_detached_jws_against_method(
    detached_jws: &str,
    payload_bytes: &[u8],
    verification_methods: &[crate::handlers::arkret::VerificationMethod],
    verification_method: &str,
) -> Result<(), SdkJwsVerifyError> {
    let method = verification_methods
        .iter()
        .find(|method| method.id == verification_method)
        .ok_or_else(|| SdkJwsVerifyError::MethodNotFound(verification_method.to_owned()))?;
    let material = method
        .public_key_material()
        .map_err(SdkJwsVerifyError::UnsupportedJwk)?;
    let verified = arkret_signatures::proof::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws_with_metadata(detached_jws, payload_bytes, &material)
        .map_err(|error| SdkJwsVerifyError::VerificationFailed(error.to_string()))?;
    if let Some(kid) = verified.key_id()
        && kid != verification_method
    {
        return Err(SdkJwsVerifyError::KeyIdMismatch(kid.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64ct::Base64UrlUnpadded;
    use ed25519_dalek::Signer as _;

    use super::*;

    fn fixture() -> (
        arkret_models_identity::AccountRegistrationControlProof,
        coauth_data::DidBindingChallengeRecord,
        DidResolution,
        coauth_data::Ulid,
        arkret_identifiers::Hash,
        arkret_identifiers::DidCoreId,
        arkret_identifiers::TrustDomainId,
    ) {
        let account_id = coauth_data::Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCM").unwrap();
        let grant_id = coauth_data::Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCN").unwrap();
        let did =
            arkret_identifiers::Did::new("did:webvh:QmTest:alice.example".to_owned()).unwrap();
        let principal_id = arkret_identifiers::project_did_to_core_id(&did).unwrap();
        let audience =
            arkret_identifiers::DidCoreId::new("ak:did_core:web:auth.example".to_owned()).unwrap();
        let trust_domain =
            arkret_identifiers::TrustDomainId::new("ak:trust_domain:auth.example".to_owned())
                .unwrap();
        let account_subject =
            arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let request_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let log_head_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap();
        let issued_at = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let expires_at = issued_at + chrono::Duration::minutes(5);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let control_key_digest = arkret_identifiers::Hash::new(format!(
            "sha256:{}",
            arkret_canonical::sha256_hex(signing_key.verifying_key().as_bytes())
        ))
        .unwrap();
        let verification_method =
            arkret_wire::DidUrl::new(format!("{}#update-key", did.as_str())).unwrap();
        let mut proof = arkret_models_identity::AccountRegistrationControlProof {
            proof_kind:
                arkret_models_identity::AccountRegistrationControlProofKind::DidBoundSignature,
            challenge_id: "challenge-id".to_owned(),
            challenge: "Y2hhbGxlbmdlLXdpdGgtMTI4LWJpdHM".to_owned(),
            purpose: arkret_models_identity::DidBindingPurpose::AccountBindingForPublishedDid,
            request_canonical_digest: request_digest.clone(),
            account_subject: account_subject.clone(),
            principal_id: principal_id.clone(),
            did: did.clone(),
            did_version_id: "2-QmHead".to_owned(),
            log_head_digest: log_head_digest.clone(),
            control_key_digest: control_key_digest.clone(),
            dpop_jkt: "dpop-thumbprint".to_owned(),
            audience_id: audience.clone(),
            origin: arkret_identifiers::WebOrigin::new("https://auth.example").unwrap(),
            trust_domain: trust_domain.clone(),
            issued_at,
            expires_at,
            verification_method: verification_method.clone(),
            witness_evidence: None,
            signature: "pending".to_owned(),
        };
        proof.signature = Base64UrlUnpadded::encode_string(
            &signing_key
                .sign(&proof.canonical_signing_bytes().unwrap())
                .to_bytes(),
        );
        let challenge = coauth_data::DidBindingChallengeRecord {
            input: coauth_data::DidBindingChallengeInput {
                request_id: arkret_identifiers::RequestId::new(
                    "ak:request:0196419b-0000-7000-8000-000000000001",
                )
                .unwrap(),
                request_digest,
                issuing_handoff_grant_id: grant_id,
                local_account_id: account_id,
                account_subject: account_subject.clone(),
                principal_id,
                did: did.clone(),
                did_version_id: proof.did_version_id.clone(),
                log_head_digest: log_head_digest.clone(),
                control_key_digest: control_key_digest.clone(),
                witness_evidence: None,
                challenge_id: proof.challenge_id.clone(),
                challenge: proof.challenge.clone(),
                dpop_jkt: proof.dpop_jkt.clone(),
                audience_id: audience.clone(),
                origin: proof.origin.clone(),
                trust_domain: trust_domain.clone(),
                issued_at,
                expires_at,
            },
            consumed_at: None,
            register_request_digest: None,
            register_outcome: None,
        };
        let public_key = Base64UrlUnpadded::encode_string(signing_key.verifying_key().as_bytes());
        let resolution = DidResolution {
            document: crate::handlers::arkret::DidDocument {
                id: did.to_string(),
                also_known_as: Vec::new(),
                verification_method: vec![
                    serde_json::from_value(serde_json::json!({
                        "id": verification_method,
                        "type": "JsonWebKey2020",
                        "controller": did,
                        "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": public_key}
                    }))
                    .unwrap(),
                ],
                authentication: Vec::new(),
                assertion_method: Vec::new(),
                service: Vec::new(),
                metadata: None,
            },
            source: crate::services::did_resolver::DidResolutionSource::DelegatedResolver,
            verified_local_binding: false,
            key_log_head: Some(log_head_digest.clone()),
            method_evidence: serde_json::json!({"kind": "did_webvh"}),
            closed_method_evidence: Some(
                arkret_models_identity::IdentityMethodEvidence::DidWebvh {
                    version_id: arkret_wire::NonEmptyString::new("2-QmHead").unwrap(),
                    log_head_digest,
                    control_key_digest,
                },
            ),
            identity_fact_rejection: None,
        };
        (
            proof,
            challenge,
            resolution,
            account_id,
            account_subject,
            audience,
            trust_domain,
        )
    }

    #[test]
    fn standard_control_proof_accepts_exact_challenge_and_resolution() {
        let (proof, challenge, resolution, account_id, subject, audience, trust_domain) = fixture();
        validate_account_registration_control_proof(
            &proof,
            &challenge,
            &resolution,
            account_id,
            &subject,
            &audience,
            "https://auth.example",
            &trust_domain,
            "dpop-thumbprint",
            proof.issued_at + chrono::Duration::seconds(1),
        )
        .unwrap();
    }

    #[test]
    fn standard_control_proof_rejects_pin_and_receiver_mismatch() {
        let (mut proof, challenge, resolution, account_id, subject, audience, trust_domain) =
            fixture();
        proof.control_key_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap();
        let error = validate_account_registration_control_proof(
            &proof,
            &challenge,
            &resolution,
            account_id,
            &subject,
            &audience,
            "https://auth.example",
            &trust_domain,
            "dpop-thumbprint",
            proof.issued_at + chrono::Duration::seconds(1),
        )
        .unwrap_err();
        assert!(matches!(error, DidBindingProofError::ChallengeMismatch(_)));
    }

    #[test]
    fn standard_control_proof_rejects_a_signed_method_that_is_not_the_pinned_update_key() {
        let (mut proof, mut challenge, mut resolution, account_id, subject, audience, trust_domain) =
            fixture();
        let unbound_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap();
        proof.control_key_digest = unbound_digest.clone();
        challenge.input.control_key_digest = unbound_digest.clone();
        resolution.closed_method_evidence =
            Some(arkret_models_identity::IdentityMethodEvidence::DidWebvh {
                version_id: arkret_wire::NonEmptyString::new("2-QmHead").unwrap(),
                log_head_digest: proof.log_head_digest.clone(),
                control_key_digest: unbound_digest,
            });
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        proof.signature = Base64UrlUnpadded::encode_string(
            &signing_key
                .sign(&proof.canonical_signing_bytes().unwrap())
                .to_bytes(),
        );

        let error = validate_account_registration_control_proof(
            &proof,
            &challenge,
            &resolution,
            account_id,
            &subject,
            &audience,
            "https://auth.example",
            &trust_domain,
            "dpop-thumbprint",
            proof.issued_at + chrono::Duration::seconds(1),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DidBindingProofError::ResolutionPinsMismatch
        ));
    }

    fn jwk_verification_method(
        id: &str,
        controller: &str,
        verifying_key: &[u8; 32],
    ) -> crate::handlers::arkret::VerificationMethod {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "type": "JsonWebKey2020",
            "controller": controller,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": Base64UrlUnpadded::encode_string(verifying_key),
            }
        }))
        .unwrap()
    }

    #[test]
    fn detached_jws_against_method_accepts_sdk_signed_kid_less_proof() {
        let signing_key = ed25519_dalek_3::SigningKey::from_bytes(&[7u8; 32]);
        let method_id = "did:webvh:QmTest:service.example#notary-key";
        let methods = vec![jwk_verification_method(
            method_id,
            "did:webvh:QmTest:service.example",
            &signing_key.verifying_key().to_bytes(),
        )];
        let payload = br#"{"context":"ak.proof.device_revocation_gate_decision.v1"}"#;
        // The exact signer the Station uses for gate receipts.
        let jws = arkret_signatures::jws::sign_jws_ed25519(payload, &signing_key).unwrap();
        verify_detached_jws_against_method(&jws, payload, &methods, method_id).unwrap();
    }

    #[test]
    fn detached_jws_against_method_rejects_unknown_method() {
        let signing_key = ed25519_dalek_3::SigningKey::from_bytes(&[8u8; 32]);
        let method_id = "did:webvh:QmTest:service.example#notary-key";
        let methods = vec![jwk_verification_method(
            method_id,
            "did:webvh:QmTest:service.example",
            &signing_key.verifying_key().to_bytes(),
        )];
        let payload = b"payload";
        let jws = arkret_signatures::jws::sign_jws_ed25519(payload, &signing_key).unwrap();
        let error = verify_detached_jws_against_method(
            &jws,
            payload,
            &methods,
            "did:webvh:QmTest:service.example#other-key",
        )
        .unwrap_err();
        assert!(matches!(error, SdkJwsVerifyError::MethodNotFound(_)));
    }

    #[test]
    fn detached_jws_against_method_rejects_tampered_payload() {
        let signing_key = ed25519_dalek_3::SigningKey::from_bytes(&[9u8; 32]);
        let method_id = "did:webvh:QmTest:service.example#notary-key";
        let methods = vec![jwk_verification_method(
            method_id,
            "did:webvh:QmTest:service.example",
            &signing_key.verifying_key().to_bytes(),
        )];
        let jws = arkret_signatures::jws::sign_jws_ed25519(b"payload", &signing_key).unwrap();
        assert!(
            verify_detached_jws_against_method(&jws, b"tampered", &methods, method_id).is_err()
        );
    }

    #[test]
    fn detached_jws_against_method_rejects_kid_that_disagrees_with_outer_method() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
        let method_id = "did:webvh:QmTest:service.example#notary-key";
        let methods = vec![jwk_verification_method(
            method_id,
            "did:webvh:QmTest:service.example",
            &signing_key.verifying_key().to_bytes(),
        )];
        let payload = b"payload";
        let sign_with_kid = |kid: &str| {
            let signing_input =
                arkret_signatures::proof::ed25519_detached_jws_signing_input(payload, Some(kid))
                    .unwrap();
            let signature = signing_key.sign(signing_input.as_bytes());
            arkret_signatures::proof::ed25519_detached_jws_from_signature(
                &signature.to_bytes(),
                Some(kid),
            )
            .unwrap()
        };
        // A matching kid is tolerated; a disagreeing kid fails closed.
        verify_detached_jws_against_method(&sign_with_kid(method_id), payload, &methods, method_id)
            .unwrap();
        let error = verify_detached_jws_against_method(
            &sign_with_kid("did:webvh:QmTest:service.example#other-key"),
            payload,
            &methods,
            method_id,
        )
        .unwrap_err();
        assert!(matches!(error, SdkJwsVerifyError::KeyIdMismatch(_)));
    }
}
