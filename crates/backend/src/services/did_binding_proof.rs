//! Shared DID-signature verification and the canonical published-DID account
//! registration control proof.

use arkret_signatures::proof::verify_detached_ed25519_signature;
use arkret_signatures::{Ed25519DetachedJwsVerifier, VerifierError};
use chrono::{DateTime, Utc};
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
    #[error("test_signing_material_denied")]
    TestSigningMaterialDenied,
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
        control_key_digest,
    }) = resolution.closed_method_evidence.as_ref()
    else {
        return Err(DidBindingProofError::ResolutionPinsMismatch);
    };
    if version_id.as_str() != proof.did_version_id
        || resolution.key_log_head.as_ref() != Some(&stored.log_head_digest)
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
    method
        .enforce_formal_key_admission(&resolution.document.id, Some(expected_trust_domain))
        .map_err(|error| match error {
            crate::handlers::arkret::FormalKeyAdmissionError::TestSigningMaterialDenied => {
                DidBindingProofError::TestSigningMaterialDenied
            }
            crate::handlers::arkret::FormalKeyAdmissionError::Invalid(message) => {
                DidBindingProofError::InvalidShape(message)
            }
        })?;
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
    #[error("verification_method '{0}' not present in the resolved DID document")]
    MethodNotFound(String),
    #[error("resolved verification_method JWK is not a supported Ed25519 key: {0}")]
    UnsupportedJwk(String),
    #[error("Ed25519 signature did not verify")]
    SignatureMismatch,
    #[error("test_signing_material_denied")]
    TestSigningMaterialDenied,
}

pub(crate) fn verify_detached_jws_with_sdk(
    detached_jws: &str,
    payload_bytes: &[u8],
    verification_methods: &[crate::handlers::arkret::VerificationMethod],
) -> Result<String, SdkJwsVerifyError> {
    let verifier = Ed25519DetachedJwsVerifier::new();
    let verification_method = verifier
        .detached_jws_key_id(detached_jws)
        .map_err(|error| SdkJwsVerifyError::InvalidShape(error.to_string()))?
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing kid".to_owned()))?
        .clone();
    let method = verification_methods
        .iter()
        .find(|method| method.id == verification_method)
        .ok_or_else(|| SdkJwsVerifyError::MethodNotFound(verification_method.clone()))?;
    method
        .enforce_formal_key_admission(&method.controller, None)
        .map_err(|error| match error {
            crate::handlers::arkret::FormalKeyAdmissionError::TestSigningMaterialDenied => {
                SdkJwsVerifyError::TestSigningMaterialDenied
            }
            crate::handlers::arkret::FormalKeyAdmissionError::Invalid(message) => {
                SdkJwsVerifyError::UnsupportedJwk(message)
            }
        })?;
    let material = method
        .public_key_material()
        .map_err(SdkJwsVerifyError::UnsupportedJwk)?;
    let verified = verifier
        .verify_detached_jws_with_metadata(detached_jws, payload_bytes, &material)
        .map_err(|error| match error {
            VerifierError::Encoding(message) | VerifierError::Binding(message) => {
                SdkJwsVerifyError::InvalidShape(message)
            }
            VerifierError::UnsupportedKey(message) => SdkJwsVerifyError::UnsupportedJwk(message),
            VerifierError::Backend(_) => SdkJwsVerifyError::SignatureMismatch,
        })?;
    if verified.key_id() != Some(verification_method.as_str()) {
        return Err(SdkJwsVerifyError::InvalidShape(
            "canonical protected-header kid changed during verification".to_owned(),
        ));
    }
    Ok(verification_method)
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use ed25519_dalek::Signer as _;

    use super::*;

    fn detached_jws_fixture(
        payload: &[u8],
        extra_header: serde_json::Map<String, serde_json::Value>,
    ) -> (String, Vec<crate::handlers::arkret::VerificationMethod>) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
        let verification_method = "did:web:issuer.example#key-1";
        let mut header = serde_json::Map::from_iter([
            ("alg".to_owned(), serde_json::json!("Ed25519")),
            ("kid".to_owned(), serde_json::json!(verification_method)),
        ]);
        header.extend(extra_header);
        let header_bytes = arkret_canonical::canonical_json_bytes(&header).unwrap();
        let header_b64u = Base64UrlUnpadded::encode_string(&header_bytes);
        let signing_input = format!(
            "{header_b64u}.{}",
            Base64UrlUnpadded::encode_string(payload)
        );
        let signature = Base64UrlUnpadded::encode_string(
            &signing_key.sign(signing_input.as_bytes()).to_bytes(),
        );
        let methods = vec![
            serde_json::from_value(serde_json::json!({
                "id": verification_method,
                "type": "JsonWebKey2020",
                "controller": "did:web:issuer.example",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": Base64UrlUnpadded::encode_string(
                        signing_key.verifying_key().as_bytes()
                    )
                }
            }))
            .unwrap(),
        ];
        (format!("{header_b64u}..{signature}"), methods)
    }

    #[test]
    fn detached_jws_consumer_uses_the_sdk_canonical_carrier() {
        let payload = b"canonical payload";
        let (jws, methods) = detached_jws_fixture(payload, serde_json::Map::new());
        assert_eq!(
            verify_detached_jws_with_sdk(&jws, payload, &methods).unwrap(),
            "did:web:issuer.example#key-1"
        );

        let attached = jws.replacen("..", ".YXR0YWNoZWQ.", 1);
        assert!(matches!(
            verify_detached_jws_with_sdk(&attached, payload, &methods),
            Err(SdkJwsVerifyError::InvalidShape(_))
        ));

        let protected = jws.split_once("..").unwrap().0;
        let tampered = format!(
            "{protected}..{}",
            Base64UrlUnpadded::encode_string(&[0_u8; 64])
        );
        assert!(matches!(
            verify_detached_jws_with_sdk(&tampered, payload, &methods),
            Err(SdkJwsVerifyError::SignatureMismatch)
        ));
    }

    #[test]
    fn detached_jws_consumer_rejects_unregistered_header_extensions() {
        let payload = b"canonical payload";
        let (jws, methods) = detached_jws_fixture(
            payload,
            serde_json::Map::from_iter([("crit".to_owned(), serde_json::json!(["exp"]))]),
        );
        assert!(matches!(
            verify_detached_jws_with_sdk(&jws, payload, &methods),
            Err(SdkJwsVerifyError::InvalidShape(_))
        ));
    }

    fn fixture() -> (
        arkret_models_identity::AccountRegistrationControlProof,
        coauth_data::DidBindingChallengeRecord,
        DidResolution,
        coauth_data::Ulid,
        arkret_identifiers::Hash,
        arkret_identifiers::DidCoreId,
        arkret_identifiers::TrustDomainId,
    ) {
        fixture_with_seed([9; 32])
    }

    fn fixture_with_seed(
        seed: [u8; 32],
    ) -> (
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
            arkret_identifiers::TrustDomainId::new("ak:trust_domain:auth.production".to_owned())
                .unwrap();
        let account_subject =
            arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let request_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let log_head_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap();
        let issued_at = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let expires_at = issued_at + chrono::Duration::minutes(5);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
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
    fn valid_published_signature_is_denied_before_it_becomes_an_authorization_basis() {
        let seed: [u8; 32] = std::array::from_fn(|index| index as u8);
        let (proof, challenge, mut resolution, account_id, subject, audience, trust_domain) =
            fixture_with_seed(seed);
        let method = &resolution.document.verification_method[0];
        let material = method.public_key_material().unwrap();
        assert!(verify_detached_ed25519_signature(
            &material,
            &proof.canonical_signing_bytes().unwrap(),
            &proof.signature,
        ));

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
        .expect_err("valid published signing material must still be refused");
        assert!(matches!(
            &error,
            DidBindingProofError::TestSigningMaterialDenied
        ));
        assert_eq!(
            error.to_string(),
            arkret_identity::test_material::TEST_SIGNING_MATERIAL_DENIED
        );

        let public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        resolution.document.verification_method[0].public_key_jwk = None;
        resolution.document.verification_method[0].public_key_multibase = Some(
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public_key),
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
        .expect_err("re-encoding the same key must not evade the refusal");
        assert!(matches!(
            error,
            DidBindingProofError::TestSigningMaterialDenied
        ));
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
    fn wire_pin_reduction_preserves_the_durable_full_entry_pin_check() {
        let (proof, challenge, mut resolution, account_id, subject, audience, trust_domain) =
            fixture();
        assert!(
            serde_json::to_value(&proof)
                .unwrap()
                .get("log_head_digest")
                .is_none()
        );
        for head in [
            None,
            Some(arkret_identifiers::Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap()),
        ] {
            resolution.key_log_head = head;
            assert!(matches!(
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
                ),
                Err(DidBindingProofError::ResolutionPinsMismatch)
            ));
        }
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
}
