use arkret_models_collaboration::events_payloads::event_wire::VerificationStub;
use arkret_models_collaboration::governance::erasure::{
    ErasureReceipt, ErasureReceiptPackage, ErasureReceiptProof,
};
use arkret_wire::{DidCoreId, Hash};
use coauth_config::ArkretConfig;
use coauth_data::{BoxRepository, UrlBuilder};
use coauth_keyring::Keyring;
use thiserror::Error;

use crate::services::did_binding_proof::verify_detached_jws_with_sdk;
use crate::services::did_resolver::{DidResolveError, DidResolverService};

#[derive(Debug, Error)]
pub enum ErasureReceiptVerificationError {
    #[error("retained verification stub is required")]
    MissingRetainedStub,
    #[error("receipt validation failed: {0}")]
    Receipt(#[from] arkret_wire::WireError),
    #[error("issuer DID resolution failed: {0}")]
    DidResolve(#[from] DidResolveError),
    #[error("issuer DID document is not authority-grade: {0}")]
    ResolverNotAuthorityGrade(String),
    #[error("issuer DID document has no verificationMethod entries")]
    NoVerificationMethod,
    #[error("no receipt proof verified under the issuer DID")]
    NoValidIssuerProof,
}

fn is_issuer_proof_candidate(
    proof: &ErasureReceiptProof,
    expected_digest: &Hash,
    issuer_id: &DidCoreId,
) -> bool {
    if &proof.payload_digest != expected_digest {
        return false;
    }

    let Ok(controller_did) =
        arkret_identity::verification_method_did(proof.verification_method.as_str())
    else {
        return false;
    };
    arkret_identifiers::project_did_to_core_id(&controller_did)
        .is_ok_and(|controller_id| controller_id == *issuer_id)
}

fn validate_retained_stub(
    receipt: &ErasureReceipt,
    retained_stub: Option<&VerificationStub>,
) -> Result<(), ErasureReceiptVerificationError> {
    if let Some(retained_stub) = retained_stub {
        receipt.validate_with_retained_stub(retained_stub)?;
        return Ok(());
    }

    if receipt.retained_stub.is_none() {
        return Err(ErasureReceiptVerificationError::MissingRetainedStub);
    }
    receipt.validate_with_inline_retained_stub()?;
    Ok(())
}

/// Verify a `ak.schema.erasure_receipt.v1` receipt before accepting it as a
/// completed erasure proof.
#[allow(clippy::too_many_arguments)]
pub async fn verify_erasure_receipt(
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    keyring: &Keyring,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    binding_store: &crate::services::did_binding::DurableVerifiedDidBindingStore,
    receipt: &ErasureReceipt,
    retained_stub: Option<&VerificationStub>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), ErasureReceiptVerificationError> {
    validate_retained_stub(receipt, retained_stub)?;
    let expected_digest = receipt.canonical_payload_digest()?;
    let proof_payload = receipt.canonical_proof_input()?;

    // Reject proofs whose verification method cannot name this exact issuer
    // before authority resolution. Besides avoiding needless resolution, this
    // keeps foreign or unsupported DID-method proofs on a zero-effect path.
    if !receipt
        .proofs
        .iter()
        .any(|proof| is_issuer_proof_candidate(proof, &expected_digest, &receipt.issuer_id))
    {
        return Err(ErasureReceiptVerificationError::NoValidIssuerProof);
    }

    // §4 last row — "verifying a third-party claim / receipt / attestation
    // when this deployment holds no accepted binding for its issuer key". The
    // DID resolved here is literally `receipt.issuer`, so the closed purpose is
    // `Issuer` (not `AdminAction`, which is reserved for the *acting admin's
    // own* DID in `revocation_approval` / `risk_action`). Erasure is a
    // high-risk write, hence `fresh_within(HIGH_RISK_MAX_AGE)`; degraded /
    // fallback / unproven-controller evidence fails closed inside
    // `authority_document`, replacing the previous `identity_fact_rejection`
    // gate.
    let resolution = crate::services::did_binding::authority_document(
        http_client,
        url_builder,
        arkret_config,
        keyring,
        repo,
        did_resolver,
        binding_store,
        receipt.issuer_id.as_str(),
        arkret_identity::DidBindingPurpose::Issuer,
        crate::services::did_binding::high_risk_freshness(),
        now,
    )
    .await
    .map_err(|error| {
        ErasureReceiptVerificationError::ResolverNotAuthorityGrade(error.to_string())
    })?;
    if resolution.document.verification_method.is_empty() {
        return Err(ErasureReceiptVerificationError::NoVerificationMethod);
    }

    for proof in &receipt.proofs {
        if !is_issuer_proof_candidate(proof, &expected_digest, &receipt.issuer_id) {
            continue;
        }
        let verified_method = verify_detached_jws_with_sdk(
            &proof.signature,
            &proof_payload,
            &resolution.document.verification_method,
        );
        if let Ok(verified_method) = verified_method
            && verified_method == proof.verification_method
        {
            return Ok(());
        }
    }

    Err(ErasureReceiptVerificationError::NoValidIssuerProof)
}

/// Verify the standard peer carrier package, including the package digest and
/// exact retained-stub binding, before resolving and authenticating its issuer.
#[allow(clippy::too_many_arguments)]
pub async fn verify_erasure_receipt_package(
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    keyring: &Keyring,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    binding_store: &crate::services::did_binding::DurableVerifiedDidBindingStore,
    package: &ErasureReceiptPackage,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), ErasureReceiptVerificationError> {
    package.validate_bindings()?;
    verify_erasure_receipt(
        http_client,
        url_builder,
        arkret_config,
        keyring,
        repo,
        did_resolver,
        binding_store,
        &package.receipt,
        Some(&package.retained_stub),
        now,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_models_collaboration::governance::erasure::ErasureReceiptProof;
    use arkret_wire::{Did, DidUrl, Hash};

    use super::is_issuer_proof_candidate;

    fn digest(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).expect("test digest")
    }

    fn proof(verification_method: &str, payload_digest: Hash) -> ErasureReceiptProof {
        ErasureReceiptProof {
            verification_method: DidUrl::new(verification_method).expect("test DID URL"),
            payload_digest,
            signature: "test-signature".to_owned(),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn issuer_candidate_uses_canonical_controller_projection() {
        let issuer_did = Did::new("did:web:issuer.example").expect("test issuer DID");
        let issuer_id =
            arkret_identifiers::project_did_to_core_id(&issuer_did).expect("test issuer core ID");
        let expected_digest = digest(7);
        let proof = proof(
            "did:web:issuer.example#receipt-key",
            expected_digest.clone(),
        );

        assert!(is_issuer_proof_candidate(
            &proof,
            &expected_digest,
            &issuer_id
        ));
    }

    #[test]
    fn foreign_controller_is_rejected() {
        let issuer_did = Did::new("did:web:issuer.example").expect("test issuer DID");
        let issuer_id =
            arkret_identifiers::project_did_to_core_id(&issuer_did).expect("test issuer core ID");
        let expected_digest = digest(7);
        let proof = proof(
            "did:web:foreign.example#receipt-key",
            expected_digest.clone(),
        );

        assert!(!is_issuer_proof_candidate(
            &proof,
            &expected_digest,
            &issuer_id
        ));
    }

    #[test]
    fn unsupported_controller_and_wrong_digest_are_zero_effect_candidates() {
        let issuer_did = Did::new("did:web:issuer.example").expect("test issuer DID");
        let issuer_id =
            arkret_identifiers::project_did_to_core_id(&issuer_did).expect("test issuer core ID");
        let expected_digest = digest(7);
        let unsupported = proof("did:example:issuer#receipt-key", expected_digest.clone());
        let wrong_digest = proof("did:web:issuer.example#receipt-key", digest(8));

        assert!(!is_issuer_proof_candidate(
            &unsupported,
            &expected_digest,
            &issuer_id
        ));
        assert!(!is_issuer_proof_candidate(
            &wrong_digest,
            &expected_digest,
            &issuer_id
        ));
    }
}
