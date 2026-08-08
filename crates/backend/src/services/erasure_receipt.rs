use arkret_models_collaboration::events_payloads::event_wire::VerificationStub;
use arkret_models_collaboration::governance::erasure::{ErasureReceipt, ErasureReceiptPackage};
use coauth_config::ArkretConfig;
use coauth_data::{BoxRepository, UrlBuilder};
use coauth_keystore::Keystore;
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
    #[error("issuer DID document cannot back a full identity fact: {0}")]
    ResolverNotFullIdentityFact(String),
    #[error("issuer DID document has no verificationMethod entries")]
    NoVerificationMethod,
    #[error("no receipt proof verified under the issuer DID")]
    NoValidIssuerProof,
}

fn verification_method_did(verification_method: &str) -> &str {
    let without_fragment = verification_method
        .split_once('#')
        .map_or(verification_method, |(did, _)| did);
    without_fragment
        .split_once('?')
        .map_or(without_fragment, |(did, _)| did)
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
    key_store: &Keystore,
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
        key_store,
        repo,
        did_resolver,
        binding_store,
        receipt.issuer.as_str(),
        arkret_identity::DidBindingPurpose::Issuer,
        crate::services::did_binding::high_risk_freshness(),
        now,
    )
    .await
    .map_err(|error| {
        ErasureReceiptVerificationError::ResolverNotFullIdentityFact(error.to_string())
    })?;
    if resolution.document.verification_method.is_empty() {
        return Err(ErasureReceiptVerificationError::NoVerificationMethod);
    }

    let issuer = receipt.issuer.as_str();
    for proof in &receipt.proofs {
        if proof.payload_digest != expected_digest {
            continue;
        }
        if verification_method_did(&proof.verification_method) != issuer {
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
    key_store: &Keystore,
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
        key_store,
        repo,
        did_resolver,
        binding_store,
        &package.receipt,
        Some(&package.retained_stub),
        now,
    )
    .await
}
