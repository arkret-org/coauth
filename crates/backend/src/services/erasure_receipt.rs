use coauth_config::ArkretConfig;
use coauth_data::{BoxRepository, UrlBuilder};
use coauth_keystore::Keystore;
use arkret_core::ErasureReceipt;
use serde_json::Value;
use thiserror::Error;

use crate::services::did_binding_proof::verify_detached_jws_with_sdk;
use crate::services::did_resolver::{DidResolveError, DidResolverService};

#[derive(Debug, Error)]
pub enum ErasureReceiptVerificationError {
    #[error("retained verification stub is required")]
    MissingRetainedStub,
    #[error("receipt validation failed: {0}")]
    Receipt(#[from] arkret_core::Error),
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
    retained_stub: Option<&Value>,
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
    receipt: &ErasureReceipt,
    retained_stub: Option<&Value>,
) -> Result<(), ErasureReceiptVerificationError> {
    validate_retained_stub(receipt, retained_stub)?;
    let expected_digest = receipt.canonical_payload_digest()?;
    let proof_payload = receipt.canonical_proof_input()?;

    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            arkret_config,
            key_store,
            repo,
            receipt.issuer.as_str(),
        )
        .await?;
    if let Some(rejection) = resolution.identity_fact_rejection() {
        return Err(
            ErasureReceiptVerificationError::ResolverNotFullIdentityFact(
                rejection.as_str().to_owned(),
            ),
        );
    }
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
