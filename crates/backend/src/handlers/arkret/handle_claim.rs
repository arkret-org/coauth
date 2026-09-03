use arkret_identifiers::Hash;
use arkret_models_identity::{
    Handle, HandleClaim as HandleClaimPayload, HandleClaimCore, HandleClaimKind, HandleClaimStatus,
    HandleClaimVariant, HandleVisibility, handle_claim_proof_signing_bytes,
};
use arkret_wire::{Audience, PayloadProof, PayloadProofPurpose, SchemaId, proof_kind};
use chrono::{DateTime, Duration, Utc};
use coauth_config::ArkretConfig;
use coauth_data::{Clock, UrlBuilder, User};
use coauth_keystore::Keystore;

use super::*;

/// Output of [`issue_handle_claim`]. Carries the signed payload and the
/// wire-level claim digest used as the audit-chain anchor.
#[derive(Debug, Clone)]
pub struct HandleClaimMaterial {
    pub payload: HandleClaimPayload,
    pub claim_digest: String,
    pub expires_at: DateTime<Utc>,
}

/// TTL applied to handle claim JWTs. Short by design — claims are meant
/// to round-trip through a directory / candidate builder in seconds, not
/// be stored as long-lived bearer credentials.
pub(crate) const HANDLE_CLAIM_TTL_MINUTES: i64 = 5;

fn hash_for_handle_claim(value: impl Into<String>) -> Result<Hash, SessionGrantError> {
    Hash::new(value).map_err(|error| SessionGrantError::Other(error.into()))
}

/// `<service DID>#<kid>` as a strongly typed DID URL.
///
/// The issuer service id is a DID and the keystore `kid` is the JWS `kid`;
/// a deployment whose `kid` uses characters outside the spec `did_url`
/// fragment charset fails closed here instead of emitting a wire-invalid
/// `verification_method`.
fn did_url_for_handle_claim(value: String) -> Result<arkret_wire::DidUrl, SessionGrantError> {
    arkret_wire::DidUrl::new(value).map_err(|error| {
        SessionGrantError::Other(anyhow::anyhow!(
            "handle claim verification_method is not a DID URL: {error}"
        ))
    })
}

/// Mint a handle-claim JWT bound to `audience`. The claim's
/// Signs with the same preferred ed25519 key used for session grants, so
/// downstream verifiers can use coauth's published DID Document
/// `verificationMethod` to validate both artefacts.
pub(crate) fn issue_handle_claim(
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    user: &User,
    account_id: &arkret_wire::AccountId,
    claim_kind: HandleClaimKind,
    audience: String,
) -> Result<HandleClaimMaterial, SessionGrantError> {
    use crate::services::handle_subject_validator::ensure_subject_is_principal_core_id;

    let issuer_id = owning_station_id_for(arkret_config);
    let issuer_did = owning_station_did_for(arkret_config);
    account_id.validate()?;
    ensure_subject_is_principal_core_id(account_id.principal_id.as_str())?;

    // Spec 7157ee8 §3.1 — canonical handle wire form is
    // `<localpart>:<domain>`.
    let handle = Handle::parse(&user_handle(url_builder, user))?;
    let mut aliases = vec![handle.to_acct()];
    aliases.extend(user.handle_aliases.iter().cloned());
    // De-duplicate while preserving first-seen order.
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|s| seen.insert(s.clone()));

    let now = clock.now();
    let expires_at = now + Duration::try_minutes(HANDLE_CLAIM_TTL_MINUTES).unwrap();

    let claim = match claim_kind {
        HandleClaimKind::HandleBinding => HandleClaimVariant::HandleBinding,
        HandleClaimKind::OrganizationHandle => {
            return Err(SessionGrantError::Other(anyhow::anyhow!(
                "organization HandleClaim issuance requires an explicit organization_id"
            )));
        }
    };
    let signing_key = ed25519_dalek_3::SigningKey::from_bytes(
        &key_store
            .account_authority_seed()
            .map_err(|error| SessionGrantError::Other(error.into()))?,
    );
    // `issuer_did` is the owning Station; the Station's DID document authorizes
    // this Account Authority under the shared fragment, not under coauth's
    // internal keystore `kid`. A verifier resolves the fragment from that
    // document, so the keystore name would be unresolvable there.
    let verification_method = did_url_for_handle_claim(format!(
        "{issuer_did}#{}",
        crate::services::peer_protocol_client::ACCOUNT_AUTHORITY_VERIFICATION_METHOD_FRAGMENT
    ))?;
    let placeholder_digest = hash_for_handle_claim(format!("sha256:{}", "0".repeat(64)))?;
    let placeholder = handle_claim_proof(
        placeholder_digest,
        PayloadProofPurpose::IssuerAttestation,
        now,
        Some(&audience),
        verification_method.clone(),
        &signing_key,
    )?;
    let mut core = HandleClaimCore {
        schema: HandleClaimCore::SCHEMA.to_owned(),
        handle,
        handle_aliases: aliases,
        subject_account_id: account_id.clone(),
        issuer_id: issuer_id.clone(),
        claim,
        visibility: HandleVisibility::Restricted,
        audience: Some(audience.clone()),
        issued_at: now,
        expires_at: Some(expires_at),
        source_refs: Vec::new(),
        proofs: [placeholder.clone(), placeholder],
    };
    let claim_digest = core.claim_digest()?;
    core.proofs = [
        handle_claim_proof(
            claim_digest.clone(),
            PayloadProofPurpose::IssuerAttestation,
            now,
            Some(&audience),
            verification_method.clone(),
            &signing_key,
        )?,
        handle_claim_proof(
            claim_digest.clone(),
            PayloadProofPurpose::HolderAcceptance,
            now,
            Some(&audience),
            verification_method.clone(),
            &signing_key,
        )?,
    ];
    let fresh_until = now + Duration::try_minutes(5).unwrap();
    let mut final_payload = HandleClaimPayload {
        schema: SchemaId::HANDLE_CLAIM_V1.to_owned(),
        claim: core,
        status: HandleClaimStatus::Verified,
        as_of: now,
        verifier_id: issuer_id,
        verified_at: Some(now),
        revocation: None,
        fresh_until,
        status_proof: handle_claim_proof(
            claim_digest.clone(),
            PayloadProofPurpose::StatusAttestation,
            now,
            Some(&audience),
            verification_method.clone(),
            &signing_key,
        )?,
    };
    final_payload.status_proof = handle_claim_proof(
        final_payload.status_digest()?,
        PayloadProofPurpose::StatusAttestation,
        now,
        Some(&audience),
        verification_method,
        &signing_key,
    )?;
    final_payload.validate()?;
    Ok(HandleClaimMaterial {
        payload: final_payload,
        claim_digest: claim_digest.to_string(),
        expires_at,
    })
}

fn handle_claim_proof(
    payload_digest: Hash,
    proof_purpose: PayloadProofPurpose,
    created_at: DateTime<Utc>,
    audience: Option<&str>,
    verification_method: arkret_wire::DidUrl,
    signing_key: &ed25519_dalek_3::SigningKey,
) -> Result<PayloadProof, SessionGrantError> {
    let domain = match proof_purpose {
        PayloadProofPurpose::IssuerAttestation | PayloadProofPurpose::HolderAcceptance => {
            arkret_models_identity::HANDLE_CLAIM_PROOF_DOMAIN
        }
        PayloadProofPurpose::StatusAttestation => {
            arkret_models_identity::HANDLE_CLAIM_STATUS_DOMAIN
        }
        PayloadProofPurpose::RevocationAuthorization => {
            arkret_models_identity::HANDLE_CLAIM_REVOCATION_DOMAIN
        }
        PayloadProofPurpose::GovernanceAuthorization => {
            return Err(SessionGrantError::Other(anyhow::anyhow!(
                "invalid HandleClaim proof purpose"
            )));
        }
    };
    let mut proof = PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest,
        created_at,
        domain: Some(domain.to_owned()),
        audience: audience.map(|value| Audience::Single(value.to_owned())),
        proof_purpose: Some(proof_purpose),
        jws: String::new(),
    };
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &handle_claim_proof_signing_bytes(&proof)?,
        signing_key,
    )
    .map_err(|error| SessionGrantError::Other(anyhow::anyhow!(error)))?;
    Ok(proof)
}
