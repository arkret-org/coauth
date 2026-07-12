use std::collections::BTreeMap;

use arkret_core::{
    Audience, DeliveryBindingHint as HandleClaimDeliveryBindingHint, Did, Handle,
    HandleBindingState, HandleClaim as HandleClaimPayload, HandleClaimKind, Hash, PayloadProof,
    proof_kind,
};
use chrono::{DateTime, Duration, Utc};
use coauth_config::ArkretConfig;
use coauth_data::{Clock, UrlBuilder, User};
use coauth_jose::constraints::Constrainable;
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keystore::Keystore;

use super::*;

/// Output of [`issue_handle_claim`]. Carries the signed JWT, the raw
/// payload (so the caller can persist or echo it), and the wire-level
/// claim digest used as the audit-chain anchor.
#[derive(Debug, Clone)]
pub struct HandleClaimMaterial {
    pub claim_jwt: String,
    pub payload: HandleClaimPayload,
    pub claim_digest: String,
    pub expires_at: DateTime<Utc>,
}

/// TTL applied to handle claim JWTs. Short by design — claims are meant
/// to round-trip through a directory / candidate builder in seconds, not
/// be stored as long-lived bearer credentials.
pub(crate) const HANDLE_CLAIM_TTL_MINUTES: i64 = 5;

fn did_for_handle_claim(value: impl Into<String>) -> Result<Did, SessionGrantError> {
    Did::new(value).map_err(|error| SessionGrantError::Other(error.into()))
}

fn hash_for_handle_claim(value: impl Into<String>) -> Result<Hash, SessionGrantError> {
    Hash::new(value).map_err(|error| SessionGrantError::Other(error.into()))
}

/// Mint a handle-claim JWT bound to `audience`. The claim's
/// `member_delivery_binding` MUST come from upstream policy (handed to this
/// function by the caller); we never default to `did_document_default`.
///
/// Signs with the same preferred ed25519 key used for session grants, so
/// downstream verifiers can use coauth's published DID Document
/// `verificationMethod` to validate both artefacts.
pub(crate) fn issue_handle_claim(
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    user: &User,
    subject_did: &str,
    claim_kind: HandleClaimKind,
    audience: String,
    member_delivery_binding: HandleClaimDeliveryBindingHint,
) -> Result<HandleClaimMaterial, SessionGrantError> {
    use crate::services::handle_subject_validator::ensure_subject_is_principal_did;

    let issuer_service_id = service_id_for(arkret_config);
    // The subject is the user's MINTED principal DID (`did:webvh:…` hosted
    // by the principal server), supplied by the caller. coauth used to
    // derive it via `user_did_for` (`did:web:<coauth-host>:users:<ulid>`),
    // but coauth hosts no DID documents, so that form resolves nowhere and
    // would also mismatch the session-grant subject minted at login.
    let subject_id = subject_did.to_owned();

    // HC-COAUTH-2 — the subject MUST be a holder/principal DID, not a
    // `ak:actor:` / `ak:account:` typed id or a service DID. Validating
    // here keeps the issuer honest about whatever the caller passed and
    // lets the same reason code surface as soland / the SDK.
    ensure_subject_is_principal_did(&subject_id)?;
    ensure_principal_did_method_allowed(arkret_config, &subject_id)?;
    let subject = did_for_handle_claim(subject_id.clone())?;
    let issuer_service = did_for_handle_claim(issuer_service_id.clone())?;

    // Spec 7157ee8 §3.1 — canonical handle wire form is
    // `<localpart>:<domain>`.
    let handle = Handle::parse(&user_handle(url_builder, user))?;
    let mut aliases = vec![user_handle_acct_alias(url_builder, user)];
    aliases.extend(user.handle_aliases.iter().cloned());
    // De-duplicate while preserving first-seen order.
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|s| seen.insert(s.clone()));

    let now = clock.now();
    let expires_at = now + Duration::try_minutes(HANDLE_CLAIM_TTL_MINUTES).unwrap();

    // Build the payload sans proofs so we can hash it deterministically.
    // The proof block then carries that hash; the JWT signs the complete
    // payload.
    let payload_no_proofs = HandleClaimPayload {
        schema: "ak.schema.handle_claim.v1".to_owned(),
        handle: Some(handle),
        handle_aliases: aliases.clone(),
        subject: Some(subject),
        issuer: Some(issuer_service_id.clone()),
        issuer_service_id: Some(issuer_service),
        binding_state: Some(HandleBindingState::Verified),
        claim_kind: Some(claim_kind),
        visibility: None,
        audience: Some(audience.clone()),
        challenge: None,
        claim_scope: BTreeMap::new(),
        member_delivery_binding: Some(member_delivery_binding.clone()),
        claims: Vec::new(),
        created_at: Some(now),
        expires_at: Some(expires_at),
        verified_at: None,
        source_refs: Vec::new(),
        proofs: Vec::new(),
    };
    // PROOF-1 (spec 7157ee8 §3.2): the signing transcript MUST cover the
    // canonical `handle` field, not the retired `handle_uri`. The digest
    // input mirrors the wire shape of `HandleClaimPayload` exactly so
    // downstream verifiers can reproduce the hash from the on-the-wire
    // claim without renaming.
    let claim_digest = arkret_core::canonical::canonical_sha256(&payload_no_proofs)
        .map_err(arkret_core::Error::from)?;

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = key.kid().ok_or(SessionGrantError::NoSigningKey)?.to_owned();
    let verification_method = format!("{issuer_service_id}#{key_id}");
    let proof_payload_digest = hash_for_handle_claim(claim_digest.clone())?;

    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id.clone());
    let signer = key_store.signer_for_algorithm(&alg)?;
    let unsigned_payload = HandleClaimPayload {
        proofs: vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: alg.to_string(),
            verification_method: verification_method.clone(),
            payload_digest: proof_payload_digest.clone(),
            created_at: now,
            domain: None,
            audience: Some(Audience::Single(audience.clone())),
            // Placeholder — overwritten with the detached JWS below.
            jws: String::new(),
        }],
        ..payload_no_proofs.clone()
    };
    let claim_jwt = Jwt::sign(header, unsigned_payload.clone(), &*signer)?.into_string();

    let final_payload = HandleClaimPayload {
        proofs: vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: alg.to_string(),
            verification_method,
            payload_digest: proof_payload_digest,
            created_at: now,
            domain: None,
            audience: Some(Audience::Single(audience.clone())),
            jws: claim_jwt.clone(),
        }],
        ..payload_no_proofs
    };

    Ok(HandleClaimMaterial {
        claim_jwt,
        payload: final_payload,
        claim_digest,
        expires_at,
    })
}
