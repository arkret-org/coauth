use chrono::{DateTime, Duration, Utc};
use coauth_config::CokretConfig;
use coauth_data::{Clock, UrlBuilder, User};
use coauth_jose::{
    constraints::Constrainable,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use coauth_keystore::Keystore;
use serde::{Deserialize, Serialize};

use super::*;

/// Member delivery binding embedded in a `handle_claim`. Shape mirrors
/// `member-delivery-binding-candidate.schema.json#member_delivery_binding`
/// (commit 0a5ab85). `binding_source` MUST be one of the five values
/// enumerated below — `did_document_default` is forbidden because handle-
/// resolved candidates and DID Document fallback are independent
/// materialisation paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleClaimDeliveryBindingHint {
    pub recipient_service_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
    pub binding_source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_modes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<String>,
}

/// Detached-JWS proof attached to a `handle_claim`. Lightweight mirror of
/// `event-envelope.schema.json#/$defs/proof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleClaimProof {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub canonicalization: String,
    pub payload_digest_alg: String,
    pub payload_digest: String,
    pub created_at: DateTime<Utc>,
    pub audience: String,
    pub jws: String,
}

/// Canonical `handle_claim` payload signed by coauth's audience-bound
/// session-grant signing key. Shape aligned with
/// `member-delivery-binding-candidate.schema.json` so a downstream
/// directory can pack this directly into a candidate without rewriting
/// fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleClaimPayload {
    pub schema: String,
    /// R3.2 — `ck.schema.handle_claim.v1` `claim_kind`. coauth only emits
    /// the allow-listed values (`handle_binding` / `organization_handle`);
    /// the removed `service_handle` value is rejected at issuance time by
    /// [`crate::services::handle_subject_validator::ensure_claim_kind_supported`].
    pub claim_kind: String,
    pub subject_id: String,
    /// Canonical Cokret handle of the form `<localpart>:<domain>` per
    /// spec 7157ee8 §3.1 (replaces the legacy `handle_uri` URI form).
    pub handle: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_aliases: Vec<String>,
    pub issuer_service_did: String,
    pub audience: String,
    pub member_delivery_binding: HandleClaimDeliveryBindingHint,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub proofs: Vec<HandleClaimProof>,
    /// `sha256:<hex>` digest of the canonical-JSON encoding of the claim
    /// minus the `proofs[]` field (proofs are produced *over* this hash).
    pub claim_digest: String,
}

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

/// R3.2 — the `claim_kind` coauth's handle-claim issuer stamps on the
/// emitted `ck.schema.handle_claim.v1` payload.
///
/// Modelled as an enum so the removed `service_handle` value can never be
/// *named* by an in-process caller (fail-closed at the type level), while
/// [`issue_handle_claim`] still runs the runtime
/// [`crate::services::handle_subject_validator::ensure_claim_kind_supported`]
/// allow-list check for defence in depth against future drift. Matches the
/// SDK `HandleClass::{UserHandle, OrganizationHandle}` enum, serialised as
/// the `ck.schema.handle_claim.v1` `claim_kind` snake-case strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandleClaimKind {
    /// A holder-bound user handle (`HandleClass::UserHandle`).
    HandleBinding,
    /// An organization-assigned handle (`HandleClass::OrganizationHandle`).
    OrganizationHandle,
}

impl HandleClaimKind {
    pub(crate) const fn as_wire(self) -> &'static str {
        match self {
            Self::HandleBinding => "handle_binding",
            Self::OrganizationHandle => "organization_handle",
        }
    }
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
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    user: &User,
    claim_kind: HandleClaimKind,
    audience: String,
    member_delivery_binding: HandleClaimDeliveryBindingHint,
) -> Result<HandleClaimMaterial, SessionGrantError> {
    use crate::services::handle_subject_validator::{
        ensure_claim_kind_supported, ensure_subject_is_principal_did,
    };

    let issuer_service_did = service_did_for(url_builder, cokret_config);
    let subject_id = user_did_for(url_builder, cokret_config, user);

    // HC-COAUTH-1 (business layer) — fail closed against the removed
    // `service_handle` (and any other non-allow-listed) `claim_kind`. The
    // [`HandleClaimKind`] enum already prevents an in-process caller from
    // naming `service_handle`; this re-checks the wire string so the deny
    // also covers any future code path that bypasses the enum.
    ensure_claim_kind_supported(claim_kind.as_wire())?;

    // HC-COAUTH-2 — the subject MUST be a holder/principal DID, not a
    // `ck:actor:` / `ck:account:` typed id or a service DID. coauth always
    // derives `subject_id` from `user_did_for`, but validating here keeps
    // the issuer honest if that derivation ever changes and lets the same
    // reason code surface as soland / the SDK.
    ensure_subject_is_principal_did(&subject_id)?;

    // Spec 7157ee8 §3.1 — canonical handle wire form is
    // `<localpart>:<domain>`; the legacy `cokret://…` URI is retired.
    let handle = user_handle(url_builder, user);
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
    let mut payload_no_proofs = HandleClaimPayload {
        schema: "ck.schema.handle_claim.v1".to_owned(),
        claim_kind: claim_kind.as_wire().to_owned(),
        subject_id: subject_id.clone(),
        handle,
        handle_aliases: aliases.clone(),
        issuer_service_did: issuer_service_did.clone(),
        audience: audience.clone(),
        member_delivery_binding: member_delivery_binding.clone(),
        issued_at: now,
        expires_at,
        proofs: Vec::new(),
        claim_digest: String::new(),
    };
    // PROOF-1 (spec 7157ee8 §3.2): the signing transcript MUST cover the
    // canonical `handle` field, not the retired `handle_uri`. The digest
    // input mirrors the wire shape of `HandleClaimPayload` exactly so
    // downstream verifiers can reproduce the hash from the on-the-wire
    // claim without renaming.
    let claim_digest = canonical_json_sha256(&HandleClaimDigestInput {
        schema: &payload_no_proofs.schema,
        claim_kind: &payload_no_proofs.claim_kind,
        subject_id: &payload_no_proofs.subject_id,
        handle: &payload_no_proofs.handle,
        handle_aliases: &payload_no_proofs.handle_aliases,
        issuer_service_did: &payload_no_proofs.issuer_service_did,
        audience: &payload_no_proofs.audience,
        member_delivery_binding: &payload_no_proofs.member_delivery_binding,
        issued_at: payload_no_proofs.issued_at,
        expires_at: payload_no_proofs.expires_at,
    })?;
    payload_no_proofs.claim_digest.clone_from(&claim_digest);

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = key.kid().ok_or(SessionGrantError::NoSigningKey)?.to_owned();
    let verification_method = format!("{issuer_service_did}#{key_id}");
    let proof_payload_digest = claim_digest.clone();

    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id.clone());
    let signer = key_store.signer_for_algorithm(&alg)?;
    let unsigned_payload = HandleClaimPayload {
        proofs: vec![HandleClaimProof {
            kind: "ck.handle.claim.proof.v1".to_owned(),
            alg: alg.to_string(),
            verification_method: verification_method.clone(),
            canonicalization: "json-c14n-object-key-sort-v1".to_owned(),
            payload_digest_alg: "sha-256".to_owned(),
            payload_digest: proof_payload_digest.clone(),
            created_at: now,
            audience: audience.clone(),
            // Placeholder — overwritten with the detached JWS below.
            jws: String::new(),
        }],
        ..payload_no_proofs.clone()
    };
    let claim_jwt = Jwt::sign(header, unsigned_payload.clone(), &*signer)?.into_string();

    let final_payload = HandleClaimPayload {
        proofs: vec![HandleClaimProof {
            kind: "ck.handle.claim.proof.v1".to_owned(),
            alg: alg.to_string(),
            verification_method,
            canonicalization: "json-c14n-object-key-sort-v1".to_owned(),
            payload_digest_alg: "sha-256".to_owned(),
            payload_digest: proof_payload_digest,
            created_at: now,
            audience: audience.clone(),
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

/// Helper struct used to canonicalise the *digest input* — i.e. the
/// payload minus the `proofs[]` and `claim_digest` fields. Sorting and
/// shape must match the wire shape of `HandleClaimPayload` for
/// downstream digesters to reproduce the hash.
///
/// PROOF-1: spec 7157ee8 §3.2 mandates the transcript covers `handle`
/// (canonical `<localpart>:<domain>` form). The legacy `handle_uri` shape
/// is no longer included in the digest input on any code path.
#[derive(Debug, Serialize)]
struct HandleClaimDigestInput<'a> {
    schema: &'a str,
    claim_kind: &'a str,
    subject_id: &'a str,
    handle: &'a str,
    handle_aliases: &'a Vec<String>,
    issuer_service_did: &'a str,
    audience: &'a str,
    member_delivery_binding: &'a HandleClaimDeliveryBindingHint,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}
