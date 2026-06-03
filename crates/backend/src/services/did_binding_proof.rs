//! Validate DID-binding `control_proof` payloads against the resolved DID
//! document.
//!
//! Shape: a compact JWS signed by one of the DID's verification-method
//! keys, with an attached canonical "binding statement" payload of the form:
//!
//! ```json
//! {
//!   "type": "cx.did_binding.control_proof.v1",
//!   "account_did": "<account DID>",
//!   "cx_account_id": "<local account ULID>",
//!   "verification_method": "<DID URL from verificationMethod.id>",
//!   "nonce": "<opaque nonce>",
//!   "iat": "<RFC3339 timestamp>"
//! }
//! ```
//!
//! Verification flow:
//!   1. Resolve the DID via the configured resolver chain
//!      (`DidResolverService`).
//!   2. Reject if the resolver returns no `verificationMethod` keys.
//!   3. Require the JWS `kid`, statement `verification_method`, and resolved
//!      DID document `verificationMethod.id` to match exactly.
//!   4. Reject if the JWS doesn't verify against that exact method key.
//!   5. Reject if the attached payload bytes are not the canonical JSON
//!      encoding of the decoded binding statement.
//!   6. Reject if the embedded binding statement doesn't match the request
//!      (`account_did` + `cx_account_id` + nonce all match exactly).
//!
//! SDK integration: signature verification is performed by the SDK's
//! pure-Rust `cokret_signatures::PublicKeyMaterial::ed25519_bytes()`
//! helper (which understands raw / multibase / JWK Ed25519 keys) plus
//! the underlying `ed25519_dalek` verifier. The compact JWS envelope is
//! parsed locally (header.payload.signature segments) and the canonical
//! signing input is recomputed from the wire bytes so that no JWS
//! library state intervenes between the resolved DID-document JWK and
//! the verification call. The embedded coauth_jose
//! `jwt.verify_with_jwks(...)` path has been removed; coauth_jose's JWT
//! parser is still used to extract the typed `BindingStatementClaims` /
//! `VerificationServiceProofClaims` payload, but the signature check
//! itself is now a single SDK-mediated `ed25519_dalek::Verifier::verify`
//! call against raw key bytes recovered from the OKP JWK.
//!
//! ## Verification-service proof
//!
//! [`verify_verification_service_proof`] is the sister verifier for the
//! 3PID invite chain (see `third_party_invite::verify_invite`). It
//! validates a signed JWT issued by a trusted 3PID verification service
//! whose claims attest that a 3PID (e.g. email) was verified for the
//! presented invite. Required claims: `iss` (must equal the configured
//! `expected_verification_service_did`), `aud` (must equal the local
//! coauth service DID), `sub` (SHA-256 hex of the normalized 3PID),
//! `exp` (must be in the future), `nbf` (must be ≤ now), `jti`, and
//! `nonce`. The signature is verified against the verification
//! service's resolved DID document JWKS.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::{DateTime, Utc};
use coauth_config::CokretConfig;
use coauth_data::{BoxRepository, UrlBuilder};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keystore::Keystore;
use cokret_core::canonical::canonical_json_bytes;
use cokret_signatures::proof::PublicKeyMaterial;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::services::did_resolver::{DidResolveError, DidResolverService};

/// Canonical binding statement claims embedded in a proof JWS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingStatementClaims {
    /// Discriminator. Must equal `cx.did_binding.control_proof.v1`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The DID being bound.
    pub account_did: String,
    /// The local coauth account ULID (string-encoded).
    pub cx_account_id: String,
    /// DID URL of the resolved verification method that signs the proof.
    pub verification_method: String,
    /// Nonce supplied in the binding request.
    pub nonce: String,
    /// Issuance time.
    pub iat: DateTime<Utc>,
}

/// Validation errors. All variants are deterministic from the inputs and
/// resolver response.
#[derive(Debug, Error)]
pub enum DidBindingProofError {
    #[error("control_proof must be a non-empty JWS string")]
    EmptyProof,

    #[error("control_proof JWS could not be parsed: {0}")]
    InvalidJws(String),

    #[error("DID resolver failed: {0}")]
    Resolve(#[from] DidResolveError),

    #[error("DID document has no verificationMethod entries")]
    NoVerificationKey,

    #[error("control_proof JWS header is missing a verificationMethod kid")]
    MissingVerificationMethod,

    #[error("control_proof JWS alg must be EdDSA, got {0}")]
    UnsupportedAlgorithm(String),

    #[error("control_proof verificationMethod does not match the binding statement")]
    VerificationMethodMismatch,

    #[error("control_proof verificationMethod is not present in the resolved DID document")]
    VerificationMethodNotFound,

    #[error("control_proof JWS signature did not verify against the resolved verificationMethod")]
    SignatureMismatch,

    #[error("binding statement canonical JSON could not be encoded: {0}")]
    CanonicalStatement(String),

    #[error("binding statement payload is not the canonical JSON encoding of the decoded claims")]
    CanonicalStatementMismatch,

    #[error("binding statement type discriminator mismatch")]
    StatementKindMismatch,

    #[error("binding statement account_did does not match request")]
    AccountDidMismatch,

    #[error("binding statement cx_account_id does not match request")]
    CxAccountIdMismatch,

    #[error("binding statement nonce does not match request")]
    NonceMismatch,

    #[error("binding statement iat is in the future or expired")]
    IatOutOfRange,
}

/// Maximum `iat` skew accepted, in seconds. Past or future drift beyond
/// this window rejects the proof.
const MAX_IAT_SKEW_SECS: i64 = 5 * 60;

/// Normalize a DID for any binding-write path: trim whitespace, then run
/// the value through the SDK `Did::new` validator (which enforces the
/// Round-4 `^did:[a-z0-9]+:[^\s]+$` regex).
///
/// Returns the normalized DID string on success, or
/// `DidBindingProofError::InvalidJws` on rejection (re-using the
/// existing error variant so the wire surface stays stable).
///
/// Phase P2 (B-D): all DID binding writes MUST round-trip through this
/// helper so coauth never persists a legacy-shape DID. The SDK validator
/// is the single source of truth — coauth does not maintain its own
/// regex.
pub fn normalize_did_for_binding(did: &str) -> Result<String, DidBindingProofError> {
    let trimmed = did.trim();
    if trimmed.is_empty() {
        return Err(DidBindingProofError::InvalidJws(
            "did must be a non-empty DID URI".to_owned(),
        ));
    }
    if cokret_core::Did::new(trimmed.to_owned()).is_err() {
        return Err(DidBindingProofError::InvalidJws(format!(
            "did {trimmed:?} fails round-4 DID regex (^did:[a-z0-9]+:[^\\s]+$)"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Validate a `control_proof` JWS against the resolved DID document and
/// the requested binding statement.
///
/// `account_did` / `cx_account_id` / `nonce` form the canonical statement
/// that must be embedded inside the JWS payload. `now` is used to bound
/// the `iat` claim (proofs more than 5 minutes from `now` in either
/// direction are rejected).
#[allow(clippy::too_many_arguments)]
pub async fn validate_control_proof(
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    proof_jws: &str,
    account_did: &str,
    cx_account_id: Ulid,
    nonce: &str,
    now: DateTime<Utc>,
) -> Result<BindingStatementClaims, DidBindingProofError> {
    if proof_jws.trim().is_empty() {
        return Err(DidBindingProofError::EmptyProof);
    }

    // Round 4 (spec a77b995) — DID regex tightened to
    // `^did:[a-z0-9]+:[^\s]+$`. Reject any value the SDK validator
    // refuses BEFORE invoking the resolver chain, so wire-broken DIDs
    // never trigger network I/O. Delegating to the SDK's validator
    // keeps coauth in lockstep with the canonical regex.
    if cokret_core::Did::new(account_did.to_owned()).is_err() {
        return Err(DidBindingProofError::InvalidJws(format!(
            "account_did {account_did:?} fails round-4 DID regex"
        )));
    }

    // Parse JWS
    let jwt: Jwt<'_, BindingStatementClaims> =
        Jwt::try_from(proof_jws).map_err(|e| DidBindingProofError::InvalidJws(e.to_string()))?;
    if jwt.header().alg() != &JsonWebSignatureAlg::EdDsa {
        return Err(DidBindingProofError::UnsupportedAlgorithm(
            jwt.header().alg().to_string(),
        ));
    }
    let payload_bytes = decode_attached_jws_payload(proof_jws)?;
    let verification_method = jwt
        .header()
        .kid()
        .ok_or(DidBindingProofError::MissingVerificationMethod)?
        .to_owned();

    let claims = jwt.payload();
    if claims.verification_method != verification_method {
        return Err(DidBindingProofError::VerificationMethodMismatch);
    }
    validate_canonical_statement_payload(&payload_bytes, claims)?;

    // Resolve DID document
    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            cokret_config,
            key_store,
            repo,
            account_did,
        )
        .await?;

    let verification_methods = &resolution.document.verification_method;
    if verification_methods.is_empty() {
        return Err(DidBindingProofError::NoVerificationKey);
    }

    verify_compact_jws_with_sdk(proof_jws, verification_methods, &verification_method)
        .map_err(|_| DidBindingProofError::SignatureMismatch)?;

    validate_binding_statement_claims(claims, account_did, cx_account_id, nonce, now)?;

    Ok(claims.clone())
}

fn decode_attached_jws_payload(proof_jws: &str) -> Result<Vec<u8>, DidBindingProofError> {
    let mut parts = proof_jws.split('.');
    let _header = parts.next().ok_or_else(|| {
        DidBindingProofError::InvalidJws("compact JWS is missing protected header".to_owned())
    })?;
    let payload = parts.next().ok_or_else(|| {
        DidBindingProofError::InvalidJws("compact JWS is missing payload".to_owned())
    })?;
    let _signature = parts.next().ok_or_else(|| {
        DidBindingProofError::InvalidJws("compact JWS is missing signature".to_owned())
    })?;
    if parts.next().is_some() {
        return Err(DidBindingProofError::InvalidJws(
            "compact JWS has too many segments".to_owned(),
        ));
    }
    if payload.is_empty() {
        return Err(DidBindingProofError::InvalidJws(
            "control_proof must attach the canonical binding statement payload".to_owned(),
        ));
    }

    Base64UrlUnpadded::decode_vec(payload).map_err(|e| {
        DidBindingProofError::InvalidJws(format!("payload base64url decode failed: {e}"))
    })
}

fn validate_canonical_statement_payload(
    payload_bytes: &[u8],
    claims: &BindingStatementClaims,
) -> Result<(), DidBindingProofError> {
    let canonical = canonical_json_bytes(claims)
        .map_err(|e| DidBindingProofError::CanonicalStatement(e.to_string()))?;
    if payload_bytes != canonical.as_slice() {
        return Err(DidBindingProofError::CanonicalStatementMismatch);
    }

    Ok(())
}

/// Error returned by [`verify_compact_jws_with_sdk`]. Kept private to
/// this module — callers map it onto the bound public
/// `DidBindingProofError::SignatureMismatch` /
/// `VerificationProofError::SignatureMismatch` variant.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SdkJwsVerifyError {
    #[error("compact JWS shape is invalid: {0}")]
    InvalidShape(String),
    #[error("compact JWS alg must be EdDSA, got {0}")]
    UnsupportedAlgorithm(String),
    #[error("verification_method '{0}' not present in the resolved DID document")]
    MethodNotFound(String),
    #[error("resolved verification_method JWK is not a supported Ed25519 OKP key: {0}")]
    UnsupportedJwk(String),
    #[error("Ed25519 signature did not verify: {0}")]
    SignatureMismatch(String),
}

/// Verify a compact JWS using the SDK's pure-Rust Ed25519 verifier.
///
/// CXP-0007 P2B.3.1: this replaces the previous embedded
/// `coauth_jose::jwt::Jwt::verify_with_jwks` envelope-verification path.
/// The compact-JWS shape (`header.payload.signature`) is parsed into
/// segment bytes here; the signing input
/// (`b64url(header) "." b64url(payload)`) is reconstructed from the wire
/// bytes themselves so no JWS library state intervenes between the
/// resolved DID-document JWK and the final
/// `ed25519_dalek::Verifier::verify` call. The raw Ed25519 verifying-key
/// bytes are extracted from the resolved OKP JWK via the SDK helper
/// [`cokret_signatures::proof::PublicKeyMaterial::ed25519_bytes`].
pub(crate) fn verify_compact_jws_with_sdk(
    proof_jws: &str,
    verification_methods: &[crate::handlers::cokret::VerificationMethod],
    verification_method_id: &str,
) -> Result<(), SdkJwsVerifyError> {
    let mut parts = proof_jws.split('.');
    let header_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing protected header".to_owned()))?;
    let payload_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing payload segment".to_owned()))?;
    let signature_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing signature segment".to_owned()))?;
    if parts.next().is_some() {
        return Err(SdkJwsVerifyError::InvalidShape(
            "too many segments".to_owned(),
        ));
    }

    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64u)
        .map_err(|err| SdkJwsVerifyError::InvalidShape(format!("invalid header b64url: {err}")))?;
    let header: JsonWebSignatureHeader = serde_json::from_slice(&header_bytes).map_err(|err| {
        SdkJwsVerifyError::InvalidShape(format!("invalid protected header: {err}"))
    })?;
    if header.alg() != &JsonWebSignatureAlg::EdDsa {
        return Err(SdkJwsVerifyError::UnsupportedAlgorithm(
            header.alg().to_string(),
        ));
    }

    let method = verification_methods
        .iter()
        .find(|method| method.id == verification_method_id)
        .ok_or_else(|| SdkJwsVerifyError::MethodNotFound(verification_method_id.to_owned()))?;

    let signature_bytes = Base64UrlUnpadded::decode_vec(signature_b64u)
        .map_err(|err| SdkJwsVerifyError::InvalidShape(format!("invalid sig b64url: {err}")))?;
    if signature_bytes.len() != 64 {
        return Err(SdkJwsVerifyError::SignatureMismatch(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    // RFC 7515 §5.2 signing input: ASCII bytes of "<header_b64u>.<payload_b64u>".
    let mut signing_input = String::with_capacity(header_b64u.len() + 1 + payload_b64u.len());
    signing_input.push_str(header_b64u);
    signing_input.push('.');
    signing_input.push_str(payload_b64u);

    // SDK helper: bridge JWK → raw 32-byte Ed25519 verifying key.
    let jwk_value = serde_json::to_value(&method.public_key_jwk)
        .map_err(|err| SdkJwsVerifyError::UnsupportedJwk(format!("jwk serialize: {err}")))?;
    let material = PublicKeyMaterial::Jwk { value: jwk_value };
    let key_bytes = material
        .ed25519_bytes()
        .map_err(|err| SdkJwsVerifyError::UnsupportedJwk(err.to_string()))?;
    let verifying = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|err| SdkJwsVerifyError::UnsupportedJwk(err.to_string()))?;

    verifying
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|err| SdkJwsVerifyError::SignatureMismatch(err.to_string()))
}

/// Verify a compact detached JWS (`protected..signature`) over `payload_bytes`
/// using the `kid` verification method from the protected header.
pub(crate) fn verify_detached_jws_with_sdk(
    detached_jws: &str,
    payload_bytes: &[u8],
    verification_methods: &[crate::handlers::cokret::VerificationMethod],
) -> Result<String, SdkJwsVerifyError> {
    let mut parts = detached_jws.split('.');
    let header_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing protected header".to_owned()))?;
    let payload_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing payload segment".to_owned()))?;
    let signature_b64u = parts
        .next()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing signature segment".to_owned()))?;
    if parts.next().is_some() {
        return Err(SdkJwsVerifyError::InvalidShape(
            "too many segments".to_owned(),
        ));
    }
    if !payload_b64u.is_empty() {
        return Err(SdkJwsVerifyError::InvalidShape(
            "detached JWS payload segment must be empty".to_owned(),
        ));
    }

    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64u)
        .map_err(|err| SdkJwsVerifyError::InvalidShape(format!("invalid header b64url: {err}")))?;
    let header: JsonWebSignatureHeader = serde_json::from_slice(&header_bytes).map_err(|err| {
        SdkJwsVerifyError::InvalidShape(format!("invalid protected header: {err}"))
    })?;
    if header.alg() != &JsonWebSignatureAlg::EdDsa {
        return Err(SdkJwsVerifyError::UnsupportedAlgorithm(
            header.alg().to_string(),
        ));
    }
    let verification_method = header
        .kid()
        .ok_or_else(|| SdkJwsVerifyError::InvalidShape("missing kid".to_owned()))?
        .to_owned();

    let attached_payload_b64u = Base64UrlUnpadded::encode_string(payload_bytes);
    let attached = format!("{header_b64u}.{attached_payload_b64u}.{signature_b64u}");
    verify_compact_jws_with_sdk(&attached, verification_methods, &verification_method)?;
    Ok(verification_method)
}

fn validate_binding_statement_claims(
    claims: &BindingStatementClaims,
    account_did: &str,
    cx_account_id: Ulid,
    nonce: &str,
    now: DateTime<Utc>,
) -> Result<(), DidBindingProofError> {
    if claims.kind != "cx.did_binding.control_proof.v1" {
        return Err(DidBindingProofError::StatementKindMismatch);
    }
    if claims.account_did != account_did {
        return Err(DidBindingProofError::AccountDidMismatch);
    }
    if claims.cx_account_id != cx_account_id.to_string() {
        return Err(DidBindingProofError::CxAccountIdMismatch);
    }
    if claims.nonce != nonce {
        return Err(DidBindingProofError::NonceMismatch);
    }
    let skew_secs = (claims.iat - now).num_seconds().abs();
    if skew_secs > MAX_IAT_SKEW_SECS {
        return Err(DidBindingProofError::IatOutOfRange);
    }

    Ok(())
}

// ─────────────── Verification-service proof (3PID invite chain)
// ───────────────

/// JWT claims issued by the trusted 3PID verification service.
///
/// All fields are MANDATORY. Unknown / missing claims are rejected
/// up-front via the JSON deserialiser; semantic checks
/// (`iss` / `aud` / `sub` / `exp` / `nbf`) live in
/// [`verify_verification_service_proof`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationServiceProofClaims {
    /// Issuer DID — MUST equal the configured trusted verification
    /// service DID.
    pub iss: String,
    /// Audience — MUST equal the local coauth service DID.
    pub aud: String,
    /// Subject — SHA-256 (hex) of the normalized 3PID (e.g. lowercased
    /// trimmed email address).
    pub sub: String,
    /// Expiry, Unix-epoch seconds. MUST be in the future.
    pub exp: i64,
    /// Not-before, Unix-epoch seconds. MUST be ≤ now.
    pub nbf: i64,
    /// JWT ID. Used for replay defence in the calling layer.
    pub jti: String,
    /// Single-use nonce; the upper layer (`third_party_invite`)
    /// records it for cross-proof linkage.
    pub nonce: String,
}

/// Errors returned by [`verify_verification_service_proof`].
///
/// The caller MAPS these onto the public
/// `InviteVerificationError::VerificationProofInvalid` /
/// `ProofExpired` variants in `third_party_invite.rs`. We keep this
/// enum private to coauth's service layer (i.e. not exposed on the
/// wire) so we can grow it without breaking the HTTP surface.
#[derive(Debug, Error)]
pub enum VerificationProofError {
    #[error("JWS could not be parsed: {0}")]
    InvalidJws(String),
    #[error("DID resolver failed: {0}")]
    Resolve(#[from] DidResolveError),
    #[error("DID document has no verificationMethod entries")]
    NoVerificationKey,
    #[error("JWS header is missing a verificationMethod kid")]
    MissingVerificationMethod,
    #[error("JWS alg must be EdDSA, got {0}")]
    UnsupportedAlgorithm(String),
    #[error("JWS verificationMethod is not present in the resolved DID document")]
    VerificationMethodNotFound,
    #[error("JWS signature did not verify against any verification-service key")]
    SignatureMismatch,
    #[error("iss claim {actual:?} does not match expected {expected:?}")]
    IssuerMismatch { expected: String, actual: String },
    #[error("aud claim {actual:?} does not match expected audience {expected:?}")]
    AudienceMismatch { expected: String, actual: String },
    #[error("nbf claim {nbf} is in the future (now={now})")]
    NotYetValid { nbf: i64, now: i64 },
    #[error("proof has expired: {0}")]
    Expired(String),
    #[error("sub claim is empty or malformed")]
    SubjectMalformed,
}

/// Verify a verification-service proof JWS.
///
/// Steps:
/// 1. Parse the compact JWS into a typed JWT.
/// 2. Reject empty / malformed claims (`sub`).
/// 3. Match `iss` / `aud` against the expected values.
/// 4. Reject `nbf > now` and `exp <= now`.
/// 5. Resolve the issuer DID document, verify the signature against its JWKS.
///
/// Replay defence (`jti` deduplication) is NOT done here — the caller
/// owns the nonce store so a successful verify against a replayed
/// `jti` doesn't poison the store with garbage entries before the
/// signature is checked.
#[allow(clippy::too_many_arguments)]
pub async fn verify_verification_service_proof(
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    proof_jws: &str,
    expected_issuer_did: &str,
    expected_audience: &str,
    now: DateTime<Utc>,
) -> Result<VerificationServiceProofClaims, VerificationProofError> {
    if proof_jws.trim().is_empty() {
        return Err(VerificationProofError::InvalidJws("empty JWS".into()));
    }

    let jwt: Jwt<'_, VerificationServiceProofClaims> =
        Jwt::try_from(proof_jws).map_err(|e| VerificationProofError::InvalidJws(e.to_string()))?;
    if jwt.header().alg() != &JsonWebSignatureAlg::EdDsa {
        return Err(VerificationProofError::UnsupportedAlgorithm(
            jwt.header().alg().to_string(),
        ));
    }

    let claims = jwt.payload();
    if claims.sub.trim().is_empty() {
        return Err(VerificationProofError::SubjectMalformed);
    }
    if claims.iss != expected_issuer_did {
        return Err(VerificationProofError::IssuerMismatch {
            expected: expected_issuer_did.to_owned(),
            actual: claims.iss.clone(),
        });
    }
    if claims.aud != expected_audience {
        return Err(VerificationProofError::AudienceMismatch {
            expected: expected_audience.to_owned(),
            actual: claims.aud.clone(),
        });
    }
    let now_ts = now.timestamp();
    if claims.nbf > now_ts {
        return Err(VerificationProofError::NotYetValid {
            nbf: claims.nbf,
            now: now_ts,
        });
    }
    if claims.exp <= now_ts {
        return Err(VerificationProofError::Expired(format!(
            "exp {} <= now {}",
            claims.exp, now_ts
        )));
    }

    let verification_method = jwt
        .header()
        .kid()
        .ok_or(VerificationProofError::MissingVerificationMethod)?
        .to_owned();

    // Resolve the issuer DID and check the signature against the exact
    // verificationMethod selected by the protected header.
    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            cokret_config,
            key_store,
            repo,
            &claims.iss,
        )
        .await?;

    let verification_methods = &resolution.document.verification_method;
    if verification_methods.is_empty() {
        return Err(VerificationProofError::NoVerificationKey);
    }
    verify_compact_jws_with_sdk(proof_jws, verification_methods, &verification_method)
        .map_err(|_| VerificationProofError::SignatureMismatch)?;

    Ok(claims.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_claims_default() -> BindingStatementClaims {
        BindingStatementClaims {
            kind: "cx.did_binding.control_proof.v1".to_owned(),
            account_did: "did:web:alice.example".to_owned(),
            cx_account_id: Ulid::nil().to_string(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            nonce: "nonce-123".to_owned(),
            iat: chrono::DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    #[test]
    fn binding_statement_claims_round_trip() {
        let original = statement_claims_default();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: BindingStatementClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kind, original.kind);
        assert_eq!(decoded.account_did, original.account_did);
        assert_eq!(decoded.cx_account_id, original.cx_account_id);
        assert_eq!(decoded.verification_method, original.verification_method);
        assert_eq!(decoded.nonce, original.nonce);
        assert_eq!(decoded.iat, original.iat);
    }

    #[test]
    fn binding_statement_kind_must_be_explicit() {
        // Sanity check: type discriminator literal is what the validator expects.
        assert_eq!(
            statement_claims_default().kind,
            "cx.did_binding.control_proof.v1"
        );
    }

    /// Phase P2 (B-D) regression: every DID-binding write path MUST
    /// reject non-canonical DID forms BEFORE persistence. Wire shape is
    /// the SDK's Round-4 regex `^did:[a-z0-9]+:[^\s]+$`.
    #[test]
    fn normalize_did_for_binding_enforces_round4_regex() {
        // Accepted canonical forms.
        assert_eq!(
            normalize_did_for_binding("did:web:alice.example").unwrap(),
            "did:web:alice.example"
        );
        assert_eq!(
            normalize_did_for_binding("did:webvh:example").unwrap(),
            "did:webvh:example"
        );
        assert_eq!(
            normalize_did_for_binding("  did:key:z6Mki  ").unwrap(),
            "did:key:z6Mki"
        );

        // Rejected: empty / whitespace-only / not a DID URI.
        assert!(normalize_did_for_binding("").is_err());
        assert!(normalize_did_for_binding("   ").is_err());
        assert!(normalize_did_for_binding("alice.example").is_err());

        // Rejected: forbidden `did:uuid:*` method (Round 4 reserves uuid).
        assert!(
            normalize_did_for_binding("did:uuid:550e8400-e29b-41d4-a716-446655440000").is_err()
        );

        // Rejected: method names with `.`/`-`/`_` (Round-4 tightens to
        // lowercase ASCII alnum only).
        assert!(normalize_did_for_binding("did:web.test:example").is_err());
        assert!(normalize_did_for_binding("did:web-test:example").is_err());
        assert!(normalize_did_for_binding("did:web_test:example").is_err());

        // Rejected: method-specific-id contains whitespace.
        assert!(normalize_did_for_binding("did:web:exa mple").is_err());
        assert!(normalize_did_for_binding("did:web:exa\tmple").is_err());

        // Rejected: missing method-specific-id segment entirely.
        assert!(normalize_did_for_binding("did:web:").is_err());
        assert!(normalize_did_for_binding("did::abc").is_err());
    }

    #[test]
    fn binding_statement_validation_accepts_exact_request_context() {
        let claims = statement_claims_default();

        validate_binding_statement_claims(
            &claims,
            "did:web:alice.example",
            Ulid::nil(),
            "nonce-123",
            claims.iat,
        )
        .expect("matching statement should validate");
    }

    #[test]
    fn binding_statement_validation_rejects_nonce_replay() {
        let claims = statement_claims_default();

        let err = validate_binding_statement_claims(
            &claims,
            "did:web:alice.example",
            Ulid::nil(),
            "different-nonce",
            claims.iat,
        )
        .expect_err("nonce replay must reject");

        assert!(matches!(err, DidBindingProofError::NonceMismatch));
    }

    #[test]
    fn binding_statement_validation_rejects_expired_iat() {
        let claims = statement_claims_default();
        let now = claims.iat + chrono::Duration::seconds(MAX_IAT_SKEW_SECS + 1);

        let err = validate_binding_statement_claims(
            &claims,
            "did:web:alice.example",
            Ulid::nil(),
            "nonce-123",
            now,
        )
        .expect_err("expired statement must reject");

        assert!(matches!(err, DidBindingProofError::IatOutOfRange));
    }

    #[test]
    fn binding_statement_payload_must_be_canonical() {
        let claims = statement_claims_default();
        let canonical = canonical_json_bytes(&claims).unwrap();
        validate_canonical_statement_payload(&canonical, &claims).unwrap();

        let noncanonical = serde_json::to_vec(&claims).unwrap();
        assert_ne!(noncanonical, canonical);
        let err = validate_canonical_statement_payload(&noncanonical, &claims)
            .expect_err("non-canonical payload bytes must reject");
        assert!(matches!(
            err,
            DidBindingProofError::CanonicalStatementMismatch
        ));
    }

    #[test]
    fn compact_jws_sdk_verifier_requires_eddsa_alg() {
        let header_b64u = Base64UrlUnpadded::encode_string(
            serde_json::json!({
                "alg": "HS256",
                "kid": "did:web:alice.example#key-1",
            })
            .to_string()
            .as_bytes(),
        );
        let payload_b64u = Base64UrlUnpadded::encode_string(b"{}");
        let signature_b64u = Base64UrlUnpadded::encode_string(&[0_u8; 64]);
        let compact = format!("{header_b64u}.{payload_b64u}.{signature_b64u}");

        let err = verify_compact_jws_with_sdk(&compact, &[], "did:web:alice.example#key-1")
            .expect_err("non-EdDSA alg must reject before key lookup");

        assert!(matches!(
            err,
            SdkJwsVerifyError::UnsupportedAlgorithm(alg) if alg == "HS256"
        ));
    }

    #[derive(serde::Deserialize)]
    struct CryptoSignatureFixture {
        vectors: Vec<CryptoSignatureVector>,
    }

    #[derive(serde::Deserialize)]
    struct CryptoSignatureVector {
        name: String,
        did_document_fragment: FixtureDidDocumentFragment,
        binding_object: serde_json::Value,
        canonical_binding_payload: String,
        detached_payload_b64u: String,
        proof: FixtureProof,
    }

    #[derive(serde::Deserialize)]
    struct FixtureDidDocumentFragment {
        id: String,
        #[serde(rename = "type")]
        kind: String,
        controller: String,
        #[serde(rename = "publicKeyJwk")]
        public_key_jwk: coauth_jose::jwk::PublicJsonWebKey,
    }

    #[derive(serde::Deserialize)]
    struct FixtureProof {
        verification_method: String,
        jws: String,
    }

    #[test]
    fn cokret_spec_binding_proof_fixture_verifies() {
        let fixture_path = camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("..")
            .join("cokret-spec")
            .join("spec")
            .join("v1")
            .join("artifacts")
            .join("fixtures")
            .join("crypto-signature-fixture.json");
        let raw = match std::fs::read_to_string(&fixture_path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!(
                    "skipping cokret-spec fixture test; missing {}",
                    fixture_path.as_str()
                );
                return;
            }
            Err(error) => panic!(
                "failed reading cokret-spec fixture {}: {error}",
                fixture_path.as_str()
            ),
        };

        let fixture: CryptoSignatureFixture = serde_json::from_str(&raw).unwrap();
        let vector = fixture
            .vectors
            .iter()
            .find(|vector| vector.name == "ck.vector.encoding.crypto.ed25519_detached_jws.v1")
            .expect("expected Ed25519 detached JWS binding vector");

        let canonical = canonical_json_bytes(&vector.binding_object).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            vector.canonical_binding_payload
        );
        assert_eq!(
            Base64UrlUnpadded::encode_string(&canonical),
            vector.detached_payload_b64u
        );

        let compact = attach_detached_jws(&vector.proof.jws, &vector.detached_payload_b64u);
        let jwt: Jwt<'_, serde_json::Value> = Jwt::try_from(compact.as_str()).unwrap();
        let kid = jwt.header().kid().expect("fixture JWS must carry kid");
        assert_eq!(kid, vector.proof.verification_method);
        assert_eq!(kid, vector.did_document_fragment.id);
        assert_eq!(
            vector
                .binding_object
                .get("verification_method")
                .and_then(serde_json::Value::as_str),
            Some(kid)
        );

        let method = crate::handlers::cokret::VerificationMethod {
            id: vector.did_document_fragment.id.clone(),
            kind: vector.did_document_fragment.kind.clone(),
            controller: vector.did_document_fragment.controller.clone(),
            public_key_jwk: vector.did_document_fragment.public_key_jwk.clone(),
        };
        // CXP-0007 P2B.3.1: verify through the SDK-mediated pure-Rust path.
        verify_compact_jws_with_sdk(&compact, std::slice::from_ref(&method), kid)
            .expect("fixture JWS should verify against DID method key");
        assert!(
            verify_compact_jws_with_sdk(
                &compact,
                std::slice::from_ref(&method),
                "did:web:alice.example#unknown",
            )
            .is_err()
        );

        let mut tampered_binding = vector.binding_object.clone();
        tampered_binding["event_digest"] =
            serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
        let tampered_payload = canonical_json_bytes(&tampered_binding).unwrap();
        assert_ne!(tampered_payload, canonical);
        let tampered_compact = attach_detached_jws(
            &vector.proof.jws,
            &Base64UrlUnpadded::encode_string(&tampered_payload),
        );
        assert!(
            verify_compact_jws_with_sdk(&tampered_compact, std::slice::from_ref(&method), kid,)
                .is_err(),
            "altered canonical binding payload must break the fixture signature"
        );
    }

    fn attach_detached_jws(detached_jws: &str, payload_b64u: &str) -> String {
        let mut parts = detached_jws.split('.');
        let protected = parts.next().expect("detached JWS header segment");
        let payload = parts.next().expect("detached JWS payload segment");
        let signature = parts.next().expect("detached JWS signature segment");
        assert!(parts.next().is_none());
        assert_eq!(payload, "");
        format!("{protected}.{payload_b64u}.{signature}")
    }
}
