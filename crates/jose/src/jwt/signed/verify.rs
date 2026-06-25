// Signature verification for `Jwt`.
//
// Supports verification against a single typed key, a symmetric shared
// secret, or a full public JWKS (trying each candidate that matches the
// header constraints).

use signature::{SignatureEncoding, Verifier};
use thiserror::Error;

use super::Jwt;
use crate::constraints::ConstraintSet;
use crate::jwk::PublicJsonWebKeySet;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A single-key verification failure.
#[derive(Debug, Error)]
pub enum JwtVerificationError {
    #[error("could not interpret the raw signature bytes")]
    ParseSignature,

    #[error("cryptographic signature verification failed")]
    Verify {
        #[source]
        inner: signature::Error,
    },

    #[error("token marks header parameters as critical that this implementation does not support")]
    UnsupportedCriticalHeader,
}

/// Returns `true` when the header declares a non-empty `crit` list.
///
/// Per RFC 7515 §4.1.11 the `crit` parameter enumerates header parameters that
/// a recipient MUST understand and process. This implementation supports no
/// extension header parameters, so any non-empty `crit` list is unsatisfiable
/// and the token must be rejected.
fn header_has_unsupported_crit(header: &crate::jwt::JsonWebSignatureHeader) -> bool {
    header.crit().is_some_and(|crit| !crit.is_empty())
}

impl JwtVerificationError {
    #[allow(clippy::needless_pass_by_value)]
    fn bad_encoding<E>(_cause: E) -> Self {
        Self::ParseSignature
    }

    fn failed(cause: signature::Error) -> Self {
        Self::Verify { inner: cause }
    }
}

/// Returned when *no* candidate key from a set could verify the token.
#[derive(Debug, Error, Default)]
#[error("no matching key could verify the signature")]
pub struct NoKeyWorked {
    _inner: (),
}

// ---------------------------------------------------------------------------
// Verification methods on Jwt
// ---------------------------------------------------------------------------

impl<T> Jwt<'_, T> {
    /// Check the signature against a single typed verifying key.
    ///
    /// # Errors
    ///
    /// Fails when the raw bytes cannot be interpreted as the expected
    /// signature encoding, or when the cryptographic check itself fails.
    pub fn verify<K, S>(&self, key: &K) -> Result<(), JwtVerificationError>
    where
        K: Verifier<S>,
        S: SignatureEncoding,
    {
        // SECURITY: per RFC 7515 §4.1.11, reject any token that marks header
        // parameters as critical (`crit`). No extension parameter is
        // understood by this implementation, so a non-empty `crit` list can
        // never be satisfied and MUST cause verification to fail.
        if header_has_unsupported_crit(&self.header) {
            return Err(JwtVerificationError::UnsupportedCriticalHeader);
        }
        let typed_sig = S::try_from(&self.signature).map_err(JwtVerificationError::bad_encoding)?;
        key.verify(self.raw.signed_part().as_bytes(), &typed_sig)
            .map_err(JwtVerificationError::failed)
    }

    /// Verify using a symmetric (HMAC) shared secret.
    ///
    /// The algorithm is derived from the token header.
    ///
    /// # Errors
    ///
    /// Fails when the algorithm is unsupported or the signature is wrong.
    pub fn verify_with_shared_secret(&self, secret: Vec<u8>) -> Result<(), NoKeyWorked> {
        // SECURITY: per RFC 7515 §4.1.11, reject any token that marks header
        // parameters as critical (`crit`). This implementation understands no
        // extension parameters, so a non-empty `crit` list can never be
        // satisfied and MUST cause verification to fail.
        if header_has_unsupported_crit(&self.header) {
            return Err(NoKeyWorked::default());
        }
        // SECURITY: refuse `alg=none` (and any algorithm not on the
        // supported whitelist) before touching the key material. This
        // closes the classic JWT alg-stripping / alg-confusion attacks
        // where an attacker rewrites a token's header to claim no
        // signature is required.
        if !crate::jwa::is_supported_signing_alg(self.header.alg()) {
            return Err(NoKeyWorked::default());
        }
        let sym = crate::jwa::SymmetricKey::new_for_alg(secret, self.header.alg())
            .map_err(|_| NoKeyWorked::default())?;
        self.verify(&sym).map_err(|_| NoKeyWorked::default())
    }

    /// Try every matching key in the supplied JWKS until one succeeds.
    ///
    /// Keys are filtered by the header constraints (`alg`, `kid`, ...).
    ///
    /// # Errors
    ///
    /// Returns [`NoKeyWorked`] when no candidate key produces a valid
    /// signature.
    pub fn verify_with_jwks(&self, jwks: &PublicJsonWebKeySet) -> Result<(), NoKeyWorked> {
        // SECURITY: per RFC 7515 §4.1.11, reject any token that marks header
        // parameters as critical (`crit`). This implementation understands no
        // extension parameters, so a non-empty `crit` list can never be
        // satisfied and MUST cause verification to fail.
        if header_has_unsupported_crit(&self.header) {
            return Err(NoKeyWorked::default());
        }
        // SECURITY: gate verification on the supported-signing whitelist
        // first. The `alg=none` value (and any value not present in
        // `SUPPORTED_SIGNING_ALGORITHMS`) is rejected before any JWK
        // candidate is considered, so a forged token cannot bypass the
        // signature check by claiming an empty / unknown algorithm.
        if !crate::jwa::is_supported_signing_alg(self.header.alg()) {
            return Err(NoKeyWorked::default());
        }

        // SECURITY: only consider keys whose `use` is `sig` (or unspecified),
        // mirroring the signing path (`signing_key_for_algorithm`). This
        // prevents an encryption-only key from being used to verify a
        // signature.
        let constraints =
            ConstraintSet::from(&self.header).use_(&coauth_iana::jose::JsonWebKeyUse::Sig);
        let candidates = constraints.filter(&**jwks);

        for candidate in candidates {
            let Ok(vk) = crate::jwa::AsymmetricVerifyingKey::from_jwk_and_alg(
                candidate.params(),
                self.header.alg(),
            ) else {
                continue;
            };

            if self.verify(&vk).is_ok() {
                return Ok(());
            }
        }

        Err(NoKeyWorked::default())
    }
}
