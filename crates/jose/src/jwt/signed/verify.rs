// Signature verification for `Jwt`.
//
// Supports verification against a single typed key, a symmetric shared
// secret, or a full public JWKS (trying each candidate that matches the
// header constraints).

use signature::{SignatureEncoding, Verifier};
use thiserror::Error;

use super::Jwt;
use crate::{constraints::ConstraintSet, jwk::PublicJsonWebKeySet};

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
        let constraints = ConstraintSet::from(&self.header);
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
