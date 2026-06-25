use coauth_iana::jose::JsonWebSignatureAlg;
use thiserror::Error;

use super::signature::Signature;

// An enum of all supported symmetric signing algorithms keys
#[non_exhaustive]
pub enum SymmetricKey {
    Hs256(super::Hs256Key),
    Hs384(super::Hs384Key),
    Hs512(super::Hs512Key),
}

#[derive(Debug, Error)]
pub enum InvalidAlgorithm {
    #[error("Invalid algorithm {alg} used for symmetric key")]
    UnsupportedAlgorithm {
        alg: JsonWebSignatureAlg,
        key: Vec<u8>,
    },

    /// The supplied key is shorter than the minimum required by RFC 7518 §3.2
    /// for the requested HMAC algorithm.
    #[error(
        "key of {actual} bytes is too short for {alg}; RFC 7518 §3.2 requires at least {required} bytes"
    )]
    KeyTooShort {
        alg: JsonWebSignatureAlg,
        actual: usize,
        required: usize,
    },
}

impl SymmetricKey {
    /// Create a new symmetric key for the given algorithm with the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the algorithm is not supported, or if the key is
    /// shorter than the minimum length mandated by RFC 7518 §3.2 for the HMAC
    /// algorithm (HS256/HS384/HS512 require at least 32/48/64 bytes
    /// respectively, i.e. a key at least as large as the hash output).
    pub fn new_for_alg(key: Vec<u8>, alg: &JsonWebSignatureAlg) -> Result<Self, InvalidAlgorithm> {
        let required = match alg {
            JsonWebSignatureAlg::Hs256 => 32,
            JsonWebSignatureAlg::Hs384 => 48,
            JsonWebSignatureAlg::Hs512 => 64,
            _ => {
                return Err(InvalidAlgorithm::UnsupportedAlgorithm {
                    alg: alg.clone(),
                    key,
                });
            }
        };

        if key.len() < required {
            return Err(InvalidAlgorithm::KeyTooShort {
                alg: alg.clone(),
                actual: key.len(),
                required,
            });
        }

        match alg {
            JsonWebSignatureAlg::Hs256 => Ok(Self::hs256(key)),
            JsonWebSignatureAlg::Hs384 => Ok(Self::hs384(key)),
            JsonWebSignatureAlg::Hs512 => Ok(Self::hs512(key)),
            _ => unreachable!("non-HMAC algorithms are rejected above"),
        }
    }

    /// Create a new symmetric key using the HS256 algorithm with the given key.
    #[must_use]
    pub const fn hs256(key: Vec<u8>) -> Self {
        Self::Hs256(super::Hs256Key::new(key))
    }

    /// Create a new symmetric key using the HS384 algorithm with the given key.
    #[must_use]
    pub const fn hs384(key: Vec<u8>) -> Self {
        Self::Hs384(super::Hs384Key::new(key))
    }

    /// Create a new symmetric key using the HS512 algorithm with the given key.
    #[must_use]
    pub const fn hs512(key: Vec<u8>) -> Self {
        Self::Hs512(super::Hs512Key::new(key))
    }
}

impl From<super::Hs256Key> for SymmetricKey {
    fn from(key: super::Hs256Key) -> Self {
        Self::Hs256(key)
    }
}

impl From<super::Hs384Key> for SymmetricKey {
    fn from(key: super::Hs384Key) -> Self {
        Self::Hs384(key)
    }
}

impl From<super::Hs512Key> for SymmetricKey {
    fn from(key: super::Hs512Key) -> Self {
        Self::Hs512(key)
    }
}

impl signature::RandomizedSigner<Signature> for SymmetricKey {
    fn try_sign_with_rng(
        &self,
        _rng: &mut impl signature::rand_core::CryptoRngCore,
        msg: &[u8],
    ) -> Result<Signature, signature::Error> {
        // HMAC signatures are deterministic and do not consume caller RNG.
        // Implementing RandomizedSigner by delegating to Signer lets generic
        // JWT signing code treat symmetric and asymmetric keys uniformly.
        signature::Signer::try_sign(self, msg)
    }
}

impl signature::Signer<Signature> for SymmetricKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        match self {
            Self::Hs256(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Hs384(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Hs512(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
        }
    }
}

impl signature::Verifier<Signature> for SymmetricKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        match self {
            Self::Hs256(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Hs384(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Hs512(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
        }
    }
}
