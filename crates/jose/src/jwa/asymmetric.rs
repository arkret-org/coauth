use digest::Digest;
use elliptic_curve::sec1::ToEncodedPoint;
use coauth_iana::jose::{
    JsonWebKeyEcEllipticCurve, JsonWebKeyOkpEllipticCurve, JsonWebSignatureAlg,
};
use sha2::{Sha256, Sha384, Sha512};
use signature::{Signer as _, rand_core::CryptoRngCore};
use thiserror::Error;

use super::signature::Signature;
use crate::jwk::{InvalidOkpParameters, JsonWebKeyPrivateParameters, JsonWebKeyPublicParameters};

#[derive(Debug, Error)]
pub enum AsymmetricKeyFromJwkError {
    #[error("Invalid RSA parameters")]
    Rsa {
        #[from]
        inner: rsa::errors::Error,
    },

    #[error("Invalid Elliptic Curve parameters")]
    EllipticCurve {
        #[from]
        inner: elliptic_curve::Error,
    },

    #[error("Invalid OKP parameters")]
    Okp {
        #[from]
        inner: InvalidOkpParameters,
    },

    #[error("Unsupported algorithm {alg}")]
    UnsupportedAlgorithm { alg: JsonWebSignatureAlg },

    #[error("Key not suitable for algorithm {alg}")]
    KeyNotSuitable { alg: JsonWebSignatureAlg },
}

/// An enum of all supported asymmetric signature algorithms verifying keys
#[non_exhaustive]
pub enum AsymmetricSigningKey {
    Rs256(super::Rs256SigningKey),
    Rs384(super::Rs384SigningKey),
    Rs512(super::Rs512SigningKey),
    Ps256(super::Ps256SigningKey),
    Ps384(super::Ps384SigningKey),
    Ps512(super::Ps512SigningKey),
    Es256(super::Es256SigningKey),
    Es384(super::Es384SigningKey),
    Es512(super::Es512SigningKey),
    Es256K(super::Es256KSigningKey),
    EdDsa(super::EdDsaSigningKey),
}

impl AsymmetricSigningKey {
    /// Create a new signing key with the RS256 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn rs256(key: rsa::RsaPrivateKey) -> Self {
        Self::Rs256(rsa::pkcs1v15::SigningKey::new(key))
    }

    /// Create a new signing key with the RS384 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn rs384(key: rsa::RsaPrivateKey) -> Self {
        Self::Rs384(rsa::pkcs1v15::SigningKey::new(key))
    }

    /// Create a new signing key with the RS512 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn rs512(key: rsa::RsaPrivateKey) -> Self {
        Self::Rs512(rsa::pkcs1v15::SigningKey::new(key))
    }

    /// Create a new signing key with the PS256 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn ps256(key: rsa::RsaPrivateKey) -> Self {
        Self::Ps256(rsa::pss::SigningKey::new_with_salt_len(
            key,
            Sha256::output_size(),
        ))
    }

    /// Create a new signing key with the PS384 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn ps384(key: rsa::RsaPrivateKey) -> Self {
        Self::Ps384(rsa::pss::SigningKey::new_with_salt_len(
            key,
            Sha384::output_size(),
        ))
    }

    /// Create a new signing key with the PS512 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn ps512(key: rsa::RsaPrivateKey) -> Self {
        Self::Ps512(rsa::pss::SigningKey::new_with_salt_len(
            key,
            Sha512::output_size(),
        ))
    }

    /// Create a new signing key with the ES256 algorithm from the given ECDSA
    /// private key.
    #[must_use]
    pub fn es256(key: elliptic_curve::SecretKey<p256::NistP256>) -> Self {
        Self::Es256(ecdsa::SigningKey::from(key))
    }

    /// Create a new signing key with the ES384 algorithm from the given ECDSA
    /// private key.
    #[must_use]
    pub fn es384(key: elliptic_curve::SecretKey<p384::NistP384>) -> Self {
        Self::Es384(ecdsa::SigningKey::from(key))
    }

    /// Create a new signing key with the ES512 algorithm from the given ECDSA
    /// private key.
    #[must_use]
    pub fn es512(key: elliptic_curve::SecretKey<p521::NistP521>) -> Self {
        let bytes = key.to_bytes();
        let key = super::Es512SigningKey::from_bytes(&bytes)
            .expect("P-521 secret key should convert to a signing key");
        Self::Es512(key)
    }

    /// Create a new signing key with the ES256K algorithm from the given ECDSA
    /// private key.
    #[must_use]
    pub fn es256k(key: elliptic_curve::SecretKey<k256::Secp256k1>) -> Self {
        Self::Es256K(ecdsa::SigningKey::from(key))
    }

    /// Create a new signing key with the EdDSA algorithm from the given OKP
    /// private key.
    #[must_use]
    pub fn eddsa(key: ed25519_dalek::SigningKey) -> Self {
        Self::EdDsa(key)
    }

    /// Create a new signing key for the given algorithm from the given private
    /// JWK parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the key parameters are not suitable for the given
    /// algorithm.
    pub fn from_jwk_and_alg(
        params: &JsonWebKeyPrivateParameters,
        alg: &JsonWebSignatureAlg,
    ) -> Result<Self, AsymmetricKeyFromJwkError> {
        match (params, alg) {
            (JsonWebKeyPrivateParameters::Rsa(params), alg) => match alg {
                JsonWebSignatureAlg::Rs256 => Ok(Self::rs256(params.try_into()?)),
                JsonWebSignatureAlg::Rs384 => Ok(Self::rs384(params.try_into()?)),
                JsonWebSignatureAlg::Rs512 => Ok(Self::rs512(params.try_into()?)),
                JsonWebSignatureAlg::Ps256 => Ok(Self::ps256(params.try_into()?)),
                JsonWebSignatureAlg::Ps384 => Ok(Self::ps384(params.try_into()?)),
                JsonWebSignatureAlg::Ps512 => Ok(Self::ps512(params.try_into()?)),
                _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
            },

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es256)
                if params.crv == JsonWebKeyEcEllipticCurve::P256 =>
            {
                Ok(Self::es256(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es384)
                if params.crv == JsonWebKeyEcEllipticCurve::P384 =>
            {
                Ok(Self::es384(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es512)
                if params.crv == JsonWebKeyEcEllipticCurve::P521 =>
            {
                Ok(Self::es512(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es256K)
                if params.crv == JsonWebKeyEcEllipticCurve::Secp256K1 =>
            {
                Ok(Self::es256k(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Okp(params), JsonWebSignatureAlg::EdDsa)
                if params.crv == JsonWebKeyOkpEllipticCurve::Ed25519 =>
            {
                Ok(Self::eddsa(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Okp(_params), JsonWebSignatureAlg::EdDsa) => {
                Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() })
            }

            (JsonWebKeyPrivateParameters::Okp(_params), _) => {
                Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() })
            }

            _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
        }
    }
}

impl From<super::Rs256SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Rs256SigningKey) -> Self {
        Self::Rs256(key)
    }
}

impl From<super::Rs384SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Rs384SigningKey) -> Self {
        Self::Rs384(key)
    }
}

impl From<super::Rs512SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Rs512SigningKey) -> Self {
        Self::Rs512(key)
    }
}

impl From<super::Ps256SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Ps256SigningKey) -> Self {
        Self::Ps256(key)
    }
}

impl From<super::Ps384SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Ps384SigningKey) -> Self {
        Self::Ps384(key)
    }
}

impl From<super::Ps512SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Ps512SigningKey) -> Self {
        Self::Ps512(key)
    }
}

impl From<super::Es256SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es256SigningKey) -> Self {
        Self::Es256(key)
    }
}

impl From<super::Es384SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es384SigningKey) -> Self {
        Self::Es384(key)
    }
}

impl From<super::Es512SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es512SigningKey) -> Self {
        Self::Es512(key)
    }
}

impl From<super::Es256KSigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es256KSigningKey) -> Self {
        Self::Es256K(key)
    }
}

impl From<super::EdDsaSigningKey> for AsymmetricSigningKey {
    fn from(key: super::EdDsaSigningKey) -> Self {
        Self::EdDsa(key)
    }
}

impl signature::RandomizedSigner<Signature> for AsymmetricSigningKey {
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<Signature, signature::Error> {
        match self {
            Self::Rs256(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Rs384(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Rs512(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Ps256(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Ps384(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Ps512(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es256(key) => {
                let signature: ecdsa::Signature<_> = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es384(key) => {
                let signature: ecdsa::Signature<_> = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es512(key) => {
                let signature: ecdsa::Signature<_> = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es256K(key) => {
                let signature: ecdsa::Signature<_> = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::EdDsa(key) => {
                let signature: ed25519_dalek::Signature = key.sign(msg);
                Ok(Signature::from_signature(&signature))
            }
        }
    }
}

/// An enum of all supported asymmetric signature algorithms signing keys
#[non_exhaustive]
pub enum AsymmetricVerifyingKey {
    Rs256(super::Rs256VerifyingKey),
    Rs384(super::Rs384VerifyingKey),
    Rs512(super::Rs512VerifyingKey),
    Ps256(super::Ps256VerifyingKey),
    Ps384(super::Ps384VerifyingKey),
    Ps512(super::Ps512VerifyingKey),
    Es256(super::Es256VerifyingKey),
    Es384(super::Es384VerifyingKey),
    Es512(super::Es512VerifyingKey),
    Es256K(super::Es256KVerifyingKey),
    EdDsa(super::EdDsaVerifyingKey),
}

impl AsymmetricVerifyingKey {
    /// Create a new verifying key with the RS256 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn rs256(key: rsa::RsaPublicKey) -> Self {
        Self::Rs256(rsa::pkcs1v15::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the RS384 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn rs384(key: rsa::RsaPublicKey) -> Self {
        Self::Rs384(rsa::pkcs1v15::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the RS512 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn rs512(key: rsa::RsaPublicKey) -> Self {
        Self::Rs512(rsa::pkcs1v15::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the PS256 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn ps256(key: rsa::RsaPublicKey) -> Self {
        Self::Ps256(rsa::pss::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the PS384 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn ps384(key: rsa::RsaPublicKey) -> Self {
        Self::Ps384(rsa::pss::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the PS512 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn ps512(key: rsa::RsaPublicKey) -> Self {
        Self::Ps512(rsa::pss::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the ES256 algorithm from the given ECDSA
    /// public key.
    #[must_use]
    pub fn es256(key: elliptic_curve::PublicKey<p256::NistP256>) -> Self {
        Self::Es256(ecdsa::VerifyingKey::from(key))
    }

    /// Create a new verifying key with the ES384 algorithm from the given ECDSA
    /// public key.
    #[must_use]
    pub fn es384(key: elliptic_curve::PublicKey<p384::NistP384>) -> Self {
        Self::Es384(ecdsa::VerifyingKey::from(key))
    }

    /// Create a new verifying key with the ES512 algorithm from the given
    /// ECDSA public key.
    #[must_use]
    pub fn es512(key: elliptic_curve::PublicKey<p521::NistP521>) -> Self {
        let encoded = key.to_encoded_point(false);
        let key = super::Es512VerifyingKey::from_sec1_bytes(encoded.as_bytes())
            .expect("P-521 public key should convert to a verifying key");
        Self::Es512(key)
    }

    /// Create a new verifying key with the ES256K algorithm from the given
    /// ECDSA public key.
    #[must_use]
    pub fn es256k(key: elliptic_curve::PublicKey<k256::Secp256k1>) -> Self {
        Self::Es256K(ecdsa::VerifyingKey::from(key))
    }

    /// Create a new verifying key with the EdDSA algorithm from the given OKP
    /// public key.
    #[must_use]
    pub fn eddsa(key: ed25519_dalek::VerifyingKey) -> Self {
        Self::EdDsa(key)
    }

    /// Create a new verifying key for the given algorithm from the given public
    /// JWK parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the key parameters are not suitable for the given
    /// algorithm.
    pub fn from_jwk_and_alg(
        params: &JsonWebKeyPublicParameters,
        alg: &JsonWebSignatureAlg,
    ) -> Result<Self, AsymmetricKeyFromJwkError> {
        match (params, alg) {
            (JsonWebKeyPublicParameters::Rsa(params), alg) => match alg {
                JsonWebSignatureAlg::Rs256 => Ok(Self::rs256(params.try_into()?)),
                JsonWebSignatureAlg::Rs384 => Ok(Self::rs384(params.try_into()?)),
                JsonWebSignatureAlg::Rs512 => Ok(Self::rs512(params.try_into()?)),
                JsonWebSignatureAlg::Ps256 => Ok(Self::ps256(params.try_into()?)),
                JsonWebSignatureAlg::Ps384 => Ok(Self::ps384(params.try_into()?)),
                JsonWebSignatureAlg::Ps512 => Ok(Self::ps512(params.try_into()?)),
                _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
            },

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es256)
                if params.crv == JsonWebKeyEcEllipticCurve::P256 =>
            {
                Ok(Self::es256(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es384)
                if params.crv == JsonWebKeyEcEllipticCurve::P384 =>
            {
                Ok(Self::es384(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es512)
                if params.crv == JsonWebKeyEcEllipticCurve::P521 =>
            {
                Ok(Self::es512(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es256K)
                if params.crv == JsonWebKeyEcEllipticCurve::Secp256K1 =>
            {
                Ok(Self::es256k(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Okp(params), JsonWebSignatureAlg::EdDsa)
                if params.crv == JsonWebKeyOkpEllipticCurve::Ed25519 =>
            {
                Ok(Self::eddsa(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Okp(_params), JsonWebSignatureAlg::EdDsa) => {
                Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() })
            }

            (JsonWebKeyPublicParameters::Okp(_params), _) => {
                Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() })
            }

            _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
        }
    }
}

impl From<super::Rs256VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Rs256VerifyingKey) -> Self {
        Self::Rs256(key)
    }
}

impl From<super::Rs384VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Rs384VerifyingKey) -> Self {
        Self::Rs384(key)
    }
}

impl From<super::Rs512VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Rs512VerifyingKey) -> Self {
        Self::Rs512(key)
    }
}

impl From<super::Ps256VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Ps256VerifyingKey) -> Self {
        Self::Ps256(key)
    }
}

impl From<super::Ps384VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Ps384VerifyingKey) -> Self {
        Self::Ps384(key)
    }
}

impl From<super::Ps512VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Ps512VerifyingKey) -> Self {
        Self::Ps512(key)
    }
}

impl From<super::Es256VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es256VerifyingKey) -> Self {
        Self::Es256(key)
    }
}

impl From<super::Es384VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es384VerifyingKey) -> Self {
        Self::Es384(key)
    }
}

impl From<super::Es512VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es512VerifyingKey) -> Self {
        Self::Es512(key)
    }
}

impl From<super::Es256KVerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es256KVerifyingKey) -> Self {
        Self::Es256K(key)
    }
}

impl From<super::EdDsaVerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::EdDsaVerifyingKey) -> Self {
        Self::EdDsa(key)
    }
}

impl signature::Verifier<Signature> for AsymmetricVerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), ecdsa::Error> {
        match self {
            Self::Rs256(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Rs384(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Rs512(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Ps256(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Ps384(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Ps512(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es256(key) => {
                let signature: ecdsa::Signature<_> = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es384(key) => {
                let signature: ecdsa::Signature<_> = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es512(key) => {
                let signature: ecdsa::Signature<_> = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es256K(key) => {
                let signature: ecdsa::Signature<_> = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::EdDsa(key) => {
                let signature: ed25519_dalek::Signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::{PrivateJsonWebKeySet, PublicJsonWebKeySet};

    fn load_private_keys() -> PrivateJsonWebKeySet {
        serde_json::from_str(include_str!("../../tests/keys/jwks.priv.json")).unwrap()
    }

    fn load_public_keys() -> PublicJsonWebKeySet {
        serde_json::from_str(include_str!("../../tests/keys/jwks.pub.json")).unwrap()
    }

    #[test]
    fn es512_rejects_wrong_curve_private_jwk() {
        let jwks = load_private_keys();
        let p256 = jwks
            .iter()
            .find(|key| {
                matches!(
                    key.params(),
                    JsonWebKeyPrivateParameters::Ec(params)
                        if params.crv == JsonWebKeyEcEllipticCurve::P256
                )
            })
            .unwrap();

        let result =
            AsymmetricSigningKey::from_jwk_and_alg(p256.params(), &JsonWebSignatureAlg::Es512);

        match result {
            Err(AsymmetricKeyFromJwkError::KeyNotSuitable {
                alg: JsonWebSignatureAlg::Es512,
            }) => {}
            Err(_) => panic!("unexpected error variant"),
            Ok(_) => panic!("expected ES512 to reject a P-256 key"),
        }
    }

    #[test]
    fn eddsa_rejects_ed448_public_jwk() {
        let jwks = load_public_keys();
        let ed448 = jwks
            .iter()
            .find(|key| {
                matches!(
                    key.params(),
                    JsonWebKeyPublicParameters::Okp(params)
                        if params.crv == JsonWebKeyOkpEllipticCurve::Ed448
                )
            })
            .unwrap();

        let result =
            AsymmetricVerifyingKey::from_jwk_and_alg(ed448.params(), &JsonWebSignatureAlg::EdDsa);

        match result {
            Err(AsymmetricKeyFromJwkError::KeyNotSuitable {
                alg: JsonWebSignatureAlg::EdDsa,
            }) => {}
            Err(_) => panic!("unexpected error variant"),
            Ok(_) => panic!("expected EdDSA to reject an Ed448 key"),
        }
    }
}
