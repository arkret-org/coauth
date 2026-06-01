//! A crate to store keys which can then be used to sign and verify JWTs.

use std::{ops::Deref, sync::Arc};

use coauth_iana::jose::{JsonWebKeyType, JsonWebSignatureAlg};
pub use coauth_jose::jwk::{JsonWebKey, JsonWebKeySet};
use coauth_jose::{
    constraints::Constrainable,
    jwa::{AsymmetricSigningKey, AsymmetricVerifyingKey},
    jwk::{JsonWebKeyPublicParameters, ParametersInfo, PublicJsonWebKeySet, Thumbprint},
};
use der::{Decode, Encode, EncodePem, zeroize::Zeroizing};
use elliptic_curve::{pkcs8::EncodePrivateKey, sec1::ToEncodedPoint};
use pem_rfc7468::PemLabel;
use pkcs1::EncodeRsaPrivateKey;
use pkcs8::{AssociatedOid, DecodePrivateKey, PrivateKeyInfo};
use rand_core::{CryptoRng, RngCore};
use rsa::BigUint;
use thiserror::Error;

mod encrypter;

pub use aead;

pub use self::encrypter::{DecryptError, Encrypter};

/// Error type used when a key could not be loaded
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("Failed to read PEM document")]
    Pem {
        #[from]
        inner: pem_rfc7468::Error,
    },

    #[error("Invalid RSA private key")]
    Rsa {
        #[from]
        inner: rsa::errors::Error,
    },

    #[error("Failed to decode PKCS1-encoded RSA key")]
    Pkcs1 {
        #[from]
        inner: pkcs1::Error,
    },

    #[error("Failed to decode PKCS8-encoded key")]
    Pkcs8 {
        #[from]
        inner: pkcs8::Error,
    },

    #[error(transparent)]
    Der {
        #[from]
        inner: der::Error,
    },

    #[error(transparent)]
    Spki {
        #[from]
        inner: spki::Error,
    },

    #[error("Unknown Elliptic Curve OID {oid}")]
    UnknownEllipticCurveOid { oid: const_oid::ObjectIdentifier },

    #[error("Unknown algorithm OID {oid}")]
    UnknownAlgorithmOid { oid: const_oid::ObjectIdentifier },

    #[error("Unsupported PEM label {label:?}")]
    UnsupportedPemLabel { label: String },

    #[error("Missing parameters in SEC1 key")]
    MissingSec1Parameters,

    #[error("Missing curve name in SEC1 parameters")]
    MissingSec1CurveName,

    #[error("Key is encrypted and no password was provided")]
    Encrypted,

    #[error("Key is not encrypted but a password was provided")]
    Unencrypted,

    #[error("Unsupported format")]
    UnsupportedFormat,

    #[error("Could not decode encrypted payload")]
    InEncrypted {
        #[source]
        inner: Box<LoadError>,
    },
}

impl LoadError {
    /// Returns `true` if the load error is [`Encrypted`].
    ///
    /// [`Encrypted`]: LoadError::Encrypted
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted)
    }

    /// Returns `true` if the load error is [`Unencrypted`].
    ///
    /// [`Unencrypted`]: LoadError::Unencrypted
    #[must_use]
    pub fn is_unencrypted(&self) -> bool {
        matches!(self, Self::Unencrypted)
    }
}

/// OID constant for Ed25519 (RFC 8410)
const ED25519_ALGORITHM_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.101.112");

/// A single private key
#[non_exhaustive]
#[derive(Debug)]
pub enum PrivateKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    EcP256(Box<elliptic_curve::SecretKey<p256::NistP256>>),
    EcP384(Box<elliptic_curve::SecretKey<p384::NistP384>>),
    EcP521(Box<elliptic_curve::SecretKey<p521::NistP521>>),
    EcK256(Box<elliptic_curve::SecretKey<k256::Secp256k1>>),
    OkpEd25519(Box<ed25519_dalek::SigningKey>),
}

/// Error returned when the key can't be used for the requested algorithm
#[derive(Debug, Error)]
#[error("Wrong algorithm for key")]
pub struct WrongAlgorithmError;

/// Helper: parse a DER-encoded PKCS#1 RSA private key into our enum.
fn parse_pkcs1_rsa_key(pkcs1_key: &pkcs1::RsaPrivateKey) -> Result<PrivateKey, LoadError> {
    if pkcs1_key.version() != pkcs1::Version::TwoPrime {
        return Err(pkcs1::Error::Version.into());
    }

    let n = BigUint::from_bytes_be(pkcs1_key.modulus.as_bytes());
    let e = BigUint::from_bytes_be(pkcs1_key.public_exponent.as_bytes());
    let d = BigUint::from_bytes_be(pkcs1_key.private_exponent.as_bytes());
    let primes = vec![
        BigUint::from_bytes_be(pkcs1_key.prime1.as_bytes()),
        BigUint::from_bytes_be(pkcs1_key.prime2.as_bytes()),
    ];

    let rsa_key = rsa::RsaPrivateKey::from_components(n, e, d, primes)?;
    Ok(PrivateKey::Rsa(Box::new(rsa_key)))
}

/// Helper: resolve a PKCS#8 `PrivateKeyInfo` into the appropriate key variant.
fn parse_pkcs8_key_info(info: PrivateKeyInfo) -> Result<PrivateKey, LoadError> {
    let algo_oid = info.algorithm.oid;

    if algo_oid == pkcs1::ALGORITHM_OID {
        return Ok(PrivateKey::Rsa(Box::new(info.try_into()?)));
    }

    if algo_oid == elliptic_curve::ALGORITHM_OID {
        let curve_oid = info.algorithm.parameters_oid()?;
        return match curve_oid {
            oid if oid == p256::NistP256::OID => Ok(PrivateKey::EcP256(Box::new(info.try_into()?))),
            oid if oid == p384::NistP384::OID => Ok(PrivateKey::EcP384(Box::new(info.try_into()?))),
            oid if oid == p521::NistP521::OID => Ok(PrivateKey::EcP521(Box::new(info.try_into()?))),
            oid if oid == k256::Secp256k1::OID => {
                Ok(PrivateKey::EcK256(Box::new(info.try_into()?)))
            }
            other => Err(LoadError::UnknownEllipticCurveOid { oid: other }),
        };
    }

    if algo_oid == ED25519_ALGORITHM_OID {
        let serialized = info.to_der()?;
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_der(&serialized)?;
        return Ok(PrivateKey::OkpEd25519(Box::new(signing_key)));
    }

    Err(LoadError::UnknownAlgorithmOid { oid: algo_oid })
}

/// Helper: decode a SEC1-encoded EC private key into the correct curve variant.
fn parse_sec1_ec_key(ec_key: sec1::EcPrivateKey) -> Result<PrivateKey, LoadError> {
    let params = ec_key.parameters.ok_or(LoadError::MissingSec1Parameters)?;

    let curve_oid = params
        .named_curve()
        .ok_or(LoadError::MissingSec1CurveName)?;

    match curve_oid {
        oid if oid == p256::NistP256::OID => Ok(PrivateKey::EcP256(Box::new(ec_key.try_into()?))),
        oid if oid == p384::NistP384::OID => Ok(PrivateKey::EcP384(Box::new(ec_key.try_into()?))),
        oid if oid == p521::NistP521::OID => Ok(PrivateKey::EcP521(Box::new(ec_key.try_into()?))),
        oid if oid == k256::Secp256k1::OID => Ok(PrivateKey::EcK256(Box::new(ec_key.try_into()?))),
        other => Err(LoadError::UnknownEllipticCurveOid { oid: other }),
    }
}

/// Encode an EC secret key to SEC1 DER with the named-curve OID included,
/// matching OpenSSL's default output format.
fn ec_to_sec1_der<C>(key: &elliptic_curve::SecretKey<C>) -> Result<Zeroizing<Vec<u8>>, der::Error>
where
    C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic + AssociatedOid,
    elliptic_curve::PublicKey<C>: elliptic_curve::sec1::ToEncodedPoint<C>,
    C::FieldBytesSize: elliptic_curve::sec1::ModulusSize,
{
    let scalar_bytes = Zeroizing::new(key.to_bytes());
    let pub_point = key.public_key().to_encoded_point(false);
    let ec_private = sec1::EcPrivateKey {
        private_key: &scalar_bytes,
        parameters: Some(sec1::EcParameters::NamedCurve(C::OID)),
        public_key: Some(pub_point.as_bytes()),
    };
    Ok(Zeroizing::new(ec_private.to_der()?))
}

/// Encode an EC secret key to SEC1 PEM with the named-curve OID included.
fn ec_to_sec1_pem<C>(
    key: &elliptic_curve::SecretKey<C>,
    line_ending: pem_rfc7468::LineEnding,
) -> Result<Zeroizing<String>, der::Error>
where
    C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic + AssociatedOid,
    elliptic_curve::PublicKey<C>: elliptic_curve::sec1::ToEncodedPoint<C>,
    C::FieldBytesSize: elliptic_curve::sec1::ModulusSize,
{
    let scalar_bytes = Zeroizing::new(key.to_bytes());
    let pub_point = key.public_key().to_encoded_point(false);
    let ec_private = sec1::EcPrivateKey {
        private_key: &scalar_bytes,
        parameters: Some(sec1::EcParameters::NamedCurve(C::OID)),
        public_key: Some(pub_point.as_bytes()),
    };
    Ok(Zeroizing::new(ec_private.to_pem(line_ending)?))
}

impl PrivateKey {
    /// Serialize the key as a DER document
    ///
    /// It will use the most common format depending on the key type: PKCS1 for
    /// RSA keys, SEC1 for NIST/secp256k1 elliptic curve keys and PKCS8 for
    /// OKP keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoding failed
    pub fn to_der(&self) -> Result<Zeroizing<Vec<u8>>, pkcs1::Error> {
        match self {
            Self::Rsa(k) => Ok(k.to_pkcs1_der()?.to_bytes()),
            Self::EcP256(k) => Ok(ec_to_sec1_der(k)?),
            Self::EcP384(k) => Ok(ec_to_sec1_der(k)?),
            Self::EcP521(k) => Ok(ec_to_sec1_der(k)?),
            Self::EcK256(k) => Ok(ec_to_sec1_der(k)?),
            Self::OkpEd25519(k) => Ok(k.to_pkcs8_der()?.to_bytes()),
        }
    }

    /// Serialize the key as a PKCS8 DER document
    ///
    /// # Errors
    ///
    /// Returns an error if the encoding failed
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, pkcs8::Error> {
        let doc = match self {
            Self::Rsa(k) => k.to_pkcs8_der()?,
            Self::EcP256(k) => k.to_pkcs8_der()?,
            Self::EcP384(k) => k.to_pkcs8_der()?,
            Self::EcP521(k) => k.to_pkcs8_der()?,
            Self::EcK256(k) => k.to_pkcs8_der()?,
            Self::OkpEd25519(k) => k.to_pkcs8_der()?,
        };
        Ok(doc.to_bytes())
    }

    /// Serialize the key as a PEM document
    ///
    /// It will use the most common format depending on the key type: PKCS1 for
    /// RSA keys, SEC1 for NIST/secp256k1 elliptic curve keys and PKCS8 for
    /// OKP keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoding failed
    pub fn to_pem(
        &self,
        line_ending: pem_rfc7468::LineEnding,
    ) -> Result<Zeroizing<String>, pkcs1::Error> {
        match self {
            Self::Rsa(k) => Ok(k.to_pkcs1_pem(line_ending)?),
            Self::EcP256(k) => Ok(ec_to_sec1_pem(k, line_ending)?),
            Self::EcP384(k) => Ok(ec_to_sec1_pem(k, line_ending)?),
            Self::EcP521(k) => Ok(ec_to_sec1_pem(k, line_ending)?),
            Self::EcK256(k) => Ok(ec_to_sec1_pem(k, line_ending)?),
            Self::OkpEd25519(k) => Ok(k.to_pkcs8_pem(line_ending)?),
        }
    }

    /// Load an unencrypted PEM or DER encoded key
    ///
    /// # Errors
    ///
    /// Returns the same kind of errors as [`Self::load_pem`] and
    /// [`Self::load_der`].
    pub fn load(bytes: &[u8]) -> Result<Self, LoadError> {
        // Attempt PEM first when the bytes are valid UTF-8.
        if let Ok(text) = std::str::from_utf8(bytes) {
            match Self::load_pem(text) {
                Ok(key) => return Ok(key),
                Err(LoadError::Pem { .. }) => { /* fall through to DER */ }
                Err(other) => return Err(other),
            }
        }

        Self::load_der(bytes)
    }

    /// Load an encrypted PEM or DER encoded key, and decrypt it with the given
    /// password
    ///
    /// # Errors
    ///
    /// Returns the same kind of errors as [`Self::load_encrypted_pem`] and
    /// [`Self::load_encrypted_der`].
    pub fn load_encrypted(bytes: &[u8], password: impl AsRef<[u8]>) -> Result<Self, LoadError> {
        if let Ok(text) = std::str::from_utf8(bytes) {
            match Self::load_encrypted_pem(text, password.as_ref()) {
                Ok(key) => return Ok(key),
                Err(LoadError::Pem { .. }) => { /* fall through to DER */ }
                Err(other) => return Err(other),
            }
        }

        Self::load_encrypted_der(bytes, password)
    }

    /// Load an encrypted key from DER-encoded bytes, and decrypt it with the
    /// given password
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - the key is in an non-encrypted format
    ///   - the key could not be decrypted
    ///   - the PKCS8 key could not be loaded
    pub fn load_encrypted_der(der: &[u8], password: impl AsRef<[u8]>) -> Result<Self, LoadError> {
        if let Ok(encrypted_info) = pkcs8::EncryptedPrivateKeyInfo::from_der(der) {
            let decrypted = encrypted_info.decrypt(password)?;
            return Self::load_der(decrypted.as_bytes()).map_err(|inner| LoadError::InEncrypted {
                inner: Box::new(inner),
            });
        }

        // If we can parse the DER as any unencrypted format, report the mismatch.
        let is_unencrypted = pkcs8::PrivateKeyInfo::from_der(der).is_ok()
            || sec1::EcPrivateKey::from_der(der).is_ok()
            || pkcs1::RsaPrivateKey::from_der(der).is_ok();

        if is_unencrypted {
            return Err(LoadError::Unencrypted);
        }

        Err(LoadError::UnsupportedFormat)
    }

    /// Load an unencrypted key from DER-encoded bytes
    ///
    /// It tries to decode the bytes from the various known DER formats (PKCS8,
    /// SEC1 and PKCS1, in that order), and return the first one that works.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - the PKCS8 key is encrypted
    ///   - none of the formats could be decoded
    ///   - the PKCS8/SEC1/PKCS1 key could not be loaded
    pub fn load_der(der: &[u8]) -> Result<Self, LoadError> {
        // Reject encrypted keys early.
        if pkcs8::EncryptedPrivateKeyInfo::from_der(der).is_ok() {
            return Err(LoadError::Encrypted);
        }

        // Try PKCS#8 first (most general).
        if let Ok(info) = pkcs8::PrivateKeyInfo::from_der(der) {
            return parse_pkcs8_key_info(info);
        }

        // Then SEC1 for EC keys.
        if let Ok(ec_key) = sec1::EcPrivateKey::from_der(der) {
            return parse_sec1_ec_key(ec_key);
        }

        // Finally PKCS#1 for RSA.
        if let Ok(rsa_key) = pkcs1::RsaPrivateKey::from_der(der) {
            return parse_pkcs1_rsa_key(&rsa_key);
        }

        Err(LoadError::UnsupportedFormat)
    }

    /// Load an encrypted key from a PEM-encode string, and decrypt it with the
    /// given password
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - the file is not a signel PEM document
    ///   - the PEM label is not a supported format
    ///   - the underlying key is not encrypted (use [`Self::load`] instead)
    ///   - the decryption failed
    ///   - the pkcs8 key could not be loaded
    pub fn load_encrypted_pem(pem: &str, password: impl AsRef<[u8]>) -> Result<Self, LoadError> {
        let (label, raw) = pem_rfc7468::decode_vec(pem.as_bytes())?;

        if label == pkcs8::EncryptedPrivateKeyInfo::PEM_LABEL {
            let encrypted_info = pkcs8::EncryptedPrivateKeyInfo::from_der(&raw)?;
            let decrypted = encrypted_info.decrypt(password)?;
            return Self::load_der(decrypted.as_bytes()).map_err(|inner| LoadError::InEncrypted {
                inner: Box::new(inner),
            });
        }

        // Known unencrypted labels -> wrong function
        let unencrypted_labels = [
            pkcs1::RsaPrivateKey::PEM_LABEL,
            pkcs8::PrivateKeyInfo::PEM_LABEL,
            sec1::EcPrivateKey::PEM_LABEL,
        ];

        if unencrypted_labels.contains(&label) {
            return Err(LoadError::Unencrypted);
        }

        Err(LoadError::UnsupportedPemLabel {
            label: label.to_owned(),
        })
    }

    /// Load an unencrypted key from a PEM-encode string
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - the file is not a signel PEM document
    ///   - the PEM label is not a supported format
    ///   - the underlying key is encrypted (use [`Self::load_encrypted`]
    ///     instead)
    ///   - the PKCS8/PKCS1/SEC1 key could not be loaded
    pub fn load_pem(pem: &str) -> Result<Self, LoadError> {
        let (label, raw) = pem_rfc7468::decode_vec(pem.as_bytes())?;

        if label == pkcs1::RsaPrivateKey::PEM_LABEL {
            let rsa_key = pkcs1::RsaPrivateKey::from_der(&raw)?;
            return parse_pkcs1_rsa_key(&rsa_key);
        }

        if label == pkcs8::PrivateKeyInfo::PEM_LABEL {
            let info = pkcs8::PrivateKeyInfo::from_der(&raw)?;
            return parse_pkcs8_key_info(info);
        }

        if label == sec1::EcPrivateKey::PEM_LABEL {
            let ec_key = sec1::EcPrivateKey::from_der(&raw)?;
            return parse_sec1_ec_key(ec_key);
        }

        if label == pkcs8::EncryptedPrivateKeyInfo::PEM_LABEL {
            return Err(LoadError::Encrypted);
        }

        Err(LoadError::UnsupportedPemLabel {
            label: label.to_owned(),
        })
    }

    /// Get an [`AsymmetricVerifyingKey`] out of this key, for the specified
    /// [`JsonWebSignatureAlg`]
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not suited for the selected algorithm
    pub fn verifying_key_for_alg(
        &self,
        alg: &JsonWebSignatureAlg,
    ) -> Result<AsymmetricVerifyingKey, WrongAlgorithmError> {
        self.try_build_verifier(alg).ok_or(WrongAlgorithmError)
    }

    /// Internal helper that returns `None` when the key/alg combination is
    /// invalid, keeping the public API's error type unchanged.
    fn try_build_verifier(&self, alg: &JsonWebSignatureAlg) -> Option<AsymmetricVerifyingKey> {
        match self {
            Self::Rsa(rsa_key) => {
                let public = rsa_key.to_public_key();
                let vk = match alg {
                    JsonWebSignatureAlg::Rs256 => AsymmetricVerifyingKey::rs256(public),
                    JsonWebSignatureAlg::Rs384 => AsymmetricVerifyingKey::rs384(public),
                    JsonWebSignatureAlg::Rs512 => AsymmetricVerifyingKey::rs512(public),
                    JsonWebSignatureAlg::Ps256 => AsymmetricVerifyingKey::ps256(public),
                    JsonWebSignatureAlg::Ps384 => AsymmetricVerifyingKey::ps384(public),
                    JsonWebSignatureAlg::Ps512 => AsymmetricVerifyingKey::ps512(public),
                    _ => return None,
                };
                Some(vk)
            }

            Self::EcP256(k) if matches!(alg, JsonWebSignatureAlg::Es256) => {
                Some(AsymmetricVerifyingKey::es256(k.public_key()))
            }

            Self::EcP384(k) if matches!(alg, JsonWebSignatureAlg::Es384) => {
                Some(AsymmetricVerifyingKey::es384(k.public_key()))
            }

            Self::EcP521(k) if matches!(alg, JsonWebSignatureAlg::Es512) => {
                Some(AsymmetricVerifyingKey::es512(k.public_key()))
            }

            Self::EcK256(k) if matches!(alg, JsonWebSignatureAlg::Es256K) => {
                Some(AsymmetricVerifyingKey::es256k(k.public_key()))
            }

            Self::OkpEd25519(k) if matches!(alg, JsonWebSignatureAlg::EdDsa) => {
                Some(AsymmetricVerifyingKey::eddsa(k.verifying_key()))
            }

            _ => None,
        }
    }

    /// Get a [`AsymmetricSigningKey`] out of this key, for the specified
    /// [`JsonWebSignatureAlg`]
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not suited for the selected algorithm
    pub fn signing_key_for_alg(
        &self,
        alg: &JsonWebSignatureAlg,
    ) -> Result<AsymmetricSigningKey, WrongAlgorithmError> {
        self.try_build_signer(alg).ok_or(WrongAlgorithmError)
    }

    /// Internal helper that returns `None` when the key/alg combination is
    /// invalid.
    fn try_build_signer(&self, alg: &JsonWebSignatureAlg) -> Option<AsymmetricSigningKey> {
        match self {
            Self::Rsa(rsa_key) => {
                let cloned: rsa::RsaPrivateKey = *rsa_key.clone();
                let sk = match alg {
                    JsonWebSignatureAlg::Rs256 => AsymmetricSigningKey::rs256(cloned),
                    JsonWebSignatureAlg::Rs384 => AsymmetricSigningKey::rs384(cloned),
                    JsonWebSignatureAlg::Rs512 => AsymmetricSigningKey::rs512(cloned),
                    JsonWebSignatureAlg::Ps256 => AsymmetricSigningKey::ps256(cloned),
                    JsonWebSignatureAlg::Ps384 => AsymmetricSigningKey::ps384(cloned),
                    JsonWebSignatureAlg::Ps512 => AsymmetricSigningKey::ps512(cloned),
                    _ => return None,
                };
                Some(sk)
            }

            Self::EcP256(k) if matches!(alg, JsonWebSignatureAlg::Es256) => {
                Some(AsymmetricSigningKey::es256(*k.clone()))
            }

            Self::EcP384(k) if matches!(alg, JsonWebSignatureAlg::Es384) => {
                Some(AsymmetricSigningKey::es384(*k.clone()))
            }

            Self::EcP521(k) if matches!(alg, JsonWebSignatureAlg::Es512) => {
                Some(AsymmetricSigningKey::es512(*k.clone()))
            }

            Self::EcK256(k) if matches!(alg, JsonWebSignatureAlg::Es256K) => {
                Some(AsymmetricSigningKey::es256k(*k.clone()))
            }

            Self::OkpEd25519(k) if matches!(alg, JsonWebSignatureAlg::EdDsa) => {
                Some(AsymmetricSigningKey::eddsa(k.as_ref().clone()))
            }

            _ => None,
        }
    }

    /// Generate a RSA key with 2048 bit size
    ///
    /// # Errors
    ///
    /// Returns any error from the underlying key generator
    pub fn generate_rsa<R: RngCore + CryptoRng>(mut rng: R) -> Result<Self, rsa::errors::Error> {
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
        Ok(Self::Rsa(Box::new(key)))
    }

    /// Generate an Elliptic Curve key for the P-256 curve
    pub fn generate_ec_p256<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        Self::EcP256(Box::new(elliptic_curve::SecretKey::random(&mut rng)))
    }

    /// Generate an Elliptic Curve key for the P-384 curve
    pub fn generate_ec_p384<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        Self::EcP384(Box::new(elliptic_curve::SecretKey::random(&mut rng)))
    }

    /// Generate an Elliptic Curve key for the P-521 curve
    pub fn generate_ec_p521<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        Self::EcP521(Box::new(elliptic_curve::SecretKey::random(&mut rng)))
    }

    /// Generate an Elliptic Curve key for the secp256k1 curve
    pub fn generate_ec_k256<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        Self::EcK256(Box::new(elliptic_curve::SecretKey::random(&mut rng)))
    }

    /// Generate an Ed25519 key.
    pub fn generate_ed25519<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        Self::OkpEd25519(Box::new(ed25519_dalek::SigningKey::generate(&mut rng)))
    }
}

impl From<&PrivateKey> for JsonWebKeyPublicParameters {
    fn from(key: &PrivateKey) -> Self {
        match key {
            PrivateKey::Rsa(k) => k.to_public_key().into(),
            PrivateKey::EcP256(k) => k.public_key().into(),
            PrivateKey::EcP384(k) => k.public_key().into(),
            PrivateKey::EcP521(k) => k.public_key().into(),
            PrivateKey::EcK256(k) => k.public_key().into(),
            PrivateKey::OkpEd25519(k) => k.verifying_key().into(),
        }
    }
}

impl ParametersInfo for PrivateKey {
    fn kty(&self) -> JsonWebKeyType {
        match self {
            Self::Rsa(_) => JsonWebKeyType::Rsa,
            Self::EcP256(_) | Self::EcP384(_) | Self::EcP521(_) | Self::EcK256(_) => {
                JsonWebKeyType::Ec
            }
            Self::OkpEd25519(_) => JsonWebKeyType::Okp,
        }
    }

    fn possible_algs(&self) -> &'static [JsonWebSignatureAlg] {
        match self {
            Self::Rsa(_) => &[
                JsonWebSignatureAlg::Rs256,
                JsonWebSignatureAlg::Rs384,
                JsonWebSignatureAlg::Rs512,
                JsonWebSignatureAlg::Ps256,
                JsonWebSignatureAlg::Ps384,
                JsonWebSignatureAlg::Ps512,
            ],
            Self::EcP256(_) => &[JsonWebSignatureAlg::Es256],
            Self::EcP384(_) => &[JsonWebSignatureAlg::Es384],
            Self::EcP521(_) => &[JsonWebSignatureAlg::Es512],
            Self::EcK256(_) => &[JsonWebSignatureAlg::Es256K],
            Self::OkpEd25519(_) => &[JsonWebSignatureAlg::EdDsa],
        }
    }
}

impl Thumbprint for PrivateKey {
    fn thumbprint_prehashed(&self) -> String {
        JsonWebKeyPublicParameters::from(self).thumbprint_prehashed()
    }
}

/// Cache key for a built [`AsymmetricSigningKey`]: the JWK `kid` (or an empty
/// string when the key has none) paired with the signature algorithm.
type SignerCacheKey = (String, JsonWebSignatureAlg);

/// A structure to store a list of [`PrivateKey`]. The keys are held in an
/// [`Arc`] to ensure they are only loaded once in memory and allow cheap
/// cloning
#[derive(Clone, Default)]
pub struct Keystore {
    inner: Arc<JsonWebKeySet<PrivateKey>>,

    /// Precomputed public JWKS, built once in [`Keystore::new`] so that
    /// [`Keystore::public_jwks`] does not have to rebuild it on every call.
    public_jwks: Arc<PublicJsonWebKeySet>,

    /// Cache of already-built signers, keyed by `(kid, alg)`, so that the
    /// (potentially expensive) RSA/EC key clone + signer construction in
    /// [`PrivateKey::try_build_signer`] happens at most once per
    /// `(kid, alg)` pair.
    signer_cache: Arc<
        std::sync::RwLock<std::collections::HashMap<SignerCacheKey, Arc<AsymmetricSigningKey>>>,
    >,
}

impl Keystore {
    /// Create a keystore out of a JSON Web Key Set
    #[must_use]
    pub fn new(keys: JsonWebKeySet<PrivateKey>) -> Self {
        let inner = Arc::new(keys);
        let public_jwks: PublicJsonWebKeySet = inner
            .iter()
            .map(|jwk| jwk.cloned_map(|priv_params: &PrivateKey| priv_params.into()))
            .collect();
        let public_jwks = Arc::new(public_jwks);
        Self {
            inner,
            public_jwks,
            signer_cache: Arc::default(),
        }
    }

    /// Get the public JSON Web Key Set for the keys stored in this [`Keystore`]
    ///
    /// The set is computed once in [`Keystore::new`]; this returns a clone of
    /// the precomputed value (the keyset is immutable after construction).
    #[must_use]
    pub fn public_jwks(&self) -> PublicJsonWebKeySet {
        (*self.public_jwks).clone()
    }

    /// Get a signer for the given algorithm, reusing a previously built signer
    /// when available.
    ///
    /// On a cache miss this finds the JWK matching the algorithm (via
    /// [`JsonWebKeySet::signing_key_for_algorithm`]), builds the signer once
    /// through the existing [`PrivateKey::signing_key_for_alg`] path, caches it
    /// keyed by `(kid, alg)` and returns the [`Arc`].
    ///
    /// # Errors
    ///
    /// Returns [`WrongAlgorithmError`] if no key in the store can sign with the
    /// requested algorithm.
    pub fn signer_for_algorithm(
        &self,
        alg: &JsonWebSignatureAlg,
    ) -> Result<Arc<AsymmetricSigningKey>, WrongAlgorithmError> {
        let jwk = self
            .inner
            .signing_key_for_algorithm(alg)
            .ok_or(WrongAlgorithmError)?;
        let kid = jwk.kid().unwrap_or_default().to_owned();
        let cache_key: SignerCacheKey = (kid, alg.clone());

        // Fast path: return a cached signer if present.
        if let Ok(cache) = self.signer_cache.read()
            && let Some(signer) = cache.get(&cache_key)
        {
            return Ok(Arc::clone(signer));
        }

        // Cache miss: build the signer once via the existing builder path.
        let signer = Arc::new(jwk.params().signing_key_for_alg(alg)?);

        if let Ok(mut cache) = self.signer_cache.write() {
            // Another thread may have inserted the same key in the meantime;
            // `entry` keeps whichever signer is already there.
            let entry = cache
                .entry(cache_key)
                .or_insert_with(|| Arc::clone(&signer));
            return Ok(Arc::clone(entry));
        }

        Ok(signer)
    }
}

impl Deref for Keystore {
    type Target = JsonWebKeySet<PrivateKey>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
