use coauth_iana::jose::JsonWebSignatureAlg;
use sha2::{Sha256, Sha384, Sha512};

mod asymmetric;
pub(crate) mod hmac;
mod signature;
mod symmetric;

pub use self::asymmetric::{
    AsymmetricKeyFromJwkError, AsymmetricSigningKey, AsymmetricVerifyingKey,
};
pub use self::signature::Signature;
pub use self::symmetric::{InvalidAlgorithm, SymmetricKey};

pub type Hs256Key = self::hmac::Hmac<Sha256>;
pub type Hs384Key = self::hmac::Hmac<Sha384>;
pub type Hs512Key = self::hmac::Hmac<Sha512>;

pub type Rs256SigningKey = rsa::pkcs1v15::SigningKey<Sha256>;
pub type Rs256VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha256>;
pub type Rs384SigningKey = rsa::pkcs1v15::SigningKey<Sha384>;
pub type Rs384VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha384>;
pub type Rs512SigningKey = rsa::pkcs1v15::SigningKey<Sha512>;
pub type Rs512VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha512>;

pub type Ps256SigningKey = rsa::pss::SigningKey<Sha256>;
pub type Ps256VerifyingKey = rsa::pss::VerifyingKey<Sha256>;
pub type Ps384SigningKey = rsa::pss::SigningKey<Sha384>;
pub type Ps384VerifyingKey = rsa::pss::VerifyingKey<Sha384>;
pub type Ps512SigningKey = rsa::pss::SigningKey<Sha512>;
pub type Ps512VerifyingKey = rsa::pss::VerifyingKey<Sha512>;

pub type Es256SigningKey = ecdsa::SigningKey<p256::NistP256>;
pub type Es256VerifyingKey = ecdsa::VerifyingKey<p256::NistP256>;
pub type Es384SigningKey = ecdsa::SigningKey<p384::NistP384>;
pub type Es384VerifyingKey = ecdsa::VerifyingKey<p384::NistP384>;
pub type Es512SigningKey = p521::ecdsa::SigningKey;
pub type Es512VerifyingKey = p521::ecdsa::VerifyingKey;
pub type Es256KSigningKey = ecdsa::SigningKey<k256::Secp256k1>;
pub type Es256KVerifyingKey = ecdsa::VerifyingKey<k256::Secp256k1>;
pub type Ed25519SigningKey = ed25519_dalek::SigningKey;
pub type Ed25519VerifyingKey = ed25519_dalek::VerifyingKey;

/// All the signing algorithms supported by this crate.
///
/// SECURITY: `alg=none` is intentionally NOT listed here and MUST never
/// be added. Verification helpers (`Jwt::verify_with_jwks`, etc.) reject
/// any algorithm that is not present in this whitelist before any key
/// lookup, which closes the classic JWT alg-confusion / alg-stripping
/// attack family (a peer cannot get an unsigned token accepted just by
/// setting `alg` to `none`).
pub const SUPPORTED_SIGNING_ALGORITHMS: [JsonWebSignatureAlg; 14] = [
    JsonWebSignatureAlg::Hs256,
    JsonWebSignatureAlg::Hs384,
    JsonWebSignatureAlg::Hs512,
    JsonWebSignatureAlg::Rs256,
    JsonWebSignatureAlg::Rs384,
    JsonWebSignatureAlg::Rs512,
    JsonWebSignatureAlg::Ps256,
    JsonWebSignatureAlg::Ps384,
    JsonWebSignatureAlg::Ps512,
    JsonWebSignatureAlg::Es256,
    JsonWebSignatureAlg::Es384,
    JsonWebSignatureAlg::Es256K,
    JsonWebSignatureAlg::Es512,
    JsonWebSignatureAlg::Ed25519,
];

/// Returns `true` when `alg` is in the supported whitelist.
///
/// Used by JWT verification entry points to refuse `alg=none` (and any
/// not-yet-supported algorithm) up front.
#[must_use]
pub fn is_supported_signing_alg(alg: &JsonWebSignatureAlg) -> bool {
    SUPPORTED_SIGNING_ALGORITHMS
        .iter()
        .any(|candidate| candidate == alg)
}
