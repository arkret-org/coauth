//! JOSE (JSON Object Signing and Encryption) IANA registry values.
//!
//! See <https://www.iana.org/assignments/jose/jose.xhtml>

use crate::macros::open_enum;

open_enum! {
    /// JSON Web Signature algorithm (`alg` parameter).
    ///
    /// Source: <https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv>
    pub enum JsonWebSignatureAlg {
        /// HMAC using SHA-256
        Hs256 => "HS256",
        /// HMAC using SHA-384
        Hs384 => "HS384",
        /// HMAC using SHA-512
        Hs512 => "HS512",
        /// RSASSA-PKCS1-v1_5 using SHA-256
        Rs256 => "RS256",
        /// RSASSA-PKCS1-v1_5 using SHA-384
        Rs384 => "RS384",
        /// RSASSA-PKCS1-v1_5 using SHA-512
        Rs512 => "RS512",
        /// ECDSA using P-256 and SHA-256
        Es256 => "ES256",
        /// ECDSA using P-384 and SHA-384
        Es384 => "ES384",
        /// ECDSA using P-521 and SHA-512
        Es512 => "ES512",
        /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
        Ps256 => "PS256",
        /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
        Ps384 => "PS384",
        /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
        Ps512 => "PS512",
        /// No digital signature or MAC performed
        None => "none",
        /// EdDSA signature algorithms
        EdDsa => "EdDSA",
        /// ECDSA using secp256k1 curve and SHA-256
        Es256K => "ES256K",
        /// EdDSA using Ed25519 curve
        Ed25519 => "Ed25519",
        /// EdDSA using Ed448 curve
        Ed448 => "Ed448",
    }
}

open_enum! {
    /// JSON Web Encryption algorithm (`alg` parameter).
    ///
    /// Source: <https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv>
    pub enum JsonWebEncryptionAlg {
        /// RSAES-PKCS1-v1_5
        Rsa15 => "RSA1_5",
        /// RSAES OAEP using default parameters
        RsaOaep => "RSA-OAEP",
        /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
        RsaOaep256 => "RSA-OAEP-256",
        /// AES Key Wrap using 128-bit key
        A128Kw => "A128KW",
        /// AES Key Wrap using 192-bit key
        A192Kw => "A192KW",
        /// AES Key Wrap using 256-bit key
        A256Kw => "A256KW",
        /// Direct use of a shared symmetric key
        Dir => "dir",
        /// ECDH-ES using Concat KDF
        EcdhEs => "ECDH-ES",
        /// ECDH-ES using Concat KDF and A128KW wrapping
        EcdhEsA128Kw => "ECDH-ES+A128KW",
        /// ECDH-ES using Concat KDF and A192KW wrapping
        EcdhEsA192Kw => "ECDH-ES+A192KW",
        /// ECDH-ES using Concat KDF and A256KW wrapping
        EcdhEsA256Kw => "ECDH-ES+A256KW",
        /// AES-GCM key wrap using 128-bit key
        A128Gcmkw => "A128GCMKW",
        /// AES-GCM key wrap using 192-bit key
        A192Gcmkw => "A192GCMKW",
        /// AES-GCM key wrap using 256-bit key
        A256Gcmkw => "A256GCMKW",
        /// PBES2 with HMAC SHA-256 and A128KW wrapping
        Pbes2Hs256A128Kw => "PBES2-HS256+A128KW",
        /// PBES2 with HMAC SHA-384 and A192KW wrapping
        Pbes2Hs384A192Kw => "PBES2-HS384+A192KW",
        /// PBES2 with HMAC SHA-512 and A256KW wrapping
        Pbes2Hs512A256Kw => "PBES2-HS512+A256KW",
        /// RSAES OAEP using SHA-384 and MGF1 with SHA-384
        RsaOaep384 => "RSA-OAEP-384",
        /// RSAES OAEP using SHA-512 and MGF1 with SHA-512
        RsaOaep512 => "RSA-OAEP-512",
    }
}

open_enum! {
    /// JSON Web Encryption content encryption algorithm (`enc` parameter).
    ///
    /// Source: <https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv>
    pub enum JsonWebEncryptionEnc {
        /// AES_128_CBC_HMAC_SHA_256 authenticated encryption
        A128CbcHs256 => "A128CBC-HS256",
        /// AES_192_CBC_HMAC_SHA_384 authenticated encryption
        A192CbcHs384 => "A192CBC-HS384",
        /// AES_256_CBC_HMAC_SHA_512 authenticated encryption
        A256CbcHs512 => "A256CBC-HS512",
        /// AES-GCM using 128-bit key
        A128Gcm => "A128GCM",
        /// AES-GCM using 192-bit key
        A192Gcm => "A192GCM",
        /// AES-GCM using 256-bit key
        A256Gcm => "A256GCM",
    }
}

open_enum! {
    /// JSON Web Encryption compression algorithm (`zip` parameter).
    pub enum JsonWebEncryptionCompressionAlgorithm {
        /// DEFLATE compression
        Def => "DEF",
    }
}

open_enum! {
    /// JSON Web Key type (`kty` parameter).
    ///
    /// Source: <https://www.iana.org/assignments/jose/web-key-types.csv>
    pub enum JsonWebKeyType {
        /// Elliptic Curve
        Ec => "EC",
        /// RSA
        Rsa => "RSA",
        /// Octet sequence (symmetric key)
        Oct => "oct",
        /// Octet Key Pair (Edwards curves)
        Okp => "OKP",
    }
}

open_enum! {
    /// JSON Web Key EC elliptic curve (`crv` parameter for `kty: EC`).
    ///
    /// Source: <https://www.iana.org/assignments/jose/web-key-elliptic-curve.csv>
    pub enum JsonWebKeyEcEllipticCurve {
        /// P-256 (NIST) curve
        P256 => "P-256",
        /// P-384 (NIST) curve
        P384 => "P-384",
        /// P-521 (NIST) curve
        P521 => "P-521",
        /// secp256k1 (Bitcoin) curve
        Secp256K1 => "secp256k1",
    }
}

open_enum! {
    /// JSON Web Key OKP elliptic curve (`crv` parameter for `kty: OKP`).
    ///
    /// Source: <https://www.iana.org/assignments/jose/web-key-elliptic-curve.csv>
    pub enum JsonWebKeyOkpEllipticCurve {
        /// Ed25519 signature algorithm key pairs
        Ed25519 => "Ed25519",
        /// Ed448 signature algorithm key pairs
        Ed448 => "Ed448",
        /// X25519 function key pairs
        X25519 => "X25519",
        /// X448 function key pairs
        X448 => "X448",
    }
}

open_enum! {
    /// JSON Web Key intended use (`use` parameter).
    ///
    /// Source: <https://www.iana.org/assignments/jose/web-key-use.csv>
    pub enum JsonWebKeyUse {
        /// Digital Signature or MAC
        Sig => "sig",
        /// Encryption
        Enc => "enc",
    }
}

open_enum! {
    /// JSON Web Key operation (`key_ops` parameter).
    ///
    /// Source: <https://www.iana.org/assignments/jose/web-key-operations.csv>
    pub enum JsonWebKeyOperation {
        /// Compute digital signature or MAC
        Sign => "sign",
        /// Verify digital signature or MAC
        Verify => "verify",
        /// Encrypt content
        Encrypt => "encrypt",
        /// Decrypt content and validate decryption
        Decrypt => "decrypt",
        /// Encrypt key
        WrapKey => "wrapKey",
        /// Decrypt key and validate decryption
        UnwrapKey => "unwrapKey",
        /// Derive key
        DeriveKey => "deriveKey",
        /// Derive bits not to be used as a key
        DeriveBits => "deriveBits",
    }
}
