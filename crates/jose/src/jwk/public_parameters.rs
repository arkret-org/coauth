// JWK public parameters for RSA, EC, and OKP key types.
//
// Each key type has its own parameter struct that implements
// `ParametersInfo` to report the key type and compatible algorithms.

use coauth_iana::jose::{
    JsonWebKeyEcEllipticCurve, JsonWebKeyOkpEllipticCurve, JsonWebKeyType, JsonWebSignatureAlg,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ParametersInfo;
use crate::{base64::Base64UrlNoPad, jwk::Thumbprint};

// ---------------------------------------------------------------------------
// RSA parameters
// ---------------------------------------------------------------------------

/// Public parameters for an RSA key (modulus `n` and exponent `e`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RsaPublicParameters {
    /// RSA modulus
    #[schemars(with = "String")]
    n: Base64UrlNoPad,

    /// RSA public exponent
    #[schemars(with = "String")]
    e: Base64UrlNoPad,
}

impl RsaPublicParameters {
    /// Create a new set of RSA public parameters from the raw
    /// base64url-encoded modulus and exponent.
    pub const fn new(n: Base64UrlNoPad, e: Base64UrlNoPad) -> Self {
        Self { n, e }
    }
}

/// All RSA signature algorithms that are compatible with any RSA key.
const RSA_COMPATIBLE_ALGS: &[JsonWebSignatureAlg] = &[
    JsonWebSignatureAlg::Rs256,
    JsonWebSignatureAlg::Rs384,
    JsonWebSignatureAlg::Rs512,
    JsonWebSignatureAlg::Ps256,
    JsonWebSignatureAlg::Ps384,
    JsonWebSignatureAlg::Ps512,
];

impl ParametersInfo for RsaPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Rsa
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        RSA_COMPATIBLE_ALGS
    }
}

// ---------------------------------------------------------------------------
// Elliptic Curve (EC) parameters
// ---------------------------------------------------------------------------

/// Public parameters for an Elliptic Curve key, consisting of the
/// curve identifier and the affine coordinates (`x`, `y`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EcPublicParameters {
    /// The named curve this key belongs to
    pub(crate) crv: JsonWebKeyEcEllipticCurve,

    /// X coordinate of the public point
    #[schemars(with = "String")]
    x: Base64UrlNoPad,

    /// Y coordinate of the public point
    #[schemars(with = "String")]
    y: Base64UrlNoPad,
}

impl EcPublicParameters {
    /// Construct EC public parameters from the curve identifier
    /// and the base64url-encoded coordinates.
    pub const fn new(crv: JsonWebKeyEcEllipticCurve, x: Base64UrlNoPad, y: Base64UrlNoPad) -> Self {
        Self { crv, x, y }
    }

    /// Determine which signature algorithms are usable with this
    /// key based on the curve.
    fn algs_for_curve(&self) -> &[JsonWebSignatureAlg] {
        match &self.crv {
            JsonWebKeyEcEllipticCurve::P256 => &[JsonWebSignatureAlg::Es256],
            JsonWebKeyEcEllipticCurve::P384 => &[JsonWebSignatureAlg::Es384],
            JsonWebKeyEcEllipticCurve::P521 => &[JsonWebSignatureAlg::Es512],
            JsonWebKeyEcEllipticCurve::Secp256K1 => &[JsonWebSignatureAlg::Es256K],
            _ => &[],
        }
    }
}

impl ParametersInfo for EcPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Ec
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        self.algs_for_curve()
    }
}

// ---------------------------------------------------------------------------
// Octet Key Pair (OKP) parameters
// ---------------------------------------------------------------------------

/// Public parameters for an Octet Key Pair (OKP) key, such as
/// Ed25519 or X25519.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OkpPublicParameters {
    /// The named curve for this OKP key
    pub(crate) crv: JsonWebKeyOkpEllipticCurve,

    /// The public key value
    #[schemars(with = "String")]
    x: Base64UrlNoPad,
}

impl OkpPublicParameters {
    /// Construct OKP public parameters from the curve identifier
    /// and the base64url-encoded public key.
    pub const fn new(crv: JsonWebKeyOkpEllipticCurve, x: Base64UrlNoPad) -> Self {
        Self { crv, x }
    }
}

impl ParametersInfo for OkpPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Okp
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        &[JsonWebSignatureAlg::EdDsa]
    }
}

// ---------------------------------------------------------------------------
// Top-level enum combining all key types
// ---------------------------------------------------------------------------

/// Tagged union of public parameters for all supported JWK key types.
/// The `kty` field in the serialized form determines which variant is used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kty")]
pub enum JsonWebKeyPublicParameters {
    /// RSA key parameters
    #[serde(rename = "RSA")]
    Rsa(RsaPublicParameters),

    /// Elliptic Curve key parameters
    #[serde(rename = "EC")]
    Ec(EcPublicParameters),

    /// Octet Key Pair parameters
    #[serde(rename = "OKP")]
    Okp(OkpPublicParameters),
}

impl JsonWebKeyPublicParameters {
    /// Try to extract RSA parameters, returning `None` for other key types.
    #[must_use]
    pub const fn rsa(&self) -> Option<&RsaPublicParameters> {
        match self {
            Self::Rsa(params) => Some(params),
            _ => None,
        }
    }

    /// Try to extract EC parameters, returning `None` for other key types.
    #[must_use]
    pub const fn ec(&self) -> Option<&EcPublicParameters> {
        match self {
            Self::Ec(params) => Some(params),
            _ => None,
        }
    }

    /// Try to extract OKP parameters, returning `None` for other key types.
    #[must_use]
    pub const fn okp(&self) -> Option<&OkpPublicParameters> {
        match self {
            Self::Okp(params) => Some(params),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Trait implementations for the top-level enum
// ---------------------------------------------------------------------------

impl ParametersInfo for JsonWebKeyPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        match self {
            Self::Rsa(_) => JsonWebKeyType::Rsa,
            Self::Ec(_) => JsonWebKeyType::Ec,
            Self::Okp(_) => JsonWebKeyType::Okp,
        }
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        match self {
            Self::Rsa(p) => p.possible_algs(),
            Self::Ec(p) => p.possible_algs(),
            Self::Okp(p) => p.possible_algs(),
        }
    }
}

impl Thumbprint for JsonWebKeyPublicParameters {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            Self::Rsa(RsaPublicParameters { n, e }) => {
                format!("{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}")
            }
            Self::Ec(EcPublicParameters { crv, x, y }) => {
                format!("{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")
            }
            Self::Okp(OkpPublicParameters { crv, x }) => {
                format!("{{\"crv\":\"{crv}\",\"kty\":\"OKP\",\"x\":\"{x}\"}}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RSA conversion implementations
// ---------------------------------------------------------------------------

mod rsa_impls {
    use rsa::{BigUint, RsaPublicKey, traits::PublicKeyParts};

    use super::{JsonWebKeyPublicParameters, RsaPublicParameters};
    use crate::base64::Base64UrlNoPad;

    impl From<RsaPublicKey> for JsonWebKeyPublicParameters {
        fn from(key: RsaPublicKey) -> Self {
            Self::from(&key)
        }
    }

    impl From<&RsaPublicKey> for JsonWebKeyPublicParameters {
        fn from(key: &RsaPublicKey) -> Self {
            Self::Rsa(key.into())
        }
    }

    impl From<RsaPublicKey> for RsaPublicParameters {
        fn from(key: RsaPublicKey) -> Self {
            Self::from(&key)
        }
    }

    impl From<&RsaPublicKey> for RsaPublicParameters {
        fn from(key: &RsaPublicKey) -> Self {
            let modulus = Base64UrlNoPad::new(key.n().to_bytes_be());
            let exponent = Base64UrlNoPad::new(key.e().to_bytes_be());
            Self {
                n: modulus,
                e: exponent,
            }
        }
    }

    impl TryFrom<RsaPublicParameters> for RsaPublicKey {
        type Error = rsa::errors::Error;

        fn try_from(params: RsaPublicParameters) -> Result<Self, Self::Error> {
            Self::try_from(&params)
        }
    }

    impl TryFrom<&RsaPublicParameters> for RsaPublicKey {
        type Error = rsa::errors::Error;

        fn try_from(params: &RsaPublicParameters) -> Result<Self, Self::Error> {
            let modulus = BigUint::from_bytes_be(params.n.as_bytes());
            let exponent = BigUint::from_bytes_be(params.e.as_bytes());
            RsaPublicKey::new(modulus, exponent)
        }
    }
}

// ---------------------------------------------------------------------------
// Elliptic Curve conversion implementations
// ---------------------------------------------------------------------------

// `FieldBytes::<C>::from_slice` ultimately resolves to
// `generic_array 0.14::GenericArray::from_slice`, which `digest 0.10`
// re-exports with a `#[deprecated]` nudge toward `generic-array 1.x`. The
// workspace is pinned to the 0.10/0.14 RustCrypto stack (see root
// `Cargo.toml`), so suppress the warning module-locally until the upstream
// migration ships.
#[allow(deprecated)]
mod ec_impls {
    use digest::typenum::Unsigned;
    use ecdsa::EncodedPoint;
    use elliptic_curve::{
        AffinePoint, FieldBytes, PublicKey,
        sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    };

    use super::{super::JwkEcCurve, EcPublicParameters, JsonWebKeyPublicParameters};
    use crate::base64::Base64UrlNoPad;

    impl<C> TryFrom<&EcPublicParameters> for PublicKey<C>
    where
        C: elliptic_curve::CurveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize + Unsigned,
    {
        type Error = elliptic_curve::Error;

        fn try_from(params: &EcPublicParameters) -> Result<Self, Self::Error> {
            let field_size = C::FieldBytesSize::USIZE;

            let x_bytes = params
                .x
                .as_bytes()
                .get(..field_size)
                .ok_or(elliptic_curve::Error)?;
            let y_bytes = params
                .y
                .as_bytes()
                .get(..field_size)
                .ok_or(elliptic_curve::Error)?;

            let x_field = FieldBytes::<C>::from_slice(x_bytes);
            let y_field = FieldBytes::<C>::from_slice(y_bytes);

            let encoded = EncodedPoint::<C>::from_affine_coordinates(x_field, y_field, false);
            let maybe_key: Option<_> = PublicKey::from_encoded_point(&encoded).into();
            maybe_key.ok_or(elliptic_curve::Error)
        }
    }

    impl<C> From<PublicKey<C>> for JsonWebKeyPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: PublicKey<C>) -> Self {
            Self::from(&key)
        }
    }

    impl<C> From<&PublicKey<C>> for JsonWebKeyPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: &PublicKey<C>) -> Self {
            Self::Ec(key.into())
        }
    }

    impl<C> From<PublicKey<C>> for EcPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: PublicKey<C>) -> Self {
            Self::from(&key)
        }
    }

    impl<C> From<&PublicKey<C>> for EcPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: &PublicKey<C>) -> Self {
            let uncompressed_point = key.to_encoded_point(false);
            let Coordinates::Uncompressed { x, y } = uncompressed_point.coordinates() else {
                unreachable!()
            };
            EcPublicParameters {
                crv: C::CRV,
                x: Base64UrlNoPad::new(x.to_vec()),
                y: Base64UrlNoPad::new(y.to_vec()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OKP (Ed25519) conversion implementations
// ---------------------------------------------------------------------------

mod okp_impls {
    use coauth_iana::jose::JsonWebKeyOkpEllipticCurve;
    use ed25519_dalek::VerifyingKey;

    use super::{JsonWebKeyPublicParameters, OkpPublicParameters};
    use crate::{base64::Base64UrlNoPad, jwk::InvalidOkpParameters};

    impl TryFrom<OkpPublicParameters> for VerifyingKey {
        type Error = InvalidOkpParameters;

        fn try_from(params: OkpPublicParameters) -> Result<Self, Self::Error> {
            Self::try_from(&params)
        }
    }

    impl TryFrom<&OkpPublicParameters> for VerifyingKey {
        type Error = InvalidOkpParameters;

        fn try_from(params: &OkpPublicParameters) -> Result<Self, Self::Error> {
            // Only Ed25519 is supported for OKP signature verification
            if params.crv != JsonWebKeyOkpEllipticCurve::Ed25519 {
                return Err(InvalidOkpParameters);
            }

            let raw_bytes = params
                .x
                .as_bytes()
                .try_into()
                .map_err(|_| InvalidOkpParameters)?;

            VerifyingKey::from_bytes(&raw_bytes).map_err(|_| InvalidOkpParameters)
        }
    }

    impl From<VerifyingKey> for JsonWebKeyPublicParameters {
        fn from(key: VerifyingKey) -> Self {
            Self::from(&key)
        }
    }

    impl From<&VerifyingKey> for JsonWebKeyPublicParameters {
        fn from(key: &VerifyingKey) -> Self {
            Self::Okp(key.into())
        }
    }

    impl From<VerifyingKey> for OkpPublicParameters {
        fn from(key: VerifyingKey) -> Self {
            Self::from(&key)
        }
    }

    impl From<&VerifyingKey> for OkpPublicParameters {
        fn from(key: &VerifyingKey) -> Self {
            let public_bytes = key.to_bytes().to_vec();
            Self {
                crv: JsonWebKeyOkpEllipticCurve::Ed25519,
                x: Base64UrlNoPad::new(public_bytes),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the JWK thumbprint computation against the example
    /// from RFC 7638 Section 3.1.
    #[test]
    fn test_thumbprint_rfc_example() {
        let n = Base64UrlNoPad::parse(
            "\
            0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
            VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\
            4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\
            W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\
            1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\
            aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        )
        .unwrap();
        let e = Base64UrlNoPad::parse("AQAB").unwrap();

        let rsa_params = RsaPublicParameters { n, e };
        let public_key = JsonWebKeyPublicParameters::Rsa(rsa_params);

        assert_eq!(
            public_key.thumbprint_sha256_base64(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
