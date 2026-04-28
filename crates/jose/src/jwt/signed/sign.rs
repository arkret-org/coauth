// JWT signing -- creating new compact-serialisation tokens.
//
// The header and payload are JSON-serialised, base64url-encoded, joined with
// a dot, signed, and then the signature is appended as a third segment.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;
use signature::{RandomizedSigner, SignatureEncoding, rand_core::CryptoRngCore};
use thiserror::Error;

use super::Jwt;
use crate::jwt::{header::JsonWebSignatureHeader, raw::RawJwt};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Problems that can occur while producing a signed JWT.
#[derive(Debug, Error)]
pub enum JwtSignatureError {
    #[error("could not serialise the JWS header")]
    EncodeHeader {
        #[source]
        inner: serde_json::Error,
    },

    #[error("could not serialise the JWT payload")]
    EncodePayload {
        #[source]
        inner: serde_json::Error,
    },

    #[error("signing operation failed")]
    Signature {
        #[from]
        inner: signature::Error,
    },
}

impl JwtSignatureError {
    fn header_serialisation(cause: serde_json::Error) -> Self {
        Self::EncodeHeader { inner: cause }
    }
    fn payload_serialisation(cause: serde_json::Error) -> Self {
        Self::EncodePayload { inner: cause }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// JSON-encode `value` and then base64url-encode the resulting bytes (no
/// padding).
fn serialize_to_b64url<S: Serialize>(value: &S) -> Result<String, serde_json::Error> {
    let json_bytes = serde_json::to_vec(value)?;
    Ok(Base64UrlUnpadded::encode_string(&json_bytes))
}

// ---------------------------------------------------------------------------
// Signing methods on Jwt
// ---------------------------------------------------------------------------

impl<T> Jwt<'static, T> {
    /// Sign `payload` under `header` using the default thread RNG.
    ///
    /// # Errors
    ///
    /// Returns an error when serialisation fails or the key cannot sign.
    pub fn sign<K, S>(
        header: JsonWebSignatureHeader,
        payload: T,
        key: &K,
    ) -> Result<Self, JwtSignatureError>
    where
        K: RandomizedSigner<S>,
        S: SignatureEncoding,
        T: Serialize,
    {
        Self::sign_with_rng(&mut signature::rand_core::OsRng, header, payload, key)
    }

    /// Sign `payload` under `header` using the supplied RNG.
    ///
    /// # Errors
    ///
    /// Returns an error when serialisation fails or the key cannot sign.
    pub fn sign_with_rng<R, K, S>(
        rng: &mut R,
        header: JsonWebSignatureHeader,
        payload: T,
        key: &K,
    ) -> Result<Self, JwtSignatureError>
    where
        R: CryptoRngCore,
        K: RandomizedSigner<S>,
        S: SignatureEncoding,
        T: Serialize,
    {
        let encoded_hdr =
            serialize_to_b64url(&header).map_err(JwtSignatureError::header_serialisation)?;
        let encoded_pay =
            serialize_to_b64url(&payload).map_err(JwtSignatureError::payload_serialisation)?;

        // The message to sign is "<base64-header>.<base64-payload>"
        let message = format!("{encoded_hdr}.{encoded_pay}");
        let dot1 = encoded_hdr.len();
        let dot2 = message.len();

        // Produce the cryptographic signature and base64url-encode it.
        let raw_sig = key.try_sign_with_rng(rng, message.as_bytes())?.to_vec();
        let encoded_sig = Base64UrlUnpadded::encode_string(&raw_sig);

        // Build the full compact token: "<header>.<payload>.<signature>"
        let mut compact = message;
        compact.reserve_exact(1 + encoded_sig.len());
        compact.push('.');
        compact.push_str(&encoded_sig);

        Ok(Self {
            raw: RawJwt::new(compact, dot1, dot2),
            header,
            payload,
            signature: raw_sig,
        })
    }
}
