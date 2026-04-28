// Compact-serialisation decoding for `Jwt`.
//
// The three base64url segments (header, payload, signature) are decoded and
// deserialised into their typed representations.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;
use thiserror::Error;

use super::Jwt;
use crate::jwt::raw::RawJwt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Problems that can occur while parsing the compact JWT serialisation.
#[derive(Debug, Error)]
pub enum JwtDecodeError {
    #[error(transparent)]
    RawDecode {
        #[from]
        inner: super::super::raw::DecodeError,
    },

    #[error("base64 decoding of the JWT header failed")]
    DecodeHeader {
        #[source]
        inner: base64ct::Error,
    },

    #[error("JSON deserialisation of the JWT header failed")]
    DeserializeHeader {
        #[source]
        inner: serde_json::Error,
    },

    #[error("base64 decoding of the JWT payload failed")]
    DecodePayload {
        #[source]
        inner: base64ct::Error,
    },

    #[error("JSON deserialisation of the JWT payload failed")]
    DeserializePayload {
        #[source]
        inner: serde_json::Error,
    },

    #[error("base64 decoding of the JWT signature failed")]
    DecodeSignature {
        #[source]
        inner: base64ct::Error,
    },
}

// Private constructors, grouped by segment.
impl JwtDecodeError {
    fn header_base64(source: base64ct::Error) -> Self {
        Self::DecodeHeader { inner: source }
    }
    fn header_json(source: serde_json::Error) -> Self {
        Self::DeserializeHeader { inner: source }
    }
    fn payload_base64(source: base64ct::Error) -> Self {
        Self::DecodePayload { inner: source }
    }
    fn payload_json(source: serde_json::Error) -> Self {
        Self::DeserializePayload { inner: source }
    }
    fn signature_base64(source: base64ct::Error) -> Self {
        Self::DecodeSignature { inner: source }
    }
}

// ---------------------------------------------------------------------------
// Parsing logic
// ---------------------------------------------------------------------------

/// Take an already-split `RawJwt` and decode every segment into typed parts.
fn parse_compact_parts<'a, T: DeserializeOwned>(
    raw: RawJwt<'a>,
) -> Result<Jwt<'a, T>, JwtDecodeError> {
    // 1. header
    let header_decoder = base64ct::Decoder::<'_, Base64UrlUnpadded>::new(raw.header().as_bytes())
        .map_err(JwtDecodeError::header_base64)?;
    let header = serde_json::from_reader(header_decoder).map_err(JwtDecodeError::header_json)?;

    // 2. payload
    let payload_decoder = base64ct::Decoder::<'_, Base64UrlUnpadded>::new(raw.payload().as_bytes())
        .map_err(JwtDecodeError::payload_base64)?;
    let payload: T =
        serde_json::from_reader(payload_decoder).map_err(JwtDecodeError::payload_json)?;

    // 3. signature (raw bytes, not typed yet -- that happens at verification)
    let sig_bytes =
        Base64UrlUnpadded::decode_vec(raw.signature()).map_err(JwtDecodeError::signature_base64)?;

    Ok(Jwt {
        raw,
        header,
        payload,
        signature: sig_bytes,
    })
}

// ---------------------------------------------------------------------------
// TryFrom implementations -- delegate to `parse_compact_parts`
// ---------------------------------------------------------------------------

impl<'a, T: DeserializeOwned> TryFrom<RawJwt<'a>> for Jwt<'a, T> {
    type Error = JwtDecodeError;

    fn try_from(raw: RawJwt<'a>) -> Result<Self, Self::Error> {
        parse_compact_parts(raw)
    }
}

impl<'a, T: DeserializeOwned> TryFrom<&'a str> for Jwt<'a, T> {
    type Error = JwtDecodeError;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        let raw = RawJwt::try_from(input)?;
        parse_compact_parts(raw)
    }
}

impl<T: DeserializeOwned> TryFrom<String> for Jwt<'static, T> {
    type Error = JwtDecodeError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        let raw = RawJwt::try_from(input)?;
        parse_compact_parts(raw)
    }
}
