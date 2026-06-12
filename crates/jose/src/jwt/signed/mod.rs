// Signed JWT implementation, split across sub-modules for clarity.
//
// This module provides `Jwt<T>` -- a compact-serialisation JWT that can be
// constructed (signed), parsed, and verified.  The heavy lifting lives in
// neighbouring sub-modules:
//
//   * `decode` -- parsing the three-segment compact form
//   * `verify` -- signature verification against keys / JWKS
//   * `sign`   -- creating new signed tokens

mod decode;
mod sign;
mod verify;

pub use self::decode::JwtDecodeError;
pub use self::sign::JwtSignatureError;
pub use self::verify::{JwtVerificationError, NoKeyWorked};
use super::header::JsonWebSignatureHeader;
use super::raw::RawJwt;

// ---------------------------------------------------------------------------
// Core type
// ---------------------------------------------------------------------------

/// A parsed, optionally-verified, signed JSON Web Token.
#[derive(Clone, PartialEq, Eq)]
pub struct Jwt<'a, T> {
    raw: RawJwt<'a>,
    header: JsonWebSignatureHeader,
    payload: T,
    signature: Vec<u8>,
}

// -- Display / Debug --------------------------------------------------------

impl<T> std::fmt::Display for Jwt<'_, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.raw, formatter)
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Jwt<'_, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Jwt")
            .field("raw", &"<compact>")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .field("signature", &"<bytes>")
            .finish()
    }
}

// -- Accessors --------------------------------------------------------------

impl<'a, T> Jwt<'a, T> {
    /// Borrow the parsed JWS header.
    pub fn header(&self) -> &JsonWebSignatureHeader {
        &self.header
    }

    /// Borrow the deserialised payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Convert to an owning (`'static`) lifetime.
    pub fn into_owned(self) -> Jwt<'static, T> {
        Jwt {
            raw: self.raw.into_owned(),
            header: self.header,
            payload: self.payload,
            signature: self.signature,
        }
    }

    /// Return the compact serialisation as a `&str`.
    pub fn as_str(&'a self) -> &'a str {
        &self.raw
    }

    /// Consume the token and return the compact serialisation.
    pub fn into_string(self) -> String {
        self.raw.into()
    }

    /// Destructure into the header and the payload, discarding the raw form.
    pub fn into_parts(self) -> (JsonWebSignatureHeader, T) {
        (self.header, self.payload)
    }
}

// -- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use coauth_iana::jose::JsonWebSignatureAlg;

    use super::*;

    /// Well-known reference JWT (jwt.io HS256 example) used for decode checks.
    const REFERENCE_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
        SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn decode_reference_token_segments() {
        let token: Jwt<'_, serde_json::Value> = Jwt::try_from(REFERENCE_TOKEN).unwrap();

        assert_eq!(token.raw.header(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assert_eq!(
            token.raw.payload(),
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        );
        assert_eq!(
            token.raw.signature(),
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
        assert_eq!(
            token.raw.signed_part(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        );
    }

    #[test]
    fn roundtrip_sign_then_verify() {
        let hdr = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Es256);
        let body = serde_json::json!({"hello": "world"});

        let sk = ecdsa::SigningKey::<p256::NistP256>::random(&mut signature::rand_core::OsRng);
        let signed = Jwt::sign::<_, ecdsa::Signature<_>>(hdr, body, &sk).unwrap();

        signed
            .verify::<_, ecdsa::Signature<_>>(sk.verifying_key())
            .unwrap();
    }
}
