// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Proof Key for Code Exchange (PKCE) per [RFC 7636].
//!
//! [RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636

use std::borrow::Cow;

use base64ct::{Base64UrlUnpadded, Encoding};
use coauth_iana::oauth::PkceCodeChallengeMethod;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Min length of a code verifier (RFC 7636 §4.1).
const VERIFIER_MIN_LEN: usize = 43;
/// Max length of a code verifier (RFC 7636 §4.1).
const VERIFIER_MAX_LEN: usize = 128;

/// Errors arising from PKCE code challenge operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodeChallengeError {
    /// The code verifier should be at least 43 characters long.
    #[error("code_verifier should be at least 43 characters long")]
    TooShort,

    /// The code verifier should be at most 128 characters long.
    #[error("code_verifier should be at most 128 characters long")]
    TooLong,

    /// The code verifier contains invalid characters.
    #[error("code_verifier contains invalid characters")]
    InvalidCharacters,

    /// The challenge verification failed.
    #[error("challenge verification failed")]
    VerificationFailed,

    /// The challenge method is unsupported.
    #[error("unknown challenge method")]
    UnknownChallengeMethod,
}

/// Validate that a code verifier conforms to [RFC 7636 §4.1]:
///
///   code-verifier = 43*128unreserved
///   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
///
/// [RFC 7636 §4.1]: https://www.rfc-editor.org/rfc/rfc7636#section-4.1
fn check_verifier(verifier: &str) -> Result<(), CodeChallengeError> {
    if verifier.len() < VERIFIER_MIN_LEN {
        return Err(CodeChallengeError::TooShort);
    }
    if verifier.len() > VERIFIER_MAX_LEN {
        return Err(CodeChallengeError::TooLong);
    }
    let all_unreserved = verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~');
    if !all_unreserved {
        return Err(CodeChallengeError::InvalidCharacters);
    }
    Ok(())
}

/// Extension trait for computing and verifying PKCE code challenges.
pub trait CodeChallengeMethodExt {
    /// Derive the code challenge from the given verifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the verifier violates the length or character
    /// constraints defined in RFC 7636.
    fn compute_challenge<'a>(&self, verifier: &'a str) -> Result<Cow<'a, str>, CodeChallengeError>;

    /// Verify that `verifier` matches the previously stored `challenge`.
    ///
    /// # Errors
    ///
    /// Returns [`CodeChallengeError::VerificationFailed`] on mismatch, or
    /// any error that [`compute_challenge`](Self::compute_challenge) may
    /// produce.
    fn verify(&self, challenge: &str, verifier: &str) -> Result<(), CodeChallengeError>
    where
        Self: Sized,
    {
        let computed = self.compute_challenge(verifier)?;
        if computed == challenge {
            Ok(())
        } else {
            Err(CodeChallengeError::VerificationFailed)
        }
    }
}

impl CodeChallengeMethodExt for PkceCodeChallengeMethod {
    fn compute_challenge<'a>(&self, verifier: &'a str) -> Result<Cow<'a, str>, CodeChallengeError> {
        check_verifier(verifier)?;

        match self {
            Self::Plain => Ok(Cow::Borrowed(verifier)),
            Self::S256 => {
                let digest = Sha256::digest(verifier.as_bytes());
                Ok(Cow::Owned(Base64UrlUnpadded::encode_string(&digest)))
            }
            _ => Err(CodeChallengeError::UnknownChallengeMethod),
        }
    }
}

/// PKCE parameters attached to an authorization request.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The challenge method used.
    pub code_challenge_method: PkceCodeChallengeMethod,

    /// The computed challenge value.
    pub code_challenge: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from RFC 7636 Appendix B.
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE_S256: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn s256_matches_rfc_vector() {
        assert!(
            PkceCodeChallengeMethod::S256
                .verify(RFC_CHALLENGE_S256, RFC_VERIFIER)
                .is_ok()
        );
    }

    #[test]
    fn plain_identity() {
        assert!(
            PkceCodeChallengeMethod::Plain
                .verify(RFC_CHALLENGE_S256, RFC_CHALLENGE_S256)
                .is_ok()
        );
    }

    #[test]
    fn s256_wrong_verifier() {
        assert_eq!(
            PkceCodeChallengeMethod::S256.verify(
                RFC_CHALLENGE_S256,
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            ),
            Err(CodeChallengeError::VerificationFailed),
        );
    }

    #[test]
    fn rejects_short_verifier() {
        assert_eq!(
            PkceCodeChallengeMethod::S256.verify(RFC_CHALLENGE_S256, "tooshort"),
            Err(CodeChallengeError::TooShort),
        );
    }

    #[test]
    fn rejects_long_verifier() {
        let long = "a".repeat(VERIFIER_MAX_LEN + 1);
        assert_eq!(
            PkceCodeChallengeMethod::S256.verify(RFC_CHALLENGE_S256, &long),
            Err(CodeChallengeError::TooLong),
        );
    }

    #[test]
    fn rejects_invalid_characters() {
        assert_eq!(
            PkceCodeChallengeMethod::S256.verify(
                RFC_CHALLENGE_S256,
                "this is long enough but has invalid characters in it",
            ),
            Err(CodeChallengeError::InvalidCharacters),
        );
    }
}
