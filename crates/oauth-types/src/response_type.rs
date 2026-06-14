// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! OAuth / OpenID Connect response type handling.
//!
//! A response type is a space-separated set of tokens that determines which
//! artifacts the authorization endpoint returns.
//!
//! See [OpenID Connect Core 1.0 §3] and [RFC 6749 §3.1.1].
//!
//! [OpenID Connect Core 1.0 §3]: https://openid.net/specs/openid-connect-core-1_0.html#Authentication
//! [RFC 6749 §3.1.1]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1.1

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use coauth_iana::oauth::OAuthAuthorizationEndpointResponseType;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

/// Returned when a response type string cannot be parsed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid response type")]
pub struct InvalidResponseType;

/// Individual tokens that can appear inside a [`ResponseType`].
///
/// The special value `none` is not represented here; instead an empty
/// [`ResponseType`] set models the `none` response type.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
#[non_exhaustive]
pub enum ResponseTypeToken {
    /// `code` — authorization code strand.
    Code,
    /// `id_token` — implicit strand returning an ID token.
    IdToken,
    /// `token` — implicit strand returning an access token.
    Token,
    /// Unrecognized token preserved verbatim.
    Unknown(String),
}

impl fmt::Display for ResponseTypeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code => f.write_str("code"),
            Self::IdToken => f.write_str("id_token"),
            Self::Token => f.write_str("token"),
            Self::Unknown(v) => f.write_str(v),
        }
    }
}

impl FromStr for ResponseTypeToken {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "code" => Self::Code,
            "id_token" => Self::IdToken,
            "token" => Self::Token,
            other => Self::Unknown(other.to_owned()),
        })
    }
}

/// A set of response type tokens.
///
/// Serialized as a space-separated string (e.g. `"code id_token"`).
/// An empty set serializes as `"none"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr)]
pub struct ResponseType(BTreeSet<ResponseTypeToken>);

impl std::ops::Deref for ResponseType {
    type Target = BTreeSet<ResponseTypeToken>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ResponseType {
    /// Whether the set contains the `code` token.
    #[must_use]
    pub fn has_code(&self) -> bool {
        self.0.contains(&ResponseTypeToken::Code)
    }

    /// Whether the set contains the `id_token` token.
    #[must_use]
    pub fn has_id_token(&self) -> bool {
        self.0.contains(&ResponseTypeToken::IdToken)
    }

    /// Whether the set contains the `token` token.
    #[must_use]
    pub fn has_token(&self) -> bool {
        self.0.contains(&ResponseTypeToken::Token)
    }
}

impl FromStr for ResponseType {
    type Err = InvalidResponseType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(InvalidResponseType);
        }
        if trimmed == "none" {
            return Ok(Self(BTreeSet::new()));
        }
        let tokens: Result<BTreeSet<_>, _> = trimmed
            .split_ascii_whitespace()
            .map(|part| ResponseTypeToken::from_str(part).or(Err(InvalidResponseType)))
            .collect();
        Ok(Self(tokens?))
    }
}

impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("none");
        }
        let mut first = true;
        for token in &self.0 {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            fmt::Display::fmt(token, f)?;
        }
        Ok(())
    }
}

impl FromIterator<ResponseTypeToken> for ResponseType {
    fn from_iter<I: IntoIterator<Item = ResponseTypeToken>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

// ── Conversions to/from IANA registry type ────────────────────────────

impl From<OAuthAuthorizationEndpointResponseType> for ResponseType {
    fn from(iana: OAuthAuthorizationEndpointResponseType) -> Self {
        use OAuthAuthorizationEndpointResponseType as I;
        use ResponseTypeToken::{Code, IdToken, Token};

        let tokens: &[ResponseTypeToken] = match iana {
            I::Code => &[Code],
            I::IdToken => &[IdToken],
            I::Token => &[Token],
            I::CodeIdToken => &[Code, IdToken],
            I::CodeToken => &[Code, Token],
            I::IdTokenToken => &[IdToken, Token],
            I::CodeIdTokenToken => &[Code, IdToken, Token],
            I::None => &[],
        };
        Self(tokens.iter().cloned().collect())
    }
}

impl TryFrom<ResponseType> for OAuthAuthorizationEndpointResponseType {
    type Error = InvalidResponseType;

    fn try_from(rt: ResponseType) -> Result<Self, Self::Error> {
        use OAuthAuthorizationEndpointResponseType as O;
        use ResponseTypeToken::{Code, IdToken, Token, Unknown};

        // Reject if any unknown tokens are present
        if rt.iter().any(|t| matches!(t, Unknown(_))) {
            return Err(InvalidResponseType);
        }

        let sorted: Vec<_> = rt.iter().collect();
        Ok(match sorted.as_slice() {
            [] => O::None,
            [Code] => O::Code,
            [IdToken] => O::IdToken,
            [Token] => O::Token,
            [Code, IdToken] => O::CodeIdToken,
            [Code, Token] => O::CodeToken,
            [IdToken, Token] => O::IdTokenToken,
            [Code, IdToken, Token] => O::CodeIdTokenToken,
            _ => O::None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Token parsing ────────────────────────────────────────────────

    #[test]
    fn token_round_trip() {
        for (json, expected) in [
            ("\"code\"", ResponseTypeToken::Code),
            ("\"id_token\"", ResponseTypeToken::IdToken),
            ("\"token\"", ResponseTypeToken::Token),
            (
                "\"something_unsupported\"",
                ResponseTypeToken::Unknown("something_unsupported".into()),
            ),
        ] {
            let parsed: ResponseTypeToken = serde_json::from_str(json).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(serde_json::to_string(&expected).unwrap(), json);
        }
    }

    // ── Composite response type parsing ──────────────────────────────

    #[test]
    fn reject_empty() {
        serde_json::from_str::<ResponseType>("\"\"").unwrap_err();
    }

    #[test]
    fn parse_none() {
        let rt = serde_json::from_str::<ResponseType>("\"none\"").unwrap();
        assert!(rt.is_empty());
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(rt).unwrap(),
            OAuthAuthorizationEndpointResponseType::None,
        );
    }

    #[test]
    fn parse_single_tokens() {
        for (json, iana) in [
            ("\"code\"", OAuthAuthorizationEndpointResponseType::Code),
            (
                "\"id_token\"",
                OAuthAuthorizationEndpointResponseType::IdToken,
            ),
            ("\"token\"", OAuthAuthorizationEndpointResponseType::Token),
        ] {
            let rt = serde_json::from_str::<ResponseType>(json).unwrap();
            assert_eq!(
                OAuthAuthorizationEndpointResponseType::try_from(rt).unwrap(),
                iana,
            );
        }
    }

    #[test]
    fn unknown_token_blocks_iana_conversion() {
        let rt = serde_json::from_str::<ResponseType>("\"something_unsupported\"").unwrap();
        assert!(OAuthAuthorizationEndpointResponseType::try_from(rt).is_err());
    }

    #[test]
    fn parse_multi_tokens() {
        let cases = [
            (
                "\"code id_token\"",
                OAuthAuthorizationEndpointResponseType::CodeIdToken,
            ),
            (
                "\"code token\"",
                OAuthAuthorizationEndpointResponseType::CodeToken,
            ),
            (
                "\"id_token token\"",
                OAuthAuthorizationEndpointResponseType::IdTokenToken,
            ),
            (
                "\"code id_token token\"",
                OAuthAuthorizationEndpointResponseType::CodeIdTokenToken,
            ),
        ];
        for (json, iana) in cases {
            let rt = serde_json::from_str::<ResponseType>(json).unwrap();
            assert_eq!(
                OAuthAuthorizationEndpointResponseType::try_from(rt).unwrap(),
                iana,
            );
        }
    }

    #[test]
    fn order_is_normalized() {
        let a = serde_json::from_str::<ResponseType>("\"token code id_token\"").unwrap();
        let b = serde_json::from_str::<ResponseType>("\"code id_token token\"").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            "\"code id_token token\""
        );
    }

    #[test]
    fn duplicates_are_ignored() {
        let rt = serde_json::from_str::<ResponseType>("\"id_token token id_token code\"").unwrap();
        assert_eq!(rt.len(), 3);
        assert_eq!(
            OAuthAuthorizationEndpointResponseType::try_from(rt).unwrap(),
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken,
        );
    }

    // ── Serialization ────────────────────────────────────────────────

    #[test]
    fn serialize_all_iana_variants() {
        use OAuthAuthorizationEndpointResponseType as O;
        let cases = [
            (O::None, "\"none\""),
            (O::Code, "\"code\""),
            (O::IdToken, "\"id_token\""),
            (O::Token, "\"token\""),
            (O::CodeIdToken, "\"code id_token\""),
            (O::CodeToken, "\"code token\""),
            (O::IdTokenToken, "\"id_token token\""),
            (O::CodeIdTokenToken, "\"code id_token token\""),
        ];
        for (variant, expected) in cases {
            let rt = ResponseType::from(variant);
            assert_eq!(serde_json::to_string(&rt).unwrap(), expected);
        }
    }

    #[test]
    fn serialize_with_unknown() {
        let rt: ResponseType = [
            ResponseTypeToken::Unknown("something_unsupported".into()),
            ResponseTypeToken::Code,
        ]
        .into_iter()
        .collect();
        assert_eq!(
            serde_json::to_string(&rt).unwrap(),
            "\"code something_unsupported\"",
        );
    }
}
