// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! OAuth 2.0 access token scope types per [RFC 6749 Section 3.3].
//!
//! [RFC 6749 Section 3.3]: https://www.rfc-editor.org/rfc/rfc6749#section-3.3

#![allow(clippy::module_name_repetitions)]

use std::{
    borrow::Cow,
    collections::BTreeSet,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error returned when parsing an invalid scope string.
#[derive(Debug, Error, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[error("Invalid scope format")]
pub struct InvalidScope;

/// A single scope token (one element of a space-separated scope list).
///
/// See [RFC 6749 Appendix A.4] for the syntax:
/// `scope-token = 1*NQCHAR`
///
/// [RFC 6749 Appendix A.4]: https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.4
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeToken(Cow<'static, str>);

impl ScopeToken {
    /// Build a `ScopeToken` from a string literal known at compile time.
    ///
    /// No validation is performed — the caller must ensure the value
    /// consists only of NQCHAR characters.
    #[must_use]
    pub const fn from_static(token: &'static str) -> Self {
        Self(Cow::Borrowed(token))
    }

    /// Return the token value as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

// ── Well-known scope constants (OpenID Connect Core 1.0 §5.4) ──────────

/// `openid` — required in every OpenID Connect request.
pub const OPENID: ScopeToken = ScopeToken::from_static("openid");

/// `profile` — requests the default profile claims.
pub const PROFILE: ScopeToken = ScopeToken::from_static("profile");

/// `email` — requests the `email` and `email_verified` claims.
pub const EMAIL: ScopeToken = ScopeToken::from_static("email");

/// `address` — requests the `address` claim.
pub const ADDRESS: ScopeToken = ScopeToken::from_static("address");

/// `phone` — requests the `phone_number` and `phone_number_verified` claims.
pub const PHONE: ScopeToken = ScopeToken::from_static("phone");

/// `offline_access` — requests a refresh token for long-lived access.
pub const OFFLINE_ACCESS: ScopeToken = ScopeToken::from_static("offline_access");

/// Check whether a character belongs to the NQCHAR set defined in
/// [RFC 6749 Appendix A]:
///
///   NQCHAR = %x21 / %x23-5B / %x5D-7E
///
/// [RFC 6749 Appendix A]: https://datatracker.ietf.org/doc/html/rfc6749#appendix-A
fn is_nqchar(ch: char) -> bool {
    matches!(ch, '\x21' | '\x23'..='\x5B' | '\x5D'..='\x7E')
}

impl FromStr for ScopeToken {
    type Err = InvalidScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || !s.chars().all(is_nqchar) {
            return Err(InvalidScope);
        }
        Ok(ScopeToken(Cow::Owned(s.to_owned())))
    }
}

impl Deref for ScopeToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for ScopeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An ordered set of scope tokens, serialized as a space-separated string
/// per [RFC 6749 Appendix A.4]:
///
///   scope = scope-token *( SP scope-token )
///
/// [RFC 6749 Appendix A.4]: https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope(BTreeSet<ScopeToken>);

impl Deref for Scope {
    type Target = BTreeSet<ScopeToken>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Scope {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromStr for Scope {
    type Err = InvalidScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tokens: Result<BTreeSet<ScopeToken>, _> =
            s.split(' ').map(ScopeToken::from_str).collect();
        Ok(Self(tokens?))
    }
}

impl Scope {
    /// Returns `true` when this scope contains no tokens.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of individual tokens in this scope.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks whether a specific scope value is present.
    #[must_use]
    pub fn contains(&self, token: &str) -> bool {
        ScopeToken::from_str(token)
            .map(|t| self.0.contains(&t))
            .unwrap_or(false)
    }

    /// Inserts a token, returning `true` if it was not already present.
    pub fn insert(&mut self, value: ScopeToken) -> bool {
        self.0.insert(value)
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for token in &self.0 {
            if first {
                first = false;
            } else {
                f.write_str(" ")?;
            }
            std::fmt::Display::fmt(token, f)?;
        }
        Ok(())
    }
}

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Scope::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

impl FromIterator<ScopeToken> for Scope {
    fn from_iter<I: IntoIterator<Item = ScopeToken>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_scope_token() {
        let token = ScopeToken::from_str("openid").unwrap();
        assert_eq!(token, OPENID);
    }

    #[test]
    fn invalid_scope_token() {
        assert_eq!(ScopeToken::from_str("bad\\char"), Err(InvalidScope));
        assert_eq!(ScopeToken::from_str(""), Err(InvalidScope));
    }

    #[test]
    fn parse_multi_token_scope() {
        let scope = Scope::from_str("openid profile address").unwrap();
        assert_eq!(scope.len(), 3);
        assert!(scope.contains("openid"));
        assert!(scope.contains("profile"));
        assert!(scope.contains("address"));
        assert!(!scope.contains("unknown"));
    }

    #[test]
    fn single_token_scope() {
        let scope = Scope::from_str("openid").unwrap();
        assert_eq!(scope.len(), 1);
        assert!(scope.contains("openid"));
        assert!(!scope.contains("profile"));
    }

    #[test]
    fn scope_rejects_empty() {
        assert!(Scope::from_str("").is_err());
    }

    #[test]
    fn scope_rejects_invalid_chars() {
        assert!(Scope::from_str("invalid\\scope").is_err());
    }

    #[test]
    fn scope_rejects_double_spaces() {
        assert!(Scope::from_str("no  double space").is_err());
    }

    #[test]
    fn scope_rejects_edge_spaces() {
        assert!(Scope::from_str(" no leading space").is_err());
        assert!(Scope::from_str("no trailing space ").is_err());
    }

    #[test]
    fn scope_order_independent() {
        assert_eq!(
            Scope::from_str("order does not matter"),
            Scope::from_str("matter not order does"),
        );
    }

    #[test]
    fn scope_accepts_uris() {
        assert!(Scope::from_str("http://example.com").is_ok());
        assert!(Scope::from_str("urn:matrix:client:api:*").is_ok());
        assert!(Scope::from_str("urn:matrix:org.matrix.msc2967.client:api:*").is_ok());
    }
}
