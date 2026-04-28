// Independent implementation of JWT claims extraction and validation.
//
// Provides typed claim accessors for RFC 7519 registered claims,
// OpenID Connect Core claims, and OpenID Connect Frontchannel claims.
// Each claim constant carries its value type and an optional validator
// type so that extraction and validation are a single step.

use std::{collections::HashMap, convert::Infallible, ops::Deref};

use base64ct::{Base64UrlUnpadded, Encoding};
use coauth_iana::jose::JsonWebSignatureAlg;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Core error type
// ---------------------------------------------------------------------------

/// Errors that can occur when extracting or validating a claim.
#[derive(Debug, Error)]
pub enum ClaimError {
    #[error("missing claim {0:?}")]
    MissingClaim(&'static str),

    #[error("invalid claim {0:?}")]
    InvalidClaim(&'static str),

    #[error("could not validate claim {claim:?}")]
    ValidationError {
        claim: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

// ---------------------------------------------------------------------------
// Validator trait
// ---------------------------------------------------------------------------

/// A predicate that checks whether a claim value is acceptable.
pub trait Validator<T> {
    /// The associated error type returned by this validator.
    type Error;

    /// Validate a claim value
    ///
    /// # Errors
    ///
    /// Returns an error if the value is invalid.
    fn validate(&self, value: &T) -> Result<(), Self::Error>;
}

/// The unit validator always succeeds.
impl<T> Validator<T> for () {
    type Error = Infallible;

    fn validate(&self, _value: &T) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Claim – typed accessor into a claims map
// ---------------------------------------------------------------------------

/// A typed claim accessor that knows its JSON key, value type, and validator.
///
/// Uses a `PhantomData` over a function-pointer type so that `Claim` is
/// unconditionally `Send + Sync` regardless of `T` and `V`, while still
/// being constructible in `const` context.
pub struct Claim<T, V = ()> {
    /// The JSON key for this claim (e.g. `"iss"`, `"exp"`).
    key: &'static str,
    /// Carries the type parameters without owning them.  `fn() -> X` is
    /// always `Send + Sync`, so no manual unsafe impls are needed.
    _types: std::marker::PhantomData<fn() -> (T, V)>,
}

impl<T, V> Claim<T, V>
where
    V: Validator<T>,
{
    /// Create a new claim accessor for the given JSON key.
    #[must_use]
    pub const fn new(claim: &'static str) -> Self {
        Self {
            key: claim,
            _types: std::marker::PhantomData,
        }
    }

    // -- insertion ----------------------------------------------------------

    /// Insert a claim into the given claims map.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to serialize.
    pub fn insert<I>(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
        value: I,
    ) -> Result<(), ClaimError>
    where
        I: Into<T>,
        T: Serialize,
    {
        let converted = value.into();
        let json =
            serde_json::to_value(&converted).map_err(|_| ClaimError::InvalidClaim(self.key))?;
        claims.insert(self.key.to_owned(), json);
        Ok(())
    }

    // -- extraction helpers -------------------------------------------------

    /// Decode a `serde_json::Value` into `T` and run the validator.
    fn decode_and_validate(&self, raw: serde_json::Value, validator: V) -> Result<T, ClaimError>
    where
        T: DeserializeOwned,
        V::Error: std::error::Error + Send + Sync + 'static,
    {
        let decoded: T =
            serde_json::from_value(raw).map_err(|_| ClaimError::InvalidClaim(self.key))?;

        validator
            .validate(&decoded)
            .map_err(|e| ClaimError::ValidationError {
                claim: self.key,
                source: Box::new(e),
            })?;

        Ok(decoded)
    }

    // -- required extraction ------------------------------------------------

    /// Extract a claim from the given claims map.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to deserialize, if its value is
    /// invalid or if the claim is missing.
    pub fn extract_required(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
    ) -> Result<T, ClaimError>
    where
        T: DeserializeOwned,
        V: Default,
        V::Error: std::error::Error + Send + Sync + 'static,
    {
        self.extract_required_with_options(claims, V::default())
    }

    /// Extract a claim from the given claims map, with the given options.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to deserialize, if its value is
    /// invalid or if the claim is missing.
    pub fn extract_required_with_options<I>(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
        validator: I,
    ) -> Result<T, ClaimError>
    where
        T: DeserializeOwned,
        I: Into<V>,
        V::Error: std::error::Error + Send + Sync + 'static,
    {
        let raw = claims
            .remove(self.key)
            .ok_or(ClaimError::MissingClaim(self.key))?;

        self.decode_and_validate(raw, validator.into())
    }

    // -- optional extraction ------------------------------------------------

    /// Extract a claim from the given claims map, if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to deserialize or if its value is
    /// invalid.
    pub fn extract_optional(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
    ) -> Result<Option<T>, ClaimError>
    where
        T: DeserializeOwned,
        V: Default,
        V::Error: std::error::Error + Send + Sync + 'static,
    {
        self.extract_optional_with_options(claims, V::default())
    }

    /// Extract a claim from the given claims map, if it exists, with the given
    /// options.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to deserialize or if its value is
    /// invalid.
    pub fn extract_optional_with_options<I>(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
        validator: I,
    ) -> Result<Option<T>, ClaimError>
    where
        T: DeserializeOwned,
        I: Into<V>,
        V::Error: std::error::Error + Send + Sync + 'static,
    {
        let raw = match claims.remove(self.key) {
            Some(v) => v,
            None => return Ok(None),
        };
        self.decode_and_validate(raw, validator.into()).map(Some)
    }

    // -- absence assertion --------------------------------------------------

    /// Assert that the claim is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the claim is present.
    pub fn assert_absent(
        &self,
        claims: &HashMap<String, serde_json::Value>,
    ) -> Result<(), ClaimError> {
        if claims.contains_key(self.key) {
            Err(ClaimError::InvalidClaim(self.key))
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// TimeOptions – configuration for temporal claim validation
// ---------------------------------------------------------------------------

/// Controls how temporal claims (`nbf`, `exp`, `iat`) are validated.
#[derive(Debug, Clone)]
pub struct TimeOptions {
    when: chrono::DateTime<chrono::Utc>,
    leeway: chrono::Duration,
}

/// Default leeway: 5 minutes expressed in whole seconds.
const DEFAULT_LEEWAY_SECS: i64 = 5 * 60;

impl TimeOptions {
    #[must_use]
    pub fn new(when: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            when,
            leeway: chrono::Duration::try_seconds(DEFAULT_LEEWAY_SECS)
                .expect("5-minute leeway is always representable"),
        }
    }

    #[must_use]
    pub fn leeway(mut self, leeway: chrono::Duration) -> Self {
        self.leeway = leeway;
        self
    }
}

// ---------------------------------------------------------------------------
// Time validators
// ---------------------------------------------------------------------------

/// Error returned when a temporal claim falls outside the acceptable window.
#[derive(Debug, Clone, Copy, Error)]
#[error("Current time is too far away")]
pub struct TimeTooFarError;

/// Validates that the current time has NOT passed the claim value
/// (plus leeway). Used for `exp`.
#[derive(Debug, Clone)]
pub struct TimeNotAfter(TimeOptions);

impl Validator<Timestamp> for TimeNotAfter {
    type Error = TimeTooFarError;

    fn validate(&self, ts: &Timestamp) -> Result<(), Self::Error> {
        let deadline = ts.0 + self.0.leeway;
        if self.0.when <= deadline {
            Ok(())
        } else {
            Err(TimeTooFarError)
        }
    }
}

impl From<TimeOptions> for TimeNotAfter {
    fn from(opt: TimeOptions) -> Self {
        Self(opt)
    }
}

impl From<&TimeOptions> for TimeNotAfter {
    fn from(opt: &TimeOptions) -> Self {
        Self(opt.clone())
    }
}

/// Validates that the current time is NOT before the claim value
/// (minus leeway). Used for `nbf` and `iat`.
#[derive(Debug, Clone)]
pub struct TimeNotBefore(TimeOptions);

impl Validator<Timestamp> for TimeNotBefore {
    type Error = TimeTooFarError;

    fn validate(&self, ts: &Timestamp) -> Result<(), Self::Error> {
        let earliest = ts.0 - self.0.leeway;
        if self.0.when >= earliest {
            Ok(())
        } else {
            Err(TimeTooFarError)
        }
    }
}

impl From<TimeOptions> for TimeNotBefore {
    fn from(opt: TimeOptions) -> Self {
        Self(opt)
    }
}

impl From<&TimeOptions> for TimeNotBefore {
    fn from(opt: &TimeOptions) -> Self {
        Self(opt.clone())
    }
}

// ---------------------------------------------------------------------------
// Token hashing (at_hash / c_hash per OIDC Core)
// ---------------------------------------------------------------------------

/// Errors from token-hash operations.
#[derive(Debug, Clone, Copy, Error)]
pub enum TokenHashError {
    #[error("Hashes don't match")]
    HashMismatch,

    #[error("Unsupported algorithm for hashing")]
    UnsupportedAlgorithm,
}

/// Categorise a JWS algorithm into a SHA family for token hashing.
enum ShaFamily {
    Sha256,
    Sha384,
    Sha512,
}

/// Map an algorithm to its SHA family.  The OIDC spec says to use the hash
/// algorithm that matches the `alg` parameter of the ID Token header.
fn sha_family_for(alg: &JsonWebSignatureAlg) -> Result<ShaFamily, TokenHashError> {
    // Group by the trailing bit-size that each algorithm family implies.
    let name = alg.to_string();
    if name.ends_with("256") || name == "ES256K" {
        Ok(ShaFamily::Sha256)
    } else if name.ends_with("384") {
        Ok(ShaFamily::Sha384)
    } else if name.ends_with("512")
        || matches!(
            alg,
            JsonWebSignatureAlg::EdDsa | JsonWebSignatureAlg::Ed25519
        )
    {
        Ok(ShaFamily::Sha512)
    } else {
        Err(TokenHashError::UnsupportedAlgorithm)
    }
}

/// Hash the given token with the given algorithm for an ID Token claim.
///
/// According to the [OpenID Connect Core 1.0 specification].
///
/// # Errors
///
/// Returns an error if the algorithm is not supported.
///
/// [OpenID Connect Core 1.0 specification]: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
pub fn hash_token(alg: &JsonWebSignatureAlg, token: &str) -> Result<String, TokenHashError> {
    let left_half = match sha_family_for(alg)? {
        ShaFamily::Sha256 => {
            let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            digest[..16].to_vec()
        }
        ShaFamily::Sha384 => {
            let digest: [u8; 48] = Sha384::digest(token.as_bytes()).into();
            digest[..24].to_vec()
        }
        ShaFamily::Sha512 => {
            let digest: [u8; 64] = Sha512::digest(token.as_bytes()).into();
            digest[..32].to_vec()
        }
    };

    Ok(Base64UrlUnpadded::encode_string(&left_half))
}

/// Validator that compares a stored hash claim against a freshly computed hash.
#[derive(Debug, Clone)]
pub struct TokenHash<'a> {
    alg: &'a JsonWebSignatureAlg,
    token: &'a str,
}

impl<'a> TokenHash<'a> {
    /// Creates a new `TokenHash` validator for the given algorithm and token.
    #[must_use]
    pub fn new(alg: &'a JsonWebSignatureAlg, token: &'a str) -> Self {
        Self { alg, token }
    }
}

impl Validator<String> for TokenHash<'_> {
    type Error = TokenHashError;

    fn validate(&self, stored: &String) -> Result<(), Self::Error> {
        let computed = hash_token(self.alg, self.token)?;
        if computed == *stored {
            Ok(())
        } else {
            Err(TokenHashError::HashMismatch)
        }
    }
}

// ---------------------------------------------------------------------------
// Equality validator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Error)]
#[error("Values don't match")]
pub struct EqualityError;

/// Validates that a claim value equals an expected reference value.
#[derive(Debug, Clone)]
pub struct Equality<'a, T: ?Sized> {
    value: &'a T,
}

impl<'a, T: ?Sized> Equality<'a, T> {
    /// Creates a new `Equality` validator for the given value.
    #[must_use]
    pub fn new(value: &'a T) -> Self {
        Self { value }
    }
}

impl<T1, T2> Validator<T1> for Equality<'_, T2>
where
    T2: PartialEq<T1> + ?Sized,
{
    type Error = EqualityError;

    fn validate(&self, actual: &T1) -> Result<(), Self::Error> {
        if *self.value == *actual {
            Ok(())
        } else {
            Err(EqualityError)
        }
    }
}

impl<'a, T: ?Sized> From<&'a T> for Equality<'a, T> {
    fn from(value: &'a T) -> Self {
        Self::new(value)
    }
}

// ---------------------------------------------------------------------------
// Contains validator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Error)]
#[error("OneOrMany doesn't contain value")]
pub struct ContainsError;

/// Validates that a `OneOrMany<T>` collection contains the expected element.
#[derive(Debug, Clone)]
pub struct Contains<'a, T> {
    value: &'a T,
}

impl<'a, T> Contains<'a, T> {
    /// Creates a new `Contains` validator for the given value.
    #[must_use]
    pub fn new(value: &'a T) -> Self {
        Self { value }
    }
}

impl<T> Validator<OneOrMany<T>> for Contains<'_, T>
where
    T: PartialEq,
{
    type Error = ContainsError;

    fn validate(&self, collection: &OneOrMany<T>) -> Result<(), Self::Error> {
        if collection.contains(self.value) {
            Ok(())
        } else {
            Err(ContainsError)
        }
    }
}

impl<'a, T> From<&'a T> for Contains<'a, T> {
    fn from(value: &'a T) -> Self {
        Self::new(value)
    }
}

// ---------------------------------------------------------------------------
// Timestamp – chrono wrapper with UNIX-seconds serde
// ---------------------------------------------------------------------------

/// A UTC timestamp that serializes as a UNIX epoch integer (seconds).
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct Timestamp(#[serde(with = "chrono::serde::ts_seconds")] chrono::DateTime<chrono::Utc>);

impl Deref for Timestamp {
    type Target = chrono::DateTime<chrono::Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
    fn from(value: chrono::DateTime<chrono::Utc>) -> Self {
        Timestamp(value)
    }
}

// ---------------------------------------------------------------------------
// OneOrMany<T> – hand-rolled serde to avoid serde_with dependency pattern
// ---------------------------------------------------------------------------

/// A value that may appear in JSON as either a single `T` or an array of `T`.
///
/// Always normalised to a `Vec<T>` internally.  Serializes back to a bare
/// value when the vector has exactly one element ("prefer one" policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneOrMany<T>(Vec<T>);

impl<T> Deref for OneOrMany<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self(vec![value])
    }
}

// Custom Serialize: emit bare value for single-element vecs.
impl<T: Serialize> Serialize for OneOrMany<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.len() == 1 {
            self.0[0].serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

// Custom Deserialize: accept either a single value or an array.
impl<'de, T: Deserialize<'de>> Deserialize<'de> for OneOrMany<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct OneOrManyVisitor<U>(std::marker::PhantomData<U>);

        impl<'de, U: Deserialize<'de>> serde::de::Visitor<'de> for OneOrManyVisitor<U> {
            type Value = OneOrMany<U>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a single value or an array of values")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // Wrap the string in a JSON Value and deserialize U from it
                // so that we support `OneOrMany<String>` and similar types
                // that implement Deserialize from a string.
                let val = U::deserialize(serde::de::value::StrDeserializer::new(v))?;
                Ok(OneOrMany(vec![val]))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let val = U::deserialize(serde::de::value::StringDeserializer::new(v))?;
                Ok(OneOrMany(vec![val]))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(1));
                while let Some(elem) = seq.next_element()? {
                    items.push(elem);
                }
                Ok(OneOrMany(items))
            }

            // Support bare numeric / bool values so that `OneOrMany<i64>` etc. work.
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let val = U::deserialize(serde::de::value::I64Deserializer::new(v))?;
                Ok(OneOrMany(vec![val]))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let val = U::deserialize(serde::de::value::U64Deserializer::new(v))?;
                Ok(OneOrMany(vec![val]))
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let val = U::deserialize(serde::de::value::BoolDeserializer::new(v))?;
                Ok(OneOrMany(vec![val]))
            }
        }

        deserializer.deserialize_any(OneOrManyVisitor(std::marker::PhantomData))
    }
}

// ===========================================================================
// Standard claim constants
// ===========================================================================

/// Claims defined in RFC 7519 sec. 4.1
/// <https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1>
mod rfc7519 {
    use super::{Claim, Contains, Equality, OneOrMany, TimeNotAfter, TimeNotBefore, Timestamp};

    pub const ISS: Claim<String, Equality<str>> = Claim::new("iss");
    pub const SUB: Claim<String> = Claim::new("sub");
    pub const AUD: Claim<OneOrMany<String>, Contains<String>> = Claim::new("aud");
    pub const NBF: Claim<Timestamp, TimeNotBefore> = Claim::new("nbf");
    pub const EXP: Claim<Timestamp, TimeNotAfter> = Claim::new("exp");
    pub const IAT: Claim<Timestamp, TimeNotBefore> = Claim::new("iat");
    pub const JTI: Claim<String> = Claim::new("jti");
}

/// Claims defined in OIDC Core sec. 2 and sec. 5.1
/// <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>
/// <https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims>
mod oidc_core {
    use url::Url;

    use super::{Claim, Equality, Timestamp, TokenHash};

    pub const AUTH_TIME: Claim<Timestamp> = Claim::new("auth_time");
    pub const NONCE: Claim<String, Equality<str>> = Claim::new("nonce");
    pub const AT_HASH: Claim<String, TokenHash> = Claim::new("at_hash");
    pub const C_HASH: Claim<String, TokenHash> = Claim::new("c_hash");

    pub const NAME: Claim<String> = Claim::new("name");
    pub const GIVEN_NAME: Claim<String> = Claim::new("given_name");
    pub const FAMILY_NAME: Claim<String> = Claim::new("family_name");
    pub const MIDDLE_NAME: Claim<String> = Claim::new("middle_name");
    pub const NICKNAME: Claim<String> = Claim::new("nickname");
    pub const PREFERRED_USERNAME: Claim<String> = Claim::new("preferred_username");
    pub const PROFILE: Claim<Url> = Claim::new("profile");
    pub const PICTURE: Claim<Url> = Claim::new("picture");
    pub const WEBSITE: Claim<Url> = Claim::new("website");
    // TODO: email type?
    pub const EMAIL: Claim<String> = Claim::new("email");
    pub const EMAIL_VERIFIED: Claim<bool> = Claim::new("email_verified");
    pub const GENDER: Claim<String> = Claim::new("gender");
    // TODO: date type
    pub const BIRTHDATE: Claim<String> = Claim::new("birthdate");
    // TODO: timezone type
    pub const ZONEINFO: Claim<String> = Claim::new("zoneinfo");
    // TODO: locale type
    pub const LOCALE: Claim<String> = Claim::new("locale");
    // TODO: phone number type
    pub const PHONE_NUMBER: Claim<String> = Claim::new("phone_number");
    pub const PHONE_NUMBER_VERIFIED: Claim<bool> = Claim::new("phone_number_verified");
    // TODO: pub const ADDRESS: Claim<Timestamp> = Claim::new("address");
    pub const UPDATED_AT: Claim<Timestamp> = Claim::new("updated_at");
}

/// Claims defined in OpenID.FrontChannel
/// <https://openid.net/specs/openid-connect-frontchannel-1_0.html#ClaimsContents>
mod oidc_frontchannel {
    use super::Claim;

    pub const SID: Claim<String> = Claim::new("sid");
}

pub use self::{oidc_core::*, oidc_frontchannel::*, rfc7519::*};

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::TimeZone;
    use sha2::{Digest, Sha512};

    use super::*;

    // -----------------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------------

    /// Builds a standard set of JWT claims at a known point in time.
    fn standard_claims_fixture() -> (
        chrono::DateTime<chrono::Utc>,
        HashMap<String, serde_json::Value>,
    ) {
        let now = chrono::Utc
            .with_ymd_and_hms(2018, 1, 18, 1, 30, 22)
            .unwrap();
        let claims = serde_json::json!({
            "iss": "https://foo.com",
            "sub": "johndoe",
            "aud": ["abcd-efgh"],
            "iat": 1_516_239_022,
            "nbf": 1_516_239_022,
            "exp": 1_516_239_322,
            "jti": "1122-3344-5566-7788",
        });
        (now, serde_json::from_value(claims).unwrap())
    }

    /// Reference time used across multiple tests.
    fn reference_time() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .with_ymd_and_hms(2018, 1, 18, 1, 30, 22)
            .unwrap()
    }

    /// Builds claims with deliberately wrong types for negative testing.
    fn invalid_type_claims_fixture() -> HashMap<String, serde_json::Value> {
        let claims = serde_json::json!({
            "iss": 123,
            "sub": 456,
            "aud": 789,
            "iat": "123",
            "nbf": "456",
            "exp": "789",
            "jti": 123,
        });
        serde_json::from_value(claims).unwrap()
    }

    // -----------------------------------------------------------------------
    // Timestamp serde
    // -----------------------------------------------------------------------

    #[test]
    fn timestamp_roundtrips_through_json() {
        let dt = Timestamp(reference_time());
        let json_val = serde_json::Value::Number(1_516_239_022.into());

        let deserialized: Timestamp = serde_json::from_value(json_val.clone()).unwrap();
        assert_eq!(dt, deserialized);

        let serialized = serde_json::to_value(&dt).unwrap();
        assert_eq!(json_val, serialized);
    }

    // -----------------------------------------------------------------------
    // OneOrMany serde
    // -----------------------------------------------------------------------

    #[test]
    fn one_or_many_deserializes_single_and_array() {
        let single = OneOrMany(vec!["one".to_owned()]);
        let multi = OneOrMany(vec!["one".to_owned(), "two".to_owned()]);

        // bare string -> single-element vec
        assert_eq!(
            single,
            serde_json::from_value(serde_json::json!("one")).unwrap()
        );
        // single-element array -> single-element vec
        assert_eq!(
            single,
            serde_json::from_value(serde_json::json!(["one"])).unwrap()
        );
        // multi-element array
        assert_eq!(
            multi,
            serde_json::from_value(serde_json::json!(["one", "two"])).unwrap()
        );
    }

    #[test]
    fn one_or_many_serializes_prefer_one() {
        let single = OneOrMany(vec!["one".to_owned()]);
        let multi = OneOrMany(vec!["one".to_owned(), "two".to_owned()]);

        assert_eq!(
            serde_json::to_value(&single).unwrap(),
            serde_json::json!("one")
        );
        assert_eq!(
            serde_json::to_value(&multi).unwrap(),
            serde_json::json!(["one", "two"])
        );
    }

    // -----------------------------------------------------------------------
    // Token hashing
    // -----------------------------------------------------------------------

    #[test]
    fn token_hash_with_eddsa_and_ed25519() {
        let token = "access-token-value";

        // Compute expected hash manually with SHA-512, left half
        let full_hash: [u8; 64] = Sha512::digest(token.as_bytes()).into();
        let expected = Base64UrlUnpadded::encode_string(&full_hash[..32]);

        assert_eq!(
            hash_token(&JsonWebSignatureAlg::EdDsa, token).unwrap(),
            expected,
        );
        assert_eq!(
            hash_token(&JsonWebSignatureAlg::Ed25519, token).unwrap(),
            expected,
        );
    }

    // -----------------------------------------------------------------------
    // Claim extraction – happy path
    // -----------------------------------------------------------------------

    #[test]
    fn extract_all_standard_claims() {
        let (now, mut claims) = standard_claims_fixture();
        let expiration = now + chrono::Duration::try_seconds(300).unwrap();
        let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());

        let iss = ISS
            .extract_required_with_options(&mut claims, "https://foo.com")
            .unwrap();
        let sub = SUB.extract_optional(&mut claims).unwrap();
        let aud = AUD
            .extract_optional_with_options(&mut claims, &"abcd-efgh".to_owned())
            .unwrap();
        let nbf = NBF
            .extract_optional_with_options(&mut claims, &time_options)
            .unwrap();
        let exp = EXP
            .extract_optional_with_options(&mut claims, &time_options)
            .unwrap();
        let iat = IAT
            .extract_optional_with_options(&mut claims, &time_options)
            .unwrap();
        let jti = JTI.extract_optional(&mut claims).unwrap();

        assert_eq!(iss, "https://foo.com");
        assert_eq!(sub, Some("johndoe".to_owned()));
        assert_eq!(aud.as_deref(), Some(&vec!["abcd-efgh".to_owned()]));
        assert_eq!(iat.as_deref(), Some(&now));
        assert_eq!(nbf.as_deref(), Some(&now));
        assert_eq!(exp.as_deref(), Some(&expiration));
        assert_eq!(jti, Some("1122-3344-5566-7788".to_owned()));

        // Everything should have been consumed
        assert!(claims.is_empty());
    }

    // -----------------------------------------------------------------------
    // Time validation
    // -----------------------------------------------------------------------

    #[test]
    fn time_validation_scenarios() {
        let now = reference_time();

        let time_claims = serde_json::json!({
            "iat": 1_516_239_022,
            "nbf": 1_516_239_022,
            "exp": 1_516_239_322,
        });
        let base: HashMap<String, serde_json::Value> = serde_json::from_value(time_claims).unwrap();

        // Scenario 1: exactly at claim time, zero leeway => all pass
        {
            let mut c = base.clone();
            let opts = TimeOptions::new(now).leeway(chrono::Duration::zero());
            assert!(IAT.extract_required_with_options(&mut c, &opts).is_ok());
            assert!(NBF.extract_required_with_options(&mut c, &opts).is_ok());
            assert!(EXP.extract_required_with_options(&mut c, &opts).is_ok());
        }

        // Scenario 2: 1 minute before claim time, zero leeway => iat/nbf fail
        let earlier = now - chrono::Duration::try_seconds(60).unwrap();
        {
            let mut c = base.clone();
            let opts = TimeOptions::new(earlier).leeway(chrono::Duration::zero());
            assert!(matches!(
                IAT.extract_required_with_options(&mut c, &opts),
                Err(ClaimError::ValidationError { claim: "iat", .. }),
            ));
            assert!(matches!(
                NBF.extract_required_with_options(&mut c, &opts),
                Err(ClaimError::ValidationError { claim: "nbf", .. }),
            ));
            assert!(EXP.extract_required_with_options(&mut c, &opts).is_ok());
        }

        // Scenario 3: 1 minute before, 2-minute leeway => all pass
        {
            let mut c = base.clone();
            let opts =
                TimeOptions::new(earlier).leeway(chrono::Duration::try_seconds(120).unwrap());
            assert!(IAT.extract_required_with_options(&mut c, &opts).is_ok());
            assert!(NBF.extract_required_with_options(&mut c, &opts).is_ok());
            assert!(EXP.extract_required_with_options(&mut c, &opts).is_ok());
        }

        // Scenario 4: well past expiration, zero leeway => exp fails
        let later = now + chrono::Duration::try_seconds(7 * 60).unwrap();
        {
            let mut c = base.clone();
            let opts = TimeOptions::new(later).leeway(chrono::Duration::zero());
            assert!(IAT.extract_required_with_options(&mut c, &opts).is_ok());
            assert!(NBF.extract_required_with_options(&mut c, &opts).is_ok());
            assert!(matches!(
                EXP.extract_required_with_options(&mut c, &opts),
                Err(ClaimError::ValidationError { claim: "exp", .. }),
            ));
        }

        // Scenario 5: past expiration but within 2-minute leeway
        {
            let mut c = base;
            let opts = TimeOptions::new(later).leeway(chrono::Duration::try_minutes(2).unwrap());
            assert!(IAT.extract_required_with_options(&mut c, &opts).is_ok());
            assert!(NBF.extract_required_with_options(&mut c, &opts).is_ok());
            assert!(EXP.extract_required_with_options(&mut c, &opts).is_ok());
        }
    }

    // -----------------------------------------------------------------------
    // Invalid type claims
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_wrong_typed_claims() {
        let now = reference_time();
        let opts = TimeOptions::new(now).leeway(chrono::Duration::zero());
        let mut claims = invalid_type_claims_fixture();

        assert!(matches!(
            ISS.extract_required_with_options(&mut claims, "https://foo.com"),
            Err(ClaimError::InvalidClaim("iss"))
        ));
        assert!(matches!(
            SUB.extract_required(&mut claims),
            Err(ClaimError::InvalidClaim("sub"))
        ));
        assert!(matches!(
            AUD.extract_required_with_options(&mut claims, &"abcd-efgh".to_owned()),
            Err(ClaimError::InvalidClaim("aud"))
        ));
        assert!(matches!(
            NBF.extract_required_with_options(&mut claims, &opts),
            Err(ClaimError::InvalidClaim("nbf"))
        ));
        assert!(matches!(
            EXP.extract_required_with_options(&mut claims, &opts),
            Err(ClaimError::InvalidClaim("exp"))
        ));
        assert!(matches!(
            IAT.extract_required_with_options(&mut claims, &opts),
            Err(ClaimError::InvalidClaim("iat"))
        ));
        assert!(matches!(
            JTI.extract_required(&mut claims),
            Err(ClaimError::InvalidClaim("jti"))
        ));
    }

    // -----------------------------------------------------------------------
    // Missing claims
    // -----------------------------------------------------------------------

    #[test]
    fn missing_required_claims_error() {
        let mut empty: HashMap<String, serde_json::Value> = HashMap::new();

        assert!(matches!(
            ISS.extract_required_with_options(&mut empty, "https://foo.com"),
            Err(ClaimError::MissingClaim("iss"))
        ));
        assert!(matches!(
            SUB.extract_required(&mut empty),
            Err(ClaimError::MissingClaim("sub"))
        ));
        assert!(matches!(
            AUD.extract_required_with_options(&mut empty, &"abcd-efgh".to_owned()),
            Err(ClaimError::MissingClaim("aud"))
        ));
    }

    #[test]
    fn missing_optional_claims_return_none() {
        let mut empty: HashMap<String, serde_json::Value> = HashMap::new();

        assert!(matches!(
            ISS.extract_optional_with_options(&mut empty, "https://foo.com"),
            Ok(None)
        ));
        assert!(matches!(SUB.extract_optional(&mut empty), Ok(None)));
        assert!(matches!(
            AUD.extract_optional_with_options(&mut empty, &"abcd-efgh".to_owned()),
            Ok(None)
        ));
    }

    // -----------------------------------------------------------------------
    // Equality validation
    // -----------------------------------------------------------------------

    #[test]
    fn equality_validator_accepts_match() {
        let claims = serde_json::json!({ "iss": "https://foo.com" });
        let mut claims: HashMap<String, serde_json::Value> =
            serde_json::from_value(claims).unwrap();

        ISS.extract_required_with_options(&mut claims.clone(), "https://foo.com")
            .unwrap();

        assert!(matches!(
            ISS.extract_required_with_options(&mut claims, "https://bar.com"),
            Err(ClaimError::ValidationError { claim: "iss", .. }),
        ));
    }

    // -----------------------------------------------------------------------
    // Contains validation
    // -----------------------------------------------------------------------

    #[test]
    fn contains_validator_checks_membership() {
        let claims = serde_json::json!({ "aud": "abcd-efgh" });
        let mut claims: HashMap<String, serde_json::Value> =
            serde_json::from_value(claims).unwrap();

        AUD.extract_required_with_options(&mut claims.clone(), &"abcd-efgh".to_owned())
            .unwrap();

        assert!(matches!(
            AUD.extract_required_with_options(&mut claims, &"wxyz".to_owned()),
            Err(ClaimError::ValidationError { claim: "aud", .. }),
        ));
    }
}
