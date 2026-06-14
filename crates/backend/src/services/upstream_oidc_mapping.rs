//! Trusted-issuer policy mapping for inbound upstream OIDC `id_token`s.
//!
//! Round 25 introduces a typed mapping layer between an upstream OIDC
//! provider's raw `id_token` claims and the local Cokret identity model.
//!
//! Unlike the existing `upstream_oidc.rs` strand — which orchestrates the OAuth
//! authorization-code dance with a *configured* upstream provider — this
//! module is the policy-decision point: a small `TrustedIssuerPolicy` set
//! says "if you receive a token signed by issuer X with audience Y, here is
//! how to map its claims into a typed `MappedUpstreamIdentity`". This is the
//! shape consumed by experimental token-exchange and "bring-your-own-OIDC"
//! strands.
//!
//! Validation guarantees (any failure → `MappingError`):
//!
//! - the `iss` claim matches one of the trusted policies,
//! - the `aud` claim contains the policy's expected audience,
//! - signature verification against the issuer's JWKS,
//! - `exp` is in the future and `iat` is not too far in the future (≤ 5 min skew, matching SDK /
//!   spec convention).
//!
//! On success, claims are projected through the policy's `claims_mapping`
//! into a `MappedUpstreamIdentity { sub, email?, name?, role }`. A missing
//! mapped role falls back to the policy's `default_role`.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::jwk::PublicJsonWebKeySet;
use serde_json::Value;
use thiserror::Error;

use crate::oidc_client::requests::jose::{JwtVerificationData, verify_signed_jwt};

/// Maximum tolerated absolute clock skew between token timestamps and
/// local clock (5 minutes).
pub const MAX_TOKEN_CLOCK_SKEW: Duration = Duration::minutes(5);

/// Mapping rule: which raw upstream claim feeds which canonical Cokret field.
///
/// Each `Option<String>` is the *raw claim name in the upstream `id_token`*; if
/// it is `None`, the field is not extracted and stays `None` on the mapped
/// identity (or, for `role`, falls back to `default_role`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimsMapping {
    /// Source claim for `MappedUpstreamIdentity::sub`. Defaults to `sub`.
    pub sub_claim: String,
    /// Source claim for `MappedUpstreamIdentity::email`.
    pub email_claim: Option<String>,
    /// Source claim for `MappedUpstreamIdentity::name`.
    pub name_claim: Option<String>,
    /// Source claim for `MappedUpstreamIdentity::role`. If unset or the
    /// claim is missing, `TrustedIssuerPolicy::default_role` is used.
    pub role_claim: Option<String>,
}

impl Default for ClaimsMapping {
    fn default() -> Self {
        Self {
            sub_claim: "sub".to_owned(),
            email_claim: Some("email".to_owned()),
            name_claim: Some("name".to_owned()),
            role_claim: None,
        }
    }
}

/// Trust policy for a single upstream OIDC issuer.
///
/// Pure data — no I/O — so it is cheaply cloneable and can be loaded from
/// config and held in `AppState`.
#[derive(Clone, Debug)]
pub struct TrustedIssuerPolicy {
    /// Required `iss` claim value (string-equal match).
    pub issuer: String,
    /// Audience this coauth presents to the upstream issuer; must appear in
    /// the token's `aud` claim (string-array or string-scalar both
    /// accepted).
    pub audience: String,
    /// JWKS that signs tokens for this issuer.
    pub jwks: PublicJsonWebKeySet,
    /// Acceptable signing algorithm.
    pub signing_algorithm: JsonWebSignatureAlg,
    /// Per-issuer claim → field mapping.
    pub claims_mapping: ClaimsMapping,
    /// Role assigned when `claims_mapping.role_claim` produces nothing.
    pub default_role: String,
}

/// Set of `TrustedIssuerPolicy` entries; lookup is by `issuer`.
#[derive(Clone, Debug, Default)]
pub struct TrustedIssuerPolicySet {
    policies: Vec<TrustedIssuerPolicy>,
}

impl TrustedIssuerPolicySet {
    /// Build a policy set from a vector of policies. Later entries with the
    /// same `issuer` shadow earlier ones.
    #[must_use]
    pub fn new(policies: Vec<TrustedIssuerPolicy>) -> Self {
        Self { policies }
    }

    /// Find the policy matching the given issuer string, if any.
    #[must_use]
    pub fn find(&self, issuer: &str) -> Option<&TrustedIssuerPolicy> {
        self.policies.iter().rfind(|policy| policy.issuer == issuer)
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

/// Typed Cokret-side identity projected from an upstream `id_token`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappedUpstreamIdentity {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: String,
}

#[derive(Debug, Error)]
pub enum MappingError {
    #[error("no trusted-issuer policy for issuer={0}")]
    UntrustedIssuer(String),

    #[error("token verification failed: {0}")]
    Verification(String),

    #[error("token is missing required claim: {0}")]
    MissingClaim(&'static str),

    #[error("token claim {0} has invalid type")]
    InvalidClaimType(String),

    #[error("token clock-skew exceeded ({field}={token} vs now={now})")]
    ClockSkew {
        field: &'static str,
        token: i64,
        now: i64,
    },
}

/// Extract the issuer from a JWT *without* verifying its signature. Used to
/// pick a trusted-issuer policy before the cryptographic check.
///
/// # Errors
///
/// Returns an error if the JWT is malformed or has no `iss` claim.
pub fn peek_issuer(id_token: &str) -> Result<String, MappingError> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let mut parts = id_token.split('.');
    let _header = parts.next().ok_or(MappingError::MissingClaim("header"))?;
    let payload_b64 = parts.next().ok_or(MappingError::MissingClaim("payload"))?;
    let payload_bytes = Base64UrlUnpadded::decode_vec(payload_b64)
        .map_err(|err| MappingError::Verification(format!("payload base64 decode: {err}")))?;
    let payload: HashMap<String, Value> = serde_json::from_slice(&payload_bytes)
        .map_err(|err| MappingError::Verification(format!("payload json decode: {err}")))?;
    payload
        .get("iss")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(MappingError::MissingClaim("iss"))
}

/// Validate the upstream `id_token` against the matching `TrustedIssuerPolicy`
/// from `policy_set` and project the claims into `MappedUpstreamIdentity`.
///
/// # Errors
///
/// Returns a `MappingError` for any of:
/// - no policy for the token's `iss`,
/// - signature/issuer/audience/expiry verification failure,
/// - missing required `sub` claim or claims mapped to non-string types.
pub fn map_upstream_id_token(
    issuer: &str,
    id_token: &str,
    policy_set: &TrustedIssuerPolicySet,
    now: DateTime<Utc>,
) -> Result<MappedUpstreamIdentity, MappingError> {
    let policy = policy_set
        .find(issuer)
        .ok_or_else(|| MappingError::UntrustedIssuer(issuer.to_owned()))?;

    let verification_data = JwtVerificationData {
        issuer: Some(policy.issuer.as_str()),
        jwks: &policy.jwks,
        client_id: &policy.audience,
        signing_algorithm: &policy.signing_algorithm,
    };

    // Note: `verify_signed_jwt` performs JWS verification against `jwks` and
    // checks that `aud` contains `client_id` (we pass `policy.audience` as
    // the expected audience). It does not enforce `exp`/`iat` skew, so we
    // re-check those here against `MAX_TOKEN_CLOCK_SKEW`.
    // `verify_signed_jwt` performs JWS verification, issuer check, and
    // requires `aud` ∋ client_id (we wire `policy.audience` as `client_id`).
    // Any deviation surfaces here as `MappingError::Verification`.
    let jwt = verify_signed_jwt(id_token, verification_data)
        .map_err(|err| MappingError::Verification(err.to_string()))?;
    let claims = jwt.payload().clone();

    // exp / iat skew checks (5min window).
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
        let now_ts = now.timestamp();
        if exp + MAX_TOKEN_CLOCK_SKEW.num_seconds() < now_ts {
            return Err(MappingError::ClockSkew {
                field: "exp",
                token: exp,
                now: now_ts,
            });
        }
    } else {
        return Err(MappingError::MissingClaim("exp"));
    }
    if let Some(iat) = claims.get("iat").and_then(Value::as_i64) {
        let now_ts = now.timestamp();
        if iat - MAX_TOKEN_CLOCK_SKEW.num_seconds() > now_ts {
            return Err(MappingError::ClockSkew {
                field: "iat",
                token: iat,
                now: now_ts,
            });
        }
    }

    let mapping = &policy.claims_mapping;

    let sub =
        string_claim(&claims, &mapping.sub_claim)?.ok_or(MappingError::MissingClaim("sub"))?;
    let email = mapping
        .email_claim
        .as_deref()
        .map(|name| string_claim(&claims, name))
        .transpose()?
        .flatten();
    let name = mapping
        .name_claim
        .as_deref()
        .map(|name| string_claim(&claims, name))
        .transpose()?
        .flatten();
    let role = mapping
        .role_claim
        .as_deref()
        .map(|name| string_claim(&claims, name))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| policy.default_role.clone());

    Ok(MappedUpstreamIdentity {
        sub,
        email,
        name,
        role,
    })
}

fn string_claim(
    claims: &HashMap<String, Value>,
    name: &str,
) -> Result<Option<String>, MappingError> {
    match claims.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(MappingError::InvalidClaimType(name.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_set_rejects_any_issuer() {
        let err = map_upstream_id_token(
            "https://example.com",
            "irrelevant",
            &TrustedIssuerPolicySet::default(),
            Utc::now(),
        )
        .expect_err("must fail with empty policy set");
        assert!(matches!(err, MappingError::UntrustedIssuer(_)));
    }

    #[test]
    fn policy_lookup_picks_last_duplicate() {
        // Two policies with the same issuer — the last one shadows the
        // first per the docstring contract on `TrustedIssuerPolicySet::new`.
        let jwks = PublicJsonWebKeySet::default();
        let policy_a = TrustedIssuerPolicy {
            issuer: "https://idp.example".to_owned(),
            audience: "client-a".to_owned(),
            jwks: jwks.clone(),
            signing_algorithm: JsonWebSignatureAlg::Rs256,
            claims_mapping: ClaimsMapping::default(),
            default_role: "viewer".to_owned(),
        };
        let policy_b = TrustedIssuerPolicy {
            audience: "client-b".to_owned(),
            ..policy_a.clone()
        };
        let set = TrustedIssuerPolicySet::new(vec![policy_a, policy_b]);
        let resolved = set.find("https://idp.example").expect("must find");
        assert_eq!(resolved.audience, "client-b");
    }

    #[test]
    fn peek_issuer_extracts_iss_without_verifying() {
        // Hand-craft an unsigned JWT (header.payload.signature) just to
        // exercise `peek_issuer` parser. The payload is `{"iss":"x"}`.
        use base64ct::{Base64UrlUnpadded, Encoding};
        let header = Base64UrlUnpadded::encode_string(b"{\"alg\":\"none\"}");
        let payload =
            Base64UrlUnpadded::encode_string(b"{\"iss\":\"https://idp.example\",\"sub\":\"u1\"}");
        let token = format!("{header}.{payload}.");
        let issuer = peek_issuer(&token).expect("peek must succeed on well-formed token");
        assert_eq!(issuer, "https://idp.example");
    }

    #[test]
    fn peek_issuer_rejects_garbage() {
        assert!(peek_issuer("not.a.jwt!@#").is_err());
    }
}
