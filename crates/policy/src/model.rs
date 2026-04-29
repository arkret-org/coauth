//! Input and output types for policy evaluation.
//!
//! These types define the data structures passed to and returned from
//! the Open Policy Agent policy engine. JSON schemas can be generated
//! from the input types for compile-time validation.

use std::net::IpAddr;

use coauth_data::{Client, User};
use oauth2_types::{registration::VerifiedClientMetadata, scope::Scope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Policy violation codes
// ---------------------------------------------------------------------------

/// Well-known codes that identify specific policy violations.
/// Each variant maps to a kebab-case string used in policy responses.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Code {
    /// The chosen username does not meet the minimum length requirement.
    UsernameTooShort,

    /// The chosen username exceeds the maximum allowed length.
    UsernameTooLong,

    /// The chosen username contains characters that are not permitted.
    UsernameInvalidChars,

    /// The chosen username is composed entirely of numeric digits.
    UsernameAllNumeric,

    /// The chosen username has been banned by policy.
    UsernameBanned,

    /// The chosen username is not on the allowlist.
    UsernameNotAllowed,

    /// The domain portion of the email address is not permitted.
    EmailDomainNotAllowed,

    /// The domain portion of the email address has been banned.
    EmailDomainBanned,

    /// The full email address is not permitted by policy.
    EmailNotAllowed,

    /// The full email address has been banned by policy.
    EmailBanned,

    /// The user already has the maximum number of allowed sessions.
    TooManySessions,
}

impl Code {
    /// Returns the kebab-case string representation of this code,
    /// matching the serde serialization format.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UsernameTooShort => "username-too-short",
            Self::UsernameTooLong => "username-too-long",
            Self::UsernameInvalidChars => "username-invalid-chars",
            Self::UsernameAllNumeric => "username-all-numeric",
            Self::UsernameBanned => "username-banned",
            Self::UsernameNotAllowed => "username-not-allowed",
            Self::EmailDomainNotAllowed => "email-domain-not-allowed",
            Self::EmailDomainBanned => "email-domain-banned",
            Self::EmailNotAllowed => "email-not-allowed",
            Self::EmailBanned => "email-banned",
            Self::TooManySessions => "too-many-sessions",
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluation results
// ---------------------------------------------------------------------------

/// A single violation reported by the policy engine.
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct Violation {
    /// Human-readable message describing the violation
    pub msg: String,

    /// Optional URI the client should redirect to
    pub redirect_uri: Option<String>,

    /// Optional name of the input field that caused the violation
    pub field: Option<String>,

    /// Optional well-known code identifying the violation type
    pub code: Option<Code>,
}

/// Aggregated result of evaluating one or more policy rules.
/// Contains zero or more violations; an empty list means the
/// input passed all policy checks.
#[derive(Deserialize, Debug)]
pub struct EvaluationResult {
    #[serde(rename = "result")]
    pub violations: Vec<Violation>,
}

impl EvaluationResult {
    /// Returns `true` when no violations were produced,
    /// indicating the policy evaluation passed.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations.is_empty()
    }
}

impl std::fmt::Display for EvaluationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut is_first = true;
        for violation in &self.violations {
            if is_first {
                is_first = false;
            } else {
                write!(f, ", ")?;
            }
            write!(f, "{}", violation.msg)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Request context
// ---------------------------------------------------------------------------

/// Metadata about the entity making a policy-evaluated request.
#[derive(Serialize, Debug, Default, JsonSchema)]
pub struct Requester {
    /// IP address of the entity making the request, when available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<IpAddr>,

    /// HTTP User-Agent header value, when available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// ISO 3166-1 alpha-2 country code derived from the IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// How the user account registration was initiated.
#[derive(Serialize, Debug, JsonSchema)]
pub enum RegistrationMethod {
    /// Traditional password-based registration
    #[serde(rename = "password")]
    Password,

    /// Registration via an upstream OAuth 2.0 identity provider
    #[serde(rename = "upstream-oauth2")]
    UpstreamOAuth2,
}

/// Policy input for evaluating a new user registration request.
#[derive(Serialize, Debug, JsonSchema)]
#[serde(tag = "registration_method")]
pub struct RegisterInput<'a> {
    /// The method used for registration
    pub registration_method: RegistrationMethod,

    /// The requested username
    pub username: &'a str,

    /// Optional email address provided during registration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<&'a str>,

    /// Information about the entity making this request
    pub requester: Requester,
}

// ---------------------------------------------------------------------------
// Client registration
// ---------------------------------------------------------------------------

/// Policy input for evaluating an OAuth 2.0 dynamic client registration.
#[derive(Serialize, Debug, JsonSchema)]
pub struct ClientRegistrationInput<'a> {
    /// The validated client metadata from the registration request
    #[schemars(with = "std::collections::HashMap<String, serde_json::Value>")]
    pub client_metadata: &'a VerifiedClientMetadata,

    /// Information about the entity making this request
    pub requester: Requester,
}

// ---------------------------------------------------------------------------
// Authorization grants
// ---------------------------------------------------------------------------

/// The OAuth 2.0 grant type being requested.
#[derive(Serialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// Standard authorization code grant
    AuthorizationCode,

    /// Client credentials grant (no user involvement)
    ClientCredentials,

    /// Device authorization grant
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode,
}

/// Summary of how many active sessions a user currently has,
/// broken down by type.
#[derive(Serialize, Debug, JsonSchema)]
pub struct SessionCounts {
    /// Total number of active sessions across all types
    pub total: u64,

    /// Number of active OAuth 2.0 sessions
    pub oauth2: u64,

    /// Number of active personal/direct sessions
    pub personal: u64,
}

/// Policy input for evaluating an authorization grant request.
#[derive(Serialize, Debug, JsonSchema)]
pub struct AuthorizationGrantInput<'a> {
    /// The user requesting the grant, if applicable
    #[schemars(with = "Option<std::collections::HashMap<String, serde_json::Value>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<&'a User>,

    /// Current session counts for the user. Only populated
    /// when an authenticated user is involved in the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_counts: Option<SessionCounts>,

    /// The OAuth 2.0 client requesting the grant
    #[schemars(with = "std::collections::HashMap<String, serde_json::Value>")]
    pub client: &'a Client,

    /// The requested scope for the grant
    #[schemars(with = "String")]
    pub scope: &'a Scope,

    /// Which grant type is being used
    pub grant_type: GrantType,

    /// Information about the entity making this request
    pub requester: Requester,
}

// ---------------------------------------------------------------------------
// Email policy
// ---------------------------------------------------------------------------

/// Policy input for evaluating whether an email address may be added.
#[derive(Serialize, Debug, JsonSchema)]
pub struct EmailInput<'a> {
    /// The email address being evaluated
    pub email: &'a str,

    /// Information about the entity making this request
    pub requester: Requester,
}
