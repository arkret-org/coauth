use std::str::FromStr as _;

use chrono::{DateTime, Utc};
use coauth_email_types::Address;
use coauth_iana::oauth::PkceCodeChallengeMethod;
use coauth_oauth_types::pkce::{CodeChallengeError, CodeChallengeMethodExt};
use coauth_oauth_types::requests::ResponseMode;
use coauth_oauth_types::scope::{OPENID, PROFILE, Scope};
use rand_core::RngCore;
use serde::Serialize;
use ulid::Ulid;
use url::Url;

use super::session::Session;
use crate::InvalidTransitionError;

fn generate_alphanumeric(rng: &mut (impl RngCore + ?Sized), len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| CHARSET[*b as usize % CHARSET.len()] as char)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pkce {
    pub challenge_method: PkceCodeChallengeMethod,
    pub challenge: String,
}

impl Pkce {
    /// Create a new PKCE challenge, with the given method and challenge.
    #[must_use]
    pub fn new(challenge_method: PkceCodeChallengeMethod, challenge: String) -> Self {
        Pkce {
            challenge_method,
            challenge,
        }
    }

    /// Verify the PKCE challenge.
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier is invalid.
    pub fn verify(&self, verifier: &str) -> Result<(), CodeChallengeError> {
        self.challenge_method.verify(&self.challenge, verifier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub pkce: Option<Pkce>,
}

/// Workflow-progress axis of an authorization grant.
///
/// The discriminator key is deliberately `stage` (not `state`, as
/// `DeviceCodeGrantState` uses): this is a multi-step business *progress*
/// axis (`pending` → `fulfilled` → `exchanged`/`cancelled`), which
/// `common-fields.md` assigns to `stage`. The word `state` is also already
/// taken on the enclosing [`AuthorizationGrant`] for the OAuth `state`
/// request parameter, so reusing it here would be ambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(tag = "stage", rename_all = "lowercase")]
pub enum AuthorizationGrantStage {
    #[default]
    Pending,
    Fulfilled {
        session_id: Ulid,
        fulfilled_at: DateTime<Utc>,
    },
    Exchanged {
        session_id: Ulid,
        fulfilled_at: DateTime<Utc>,
        exchanged_at: DateTime<Utc>,
    },
    Cancelled {
        cancelled_at: DateTime<Utc>,
    },
}

impl AuthorizationGrantStage {
    #[must_use]
    pub fn new() -> Self {
        Self::Pending
    }

    fn fulfill(
        self,
        fulfilled_at: DateTime<Utc>,
        session: &Session,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Fulfilled {
                fulfilled_at,
                session_id: session.id,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    fn exchange(self, exchanged_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Fulfilled {
                fulfilled_at,
                session_id,
            } => Ok(Self::Exchanged {
                fulfilled_at,
                exchanged_at,
                session_id,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    /// Returns `true` if the authorization grant stage is [`Pending`].
    ///
    /// [`Pending`]: AuthorizationGrantStage::Pending
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` if the authorization grant stage is [`Fulfilled`].
    ///
    /// [`Fulfilled`]: AuthorizationGrantStage::Fulfilled
    #[must_use]
    pub fn is_fulfilled(&self) -> bool {
        matches!(self, Self::Fulfilled { .. })
    }

    /// Returns `true` if the authorization grant stage is [`Exchanged`].
    ///
    /// [`Exchanged`]: AuthorizationGrantStage::Exchanged
    #[must_use]
    pub fn is_exchanged(&self) -> bool {
        matches!(self, Self::Exchanged { .. })
    }
}

/// Parsed login hint for the authorization grant.
pub enum LoginHint<'a> {
    Username(&'a str),
    Email(Address),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationGrant {
    pub id: Ulid,
    #[serde(flatten)]
    pub stage: AuthorizationGrantStage,
    pub code: Option<AuthorizationCode>,
    pub client_id: Ulid,
    pub redirect_uri: Url,
    pub scope: Scope,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_mode: ResponseMode,
    pub response_type_id_token: bool,
    pub created_at: DateTime<Utc>,
    /// coauth extension: login hint passed through the authorization request.
    pub login_hint: Option<String>,
    /// coauth extension: preferred locale from the authorization request.
    pub locale: Option<String>,
}

impl std::ops::Deref for AuthorizationGrant {
    type Target = AuthorizationGrantStage;

    fn deref(&self) -> &Self::Target {
        &self.stage
    }
}

impl AuthorizationGrant {
    /// Parse a `login_hint`.
    ///
    /// Email addresses are returned as [`LoginHint::Email`]. Plain values
    /// without a URI scheme are treated as local usernames.
    #[must_use]
    pub fn parse_login_hint(&self) -> LoginHint<'_> {
        let Some(login_hint) = &self.login_hint else {
            return LoginHint::None;
        };

        if let Ok(email) = Address::from_str(login_hint) {
            LoginHint::Email(email)
        } else if !login_hint.trim().is_empty()
            && !login_hint.contains(':')
            && !login_hint.chars().any(char::is_whitespace)
        {
            LoginHint::Username(login_hint)
        } else {
            LoginHint::None
        }
    }

    /// Mark the authorization grant as exchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization grant is not [`Fulfilled`].
    ///
    /// [`Fulfilled`]: AuthorizationGrantStage::Fulfilled
    pub fn exchange(mut self, exchanged_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.stage = self.stage.exchange(exchanged_at)?;
        Ok(self)
    }

    /// Mark the authorization grant as fulfilled.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization grant is not [`Pending`].
    ///
    /// [`Pending`]: AuthorizationGrantStage::Pending
    pub fn fulfill(
        mut self,
        fulfilled_at: DateTime<Utc>,
        session: &Session,
    ) -> Result<Self, InvalidTransitionError> {
        self.stage = self.stage.fulfill(fulfilled_at, session)?;
        Ok(self)
    }

    #[doc(hidden)]
    pub fn sample(now: DateTime<Utc>, rng: &mut impl RngCore) -> Self {
        Self {
            id: crate::new_id(now, rng),
            stage: AuthorizationGrantStage::Pending,
            code: Some(AuthorizationCode {
                code: generate_alphanumeric(rng, 10),
                pkce: None,
            }),
            client_id: crate::new_id(now, rng),
            redirect_uri: Url::parse("http://localhost:8080").unwrap(),
            scope: Scope::from_iter([OPENID, PROFILE]),
            state: Some(generate_alphanumeric(rng, 10)),
            nonce: Some(generate_alphanumeric(rng, 10)),
            response_mode: ResponseMode::Query,
            response_type_id_token: false,
            created_at: now,
            login_hint: Some(String::from("example-user")),
            locale: Some(String::from("fr")),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;
    use crate::clock::{Clock, MockClock};

    #[test]
    fn no_login_hint() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: None,
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint();

        assert!(matches!(hint, LoginHint::None));
    }

    #[test]
    fn valid_login_hint_with_username() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: Some(String::from("example-user")),
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint();

        assert!(matches!(hint, LoginHint::Username("example-user")));
    }

    #[test]
    fn valid_login_hint_with_email() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: Some(String::from("example@user")),
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint();

        assert!(matches!(hint, LoginHint::Email(email) if email.to_string() == "example@user"));
    }

    #[test]
    fn invalid_login_hint_with_whitespace() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: Some(String::from("example user")),
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint();

        assert!(matches!(hint, LoginHint::None));
    }

    #[test]
    fn unknown_login_hint_type() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: Some(String::from("something:anything")),
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint();

        assert!(matches!(hint, LoginHint::None));
    }
}
