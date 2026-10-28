//! Encrypted browser continuation and CSRF binding for pending OAuth consent.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use coauth_data::{BrowserSession, Clock};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use ulid::Ulid;

use crate::salvo_utils::cookies::{CookieExpiration, CookieJar, TimedCookie, ulid_is_expired};

#[derive(Serialize, Deserialize)]
struct Consent {
    csrf_token: String,
    user_id: Option<Ulid>,
    session_id: Option<Ulid>,
    requirements: AuthenticationRequirements,
}

/// Constraints carried by the authenticated authorization continuation, not by
/// editable login/approval parameters. A hint never authenticates a browser.
#[derive(Default, Clone, Serialize, Deserialize)]
pub(crate) struct AuthenticationRequirements {
    pub(crate) required_auth_after: Option<DateTime<Utc>>,
    pub(crate) subject_hint: Option<String>,
}

impl AuthenticationRequirements {
    pub(crate) fn satisfied_by(
        &self,
        authenticated_at: Option<DateTime<Utc>>,
        subject: &str,
        now: DateTime<Utc>,
    ) -> bool {
        self.subject_hint
            .as_deref()
            .is_none_or(|hint| hint == subject)
            && self
                .required_auth_after
                .is_none_or(|after| authenticated_at.is_some_and(|at| at >= after && at <= now))
    }
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct PendingConsents(BTreeMap<Ulid, Consent>);

impl TimedCookie for PendingConsents {
    const COOKIE_NAME: &'static str = "oauth-authorization-consents";

    fn max_age() -> Duration {
        // Covers the existing registration continuation's one-hour lifetime.
        Duration::hours(1)
    }

    fn expire(mut self, now: DateTime<Utc>) -> Self {
        self.0
            .retain(|id, _| !ulid_is_expired(*id, now, Self::max_age()));
        self
    }
}

impl PendingConsents {
    pub(crate) fn add(
        &mut self,
        id: Ulid,
        session: Option<&BrowserSession>,
        rng: &mut dyn RngCore,
    ) {
        let mut nonce = [0_u8; 32];
        rng.fill_bytes(&mut nonce);
        self.0.insert(
            id,
            Consent {
                csrf_token: arkret_canonical::base64url_encode(nonce),
                user_id: session.map(|session| session.user.id),
                session_id: session.map(|session| session.id),
                requirements: AuthenticationRequirements::default(),
            },
        );
        // Eight continuations remain below the encrypted cookie size limit.
        while self.0.len() > 8 {
            self.0.pop_first();
        }
    }

    pub(crate) fn require(&mut self, id: Ulid, requirements: AuthenticationRequirements) {
        if let Some(consent) = self.0.get_mut(&id) {
            consent.requirements = requirements;
        }
    }

    pub(crate) fn requirements(&self, id: Ulid) -> Option<&AuthenticationRequirements> {
        self.0.get(&id).map(|consent| &consent.requirements)
    }

    pub(crate) fn bind(&mut self, id: Ulid, session: &BrowserSession) -> Option<String> {
        let consent = self.0.get_mut(&id)?;
        if consent.user_id.is_some_and(|user| user != session.user.id) {
            return None;
        }
        consent.user_id = Some(session.user.id);
        consent.session_id = Some(session.id);
        Some(consent.csrf_token.clone())
    }

    pub(crate) fn permits(&self, id: Ulid, session: &BrowserSession, csrf: &str) -> bool {
        self.0.get(&id).is_some_and(|consent| {
            consent.user_id == Some(session.user.id)
                && consent.session_id == Some(session.id)
                && bool::from(consent.csrf_token.as_bytes().ct_eq(csrf.as_bytes()))
        })
    }

    pub(crate) fn consume(&mut self, id: Ulid) {
        self.0.remove(&id);
    }

    pub(crate) fn write(self, jar: CookieJar, clock: &dyn Clock) -> CookieJar {
        let this = self.expire(clock.now());
        if this.0.is_empty() {
            jar.remove(Self::COOKIE_NAME)
        } else {
            jar.save(
                Self::COOKIE_NAME,
                &this,
                CookieExpiration::MaxAge(Self::max_age()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_constraints_require_a_real_fresh_matching_subject() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let constraints = AuthenticationRequirements {
            required_auth_after: Some(now - Duration::seconds(10)),
            subject_hint: Some("did:web:alice.example".to_owned()),
        };
        assert!(constraints.satisfied_by(Some(now), "did:web:alice.example", now));
        assert!(!constraints.satisfied_by(None, "did:web:alice.example", now));
        assert!(!constraints.satisfied_by(
            Some(now - Duration::seconds(11)),
            "did:web:alice.example",
            now
        ));
        assert!(!constraints.satisfied_by(
            Some(now + Duration::seconds(1)),
            "did:web:alice.example",
            now
        ));
        assert!(!constraints.satisfied_by(Some(now), "did:web:mallory.example", now));
    }
}
