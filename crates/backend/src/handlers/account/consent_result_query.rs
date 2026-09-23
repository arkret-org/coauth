// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-service helper that consults the holder's consent result on the
//! `server_name` (`soland`) before coauth admits or relays an invite.
//!
//! Consent is holder-private state serialized by the holder's current
//! governance Station. The reader-facing surface is the typed current result
//! `consent-operations.schema.json#/$defs/consent_view`, addressed by the
//! `(peer, consent_scope)` resource key:
//!
//! ```text
//! GET /_arkret/self/consent/result?peer=<json>&consent_scope=<scope>
//! ```
//!
//! (`ak.self.consent.resource.get.v1`; the sibling
//! `ak.self.consent.read.list.v1` at `GET /_arkret/self/consent/results`
//! enumerates every result and is not what an invite gate needs.) Whether an
//! invite is allowed is decided by reading that result's `state` and
//! `consent_scope`. This module performs that read; the policy decision lives
//! at the invite handler call-site.
//!
//! Transport failures, non-success responses, and response-key mismatches
//! become [`ConsentLookup::Unknown`] so callers can degrade safely.

use arkret_models_collaboration::consent_operations::{
    ConsentState as SdkConsentState, ConsentView,
};
use arkret_models_collaboration::events_payloads::consent::ConsentPeer;
use arkret_wire::{ConsentScope, DidCoreId};
use tracing::{debug, warn};
use url::Url;

use crate::outbound_http;

/// Result of consulting a holder's consent state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentLookup {
    /// The holder's Station answered. `granted_scopes` may be empty if every
    /// grant has been revoked or none was ever recorded.
    Known(ConsentGrantState),

    /// soland is not configured, the endpoint is unreachable, or the
    /// response could not be parsed. Callers must apply their own fail-safe
    /// policy (default-deny for `consent_required` profiles, quarantine
    /// otherwise).
    Unknown { reason: &'static str },
}

/// Consent read result when soland answers for the requested resource key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrantState {
    pub consent_id: String,
    pub granted: bool,
    pub granted_scopes: Vec<ConsentScope>,
}

/// Look up the holder's consent result on their `server_name`.
///
/// * `station_url` — base URL of the holder's soland deployment. `None` means soland is not wired
///   into this coauth instance and the gate degrades to `ConsentLookup::Unknown`.
/// * `holder_principal_id` — the target holder principal used only for local diagnostics. It is not
///   transmitted; the destination derives the wire holder from its authenticated session.
/// * `consent_id` — the consent identifier the caller is asking about, echoed back to it.
/// * `peer` / `scope` — the standard self consent resource key. The helper also probes `scope=any`
///   when `scope` is more specific, preserving the invite-gate wildcard semantics.
/// * `http_client` — caller-provided client so tests can inject a wiremock server and production
///   callers can share the global pool.
pub async fn query_consent_result(
    station_url: Option<&Url>,
    holder_principal_id: &DidCoreId,
    consent_id: &str,
    peer: &ConsentPeer,
    scope: ConsentScope,
    http_client: &reqwest::Client,
) -> ConsentLookup {
    let Some(base) = station_url else {
        debug!(
            consent_id = %consent_id,
            "station_url not configured; consent gate returns Unknown",
        );
        return ConsentLookup::Unknown {
            reason: "station_url_not_configured",
        };
    };

    let mut scopes = vec![scope];
    if scope != ConsentScope::Any {
        scopes.push(ConsentScope::Any);
    }

    for candidate_scope in scopes {
        match query_consent_result_scope(
            base,
            holder_principal_id,
            peer,
            candidate_scope,
            http_client,
        )
        .await
        {
            ConsentScopeLookup::Active { result_consent_id } => {
                debug!(
                    %result_consent_id,
                    consent_id,
                    peer = ?peer,
                    scope = %candidate_scope,
                    "consent result query: active"
                );
                return ConsentLookup::Known(ConsentGrantState {
                    consent_id: consent_id.to_owned(),
                    granted: true,
                    granted_scopes: vec![candidate_scope],
                });
            }
            ConsentScopeLookup::Inactive {
                result_consent_id,
                state,
            } => {
                debug!(
                    %result_consent_id,
                    ?state,
                    consent_id,
                    peer = ?peer,
                    scope = %candidate_scope,
                    "consent result query: inactive"
                );
                return ConsentLookup::Known(ConsentGrantState {
                    consent_id: consent_id.to_owned(),
                    granted: false,
                    granted_scopes: Vec::new(),
                });
            }
            ConsentScopeLookup::Missing => {}
            ConsentScopeLookup::Unknown { reason } => {
                return ConsentLookup::Unknown { reason };
            }
        }
    }

    ConsentLookup::Known(ConsentGrantState {
        consent_id: consent_id.to_owned(),
        granted: false,
        granted_scopes: Vec::new(),
    })
}

#[derive(Debug)]
enum ConsentScopeLookup {
    Active {
        result_consent_id: String,
    },
    Inactive {
        result_consent_id: String,
        state: SdkConsentState,
    },
    Missing,
    Unknown {
        reason: &'static str,
    },
}

async fn query_consent_result_scope(
    base: &Url,
    holder_principal_id: &DidCoreId,
    peer: &ConsentPeer,
    scope: ConsentScope,
    http_client: &reqwest::Client,
) -> ConsentScopeLookup {
    let path = "_arkret/self/consent/result";
    let mut url = match base.join(path) {
        Ok(u) => u,
        Err(error) => {
            warn!(
                ?error,
                holder_principal_id = %holder_principal_id,
                "failed to build consent-result URL"
            );
            return ConsentScopeLookup::Unknown {
                reason: "invalid_station_url",
            };
        }
    };
    url.query_pairs_mut()
        .append_pair(
            "peer",
            &serde_json::to_string(peer).expect("ConsentPeer is serializable"),
        )
        .append_pair("consent_scope", scope.as_str());

    let response = match outbound_http::send_with_policy(
        outbound_http::soland_policy("consent_result_read")
            .with_timeout(std::time::Duration::from_secs(5)),
        || {
            http_client.get(url.clone()).header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_CONSENT_RESOURCE_GET_V1,
            )
        },
    )
    .await
    {
        Ok(r) => r,
        Err(error) => {
            warn!(?error, "consent result query: HTTP error");
            return ConsentScopeLookup::Unknown {
                reason: "station_unreachable",
            };
        }
    };

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return ConsentScopeLookup::Missing;
    }
    if !status.is_success() {
        warn!(?status, "consent result query: non-success status");
        return ConsentScopeLookup::Unknown {
            reason: "station_error",
        };
    }

    let parsed: ConsentView = match response.json().await {
        Ok(p) => p,
        Err(error) => {
            warn!(?error, "consent result query: failed to parse response");
            return ConsentScopeLookup::Unknown {
                reason: "station_response_invalid",
            };
        }
    };

    if parsed.validate().is_err() {
        warn!(
            consent_id = %parsed.consent_id,
            holder_principal_id = %holder_principal_id,
            "consent result query: response fails its own structural invariants"
        );
        return ConsentScopeLookup::Unknown {
            reason: "station_response_invalid",
        };
    }

    if &parsed.peer != peer || parsed.consent_scope != scope {
        warn!(
            consent_id = %parsed.consent_id,
            response_peer = ?parsed.peer,
            response_scope = parsed.consent_scope.as_str(),
            holder_principal_id = %holder_principal_id,
            peer = ?peer,
            scope = %scope,
            "consent result query: response key mismatch"
        );
        return ConsentScopeLookup::Unknown {
            reason: "station_response_invalid",
        };
    }

    let result_consent_id = parsed.consent_id.to_string();
    if parsed.state == SdkConsentState::Active {
        ConsentScopeLookup::Active { result_consent_id }
    } else {
        ConsentScopeLookup::Inactive {
            result_consent_id,
            state: parsed.state,
        }
    }
}

/// Decide whether an invite should pass the consent gate, given a consent
/// lookup result and the requested `(peer_principal_id, scope)` pair.
///
/// `consent_required` mirrors the principal control Realm's
/// the `ak.realm.policy_bundle` payload path `preauth.consent_required` toggle. When `true`
/// and the lookup result is `Unknown` or revoked/absent, the invite is
/// rejected with `ConsentRequired`. When `false` the same condition routes
/// to a holder-side quarantine (caller decides how to enact that).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteGateDecision {
    /// Invite proceeds normally.
    Allow,
    /// Holder explicitly revoked or never granted, and policy requires
    /// consent — fail closed.
    ConsentRequired,
    /// Lookup was inconclusive — defer to caller's quarantine routing.
    Quarantine,
}

/// Pure function: turn a `(ConsentLookup, scope, consent_required)` tuple into
/// a gate decision. No I/O, easy to unit-test and reuse from other
/// invite-style handlers.
///
/// The peer half of the match is not re-checked here: `query_consent_result`
/// asks the holder Station for one exact `peer`, so a lookup that comes back
/// `Known` is already the result for that peer and nothing else. Only the
/// scope is left to decide.
#[must_use]
pub fn evaluate_invite_gate(
    lookup: &ConsentLookup,
    scope: ConsentScope,
    consent_required: bool,
) -> InviteGateDecision {
    match lookup {
        ConsentLookup::Known(state) if state.granted => {
            if state
                .granted_scopes
                .iter()
                .any(|granted| *granted == scope || *granted == ConsentScope::Any)
            {
                InviteGateDecision::Allow
            } else if consent_required {
                InviteGateDecision::ConsentRequired
            } else {
                InviteGateDecision::Quarantine
            }
        }
        ConsentLookup::Known(_) => {
            // granted == false: explicit revocation or no recorded consent.
            if consent_required {
                InviteGateDecision::ConsentRequired
            } else {
                InviteGateDecision::Quarantine
            }
        }
        ConsentLookup::Unknown { .. } => {
            if consent_required {
                InviteGateDecision::ConsentRequired
            } else {
                InviteGateDecision::Quarantine
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::handlers::test_utils::setup;

    fn core_id(value: &str) -> DidCoreId {
        DidCoreId::new(value).unwrap()
    }

    fn peer() -> ConsentPeer {
        ConsentPeer::Actor {
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                core_id("ak:did_core:web:peer"),
                core_id("ak:did_core:web:peer-station"),
            )),
        }
    }

    fn consent_result(scope: &str, state: &str) -> serde_json::Value {
        serde_json::json!({
            "consent_id": "ak:consent:0198ff00-0000-7000-8000-000000000001",
            "peer": peer(),
            "consent_scope": scope,
            "state": state,
            "updated_at": "2026-05-01T00:00:00.000Z",
            "revision": {
                "commit_id": arkret_wire::RealmCommitId::from_digest([2; 32]),
                "stream_position": 7,
            },
        })
    }

    fn active_result(scope: &str) -> serde_json::Value {
        consent_result(scope, "active")
    }

    fn revoked_result(scope: &str) -> serde_json::Value {
        consent_result(scope, "revoked")
    }

    #[tokio::test]
    async fn consent_unknown_when_station_url_is_none() {
        setup();
        let client = reqwest::Client::new();
        let result = query_consent_result(
            None,
            &core_id("ak:did_core:web:holder"),
            "c-123",
            &peer(),
            ConsentScope::Invite,
            &client,
        )
        .await;
        match result {
            ConsentLookup::Unknown { reason } => {
                assert_eq!(reason, "station_url_not_configured");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn consent_granted_when_soland_returns_an_active_result() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/result$"))
            .and(header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_CONSENT_RESOURCE_GET_V1,
            ))
            .and(query_param("peer", serde_json::to_string(&peer()).unwrap()))
            .and(query_param("consent_scope", "invite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_result("invite")))
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_result(
            Some(&base),
            &core_id("ak:did_core:web:holder"),
            "c-123",
            &peer(),
            ConsentScope::Invite,
            &client,
        )
        .await;

        match result {
            ConsentLookup::Known(state) => {
                assert!(state.granted);
                assert_eq!(state.granted_scopes, vec![ConsentScope::Invite]);
                assert_eq!(state.consent_id, "c-123");
            }
            other => panic!("expected Known(granted), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn consent_unknown_when_result_key_mismatches_request() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();
        let mut view = active_result("invite");
        view["peer"]["actor_id"]["account_id"]["station_id"] =
            serde_json::Value::String("ak:did_core:web:other-station".to_owned());

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/result$"))
            .and(query_param("peer", serde_json::to_string(&peer()).unwrap()))
            .and(query_param("consent_scope", "invite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(view))
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_result(
            Some(&base),
            &core_id("ak:did_core:web:holder"),
            "c-123",
            &peer(),
            ConsentScope::Invite,
            &client,
        )
        .await;

        match result {
            ConsentLookup::Unknown { reason } => {
                assert_eq!(reason, "station_response_invalid");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn consent_revoked_when_result_state_is_revoked() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/result$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(revoked_result("invite")))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_result(
            Some(&base),
            &core_id("ak:did_core:web:holder"),
            "c-123",
            &peer(),
            ConsentScope::Invite,
            &client,
        )
        .await;

        match result {
            ConsentLookup::Known(state) => {
                assert!(!state.granted);
                assert!(state.granted_scopes.is_empty());
            }
            other => panic!("expected Known(empty), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn consent_unknown_when_soland_returns_500() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/result$"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_result(
            Some(&base),
            &core_id("ak:did_core:web:holder"),
            "c-123",
            &peer(),
            ConsentScope::Invite,
            &client,
        )
        .await;

        match result {
            ConsentLookup::Unknown { reason } => {
                assert_eq!(reason, "station_error");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn consent_missing_result_returns_known_empty() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/result$"))
            .respond_with(ResponseTemplate::new(404))
            .expect(2)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_result(
            Some(&base),
            &core_id("ak:did_core:web:holder"),
            "c-404",
            &peer(),
            ConsentScope::Invite,
            &client,
        )
        .await;

        match result {
            ConsentLookup::Known(state) => {
                assert!(!state.granted);
                assert!(state.granted_scopes.is_empty());
                assert_eq!(state.consent_id, "c-404");
            }
            other => panic!("expected Known(empty), got {other:?}"),
        }
    }

    #[test]
    fn invite_gate_allows_when_result_matches_peer_and_scope() {
        let lookup = ConsentLookup::Known(ConsentGrantState {
            consent_id: "c-1".into(),
            granted: true,
            granted_scopes: vec![ConsentScope::Invite],
        });
        assert_eq!(
            evaluate_invite_gate(&lookup, ConsentScope::Invite, true,),
            InviteGateDecision::Allow,
        );
    }

    #[test]
    fn invite_gate_allows_when_result_grants_any_scope() {
        let lookup = ConsentLookup::Known(ConsentGrantState {
            consent_id: "c-1".into(),
            granted: true,
            granted_scopes: vec![ConsentScope::Any],
        });
        assert_eq!(
            evaluate_invite_gate(&lookup, ConsentScope::Invite, true,),
            InviteGateDecision::Allow,
        );
    }

    #[test]
    fn invite_gate_rejects_when_required_and_unknown() {
        let lookup = ConsentLookup::Unknown {
            reason: "station_url_not_configured",
        };
        assert_eq!(
            evaluate_invite_gate(&lookup, ConsentScope::Invite, true,),
            InviteGateDecision::ConsentRequired,
        );
    }

    #[test]
    fn invite_gate_quarantines_when_not_required_and_unknown() {
        let lookup = ConsentLookup::Unknown {
            reason: "station_unreachable",
        };
        assert_eq!(
            evaluate_invite_gate(&lookup, ConsentScope::Invite, false,),
            InviteGateDecision::Quarantine,
        );
    }

    #[test]
    fn invite_gate_rejects_when_revoked_and_required() {
        let lookup = ConsentLookup::Known(ConsentGrantState {
            consent_id: "c-1".into(),
            granted: false,
            granted_scopes: vec![],
        });
        assert_eq!(
            evaluate_invite_gate(&lookup, ConsentScope::Invite, true,),
            InviteGateDecision::ConsentRequired,
        );
    }

    #[test]
    fn invite_gate_rejects_when_granted_scope_does_not_cover_the_request() {
        let lookup = ConsentLookup::Known(ConsentGrantState {
            consent_id: "c-1".into(),
            granted: true,
            granted_scopes: vec![ConsentScope::VoiceCall],
        });
        assert_eq!(
            evaluate_invite_gate(&lookup, ConsentScope::Invite, true,),
            InviteGateDecision::ConsentRequired,
        );
    }
}
