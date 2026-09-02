// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-service helper that consults the holder's consent cell on the
//! `server_name` (`soland`) before coauth admits or relays an invite.
//!
//! Per the Move/Anchor/Lattice spec (`arkret-spec` 2026-05-08,
//! `consent-model.md` §3–§9), consent is no longer reducer state on the
//! `server_name`. It is an `OrSet` cell:
//!
//! ```text
//! ak:cell:ak.component.consent.grant.v1:<consent_id>
//! ```
//!
//! `grant` adds a tag, `revoke` removes a tag. Whether an invite is allowed
//! is decided by reading the cell's join value and inspecting the tags. This
//! module performs that read; the per-cell tag-policy decision lives at the
//! invite handler call-site.
//!
//! The helper calls soland's typed consent-cell endpoint. Transport failures,
//! non-success responses, and response-key mismatches become
//! [`ConsentLookup::Unknown`] so callers can degrade safely.

use arkret_models_collaboration::account_lifecycle::{
    ConsentCellView, ConsentPeer, ConsentState as SdkConsentState,
};
use arkret_wire::{ConsentScope, DidCoreId};
use tracing::{debug, warn};
use url::Url;

use crate::outbound_http;

/// Result of consulting a holder's consent cell.
///
/// `tags` are the `OrSet` tag identifiers currently joined into the cell.
/// Each tag is opaque to this layer; the invite handler is responsible for
/// matching `(peer, scope)` patterns against them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentLookup {
    /// The cell was read successfully. `tags` may be empty if all grants
    /// have been revoked.
    Known(ConsentState),

    /// soland is not configured, the endpoint is unreachable, or the
    /// response could not be parsed. Callers must apply their own fail-safe
    /// policy (default-deny for `consent_required` profiles, quarantine
    /// otherwise).
    Unknown { reason: &'static str },
}

/// Consent-cell read result when soland confirms the cell exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentState {
    pub consent_id: String,
    pub granted: bool,
    pub tags: Vec<String>,
}

/// Look up the holder's consent-grant cell on their `server_name`.
///
/// * `station_url` — base URL of the holder's soland deployment. `None` means soland is not wired
///   into this coauth instance and the gate degrades to `ConsentLookup::Unknown`.
/// * `holder_id` — the authenticated self principal, retained only for diagnostics; the wire
///   resource derives its holder from the authenticated session.
/// * `consent_id` — the consent-cell identifier per spec §6.
/// * `peer` / `scope` — the standard self consent resource key. The helper also probes `scope=any`
///   when `scope` is more specific, preserving the invite-gate wildcard semantics.
/// * `http_client` — caller-provided client so tests can inject a wiremock server and production
///   callers can share the global pool.
pub async fn query_consent_cell(
    station_url: Option<&Url>,
    holder_id: &DidCoreId,
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
        match query_consent_cell_scope(base, holder_id, peer, candidate_scope, http_client).await {
            ConsentScopeLookup::Active { cell_id } => {
                let tag = format!("scope={candidate_scope}");
                debug!(
                    %cell_id,
                    consent_id,
                    peer = ?peer,
                    scope = %candidate_scope,
                    "consent cell query: active"
                );
                return ConsentLookup::Known(ConsentState {
                    consent_id: consent_id.to_owned(),
                    granted: true,
                    tags: vec![tag],
                });
            }
            ConsentScopeLookup::Inactive { cell_id, state } => {
                debug!(
                    %cell_id,
                    ?state,
                    consent_id,
                    peer = ?peer,
                    scope = %candidate_scope,
                    "consent cell query: inactive"
                );
                return ConsentLookup::Known(ConsentState {
                    consent_id: consent_id.to_owned(),
                    granted: false,
                    tags: Vec::new(),
                });
            }
            ConsentScopeLookup::Missing => {}
            ConsentScopeLookup::Unknown { reason } => {
                return ConsentLookup::Unknown { reason };
            }
        }
    }

    ConsentLookup::Known(ConsentState {
        consent_id: consent_id.to_owned(),
        granted: false,
        tags: Vec::new(),
    })
}

#[derive(Debug)]
enum ConsentScopeLookup {
    Active {
        cell_id: String,
    },
    Inactive {
        cell_id: String,
        state: SdkConsentState,
    },
    Missing,
    Unknown {
        reason: &'static str,
    },
}

async fn query_consent_cell_scope(
    base: &Url,
    holder_id: &DidCoreId,
    peer: &ConsentPeer,
    scope: ConsentScope,
    http_client: &reqwest::Client,
) -> ConsentScopeLookup {
    let path = "_arkret/self/consent/cell";
    let mut url = match base.join(&path) {
        Ok(u) => u,
        Err(error) => {
            warn!(
                ?error,
                holder_id = %holder_id,
                "failed to build consent-cell URL"
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
        outbound_http::soland_policy("consent_cell_read")
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
            warn!(?error, "consent cell query: HTTP error");
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
        warn!(?status, "consent cell query: non-success status");
        return ConsentScopeLookup::Unknown {
            reason: "station_error",
        };
    }

    let parsed: ConsentCellView = match response.json().await {
        Ok(p) => p,
        Err(error) => {
            warn!(?error, "consent cell query: failed to parse response");
            return ConsentScopeLookup::Unknown {
                reason: "station_response_invalid",
            };
        }
    };

    if &parsed.peer != peer || parsed.consent_scope != scope {
        warn!(
            cell_id = %parsed.cell_id,
            response_peer = ?parsed.peer,
            response_scope = parsed.consent_scope.as_str(),
            holder_id = %holder_id,
            peer = ?peer,
            scope = %scope,
            "consent cell query: response key mismatch"
        );
        return ConsentScopeLookup::Unknown {
            reason: "station_response_invalid",
        };
    }

    if parsed.state == SdkConsentState::Active {
        ConsentScopeLookup::Active {
            cell_id: parsed.cell_id,
        }
    } else {
        ConsentScopeLookup::Inactive {
            cell_id: parsed.cell_id,
            state: parsed.state,
        }
    }
}

/// Decide whether an invite should pass the consent gate, given a cell
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
/// The peer half of the match is not re-checked here: `query_consent_cell`
/// asks the holder Station for one exact `peer`, so a lookup that comes back
/// `Known` is already the cell for that peer and nothing else. Only the scope
/// tag is left to decide.
#[must_use]
pub fn evaluate_invite_gate(
    lookup: &ConsentLookup,
    scope: ConsentScope,
    consent_required: bool,
) -> InviteGateDecision {
    match lookup {
        ConsentLookup::Known(state) if state.granted => {
            // Spec §6.1: `scope=invite|any` on the peer-scoped cell.
            let want_scoped = format!("scope={scope}");
            let want_any = "scope=any";
            if state
                .tags
                .iter()
                .any(|t| t == &want_scoped || t == &want_any)
            {
                InviteGateDecision::Allow
            } else if consent_required {
                InviteGateDecision::ConsentRequired
            } else {
                InviteGateDecision::Quarantine
            }
        }
        ConsentLookup::Known(_) => {
            // granted == false: explicit revocation / empty cell.
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

// `urlencoding` is not in the dependency graph; replicate the tiny piece we
// need with a private adapter so we don't pull in a new crate.
mod urlencoding {
    /// Percent-encode a path segment. Matches the small subset of RFC 3986
    /// `pchar` that the consent cell id uses (`a-z A-Z 0-9 . - _ : *`).
    pub fn encode_path(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            let safe = matches!(
                b,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
                    | b'.' | b'-' | b'_' | b'~' | b':' | b'*'
            );
            if safe {
                out.push(b as char);
            } else {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
        out
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

    fn active_cell(scope: &str) -> serde_json::Value {
        serde_json::json!({
            "cell_id": arkret_wire::subject_cell(
                arkret_wire::CellFamilyId::CONSENT_GRANT_V1,
                &format!("c-{scope}"),
            ),
            "peer": peer(),
            "consent_scope": scope,
            "state": "active",
            "updated_at": "2026-05-01T00:00:00.000Z",
            "active_grant_dots": ["ak:event:AQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI:0"],
            "grant_dots": ["ak:event:AQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI:0"],
            "revoked_dots": [],
        })
    }

    fn revoked_cell(scope: &str) -> serde_json::Value {
        serde_json::json!({
            "cell_id": arkret_wire::subject_cell(
                arkret_wire::CellFamilyId::CONSENT_GRANT_V1,
                &format!("c-{scope}"),
            ),
            "peer": peer(),
            "consent_scope": scope,
            "state": "no_consent",
            "updated_at": "2026-05-01T00:00:00.000Z",
            "active_grant_dots": [],
            "grant_dots": ["ak:event:AQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI:0"],
            "revoked_dots": ["ak:event:AQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI:0"],
        })
    }

    #[tokio::test]
    async fn consent_unknown_when_station_url_is_none() {
        setup();
        let client = reqwest::Client::new();
        let result = query_consent_cell(
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
    async fn consent_granted_when_soland_returns_tags() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cell$"))
            .and(header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_CONSENT_RESOURCE_GET_V1,
            ))
            .and(query_param(
                "peer",
                &serde_json::to_string(&peer()).unwrap(),
            ))
            .and(query_param("consent_scope", "invite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_cell("invite")))
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_cell(
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
                assert_eq!(state.tags, vec!["scope=invite"]);
                assert_eq!(state.consent_id, "c-123");
            }
            other => panic!("expected Known(granted), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn consent_unknown_when_cell_response_key_mismatches_request() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();
        let mut cell = active_cell("invite");
        cell["peer"]["actor_id"]["account_id"]["station_id"] =
            serde_json::Value::String("ak:did_core:web:other-station".to_owned());

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cell$"))
            .and(query_param(
                "peer",
                &serde_json::to_string(&peer()).unwrap(),
            ))
            .and(query_param("consent_scope", "invite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(cell))
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_cell(
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
    async fn consent_revoked_when_response_has_empty_tags() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cell$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(revoked_cell("invite")))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_cell(
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
                assert!(state.tags.is_empty());
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
            .and(path_regex(r"^/_arkret/self/consent/cell$"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_cell(
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
    async fn consent_missing_cell_returns_known_empty() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cell$"))
            .respond_with(ResponseTemplate::new(404))
            .expect(2)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_cell(
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
                assert!(state.tags.is_empty());
                assert_eq!(state.consent_id, "c-404");
            }
            other => panic!("expected Known(empty), got {other:?}"),
        }
    }

    #[test]
    fn invite_gate_allows_when_tag_matches_peer_and_scope() {
        let lookup = ConsentLookup::Known(ConsentState {
            consent_id: "c-1".into(),
            granted: true,
            tags: vec!["peer=ak:did_core:web:peer;scope=invite".into()],
        });
        assert_eq!(
            evaluate_invite_gate(&lookup, ConsentScope::Invite, true,),
            InviteGateDecision::Allow,
        );
    }

    #[test]
    fn invite_gate_allows_when_tag_grants_any_scope() {
        let lookup = ConsentLookup::Known(ConsentState {
            consent_id: "c-1".into(),
            granted: true,
            tags: vec!["peer=ak:did_core:web:peer;scope=any".into()],
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
        let lookup = ConsentLookup::Known(ConsentState {
            consent_id: "c-1".into(),
            granted: false,
            tags: vec![],
        });
        assert_eq!(
            evaluate_invite_gate(&lookup, ConsentScope::Invite, true,),
            InviteGateDecision::ConsentRequired,
        );
    }

    #[test]
    fn invite_gate_rejects_when_tag_present_but_peer_mismatch() {
        let lookup = ConsentLookup::Known(ConsentState {
            consent_id: "c-1".into(),
            granted: true,
            tags: vec!["peer=did:web:other;scope=invite".into()],
        });
        assert_eq!(
            evaluate_invite_gate(&lookup, ConsentScope::Invite, true,),
            InviteGateDecision::ConsentRequired,
        );
    }
}
