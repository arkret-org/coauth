// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-service helper that consults the holder's consent cell on the
//! principal server (`soland`) before coauth admits or relays an invite.
//!
//! Per the Move/Anchor/Lattice spec (`contrix-spec` 2026-05-08,
//! `consent-model.md` §3–§9), consent is no longer reducer state on the
//! principal server. It is an OrSet cell:
//!
//! ```text
//! cx:cell:cx.component.consent.grant.v1:<consent_id>
//! ```
//!
//! `grant` adds a tag, `revoke` removes a tag. Whether an invite is allowed
//! is decided by reading the cell's join value and inspecting the tags. This
//! module performs that read; the per-cell tag-policy decision lives at the
//! invite handler call-site.
//!
//! ## Scope of this scaffolding
//!
//! Cross-service wire integration is a separate item. soland does not yet
//! expose an admin/cell read endpoint — see
//! `TODO(soland-cell-query)` below. Until that endpoint exists, this module
//! returns `ConsentLookup::Unknown` from the network call so callers can
//! degrade safely.

use std::time::Duration;

use serde::Deserialize;
use tracing::{debug, warn};
use url::Url;

/// Result of consulting a holder's consent cell.
///
/// `tags` are the OrSet tag identifiers currently joined into the cell.
/// Each tag is opaque to this layer; the invite handler is responsible for
/// matching `(peer, scope)` patterns against them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentLookup {
    /// The cell was read successfully. `tags` may be empty if all grants
    /// have been revoked.
    Known(ConsentState),

    /// soland is not configured, the endpoint is unreachable, or the
    /// response could not be parsed. Callers must apply their own fail-safe
    /// policy (default-deny for `require_consent` profiles, quarantine
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

/// Wire format expected from the (still-pending) soland cell-read endpoint.
///
/// Kept private — callers consume `ConsentLookup`. The shape is conservative:
/// soland returns the OrSet join value as a list of tag strings, plus the
/// cell id for echo. `granted` is derived from `!tags.is_empty()`.
#[derive(Debug, Deserialize)]
struct ConsentCellResponse {
    #[serde(default)]
    cell_id: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// Look up the holder's consent-grant cell on their principal server.
///
/// * `principal_server_url` — base URL of the holder's soland deployment.
///   `None` means soland is not wired into this coauth instance and the
///   gate degrades to `ConsentLookup::Unknown`.
/// * `holder_did` — the cell-owner DID; embedded in the request path so
///   soland can route the read to the right principal control Space.
/// * `consent_id` — the consent-cell identifier per spec §6.
/// * `http_client` — caller-provided client so tests can inject a wiremock
///   server and production callers can share the global pool.
pub async fn query_consent_cell(
    principal_server_url: Option<&Url>,
    holder_did: &str,
    consent_id: &str,
    http_client: &reqwest::Client,
) -> ConsentLookup {
    let Some(base) = principal_server_url else {
        debug!(
            consent_id = %consent_id,
            "principal_server_url not configured; consent gate returns Unknown",
        );
        return ConsentLookup::Unknown {
            reason: "principal_server_url_not_configured",
        };
    };

    // TODO(soland-cell-query): soland does not yet expose a public admin
    // endpoint for reading OrSet cell state. The path below is a forward
    // compatible guess that mirrors the existing `/api/v1/moves` POST
    // surface. Once soland adds the read endpoint, update this path and
    // align the response struct with the official schema.
    let cell_id = build_cell_id(consent_id);
    let path = format!("api/v1/admin/cells/{}", urlencoding::encode_path(&cell_id));
    let url = match base.join(&path) {
        Ok(u) => u,
        Err(error) => {
            warn!(?error, %cell_id, "failed to build cell-query URL");
            return ConsentLookup::Unknown {
                reason: "invalid_principal_server_url",
            };
        }
    };

    let response = match http_client
        .get(url)
        .header("X-Contrix-Holder-Did", holder_did)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) => r,
        Err(error) => {
            warn!(?error, "consent cell query: HTTP error");
            return ConsentLookup::Unknown {
                reason: "principal_server_unreachable",
            };
        }
    };

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        // Cell never existed or has been GC'd. Per spec §7 a missing cell is
        // semantically distinct from "no tags", but for the gate we return
        // an empty grant; the caller still gets to apply the
        // `require_consent` policy.
        return ConsentLookup::Known(ConsentState {
            consent_id: consent_id.to_owned(),
            granted: false,
            tags: Vec::new(),
        });
    }
    if !status.is_success() {
        warn!(?status, "consent cell query: non-success status");
        return ConsentLookup::Unknown {
            reason: "principal_server_error",
        };
    }

    let parsed: ConsentCellResponse = match response.json().await {
        Ok(p) => p,
        Err(error) => {
            warn!(?error, "consent cell query: failed to parse response");
            return ConsentLookup::Unknown {
                reason: "principal_server_response_invalid",
            };
        }
    };

    let granted = !parsed.tags.is_empty();
    debug!(
        cell_id = %parsed.cell_id,
        granted,
        tag_count = parsed.tags.len(),
        "consent cell query: success",
    );
    ConsentLookup::Known(ConsentState {
        consent_id: consent_id.to_owned(),
        granted,
        tags: parsed.tags,
    })
}

/// Build the canonical cell id used in storage and on the wire.
fn build_cell_id(consent_id: &str) -> String {
    format!("cx:cell:cx.component.consent.grant.v1:{consent_id}")
}

/// Decide whether an invite should pass the consent gate, given a cell
/// lookup result and the requested `(peer_did, scope)` pair.
///
/// `require_consent` mirrors the principal control Space's
/// `cx.space.policy_components.preauth.require_consent` toggle. When `true`
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

/// Pure function: turn a `(ConsentLookup, peer, scope, require_consent)`
/// tuple into a gate decision. No I/O, easy to unit-test and reuse from
/// other invite-style handlers.
pub fn evaluate_invite_gate(
    lookup: &ConsentLookup,
    peer_did: &str,
    scope: &str,
    require_consent: bool,
) -> InviteGateDecision {
    match lookup {
        ConsentLookup::Known(state) if state.granted => {
            // Spec §6.1: tag matches `peer=requester, scope=invite|any`.
            let want_scoped = format!("peer={peer_did};scope={scope}");
            let want_any = format!("peer={peer_did};scope=any");
            if state
                .tags
                .iter()
                .any(|t| t == &want_scoped || t == &want_any)
            {
                InviteGateDecision::Allow
            } else if require_consent {
                InviteGateDecision::ConsentRequired
            } else {
                InviteGateDecision::Quarantine
            }
        }
        ConsentLookup::Known(_) => {
            // granted == false: explicit revocation / empty cell.
            if require_consent {
                InviteGateDecision::ConsentRequired
            } else {
                InviteGateDecision::Quarantine
            }
        }
        ConsentLookup::Unknown { .. } => {
            if require_consent {
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
                let _ = write!(out, "%{:02X}", b);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_utils::setup;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    #[tokio::test]
    async fn consent_unknown_when_principal_server_url_is_none() {
        setup();
        let client = reqwest::Client::new();
        let result = query_consent_cell(None, "did:web:holder", "c-123", &client).await;
        match result {
            ConsentLookup::Unknown { reason } => {
                assert_eq!(reason, "principal_server_url_not_configured");
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
            .and(path_regex(r"^/api/v1/admin/cells/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cell_id": "cx:cell:cx.component.consent.grant.v1:c-123",
                "tags": ["peer=did:web:peer;scope=invite"],
            })))
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_cell(Some(&base), "did:web:holder", "c-123", &client).await;

        match result {
            ConsentLookup::Known(state) => {
                assert!(state.granted);
                assert_eq!(state.tags, vec!["peer=did:web:peer;scope=invite"]);
                assert_eq!(state.consent_id, "c-123");
            }
            other => panic!("expected Known(granted), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn consent_revoked_when_response_has_empty_tags() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/admin/cells/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cell_id": "cx:cell:cx.component.consent.grant.v1:c-123",
                "tags": [],
            })))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_cell(Some(&base), "did:web:holder", "c-123", &client).await;

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
            .and(path_regex(r"^/api/v1/admin/cells/.*"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_cell(Some(&base), "did:web:holder", "c-123", &client).await;

        match result {
            ConsentLookup::Unknown { reason } => {
                assert_eq!(reason, "principal_server_error");
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
            .and(path_regex(r"^/api/v1/admin/cells/.*"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let result = query_consent_cell(Some(&base), "did:web:holder", "c-404", &client).await;

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
            tags: vec!["peer=did:web:peer;scope=invite".into()],
        });
        assert_eq!(
            evaluate_invite_gate(&lookup, "did:web:peer", "invite", true),
            InviteGateDecision::Allow,
        );
    }

    #[test]
    fn invite_gate_allows_when_tag_grants_any_scope() {
        let lookup = ConsentLookup::Known(ConsentState {
            consent_id: "c-1".into(),
            granted: true,
            tags: vec!["peer=did:web:peer;scope=any".into()],
        });
        assert_eq!(
            evaluate_invite_gate(&lookup, "did:web:peer", "invite", true),
            InviteGateDecision::Allow,
        );
    }

    #[test]
    fn invite_gate_rejects_when_required_and_unknown() {
        let lookup = ConsentLookup::Unknown {
            reason: "principal_server_url_not_configured",
        };
        assert_eq!(
            evaluate_invite_gate(&lookup, "did:web:peer", "invite", true),
            InviteGateDecision::ConsentRequired,
        );
    }

    #[test]
    fn invite_gate_quarantines_when_not_required_and_unknown() {
        let lookup = ConsentLookup::Unknown {
            reason: "principal_server_unreachable",
        };
        assert_eq!(
            evaluate_invite_gate(&lookup, "did:web:peer", "invite", false),
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
            evaluate_invite_gate(&lookup, "did:web:peer", "invite", true),
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
            evaluate_invite_gate(&lookup, "did:web:peer", "invite", true),
            InviteGateDecision::ConsentRequired,
        );
    }
}
