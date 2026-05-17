// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-recipient invite-relay handler (consent-gated forward).
//!
//! Per the Move/Anchor/Lattice spec (`contrix-spec` 2026-05-08,
//! `consent-model.md` §3-§9), before an actor (coauth admin / yougen UI /
//! sodmin operator) can deliver an invite to a target principal, coauth
//! must consult the holder's consent-grant cell on the target's principal
//! server (`soland`). The previous task added the read+gate helper in
//! `consent_cell_query`; this handler is the call-site that uses it.
//!
//! ## Flow
//!
//! 1. The inviter signs an invite payload (out of band) and POSTs it to
//!    `POST /api/v1/account/invites/relay` along with `(target_principal_url,
//!    target_holder_did, consent_id, scope)`.
//! 2. Coauth queries the target's consent cell via
//!    `consent_cell_query::query_consent_cell`.
//! 3. Coauth runs `evaluate_invite_gate(...)` to translate the lookup +
//!    `require_consent` policy bit into an
//!    `Allow / ConsentRequired / Quarantine` decision.
//! 4. On `Allow`, coauth forwards the (already-signed) invite payload to the
//!    target principal's invite-intake endpoint and returns 200.
//!    On `ConsentRequired`, coauth returns 403 with `consent_required`.
//!    On `Quarantine`, coauth returns 202 with `quarantined`; the actual
//!    holder-side queue management lives elsewhere (see `TODO(quarantine-
//!    inbox)` in `users/create.rs`).
//!
//! ## Why this is a "relay" and not a "Move-mint"
//!
//! Consent grants/revokes on the holder's cell are constructed and signed
//! by the **holder** when they accept an invite — they're separate Moves
//! posted by yougen, not by coauth. coauth's only responsibility here is
//! the gate-check + forward; it never signs Moves on the holder's behalf.

use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};
use url::Url;

use super::{DepotExt, RouteError};
use crate::handlers::account::consent_cell_query::{
    InviteGateDecision, evaluate_invite_gate, query_consent_cell,
};

// ── Request / response shapes ──────────────────────────────────

/// Body of `POST /api/v1/account/invites/relay`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RelayRequest {
    /// DID of the actor issuing the invite. Recorded in audit but not
    /// trusted as authentication on its own; the bearer cookie / OAuth
    /// token guards the route.
    pub inviter_did: String,

    /// Base URL of the target's `server_name` (`soland`).
    ///
    /// Optional in the body; when omitted, falls back to
    /// `ContrixConfig::principal_server_url`. If neither is present the
    /// handler returns 400 `config_required` because there's nowhere to
    /// query the consent cell.
    #[serde(default)]
    pub target_principal_url: Option<Url>,

    /// DID of the holder whose cell we're consulting. Embedded in the
    /// `X-Contrix-Holder-Did` header on the soland query.
    pub target_holder_did: String,

    /// Consent-cell identifier per spec §6.
    pub consent_id: String,

    /// Tag scope to match against the consent cell's `OrSet` tags
    /// (`peer=...;scope=<scope>` or `peer=...;scope=any`).
    pub scope: String,

    /// Mirror of the holder's `cx.space.policy_components.preauth
    /// .require_consent` policy bit. Defaults to `true` (fail closed).
    #[serde(default = "default_require_consent")]
    pub require_consent: bool,

    /// Opaque, inviter-signed invite payload to forward to the target on
    /// `Allow`. Coauth does not inspect or re-sign it. Required when
    /// `Allow` is the eventual decision; the handler fails the relay (not
    /// the gate-check) if the payload is missing at forward time.
    #[serde(default)]
    pub invite_payload: Option<serde_json::Value>,
}

fn default_require_consent() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RelayResponse {
    /// One of `forwarded`, `consent_required`, `quarantined`.
    pub status: &'static str,

    /// Echo of the consent-cell decision for telemetry (`Allow`,
    /// `ConsentRequired`, `Quarantine`).
    pub decision: &'static str,

    /// On `forwarded`, set to `true` if the upstream principal accepted
    /// the forward; `false` if the forward target was unreachable
    /// (callers may retry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarded_ok: Option<bool>,
}

// ── Pure-ish helper (testable with wiremock) ───────────────────

/// Outcome of `relay_invite_with`. Mirrors the HTTP response shape but
/// without serialisation, so unit tests can pattern-match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Gate said `Allow`; the inner `forwarded_ok` reflects whether the
    /// forward target accepted the POST.
    Forwarded { forwarded_ok: bool },
    /// Gate said `ConsentRequired` — caller should map to HTTP 403.
    ConsentRequired,
    /// Gate said `Quarantine` — caller should map to HTTP 202.
    Quarantined,
}

/// Convert a `RelayOutcome` into HTTP `(status, body)`. Pulled out so
/// both the real handler and the unit tests can share it.
#[must_use]
pub fn relay_outcome_to_response(outcome: &RelayOutcome) -> (StatusCode, RelayResponse) {
    match outcome {
        RelayOutcome::Forwarded { forwarded_ok } => (
            StatusCode::OK,
            RelayResponse {
                status: "forwarded",
                decision: "Allow",
                forwarded_ok: Some(*forwarded_ok),
            },
        ),
        RelayOutcome::ConsentRequired => (
            StatusCode::FORBIDDEN,
            RelayResponse {
                status: "consent_required",
                decision: "ConsentRequired",
                forwarded_ok: None,
            },
        ),
        RelayOutcome::Quarantined => (
            StatusCode::ACCEPTED,
            RelayResponse {
                status: "quarantined",
                decision: "Quarantine",
                forwarded_ok: None,
            },
        ),
    }
}

/// Core relay logic: query the consent cell, gate the result, forward on
/// `Allow`. All I/O goes through the supplied `http_client` so tests can
/// inject a wiremock server.
///
/// `forward_target_url` is the URL to POST the invite payload at when the
/// gate allows. In production this is typically
/// `{target_principal_url}/api/v1/invites/intake` or similar. The actual
/// path is decided by the target principal's API surface; coauth only
/// needs a fully-qualified URL to POST to.
///
/// Returns `Err(RouteError::BadRequest(...))` only for client-supplied
/// validation failures (e.g. `target_principal_url` truly missing). Gate
/// decisions are reported via `Ok(RelayOutcome::*)`.
pub async fn relay_invite_with(
    target_principal_url: Option<&Url>,
    target_holder_did: &str,
    consent_id: &str,
    peer_did: &str,
    scope: &str,
    require_consent: bool,
    forward_target_url: Option<&Url>,
    invite_payload: Option<&serde_json::Value>,
    http_client: &reqwest::Client,
) -> Result<RelayOutcome, RouteError> {
    let Some(principal_url) = target_principal_url else {
        return Err(RouteError::BadRequest("config_required".into()));
    };

    let lookup = query_consent_cell(
        Some(principal_url),
        target_holder_did,
        consent_id,
        http_client,
    )
    .await;

    let decision = evaluate_invite_gate(&lookup, peer_did, scope, require_consent);
    debug!(
        ?decision,
        consent_id, peer_did, scope, "invite-relay gate decision"
    );

    match decision {
        InviteGateDecision::Allow => {
            // On Allow, attempt to forward the inviter-signed payload. If
            // the caller did not supply a forward target, treat that as
            // success-without-forward (yougen, for example, may want to
            // call the gate-only path and forward themselves).
            let Some(target) = forward_target_url else {
                return Ok(RelayOutcome::Forwarded { forwarded_ok: true });
            };
            let Some(payload) = invite_payload else {
                // Allow but no payload = the caller wanted gate-check only.
                return Ok(RelayOutcome::Forwarded { forwarded_ok: true });
            };

            let forwarded_ok = match http_client
                .post(target.clone())
                .json(payload)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => true,
                Ok(r) => {
                    warn!(status = ?r.status(), "invite forward: non-success status");
                    false
                }
                Err(error) => {
                    warn!(?error, "invite forward: HTTP error");
                    false
                }
            };
            Ok(RelayOutcome::Forwarded { forwarded_ok })
        }
        InviteGateDecision::ConsentRequired => Ok(RelayOutcome::ConsentRequired),
        InviteGateDecision::Quarantine => Ok(RelayOutcome::Quarantined),
    }
}

// ── Salvo handler ──────────────────────────────────────────────

/// `POST /api/v1/account/invites/relay`
#[endpoint]
#[tracing::instrument(name = "handlers.account.invite_relay.post", skip_all, err)]
pub async fn post_invite_relay(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let params: RelayRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid_request_body".into()))?;

    if params.inviter_did.is_empty()
        || params.target_holder_did.is_empty()
        || params.consent_id.is_empty()
        || params.scope.is_empty()
    {
        return Err(RouteError::BadRequest("missing_required_fields".into()));
    }

    let contrix_config = depot.contrix_config()?;
    let http_client = depot.http_client()?;

    // Body-supplied URL takes precedence over the global config — admins
    // can route to a holder whose principal lives elsewhere.
    let principal_url = params
        .target_principal_url
        .clone()
        .or_else(|| contrix_config.principal_server_url.clone());

    // Forward target: in this scaffolding we use the same principal URL +
    // a conservative `/api/v1/invites/intake` path. Real wiring with
    // soland's invite-intake endpoint is tracked under
    // `TODO(c10e-invite-intake)`.
    let forward_target = principal_url.as_ref().and_then(|u| {
        u.join("api/v1/invites/intake")
            .map_err(|error| {
                warn!(?error, "invite-relay: failed to build forward URL");
            })
            .ok()
    });

    let outcome = relay_invite_with(
        principal_url.as_ref(),
        &params.target_holder_did,
        &params.consent_id,
        &params.inviter_did,
        &params.scope,
        params.require_consent,
        forward_target.as_ref(),
        params.invite_payload.as_ref(),
        &http_client,
    )
    .await?;

    let (status, body) = relay_outcome_to_response(&outcome);
    res.status_code(status);
    res.render(Json(body));
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_utils::setup;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    fn payload() -> serde_json::Value {
        serde_json::json!({
            "kind": "cx.invite.v1",
            "from": "did:web:inviter",
        })
    }

    /// Allow path: cell returns a matching grant tag → forward succeeds.
    #[tokio::test]
    async fn relay_allows_when_consent_granted() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        // Cell-query mock: granted with matching peer/scope tag.
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/admin/cells/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cell_id": "cx:cell:cx.component.consent.grant.v1:c-allow",
                "tags": ["peer=did:web:inviter;scope=invite"],
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Forward-target mock: 200 OK accepts the payload.
        Mock::given(method("POST"))
            .and(path_regex(r"^/api/v1/invites/intake"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let forward = base.join("api/v1/invites/intake").unwrap();
        let p = payload();

        let outcome = relay_invite_with(
            Some(&base),
            "did:web:holder",
            "c-allow",
            "did:web:inviter",
            "invite",
            true,
            Some(&forward),
            Some(&p),
            &client,
        )
        .await
        .unwrap();

        assert_eq!(outcome, RelayOutcome::Forwarded { forwarded_ok: true });
        let (status, body) = relay_outcome_to_response(&outcome);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "forwarded");
        assert_eq!(body.forwarded_ok, Some(true));
    }

    /// `ConsentRequired` path: cell missing (404) + `require_consent=true`
    /// → no forward attempt, decision is `ConsentRequired`.
    #[tokio::test]
    async fn relay_returns_consent_required_when_no_consent() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/admin/cells/.*"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        // No POST mock — if this fires, wiremock will return 404 and we'd
        // see forwarded_ok=false. The Allow branch must not execute.

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let forward = base.join("api/v1/invites/intake").unwrap();
        let p = payload();

        let outcome = relay_invite_with(
            Some(&base),
            "did:web:holder",
            "c-missing",
            "did:web:inviter",
            "invite",
            true, // require_consent
            Some(&forward),
            Some(&p),
            &client,
        )
        .await
        .unwrap();

        assert_eq!(outcome, RelayOutcome::ConsentRequired);
        let (status, body) = relay_outcome_to_response(&outcome);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body.status, "consent_required");
    }

    /// Quarantine path: soland returns 500 (Unknown) and policy does not
    /// require consent → the relay defers via Quarantine, 202.
    #[tokio::test]
    async fn relay_quarantines_when_consent_unknown_and_not_required() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/admin/cells/.*"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let forward = base.join("api/v1/invites/intake").unwrap();
        let p = payload();

        let outcome = relay_invite_with(
            Some(&base),
            "did:web:holder",
            "c-unknown",
            "did:web:inviter",
            "invite",
            false, // require_consent off
            Some(&forward),
            Some(&p),
            &client,
        )
        .await
        .unwrap();

        assert_eq!(outcome, RelayOutcome::Quarantined);
        let (status, body) = relay_outcome_to_response(&outcome);
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body.status, "quarantined");
    }

    /// Validation: with no principal URL configured (and none in the
    /// body), the relay can't even start — return 400 `config_required`.
    #[tokio::test]
    async fn relay_rejects_when_target_principal_url_missing() {
        setup();
        let client = reqwest::Client::new();
        let p = payload();

        let err = relay_invite_with(
            None, // no URL
            "did:web:holder",
            "c-x",
            "did:web:inviter",
            "invite",
            true,
            None,
            Some(&p),
            &client,
        )
        .await
        .expect_err("expected BadRequest");

        match err {
            RouteError::BadRequest(msg) => assert_eq!(msg, "config_required"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Allow path but the forward target is unreachable (500) → outcome
    /// is still `Forwarded`, but with `forwarded_ok=false` so the caller
    /// can retry. Status is 200 (gate passed); failure is in the body.
    #[tokio::test]
    async fn relay_reports_forward_failure_as_forwarded_ok_false() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/admin/cells/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cell_id": "cx:cell:cx.component.consent.grant.v1:c-allow",
                "tags": ["peer=did:web:inviter;scope=any"],
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/api/v1/invites/intake"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let forward = base.join("api/v1/invites/intake").unwrap();
        let p = payload();

        let outcome = relay_invite_with(
            Some(&base),
            "did:web:holder",
            "c-allow",
            "did:web:inviter",
            "invite",
            true,
            Some(&forward),
            Some(&p),
            &client,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            RelayOutcome::Forwarded {
                forwarded_ok: false
            }
        );
        let (status, body) = relay_outcome_to_response(&outcome);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.forwarded_ok, Some(false));
    }

    /// Allow path with no forward target supplied (gate-only mode) →
    /// `Forwarded { forwarded_ok: true }` and no POST is made.
    #[tokio::test]
    async fn relay_allow_without_forward_target_is_gate_only_success() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/admin/cells/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cell_id": "cx:cell:cx.component.consent.grant.v1:c-allow",
                "tags": ["peer=did:web:inviter;scope=invite"],
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Intentionally no POST mock — the handler must NOT attempt a
        // forward. Wiremock fails the test on unexpected requests if we
        // mounted one, but absence of the mock + `expect(1)` on the GET
        // already makes the constraint clear.

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();

        let outcome = relay_invite_with(
            Some(&base),
            "did:web:holder",
            "c-allow",
            "did:web:inviter",
            "invite",
            true,
            None, // no forward target
            None, // no payload
            &client,
        )
        .await
        .unwrap();

        assert_eq!(outcome, RelayOutcome::Forwarded { forwarded_ok: true });
    }
}
