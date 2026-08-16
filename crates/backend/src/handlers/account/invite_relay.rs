// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-recipient invite-relay handler (consent-gated forward).
//!
//! Per the Move/Anchor/Lattice spec (`arkret-spec` 2026-05-08,
//! `consent-model.md` §3-§9), before an actor (coauth admin / inkson UI /
//! sodmin operator) can deliver an invite to a target principal, coauth
//! must consult the holder's consent-grant cell on the target's principal
//! server (`soland`). The previous task added the read+gate helper in
//! `consent_cell_query`; this handler is the call-site that uses it.
//!
//! ## Strand
//!
//! 1. The inviter signs an invite payload (out of band) and POSTs it to `POST
//!    /_coauth/self/account/invites/relay` along with `(target_principal_url, target_holder_did,
//!    consent_id, scope)`.
//! 2. Coauth queries the target's consent cell via `consent_cell_query::query_consent_cell`.
//! 3. Coauth runs `evaluate_invite_gate(...)` to translate the lookup + `consent_required` policy
//!    bit into an `Allow / ConsentRequired / Quarantine` decision.
//! 4. On `Allow`, coauth forwards the typed invite-delivery request to the target principal's
//!    `/_arkret/peer/invites` endpoint and returns 200. On `ConsentRequired`, coauth returns 403
//!    with `consent_required`. On `Quarantine`, coauth returns 202 with `quarantined`; callers
//!    retain responsibility for deferred holder-side delivery.
//!
//! ## Why this is a "relay" and not a "Move-mint"
//!
//! Consent grants/revokes on the holder's cell are constructed and signed
//! by the **holder** when they accept an invite — they're separate Moves
//! posted by inkson, not by coauth. coauth's only responsibility here is
//! the gate-check + forward; it never signs Moves on the holder's behalf.

use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use url::Url;

use super::{
    DepotExt, RouteError, extract_bound_activity_tracker, extract_session_info, get_requester,
    make_clock,
};
use crate::handlers::account::consent_cell_query::{
    InviteGateDecision, evaluate_invite_gate, query_consent_cell,
};
use crate::handlers::arkret;
use crate::services::peer_protocol_client::{PeerProtocolClient, PeerProtocolClientError};

// ── Request / response shapes ──────────────────────────────────

/// Body of `POST /_coauth/self/account/invites/relay`.
#[derive(Debug, Deserialize)]
pub struct InviteRelayRequestBody {
    /// DID of the actor issuing the invite. The route is guarded by the
    /// browser-session cookie / OAuth bearer (`post_invite_relay` runs
    /// `extract_session_info` + `get_requester`): a non-admin caller may
    /// only relay for their own published principal DID, while an admin
    /// session may relay on behalf of any `inviter_did`. The value is never
    /// trusted as authentication on its own.
    pub inviter_did: String,

    /// Base URL of the target's `server_name` (`soland`).
    ///
    /// Optional in the body; when omitted, falls back to
    /// the first configured `principal_servers[].endpoint`. If neither is present the
    /// handler returns 400 `config_required` because there's nowhere to
    /// query the consent cell.
    #[serde(default)]
    pub target_principal_url: Option<Url>,

    /// DID of the holder whose cell we're consulting. Embedded in the
    /// `X-Arkret-Holder-DidFullId` header on the soland query.
    pub target_holder_did: String,

    /// Consent-cell identifier per spec §6.
    pub consent_id: String,

    /// Tag scope to match against the consent cell's `OrSet` tags
    /// (`peer=...;scope=<scope>` or `peer=...;scope=any`).
    pub scope: String,

    /// Mirror of the holder's `ak.realm.policy_bundle` payload path
    /// `preauth.consent_required` policy bit. Defaults to `true` (fail closed).
    #[serde(default = "default_require_consent")]
    pub consent_required: bool,

    /// Typed v1 invite-delivery body for `POST /_arkret/peer/invites`.
    /// When omitted, the endpoint runs as a consent gate check only.
    #[serde(default)]
    pub invite_delivery: Option<
        arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody,
    >,
}

fn default_require_consent() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InviteRelayHttpOutcome {
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
pub fn relay_outcome_to_response(outcome: &RelayOutcome) -> (StatusCode, InviteRelayHttpOutcome) {
    match outcome {
        RelayOutcome::Forwarded { forwarded_ok } => (
            StatusCode::OK,
            InviteRelayHttpOutcome {
                status: "forwarded",
                decision: "Allow",
                forwarded_ok: Some(*forwarded_ok),
            },
        ),
        RelayOutcome::ConsentRequired => (
            StatusCode::FORBIDDEN,
            InviteRelayHttpOutcome {
                status: "consent_required",
                decision: "ConsentRequired",
                forwarded_ok: None,
            },
        ),
        RelayOutcome::Quarantined => (
            StatusCode::ACCEPTED,
            InviteRelayHttpOutcome {
                status: "quarantined",
                decision: "Quarantine",
                forwarded_ok: None,
            },
        ),
    }
}

/// Core relay logic: query the consent cell, gate the result, forward a typed
/// v1 invite-delivery request on `Allow`. All I/O goes through supplied clients
/// so tests can inject a wiremock server.
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
    consent_required: bool,
    peer_protocol_client: Option<&PeerProtocolClient<'_>>,
    invite_delivery: Option<
        &arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody,
    >,
    http_client: &reqwest::Client,
) -> Result<RelayOutcome, RouteError> {
    let Some(principal_url) = target_principal_url else {
        return Err(RouteError::BadRequest("config_required".into()));
    };

    let lookup = query_consent_cell(
        Some(principal_url),
        target_holder_did,
        consent_id,
        peer_did,
        scope,
        http_client,
    )
    .await;

    let decision = evaluate_invite_gate(&lookup, peer_did, scope, consent_required);
    debug!(
        ?decision,
        consent_id, peer_did, scope, "invite-relay gate decision"
    );

    match decision {
        InviteGateDecision::Allow => {
            // Gate-only mode lets callers verify consent without asking
            // coauth to deliver the invite.
            let Some(client) = peer_protocol_client else {
                return Ok(RelayOutcome::Forwarded { forwarded_ok: true });
            };
            let Some(delivery) = invite_delivery else {
                return Ok(RelayOutcome::Forwarded { forwarded_ok: true });
            };

            let forwarded_ok = match client.post_invite_delivery(delivery).await {
                Ok(_) => true,
                Err(error) => {
                    warn!(?error, "invite forward: peer invite delivery failed");
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

/// `POST /_coauth/self/account/invites/relay`
#[endpoint]
#[tracing::instrument(name = "handlers.account.invite_relay.post", skip_all, err)]
pub async fn post_invite_relay(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let params: InviteRelayRequestBody = req
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

    let arkret_config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let key_store = depot.key_store()?;
    let url_builder = depot.url_builder()?;

    // ── Authentication + authorization ─────────────────────────────
    // This endpoint drives a signed, coauth-DID-attested outbound forward to
    // a target principal server, so it MUST NOT be reachable anonymously
    // (the `/_coauth` parent router only mounts CORS). Mirror the standard
    // `self/` auth pattern (`viewer`, `sessions`): require an authenticated
    // requester, then bind the relay to that identity.
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);
    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user = requester.user().ok_or(RouteError::Unauthorized)?;

    // A non-admin session may only relay invites for its own published
    // principal DID. An admin session (OAuth scope) may relay on behalf of
    // any `inviter_did`. The body-supplied `inviter_did` is otherwise never
    // trusted as authentication.
    if !requester.is_admin() {
        let caller_did = arkret::published_principal_did_for_user(&mut repo, &arkret_config, user)
            .await?
            .ok_or(RouteError::Unauthorized)?;
        if caller_did != params.inviter_did {
            return Err(RouteError::Unauthorized);
        }
    }

    repo.cancel().await?;

    // Body-supplied URL takes precedence over the global config — admins
    // can route to a holder whose principal lives elsewhere.
    let principal_url = params
        .target_principal_url
        .clone()
        .or_else(|| arkret_config.primary_principal_server_url().cloned());

    // Deny-by-default for the federation hop: the relay forwards a request
    // signed under coauth's service DID, so the destination MUST resolve to
    // a configured trust anchor (a `principal_servers` endpoint, the identity
    // registry resolver, or starid).
    // This blocks the SSRF / signing-oracle vector where a caller supplies
    // an arbitrary `target_principal_url`.
    if let Some(target) = principal_url.as_ref()
        && !arkret_config.is_trusted_outbound_target(target)
    {
        warn!(
            host = target.host_str().unwrap_or("<none>"),
            "invite-relay: rejected untrusted target_principal_url"
        );
        return Err(RouteError::BadRequest("untrusted_principal_url".into()));
    }

    if let Some(delivery) = params.invite_delivery.as_ref() {
        delivery
            .validate_minimal()
            .map_err(|error| RouteError::BadRequest(format!("invalid_invite_delivery: {error}")))?;
        if delivery.invite_address.subject_id.as_str() != params.target_holder_did {
            return Err(RouteError::BadRequest(
                "invite_delivery_subject_mismatch".to_owned(),
            ));
        }
    }

    let service_id = arkret::service_id_for(&arkret_config);
    let trust_domain = arkret_identifiers::TypedTrustDomainId::new(arkret::trust_domain_for(
        &url_builder,
        &arkret_config,
    ))
    .map_err(|error| RouteError::Internal(Box::new(error)))?;
    let destination_service_id = match params.invite_delivery.as_ref() {
        Some(delivery) => delivery.invite_address.recipient_service_id.clone().into(),
        None => service_id.clone().into(),
    };
    let identity = arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding {
        source_service_id: service_id.into(),
        destination_service_id,
    };
    let peer_client = match PeerProtocolClient::new(
        principal_url.as_ref(),
        &http_client,
        &key_store,
        arkret::issuer_did_for(&arkret_config),
        identity,
        trust_domain.clone(),
        trust_domain,
    ) {
        Ok(client) => Some(client),
        Err(PeerProtocolClientError::BaseUrlNotConfigured) => None,
        Err(error) => return Err(RouteError::Internal(Box::new(error))),
    };

    let outcome = relay_invite_with(
        principal_url.as_ref(),
        &params.target_holder_did,
        &params.consent_id,
        &params.inviter_did,
        &params.scope,
        params.consent_required,
        peer_client.as_ref(),
        params.invite_delivery.as_ref(),
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
    use wiremock::matchers::{method, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::handlers::test_utils::setup;

    fn test_keystore() -> coauth_keystore::Keystore {
        use coauth_keystore::{JsonWebKey, JsonWebKeySet, PrivateKey};
        use rand_chacha::rand_core::SeedableRng as _;
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(9);
        let key = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid(coauth_keystore::SERVICE_IDENTITY_KEY_ID);
        coauth_keystore::Keystore::new(JsonWebKeySet::new(vec![key]))
    }

    fn peer_identity() -> arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding {
        let service_id =
            arkret_identifiers::DidCoreId::new("ak:did_core:web:auth.example".to_owned()).unwrap();
        arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding {
            source_service_id: service_id.clone().into(),
            destination_service_id: service_id.into(),
        }
    }

    fn source_full_id() -> arkret_identifiers::DidFullId {
        arkret_identifiers::DidFullId::new("did:web:auth.example".to_owned()).unwrap()
    }

    fn trust_domain() -> arkret_identifiers::TypedTrustDomainId {
        arkret_identifiers::TypedTrustDomainId::new("ak:trust_domain:auth.example".to_owned())
            .unwrap()
    }

    fn service_resolution() -> arkret_models_identity::identity_resolution::ServiceResolutionCarrier
    {
        arkret_models_identity::identity_resolution::ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url:
                "https://auth.example/_arkret/open/services/ak%3Adid_core%3Aweb%3Aauth.example/resolution"
                    .to_owned(),
            pinned_record_digest: None,
        }
    }

    fn payload() -> serde_json::Value {
        arkret_models_collaboration::governance::membership_invite::InviteCreatePayload::new(
            arkret_identifiers::DidCoreId::new("ak:did_core:web:holder".to_owned()).unwrap(),
            arkret_models_collaboration::governance::invite_addressing::InviteDeliveryTarget::principal_server(
                arkret_identifiers::DidCoreId::new("ak:did_core:web:auth.example".to_owned()).unwrap(),
                service_resolution(),
            ),
            arkret_identifiers::Hash::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .to_value()
        .unwrap()
    }

    fn invite_delivery()
    -> arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody {
        arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody::new(
            arkret_wire::test_support::raw_event(
                arkret_wire::EventKind::InviteCreate.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: arkret_identifiers::RealmId::new(
                        "ak:realm:Acewuy1nKbK90D-V6pWEnoWq1drBx9FVel0gtDQlninN",
                    )
                    .unwrap(),
                },
                arkret_identifiers::DidCoreId::new(
                    "ak:did_core:web:inviter".to_owned(),
                )
                .unwrap(),
                arkret_identifiers::DidCoreId::new(
                    "ak:did_core:web:auth.example".to_owned(),
                )
                .unwrap(),
                1,
                arkret_identifiers::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
                payload(),
            )
            .unwrap(),
            arkret_models_collaboration::governance::invite_addressing::InviteAddress::principal_server(
                arkret_identifiers::DidCoreId::new("ak:did_core:web:holder".to_owned()).unwrap(),
                arkret_identifiers::DidCoreId::new("ak:did_core:web:auth.example".to_owned()).unwrap(),
                service_resolution(),
            ),
            arkret_models_collaboration::governance::invite_addressing::IntroductionEvidence::ExplicitAddress,
            "idem-1",
        )
    }

    fn active_cell(scope: &str) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "cell_id": arkret_wire::subject_cell(
                arkret_wire::CellFamilyId::CONSENT_GRANT_V1,
                &format!("c-{scope}"),
            ),
            "holder_principal_id": "ak:did_core:web:holder",
            "peer_principal_id": "ak:did_core:web:inviter",
            "consent_scope": scope,
            "state": "active",
            "updated_at": "2026-05-01T00:00:00.000Z",
            "active_grant_dots": ["ak:event:AQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI:0"],
            "grant_dots": ["ak:event:AQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI:0"],
            "revoked_dots": [],
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
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .and(query_param("peer", "ak:did_core:web:inviter"))
            .and(query_param("consent_scope", "invite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_cell("invite")))
            .expect(1)
            .mount(&server)
            .await;

        // Forward-target mock: 200 OK accepts the typed invite delivery.
        Mock::given(method("POST"))
            .and(path_regex(r"^/_arkret/peer/invites"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "accepted"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let keystore = test_keystore();
        let peer = PeerProtocolClient::new(
            Some(&base),
            &client,
            &keystore,
            source_full_id(),
            peer_identity(),
            trust_domain(),
            trust_domain(),
        )
        .unwrap();
        let delivery = invite_delivery();

        let outcome = relay_invite_with(
            Some(&base),
            "ak:did_core:web:holder",
            "c-allow",
            "ak:did_core:web:inviter",
            "invite",
            true,
            Some(&peer),
            Some(&delivery),
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

    /// `ConsentRequired` path: cell missing (404) + `consent_required=true`
    /// → no forward attempt, decision is `ConsentRequired`.
    #[tokio::test]
    async fn relay_returns_consent_required_when_no_consent() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .respond_with(ResponseTemplate::new(404))
            .expect(2)
            .mount(&server)
            .await;

        // No POST mock — if this fires, wiremock will return 404 and we'd
        // see forwarded_ok=false. The Allow branch must not execute.

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();

        let outcome = relay_invite_with(
            Some(&base),
            "ak:did_core:web:holder",
            "c-missing",
            "ak:did_core:web:inviter",
            "invite",
            true, // consent_required
            None,
            None,
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
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();

        let outcome = relay_invite_with(
            Some(&base),
            "ak:did_core:web:holder",
            "c-unknown",
            "ak:did_core:web:inviter",
            "invite",
            false, // consent_required off
            None,
            None,
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

        let err = relay_invite_with(
            None, // no URL
            "ak:did_core:web:holder",
            "c-x",
            "ak:did_core:web:inviter",
            "invite",
            true,
            None,
            None,
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
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .and(query_param("consent_scope", "invite"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .and(query_param("consent_scope", "any"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_cell("any")))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/_arkret/peer/invites"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let keystore = test_keystore();
        let peer = PeerProtocolClient::new(
            Some(&base),
            &client,
            &keystore,
            source_full_id(),
            peer_identity(),
            trust_domain(),
            trust_domain(),
        )
        .unwrap();
        let delivery = invite_delivery();

        let outcome = relay_invite_with(
            Some(&base),
            "ak:did_core:web:holder",
            "c-allow",
            "ak:did_core:web:inviter",
            "invite",
            true,
            Some(&peer),
            Some(&delivery),
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
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .and(query_param("peer", "ak:did_core:web:inviter"))
            .and(query_param("consent_scope", "invite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(active_cell("invite")))
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
            "ak:did_core:web:holder",
            "c-allow",
            "ak:did_core:web:inviter",
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
