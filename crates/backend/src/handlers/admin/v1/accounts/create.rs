// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Creation endpoints: `POST /accounts` and `POST /accounts/batch-invite`.

use chrono::Duration;
use coauth_config::ArkretConfig;
use coauth_data::audit::{AdminOperation, NewAdminOperationLog};
use coauth_data::{BoxClock, BoxRepository};
use coauth_principal::ConnectorProvisionRequest;
use rand::distributions::{Alphanumeric, DistString};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use url::Url;

use super::AccountRecord;
use crate::handlers::account::consent_cell_query::{
    InviteGateDecision, evaluate_invite_gate, query_consent_cell,
};
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::model::UserRegistrationToken;
use crate::handlers::admin::response::SingleOutcome;
use crate::handlers::common::DepotExt;
use crate::services::invite_quarantine::EnqueueInviteQuarantine;
use crate::util::handle_valid;
use crate::{AppError, CreatedJsonResult};

/// # JSON payload for the `POST /_coauth/admin/accounts` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddAccountRequest")]
pub struct AddRequestBody {
    /// The handle of the account to add.
    handle: String,

    /// Skip checking with the `PrincipalServer` whether the username is
    /// available.
    ///
    /// Use this with caution. It bypasses downstream username reservation and
    /// should only be used when the caller already knows the Principal Server
    /// state is consistent.
    #[serde(default)]
    skip_principal_server_check: bool,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.add", skip_all)]
pub async fn add_account(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleOutcome<AccountRecord>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let mut rng = crate::handlers::account::make_rng();
    let principal_server = depot.principal_server()?;
    let params: AddRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    if repo.user().exists(&params.handle).await? {
        return Err(AppError::conflict("User already exists"));
    }

    // Do some basic check on the username
    if !handle_valid(&params.handle) {
        return Err(AppError::bad_request("Username is not valid"));
    }

    // Ask the PrincipalServer if the username is available
    let principal_server_available = principal_server
        .is_handle_available(&params.handle)
        .await
        .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))?;

    if !principal_server_available {
        if !params.skip_principal_server_check {
            return Err(AppError::conflict(
                "Username is reserved by the PrincipalServer",
            ));
        }

        // If we skipped the check, we still want to shout about it
        warn!(
            "Skipped PrincipalServer check for username {}",
            params.handle
        );
    }

    let user = repo.user().add(&mut rng, &clock, params.handle).await?;

    // Admin creation persists only the service account. Principal identity
    // onboarding remains a separate client-signed flow.

    principal_server
        .provision_user(&ConnectorProvisionRequest::new(&user.localpart, &user.sub))
        .await
        .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UserCreated,
        "account",
        Some(user.id),
        serde_json::json!({ "handle": user.localpart }),
    )
    .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleOutcome::new_canonical(AccountRecord::from_user(user, depot).await?),
    ))
}

/// # JSON payload for the `POST /_coauth/admin/accounts/batch-invite` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "BatchInviteRequestBody")]
pub struct BatchInviteRequestBody {
    /// Number of registration tokens to create (1-100)
    count: u32,

    /// Maximum number of times each token can be used. If not provided, each
    /// token can be used an unlimited number of times.
    usage_limit: Option<u32>,

    /// Number of hours until each token expires. If not provided, the tokens
    /// never expire.
    expires_in_hours: Option<u64>,

    /// Optional Arkret consent-gate metadata (Move/Anchor/Lattice spec
    /// `consent-model.md` §6.1). When `peer_did` is supplied **and** a
    /// `server_name` URL is configured, coauth queries the holder's
    /// consent-grant cell on `soland` before minting registration tokens
    /// and rejects / quarantines the batch when the holder has not granted
    /// the requesting peer.
    ///
    /// Requests that do not address a specific holder DID omit this field;
    /// the gate is then a no-op for local registration-token minting.
    #[serde(default)]
    consent_gate: Option<BatchInviteConsentGate>,
}

/// Inline consent-gate metadata for `BatchInviteRequestBody`.
///
/// Mirrors the fields on `account::invite_relay::InviteRelayRequestBody`, just
/// without `inviter_did` / `invite_delivery` (admin batch-invite mints
/// fresh tokens — there is no inviter-signed payload to forward).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchInviteConsentGate {
    /// DID of the requesting peer (the admin / service issuing this
    /// batch on behalf of someone). Triggers the gate when set.
    pub peer_did: String,

    /// DID of the target holder whose consent cell governs the invite.
    pub target_holder_did: String,

    /// Consent-cell identifier per spec §6.
    pub consent_id: String,

    /// Tag scope to match against the holder's `OrSet` tags. Defaults to
    /// `invite` (matches `peer=...;scope=invite` and `peer=...;scope=any`).
    #[serde(default = "default_invite_scope")]
    pub scope: String,

    /// Override the first configured Principal Server endpoint per request. Useful
    /// when a deployment fans out across multiple `server_names` and
    /// the global config points at a different one.
    #[serde(default)]
    pub target_principal_url: Option<Url>,

    /// Mirror of the holder's
    /// `ak.realm.policy_components.preauth.require_consent` policy bit.
    /// Defaults to `true` (fail closed: missing / revoked consent → 422).
    #[serde(default = "default_require_consent")]
    pub require_consent: bool,
}

fn default_invite_scope() -> String {
    "invite".to_owned()
}

fn default_require_consent() -> bool {
    true
}

/// Response containing the list of created registration tokens
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct BatchInviteOutcome {
    /// The list of created registration tokens
    pub data: Vec<SingleOutcome<UserRegistrationToken>>,
}

/// Pure parameter struct for the underlying `mint_registration_tokens`
/// helper. Mirrors the wire fields on `BatchInviteRequestBody` but without
/// the consent-gate metadata — the gate is the caller's responsibility
/// (see `batch_invite` and `invite_quarantine::resolve_invite_quarantine`).
///
/// Exposed so the quarantine-approve strand can re-mint tokens with the
/// same parameters that were originally enqueued, without re-parsing
/// the request body or re-running the consent gate (the operator
/// approving the quarantine has already vouched for it).
#[derive(Debug, Clone)]
pub struct MintRegistrationTokensParams {
    pub count: u32,
    pub usage_limit: Option<u32>,
    pub expires_in_hours: Option<u64>,
}

impl MintRegistrationTokensParams {
    /// Validate count bounds. Mirrors the inline check in `batch_invite`.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.count == 0 || self.count > 100 {
            return Err(AppError::bad_request("Count must be between 1 and 100"));
        }
        Ok(())
    }
}

/// Pure-function gate evaluation for `batch_invite`. Returns
/// `Ok(GateOutcome::Allow)` when token minting should proceed, or one of
/// the rejection variants — caller decides how to render those into HTTP
/// (the Salvo handler maps `ConsentRequired` → 422 and `Quarantined` →
/// 202; the existing `RouteError`/`AppError` shapes keep that
/// stringly-typed for now).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchInviteGateOutcome {
    /// Either the request did not include a peer DID (gate disabled) or
    /// the cell read + scope match returned `Allow`.
    Allow,
    /// Holder explicitly revoked or never granted; policy requires
    /// consent. Caller maps to HTTP 422 + `consent_required` body.
    ConsentRequired,
    /// Lookup was inconclusive and policy did not require consent.
    /// Caller routes to a holder-side quarantine outbox; HTTP 202.
    Quarantined,
}

/// Evaluate the consent gate for `batch_invite`. Pure helper; isolates the
/// I/O so unit tests can inject a wiremock-backed `reqwest::Client`.
///
/// `gate_url_override` lets the caller supply a per-request URL that wins
/// over the primary configured Principal Server endpoint. Both `None` →
/// gate is skipped (returns `Allow`) — same behaviour as omitting
/// `peer_did` entirely. This keeps the no-config / no-peer paths
/// indistinguishable, which matches the spec note that the gate is
/// optional infrastructure.
pub async fn evaluate_batch_invite_gate(
    gate: Option<&BatchInviteConsentGate>,
    arkret_config: &ArkretConfig,
    http_client: &reqwest::Client,
) -> BatchInviteGateOutcome {
    let Some(gate) = gate else {
        return BatchInviteGateOutcome::Allow;
    };

    let principal_url = gate
        .target_principal_url
        .as_ref()
        .or_else(|| arkret_config.primary_principal_server_url());

    let Some(principal_url) = principal_url else {
        // Gate metadata supplied, but no server to query. Mirror the
        // relay handler: when require_consent is on, fail closed; when
        // off, treat as quarantine. (We never silently allow.)
        debug!(
            consent_id = %gate.consent_id,
            "batch_invite consent gate: no server_name URL — falling back per require_consent",
        );
        return if gate.require_consent {
            BatchInviteGateOutcome::ConsentRequired
        } else {
            BatchInviteGateOutcome::Quarantined
        };
    };

    let lookup = query_consent_cell(
        Some(principal_url),
        &gate.target_holder_did,
        &gate.consent_id,
        &gate.peer_did,
        &gate.scope,
        http_client,
    )
    .await;

    let decision = evaluate_invite_gate(&lookup, &gate.peer_did, &gate.scope, gate.require_consent);
    match decision {
        InviteGateDecision::Allow => BatchInviteGateOutcome::Allow,
        InviteGateDecision::ConsentRequired => BatchInviteGateOutcome::ConsentRequired,
        InviteGateDecision::Quarantine => BatchInviteGateOutcome::Quarantined,
    }
}

/// Mint registration tokens against an open `BoxRepository`. Pure
/// helper — no consent gate, no JSON parsing, no audit-log assumptions
/// about the call-site.
///
/// `admin_user_id` is the Ulid of the admin who *initiated* the action
/// (the audit log slot for "who" — for the resolve-quarantine path this
/// is the operator approving the queue row, *not* the original
/// requesting admin who got quarantined). When `None`, no admin op is
/// recorded (matches the pre-round-21 behaviour for unauthenticated
/// internal call-sites).
///
/// The caller is responsible for `repo.save()` after this returns.
pub async fn mint_registration_tokens(
    repo: &mut BoxRepository,
    clock: &BoxClock,
    rng: &mut coauth_data::BoxRng,
    params: &MintRegistrationTokensParams,
    admin_user_id: Option<ulid::Ulid>,
) -> Result<Vec<SingleOutcome<UserRegistrationToken>>, AppError> {
    params.validate()?;

    let expires_at = params
        .expires_in_hours
        .and_then(|h| Duration::try_hours(h as i64))
        .map(|d| clock.now() + d);

    let mut tokens = Vec::with_capacity(params.count as usize);
    for _ in 0..params.count {
        let token_string = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
        let registration_token = repo
            .user_registration_token()
            .add(rng, clock, token_string, params.usage_limit, expires_at)
            .await?;

        if let Some(admin_id) = admin_user_id {
            repo.audit()
                .add_admin_operation(
                    rng,
                    clock,
                    NewAdminOperationLog::new(
                        admin_id,
                        AdminOperation::RegistrationTokenCreated,
                        "registration_token",
                        serde_json::json!({}),
                    )
                    .with_resource_id(registration_token.id),
                )
                .await?;
        }

        let model = crate::handlers::admin::model::to_user_registration_token(
            registration_token,
            clock.now(),
        );
        tokens.push(SingleOutcome::new_canonical(model));
    }
    Ok(tokens)
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.batch_invite", skip_all)]
pub async fn batch_invite(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<BatchInviteOutcome> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let mut rng = crate::handlers::account::make_rng();
    let params: BatchInviteRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    let mint_params = MintRegistrationTokensParams {
        count: params.count,
        usage_limit: params.usage_limit,
        expires_in_hours: params.expires_in_hours,
    };
    mint_params.validate()?;

    // ── C10.E consent gate (Move/Anchor/Lattice) ─────────────────
    //
    // Per `arkret-spec` 2026-05-08 `consent-model.md` §6.1, when an
    // invite addresses a specific holder DID we must query the holder's
    // consent-grant cell on their server_name (`soland`) before
    // proceeding. The gate is opt-in via `BatchInviteConsentGate` —
    // callers that just want bulk registration tokens omit the metadata
    // and skip the network round-trip entirely.
    //
    // For per-recipient relay (the path that forwards an inviter-signed
    // payload), see `account::invite_relay::post_invite_relay`. This
    // handler only mints registration tokens, so we don't forward a
    // payload — we simply gate the mint.
    let arkret_config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let gate_outcome =
        evaluate_batch_invite_gate(params.consent_gate.as_ref(), &arkret_config, &http_client)
            .await;
    let consent_id_for_log = params
        .consent_gate
        .as_ref()
        .map(|g| g.consent_id.clone())
        .unwrap_or_default();
    match gate_outcome {
        BatchInviteGateOutcome::Allow => {}
        BatchInviteGateOutcome::ConsentRequired => {
            warn!(
                consent_id = %consent_id_for_log,
                "batch_invite: consent gate rejected with consent_required",
            );
            return Err(AppError::unprocessable_entity("consent_required"));
        }
        BatchInviteGateOutcome::Quarantined => {
            // Spec §6.1 default-profile path: no consent + no
            // require_consent flag → route to the holder's quarantine
            // outbox. As of round 20 we persist the intent to
            // `invite_quarantine_queue` so admins (sodmin / inkson)
            // can review and either re-run the invite or reject it.
            //
            // The outcome on the wire is still 422 + `quarantined`:
            // the immediate batch_invite call did NOT mint tokens,
            // and the caller should treat the gate decision as a
            // soft-reject pending admin review. The queue id is
            // surfaced via the `quarantine_id` slot in the audit log
            // and admin-list endpoint at
            // `GET /_coauth/admin/invite-quarantine`.
            let quarantine_id = if let Some(gate) = params.consent_gate.as_ref() {
                let queue = depot.invite_quarantine_service()?;
                let payload = serde_json::json!({
                    "count": params.count,
                    "usage_limit": params.usage_limit,
                    "expires_in_hours": params.expires_in_hours,
                });
                let enqueue_result = queue
                    .enqueue(EnqueueInviteQuarantine {
                        peer_did: gate.peer_did.clone(),
                        target_holder_did: gate.target_holder_did.clone(),
                        consent_id: gate.consent_id.clone(),
                        scope: gate.scope.clone(),
                        requesting_admin_did: admin_user.as_ref().map(|u| u.localpart.clone()),
                        payload,
                    })
                    .await;
                match enqueue_result {
                    Ok(rec) => Some(rec.id),
                    Err(error) => {
                        warn!(
                            consent_id = %consent_id_for_log,
                            ?error,
                            "batch_invite: consent gate quarantine enqueue failed; surfacing quarantined-without-id",
                        );
                        None
                    }
                }
            } else {
                // Should not happen — gate outcome is Quarantined only
                // when metadata was supplied — but guard defensively.
                None
            };
            warn!(
                consent_id = %consent_id_for_log,
                quarantine_id = ?quarantine_id,
                "batch_invite: consent gate routed to quarantine outbox",
            );
            return Err(AppError::unprocessable_entity("quarantined"));
        }
    }

    let tokens = mint_registration_tokens(
        &mut repo,
        &clock,
        &mut rng,
        &mint_params,
        admin_user.as_ref().map(|u| u.id),
    )
    .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(BatchInviteOutcome {
        data: tokens,
    }))
}

#[cfg(test)]
mod consent_gate_tests {
    //! Unit tests for the `batch_invite` consent gate (Allow /
    //! `ConsentRequired` / Quarantine). Exercises
    //! `evaluate_batch_invite_gate` end-to-end with a wiremock-backed
    //! soland stub, mirroring the per-recipient relay tests.
    //!
    //! The full Salvo handler is covered by integration tests in
    //! `accounts::tests`; here we only need to confirm the gate logic
    //! routes the three outcomes correctly given the principal-server
    //! response.
    use coauth_config::ArkretConfig;
    use wiremock::matchers::{method, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::handlers::test_utils::setup;

    fn empty_config() -> ArkretConfig {
        ArkretConfig::default()
    }

    fn gate_for(consent_id: &str, peer: &str, holder: &str) -> BatchInviteConsentGate {
        BatchInviteConsentGate {
            peer_did: peer.to_owned(),
            target_holder_did: holder.to_owned(),
            consent_id: consent_id.to_owned(),
            scope: "invite".to_owned(),
            target_principal_url: None,
            require_consent: true,
        }
    }

    fn active_cell(peer: &str, scope: &str) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "cell_id": format!("ak:cell:ak.component.consent.grant.v1:c-{scope}"),
            "holder_did": "did:web:holder",
            "peer_did": peer,
            "consent_scope": scope,
            "state": "active",
            "updated_at": "2026-05-01T00:00:00.000Z",
            "active_grant_dots": ["ak:event:0196419b-0000-7000-8000-000000000001:0"],
            "grant_dots": ["ak:event:0196419b-0000-7000-8000-000000000001:0"],
            "revoked_dots": [],
        })
    }

    /// No gate metadata at all -> Allow local registration-token minting.
    #[tokio::test]
    async fn batch_invite_gate_allows_when_metadata_absent() {
        setup();
        let client = reqwest::Client::new();
        let outcome = evaluate_batch_invite_gate(None, &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::Allow);
    }

    /// Gate metadata + matching consent tag → Allow.
    #[tokio::test]
    async fn batch_invite_gate_allows_when_consent_granted() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .and(query_param("peer", "did:web:peer"))
            .and(query_param("consent_scope", "invite"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(active_cell("did:web:peer", "invite")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let mut gate = gate_for("c-allow", "did:web:peer", "did:web:holder");
        gate.target_principal_url = Some(base);

        let outcome = evaluate_batch_invite_gate(Some(&gate), &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::Allow);
    }

    /// Cell missing (404) + `require_consent=true` → `ConsentRequired`.
    #[tokio::test]
    async fn batch_invite_gate_returns_consent_required_when_missing() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .respond_with(ResponseTemplate::new(404))
            .expect(2)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let mut gate = gate_for("c-missing", "did:web:peer", "did:web:holder");
        gate.target_principal_url = Some(base);
        gate.require_consent = true;

        let outcome = evaluate_batch_invite_gate(Some(&gate), &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::ConsentRequired);
    }

    /// soland 500 (Unknown) + `require_consent=false` → Quarantined.
    #[tokio::test]
    async fn batch_invite_gate_quarantines_when_unknown_and_not_required() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let mut gate = gate_for("c-unknown", "did:web:peer", "did:web:holder");
        gate.target_principal_url = Some(base);
        gate.require_consent = false;

        let outcome = evaluate_batch_invite_gate(Some(&gate), &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::Quarantined);
    }

    /// Tag present but peer DID mismatch → `ConsentRequired` (require=true).
    #[tokio::test]
    async fn batch_invite_gate_rejects_when_peer_mismatch() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/_arkret/self/consent/cells/.*"))
            .respond_with(ResponseTemplate::new(404))
            .expect(2)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let mut gate = gate_for("c-other", "did:web:peer", "did:web:holder");
        gate.target_principal_url = Some(base);

        let outcome = evaluate_batch_invite_gate(Some(&gate), &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::ConsentRequired);
    }

    /// Gate metadata supplied but no principal URL anywhere +
    /// `require_consent=true` → `ConsentRequired` (fail closed). No HTTP.
    #[tokio::test]
    async fn batch_invite_gate_fails_closed_when_no_principal_url() {
        setup();
        let client = reqwest::Client::new();
        let mut gate = gate_for("c-none", "did:web:peer", "did:web:holder");
        gate.target_principal_url = None;
        gate.require_consent = true;

        let outcome = evaluate_batch_invite_gate(Some(&gate), &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::ConsentRequired);
    }
}
