// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Creation endpoints: `POST /accounts` and `POST /accounts/batch-invite`.

use arkret_wire::{ConsentScope, DidCoreId};
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
use crate::handlers::account::consent_result_query::{InviteGateDecision, evaluate_invite_gate};
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::model::UserRegistrationToken;
use crate::handlers::admin::response::SingleOutcome;
use crate::handlers::common::DepotExt;
use crate::services::admin_invite_review::EnqueueAdminInviteReview;
use crate::util::handle_valid;
use crate::{AppError, CreatedJsonResult};

/// # JSON payload for the `POST /_coauth/admin/accounts` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddAccountRequest")]
pub struct AddRequestBody {
    /// The handle of the account to add.
    handle: String,

    /// Skip checking with the `Station` whether the username is
    /// available.
    ///
    /// Use this with caution. It bypasses downstream username reservation and
    /// should only be used when the caller already knows the Station
    /// state is consistent.
    #[serde(default)]
    skip_station_check: bool,
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
    let station = depot.station()?;
    let params: AddRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    // Validate the handle before any repository lookup: the existence query
    // normalizes the localpart through the SDK PRECIS profile, so an invalid
    // handle reaches it as a repository error and escapes as a 500 instead of
    // the 400 this endpoint owes the caller.
    if !handle_valid(&params.handle) {
        return Err(AppError::bad_request("Username is not valid"));
    }

    if repo.user().exists(&params.handle).await? {
        return Err(AppError::conflict("User already exists"));
    }

    // Ask the Station if the username is available
    let station_available = station
        .is_handle_available(&params.handle)
        .await
        .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))?;

    if !station_available {
        if !params.skip_station_check {
            return Err(AppError::conflict("Username is reserved by the Station"));
        }

        // If we skipped the check, we still want to shout about it
        warn!("Skipped Station check for username {}", params.handle);
    }

    let user = repo.user().add(&mut rng, &clock, params.handle).await?;

    // Admin creation persists only the service account. Principal identity
    // onboarding remains a separate client-signed flow.

    station
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

    /// Optional metadata for the issuing deployment's local minting gate.
    /// Without metadata, token minting proceeds normally. With metadata, an
    /// unverifiable holder decision rejects a consent-required request or saves
    /// an administrator review row. This does not implement holder-side invite
    /// delivery admission or a holder-private quarantine queue.
    #[serde(default)]
    consent_gate: Option<BatchInviteConsentGate>,
}

/// Inline consent-gate metadata for `BatchInviteRequestBody`.
///
/// Mirrors the fields on `account::invite_relay::InviteRelayRequestBody`, just
/// without `inviter_id` / `invite_delivery` (admin batch-invite mints
/// fresh tokens — there is no inviter-signed payload to forward).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchInviteConsentGate {
    /// DID of the requesting peer (the admin / service issuing this
    /// batch on behalf of someone). Triggers the gate when set.
    #[schemars(with = "String")]
    pub peer_principal_id: DidCoreId,

    /// Principal DID of the target holder whose consent cell governs the invite.
    #[schemars(with = "String")]
    pub target_holder_principal_id: DidCoreId,

    /// Consent-cell identifier per spec §6.
    pub consent_id: String,

    /// Scope to match against the exact peer-keyed consent cell. Defaults to
    /// `invite` (also accepting a cell whose scope is `any`).
    #[serde(default = "default_invite_scope")]
    #[schemars(with = "String")]
    pub scope: ConsentScope,

    /// Override the first configured Station endpoint per request. Useful
    /// when a deployment fans out across multiple `server_names` and
    /// the global config points at a different one.
    #[serde(default)]
    pub target_principal_url: Option<Url>,

    /// Mirror of the holder's
    /// the `ak.realm.policy_bundle` payload path `preauth.consent_required` policy bit.
    /// Defaults to `true` (fail closed: missing / revoked consent → 422).
    #[serde(default = "default_require_consent")]
    pub consent_required: bool,
}

fn default_invite_scope() -> ConsentScope {
    ConsentScope::Invite
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
/// (see `batch_invite` and `admin_invite_review::resolve_admin_invite_review`).
///
/// Exposed so the admin-review approval flow can re-mint tokens with the
/// same parameters that were originally enqueued, without re-parsing
/// the request body or re-running the local minting gate. Administrator
/// approval does not grant or change the recipient's Consent state.
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

/// Local registration-token gate outcome. Both rejection variants map to
/// HTTP 422; `NeedsAdminReview` additionally saves an administrator review row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchInviteGateOutcome {
    /// The local minting gate allows registration-token creation. Requests
    /// without gate metadata currently take this branch.
    Allow,
    /// Holder explicitly revoked or never granted; policy requires
    /// consent. Caller maps to HTTP 422 + `consent_required` body.
    ConsentRequired,
    /// Lookup was inconclusive and policy did not require consent.
    /// Caller saves an administrator review row; HTTP 422.
    NeedsAdminReview,
}

/// Evaluate the local minting gate. Metadata without an exact peer Actor
/// cannot establish holder Consent. The current implementation returns an
/// unknown lookup rather than querying a holder from a principal-only key.
/// This function leaves holder-side invite delivery admission unchanged.
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
        .or_else(|| arkret_config.primary_station_url());

    let Some(principal_url) = principal_url else {
        // Gate metadata supplied, but no server to query. Mirror the
        // relay handler: when consent_required is on, fail closed; when
        // off, require administrator review. (We never silently allow.)
        debug!(
            consent_id = %gate.consent_id,
            "batch_invite consent gate: no server_name URL — falling back per consent_required",
        );
        return if gate.consent_required {
            BatchInviteGateOutcome::ConsentRequired
        } else {
            BatchInviteGateOutcome::NeedsAdminReview
        };
    };

    let _ = (principal_url, http_client);
    let lookup = crate::handlers::account::consent_result_query::ConsentLookup::Unknown {
        reason: "exact_peer_actor_required",
    };

    let decision = evaluate_invite_gate(&lookup, gate.scope, gate.consent_required);
    match decision {
        InviteGateDecision::Allow => BatchInviteGateOutcome::Allow,
        InviteGateDecision::ConsentRequired => BatchInviteGateOutcome::ConsentRequired,
        InviteGateDecision::Quarantine => BatchInviteGateOutcome::NeedsAdminReview,
    }
}

/// Mint registration tokens against an open `BoxRepository`. Pure
/// helper — no consent gate, no JSON parsing, no audit-log assumptions
/// about the call-site.
///
/// `admin_user_id` is the Ulid of the admin who *initiated* the action
/// (the audit log slot for "who" — for the resolve-review path this
/// is the operator approving the queue row, *not* the original
/// requesting admin whose request needed review). When `None`, no admin op is
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

    // Optional local registration-token minting gate. Per-recipient invite
    // delivery belongs to the separate holder-side admission path; this admin
    // handler only saves review parameters or mints registration tokens.
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
        BatchInviteGateOutcome::NeedsAdminReview => {
            // Save the issuing administrator's mint parameters for review.
            // This queue is local management state, not holder Consent or the
            // holder Station's private invite quarantine. No tokens are minted
            // by this request; the admin review API exposes the queued row.
            let admin_invite_review_id = if let Some(gate) = params.consent_gate.as_ref() {
                let queue = depot.admin_invite_review_service()?;
                let payload = serde_json::json!({
                    "count": params.count,
                    "usage_limit": params.usage_limit,
                    "expires_in_hours": params.expires_in_hours,
                });
                let enqueue_result = queue
                    .enqueue(EnqueueAdminInviteReview {
                        peer_principal_id: gate.peer_principal_id.clone(),
                        target_holder_principal_id: gate.target_holder_principal_id.clone(),
                        consent_id: gate.consent_id.clone(),
                        scope: gate.scope.to_string(),
                        requesting_admin_localpart: admin_user
                            .as_ref()
                            .map(|u| u.localpart.clone()),
                        payload,
                    })
                    .await;
                match enqueue_result {
                    Ok(rec) => Some(rec.id),
                    Err(error) => {
                        warn!(
                            consent_id = %consent_id_for_log,
                            ?error,
                            "batch_invite: admin invite review enqueue failed; no review id available",
                        );
                        None
                    }
                }
            } else {
                // Should not happen — gate outcome is NeedsAdminReview only
                // when metadata was supplied — but guard defensively.
                None
            };
            warn!(
                consent_id = %consent_id_for_log,
                admin_invite_review_id = ?admin_invite_review_id,
                "batch_invite: mint request saved for administrator review",
            );
            return Err(AppError::unprocessable_entity(
                "admin_invite_review_required",
            ));
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
    //! `evaluate_batch_invite_gate` end-to-end.
    //!
    //! The full Salvo handler is covered by integration tests in
    //! `accounts::tests`; here we only need to confirm the gate logic
    //! routes the three outcomes correctly.
    use coauth_config::ArkretConfig;

    use super::*;
    use crate::handlers::test_utils::setup;

    fn empty_config() -> ArkretConfig {
        ArkretConfig::default()
    }

    fn gate_for(consent_id: &str, peer: &str, holder: &str) -> BatchInviteConsentGate {
        BatchInviteConsentGate {
            peer_principal_id: DidCoreId::new(peer).unwrap(),
            target_holder_principal_id: DidCoreId::new(holder).unwrap(),
            consent_id: consent_id.to_owned(),
            scope: ConsentScope::Invite,
            target_principal_url: None,
            consent_required: true,
        }
    }

    fn principal_url() -> Url {
        Url::parse("https://station.example/").unwrap()
    }

    /// No gate metadata at all -> Allow local registration-token minting.
    #[tokio::test]
    async fn batch_invite_gate_allows_when_metadata_absent() {
        setup();
        let client = reqwest::Client::new();
        let outcome = evaluate_batch_invite_gate(None, &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::Allow);
    }

    /// A principal-only batch gate cannot reconstruct the exact Account or
    /// Service actor variant, so it fails closed before making a lookup.
    #[tokio::test]
    async fn batch_invite_gate_requires_an_exact_peer_actor() {
        setup();
        let client = reqwest::Client::new();

        let mut gate = gate_for("c-allow", "ak:did_core:web:peer", "ak:did_core:web:holder");
        gate.target_principal_url = Some(principal_url());

        let outcome = evaluate_batch_invite_gate(Some(&gate), &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::ConsentRequired);
    }

    /// Missing exact peer actor + `consent_required=false` → NeedsAdminReview.
    #[tokio::test]
    async fn batch_invite_gate_needs_admin_review_when_unknown_and_not_required() {
        setup();
        let client = reqwest::Client::new();

        let mut gate = gate_for(
            "c-unknown",
            "ak:did_core:web:peer",
            "ak:did_core:web:holder",
        );
        gate.target_principal_url = Some(principal_url());
        gate.consent_required = false;

        let outcome = evaluate_batch_invite_gate(Some(&gate), &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::NeedsAdminReview);
    }

    /// Gate metadata supplied but no principal URL anywhere +
    /// `consent_required=true` → `ConsentRequired` (fail closed). No HTTP.
    #[tokio::test]
    async fn batch_invite_gate_fails_closed_when_no_principal_url() {
        setup();
        let client = reqwest::Client::new();
        let mut gate = gate_for("c-none", "ak:did_core:web:peer", "ak:did_core:web:holder");
        gate.target_principal_url = None;
        gate.consent_required = true;

        let outcome = evaluate_batch_invite_gate(Some(&gate), &empty_config(), &client).await;
        assert_eq!(outcome, BatchInviteGateOutcome::ConsentRequired);
    }
}
