//! `POST /_arkret/gate/account/erasure-requests` —
//! `ak.gate.account.command.request_erasure.v1` (account-lifecycle.md §8.1).
//!
//! The only client entry point for self-initiated account erasure. The
//! Account Authority (coauth) accepts it directly on the gate surface and
//! does exactly three things, all inside this service and inside one
//! database transaction:
//!
//! 1. authenticates the holder as a high-risk action, judging authentication freshness from its own
//!    local facts (the browser session's most recent login / passkey authentication — coauth is the
//!    only party holding them);
//! 2. durably records the erasure intent (`user_erasure_requests`), which is also the idempotency
//!    carrier for the three-state `request_id` contract;
//! 3. continues the existing `erasure_pending` AccountStatusRecord issuance flow: issuer-ledger
//!    append + signature via [`author_transition_plan`], durable publication job, and the shared
//!    deactivation/projection-rewrite fanout jobs that already implement §8.
//!
//! This deployment grants **no withdrawal window** (§8.1 explicitly allows a
//! zero-length window as deployment governance), so acceptance and record
//! signing commit atomically and `withdrawal_window_ends_at` is always
//! omitted from the outcome. A deployment that later wants a non-zero window
//! must defer step 3 until the window ends and keep the intent live until
//! then.
//!
//! The success response is an acceptance confirmation only: it proves the
//! intent is durably recorded, not that physical erasure completed —
//! completion is observed through the account-status read surface and the
//! erasure receipt rail.

use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::{
    AccountRequestErasureOutcome, AccountRequestErasureRequestBody, AccountRequestErasureStatus,
};
use chrono::{DateTime, Utc};
use coauth_config::ArkretConfig;
use coauth_data::queue::{
    AccountProjectionRewriteJob, DeactivateUserJob, QueueJobRepositoryExt as _,
};
use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
use coauth_data::{
    BoxRepository, Clock, NewUserErasureRequest, RepositoryAccess as _, User, UserPatch,
};
use coauth_keystore::Keystore;
use coauth_principal::ConnectorAdmin;
use rand_core::RngCore;
use salvo::prelude::*;

use super::{ArkretRouteError, owning_station_id_for};
use crate::handlers::common::{DepotExt, extract_session_info, make_clock, make_rng};
use crate::services::account_status_publication::{
    author_transition_plan, enqueue_exact_publication, validate_transition_plan,
};

/// `reason_code` stamped on the self-service `erasure_pending` record so the
/// record expresses its trigger source (§8.1: SHOULD, e.g. `gdpr_request`).
const SELF_ERASURE_REASON_CODE: &str = "gdpr_request";

/// Byte-preserving acceptance response: replays must return the stored
/// canonical outcome verbatim, so the handler renders raw canonical JSON
/// bytes instead of re-serializing a struct.
pub struct ErasureAcceptanceCanonicalJson(Vec<u8>);

impl Scribe for ErasureAcceptanceCanonicalJson {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.0)
            .expect("erasure acceptance canonical JSON response body is writable");
    }
}

/// `POST /_arkret/gate/account/erasure-requests`.
#[handler]
pub async fn request_account_erasure(
    req: &mut Request,
    depot: &Depot,
) -> Result<ErasureAcceptanceCanonicalJson, ArkretRouteError> {
    let body: AccountRequestErasureRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;

    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let station = depot.station()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let session_info = extract_session_info(req, depot);
    let mut repo = depot.repo().await?;

    // Authenticate the holder from the coauth browser session. The lookup is
    // deliberately NOT `load_active_session`: that helper filters on
    // `User::is_valid()` (status == active), while §8.1 admits
    // `soft_logged_out` and `suspended` accounts to this operation. The
    // status matrix is applied explicitly below instead.
    let caller = async {
        let session_id = session_info.current_session_id().ok_or_else(|| {
            ArkretRouteError::Unauthorized(
                "account erasure requests require an authenticated session".to_owned(),
            )
        })?;
        let session = repo
            .browser_session()
            .lookup(session_id)
            .await?
            .filter(|session| session.finished_at.is_none())
            .ok_or_else(|| {
                ArkretRouteError::Unauthorized("session is finished or unknown".to_owned())
            })?;
        let last_authenticated_at = repo
            .browser_session()
            .get_last_authentication(&session)
            .await?
            .map(|authentication| authentication.created_at);
        Ok::<_, ArkretRouteError>((session.user.clone(), last_authenticated_at))
    }
    .await;
    let (user, last_authenticated_at) = match caller {
        Ok(caller) => caller,
        Err(error) => {
            repo.cancel().await.ok();
            return Err(error);
        }
    };

    let accepted = accept_erasure_request(
        &mut repo,
        &mut *rng,
        &*clock,
        &arkret_config,
        &key_store,
        station.as_ref(),
        &user,
        last_authenticated_at,
        &body,
    )
    .await;
    match accepted {
        Ok(canonical_outcome) => {
            repo.save().await?;
            Ok(ErasureAcceptanceCanonicalJson(canonical_outcome))
        }
        Err(error) => {
            // Every refusal path is zero-write by construction; rolling the
            // transaction back keeps that guarantee even for failures after
            // the intent insert (e.g. a ledger conflict during issuance).
            repo.cancel().await.ok();
            Err(error)
        }
    }
}

/// Transport-independent §8.1 acceptance semantics.
///
/// On success the durable intent row, the signed issuer-ledger record, the
/// user status patch, the publication job and the §8 fanout jobs are all
/// pending in `repo`'s open transaction and the exact canonical acceptance
/// outcome bytes are returned; the caller commits. On error nothing must be
/// committed — the caller rolls back, which makes every refusal zero-write.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn accept_erasure_request(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    station: &dyn ConnectorAdmin,
    user: &User,
    last_authenticated_at: Option<DateTime<Utc>>,
    body: &AccountRequestErasureRequestBody,
) -> Result<Vec<u8>, ArkretRouteError> {
    let request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?
        .to_string();
    let request_id = body.request_id.to_string();

    // ── Idempotency (§8.1): exact replay returns the first recorded
    // outcome byte-for-byte; the same request_id with different canonical
    // bytes — or a request_id owned by another account — is
    // `duplicate_conflict` with zero writes.
    if let Some(existing) = repo.user_erasure_request().lookup(&request_id).await? {
        if existing.user_id == user.id && existing.request_digest == request_digest {
            return Ok(existing.canonical_outcome);
        }
        return Err(duplicate_conflict());
    }

    // ── Entry conditions (§8.1): only active / soft_logged_out / suspended
    // may enter; the remaining states fail at the authentication layer with
    // their §3 status codes.
    match user.status {
        AccountStatus::Active | AccountStatus::SoftLoggedOut | AccountStatus::Suspended => {}
        AccountStatus::Locked => {
            return Err(ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::ACCOUNT_LOCKED,
                "account is locked",
            ));
        }
        AccountStatus::Deactivated => {
            return Err(ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::ACCOUNT_DEACTIVATED,
                "account is deactivated",
            ));
        }
        AccountStatus::ErasurePending => {
            return Err(ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::ACCOUNT_ERASED,
                "account erasure is already pending",
            ));
        }
    }

    // ── Fresh high-risk action authentication (§8.1): judged locally from
    // this deployment's own authentication facts. No configured policy, no
    // authentication fact, or a stale one all fail closed with zero writes.
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let fresh = arkret_config
        .erasure_request_max_auth_age
        .is_some_and(|max_age| {
            last_authenticated_at.is_some_and(|authenticated_at| {
                now.signed_duration_since(authenticated_at) <= max_age
            })
        });
    if !fresh {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::REAUTHENTICATION_REQUIRED,
            "this high-risk action requires fresh authentication",
        ));
    }

    // ── Single live intent (§8.1): a different request_id while a live
    // (record not yet signed) intent exists is `failed_precondition` with
    // reason_code `erasure_request_already_pending`.
    if repo
        .user_erasure_request()
        .find_live_for_user(user.id)
        .await?
        .is_some()
    {
        return Err(already_pending());
    }

    // ── Durable principal binding: the acceptance outcome and the record
    // both carry the bound principal identity.
    let (_destination_name, audience) = station.account_status_destination().map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            error.to_string(),
        )
    })?;
    let binding = repo
        .principal_did()
        .get_for_user_and_audience(user, audience.as_str())
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::PRECONDITION_FAILED,
                arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
                "principal_unknown",
            )
        })?;

    // ── Acceptance outcome. This deployment grants no withdrawal window, so
    // the field is omitted (§8.1: MUST omit when not configured).
    let outcome = AccountRequestErasureOutcome {
        request_id: body.request_id.clone(),
        status: AccountRequestErasureStatus::Accepted,
        principal_id: binding.principal_id.clone(),
        recorded_at: now,
        withdrawal_window_ends_at: None,
    };
    outcome.validate()?;
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;

    // ── Durable intent record. The insert races both on request_id and on
    // the single live-intent slot per user; losing either race re-applies
    // the idempotency rules.
    let inserted = repo
        .user_erasure_request()
        .insert(NewUserErasureRequest {
            request_id: request_id.clone(),
            user_id: user.id,
            request_digest: request_digest.clone(),
            canonical_outcome: canonical_outcome.clone(),
            recorded_at: now,
            withdrawal_window_ends_at: None,
        })
        .await?;
    if !inserted {
        return match repo.user_erasure_request().lookup(&request_id).await? {
            Some(existing)
                if existing.user_id == user.id && existing.request_digest == request_digest =>
            {
                Ok(existing.canonical_outcome)
            }
            Some(_) => Err(duplicate_conflict()),
            None => Err(already_pending()),
        };
    }

    // ── Trigger the existing `erasure_pending` issuance flow (§8): sign and
    // append the issuer-ledger record, patch the local status truth source,
    // enqueue the exact durable publication, and schedule the shared §8
    // fanout jobs (session teardown + projection rewrite). All of it commits
    // with the intent in one transaction — receipt and issuance are same-side
    // by design, so no cross-service intermediate state exists.
    let plan = author_transition_plan(
        repo,
        station,
        key_store,
        owning_station_id_for(arkret_config).as_str(),
        user,
        &binding,
        AccountStatus::ErasurePending,
        Some(SELF_ERASURE_REASON_CODE.to_owned()),
        now,
        rng,
    )
    .await
    .map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            error.to_string(),
        )
    })?;
    validate_transition_plan(user, &binding, AccountStatus::ErasurePending, &plan).map_err(
        |error| {
            ArkretRouteError::coded(
                StatusCode::PRECONDITION_FAILED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                error.to_string(),
            )
        },
    )?;
    let record_id = plan
        .body
        .publication
        .record()
        .account_status_record_id
        .to_string();

    let updated_user = repo
        .user()
        .patch(
            clock,
            user.clone(),
            UserPatch {
                status: Some(AccountStatus::ErasurePending),
                ..UserPatch::default()
            },
        )
        .await?;

    enqueue_exact_publication(
        repo,
        rng,
        clock,
        &plan.destination_name,
        plan.local_account_id,
        &plan.idempotency_key,
        plan.body,
    )
    .await
    .map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            error.to_string(),
        )
    })?;

    // Shared §8 fanout: DeactivateUserJob tears down local sessions without
    // downgrading the terminal status (`principal_erase = true` also keeps it
    // from issuing a second connector command — the signed record is the only
    // erasure command); AccountProjectionRewriteJob rewrites local account
    // projections for the erasure lifecycle.
    repo.queue_job()
        .schedule_job(rng, clock, DeactivateUserJob::new(&updated_user, true))
        .await?;
    repo.queue_job()
        .schedule_job(
            rng,
            clock,
            AccountProjectionRewriteJob::new(&updated_user, true),
        )
        .await?;

    // The record is signed in this same transaction, so the intent stops
    // being "live" immediately: with a zero withdrawal window there is no
    // interval in which a second request_id could observe a live intent
    // after commit.
    repo.user_erasure_request()
        .mark_record_issued(&request_id, &record_id, now)
        .await?;

    Ok(canonical_outcome)
}

fn duplicate_conflict() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
        "request_id was already used for a different erasure request",
    )
}

fn already_pending() -> ArkretRouteError {
    ArkretRouteError::CodedDetailed {
        status: StatusCode::CONFLICT,
        code: arkret_wire::ErrorCode::FAILED_PRECONDITION,
        message: "a live erasure intent is already recorded for this account".to_owned(),
        details: vec![(
            "reason_code",
            serde_json::Value::String("erasure_request_already_pending".to_owned()),
        )],
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use coauth_data::SystemClock;
    use hyper::Request;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ulid::Ulid;

    use super::*;
    use crate::handlers::test_utils::{
        CookieHelper, RequestBuilderExt, ResponseExt, TEST_STATION_AUDIENCE, TestState, setup,
        unique_test_nonce,
    };
    use crate::salvo_utils::SessionInfoExt as _;

    fn fresh_config(state: &TestState) -> ArkretConfig {
        let mut config = state.arkret_config.clone();
        config.erasure_request_max_auth_age = Duration::try_minutes(10);
        config
    }

    fn request_body() -> AccountRequestErasureRequestBody {
        AccountRequestErasureRequestBody {
            request_id: arkret_identifiers::RequestId::new(format!(
                "ak:request:{}",
                uuid::Uuid::now_v7()
            ))
            .unwrap(),
        }
    }

    async fn seed_account(state: &TestState) -> User {
        let mut repo = state.repository().await.unwrap();
        let clock = SystemClock::default();
        let mut rng = ChaChaRng::seed_from_u64(unique_test_nonce());
        let user = repo
            .user()
            .add(
                &mut rng,
                &clock,
                format!("erase{}", Ulid::generate().to_string().to_lowercase()),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        state
            .seed_principal_binding(&user, &format!("erasure-{}", unique_test_nonce()))
            .await;
        user
    }

    /// Move the account (local status truth + issuer ledger head, kept in
    /// sync) to `status` the way an admin transition would.
    async fn force_status(state: &TestState, user: &User, status: AccountStatus) -> User {
        let mut repo = state.repository().await.unwrap();
        let clock = SystemClock::default();
        let mut rng = ChaChaRng::seed_from_u64(unique_test_nonce());
        let binding = repo
            .principal_did()
            .get_for_user_and_audience(user, TEST_STATION_AUDIENCE)
            .await
            .unwrap()
            .expect("seeded principal binding");
        author_transition_plan(
            &mut repo,
            state.station_admin.as_ref(),
            &state.key_store,
            owning_station_id_for(&state.arkret_config).as_str(),
            user,
            &binding,
            status,
            None,
            Utc::now(),
            &mut rng,
        )
        .await
        .unwrap();
        let updated = repo
            .user()
            .patch(
                &clock,
                user.clone(),
                UserPatch {
                    status: Some(status),
                    ..UserPatch::default()
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        updated
    }

    async fn call(
        state: &TestState,
        config: &ArkretConfig,
        user: &User,
        last_authenticated_at: Option<chrono::DateTime<Utc>>,
        body: &AccountRequestErasureRequestBody,
    ) -> Result<Vec<u8>, ArkretRouteError> {
        let mut repo = state.repository().await.unwrap();
        let clock = SystemClock::default();
        let mut rng = ChaChaRng::seed_from_u64(unique_test_nonce());
        let result = accept_erasure_request(
            &mut repo,
            &mut rng,
            &clock,
            config,
            &state.key_store,
            state.station_admin.as_ref(),
            user,
            last_authenticated_at,
            body,
        )
        .await;
        match &result {
            Ok(_) => repo.save().await.unwrap(),
            Err(_) => {
                repo.cancel().await.ok();
            }
        }
        result
    }

    fn assert_coded(error: &ArkretRouteError, expected_code: &str) {
        match error {
            ArkretRouteError::Coded { code, .. } => assert_eq!(*code, expected_code),
            other => panic!("expected coded {expected_code}, got {other:?}"),
        }
    }

    async fn assert_zero_writes(state: &TestState, user: &User, request_id: &str) {
        let mut repo = state.repository().await.unwrap();
        assert!(
            repo.user_erasure_request()
                .lookup(request_id)
                .await
                .unwrap()
                .is_none(),
            "refused request must not record an intent"
        );
        let reloaded = repo.user().lookup(user.id).await.unwrap().unwrap();
        assert_eq!(
            reloaded.status, user.status,
            "refused request must not change account status"
        );
        repo.cancel().await.ok();
    }

    #[tokio::test]
    async fn without_deployment_policy_every_request_is_reauthentication_required() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let user = seed_account(&state).await;

        // No `erasure_request_max_auth_age` configured: even a
        // just-authenticated session fails closed (§8.1: zero writes).
        let body = request_body();
        let error = call(&state, &state.arkret_config, &user, Some(Utc::now()), &body)
            .await
            .unwrap_err();
        assert_coded(&error, arkret_wire::ErrorCode::REAUTHENTICATION_REQUIRED);
        assert_zero_writes(&state, &user, body.request_id.as_str()).await;
    }

    #[tokio::test]
    async fn stale_or_absent_authentication_is_reauthentication_required() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let user = seed_account(&state).await;
        let config = fresh_config(&state);

        let body = request_body();
        let stale = Some(Utc::now() - Duration::try_hours(2).unwrap());
        let error = call(&state, &config, &user, stale, &body)
            .await
            .unwrap_err();
        assert_coded(&error, arkret_wire::ErrorCode::REAUTHENTICATION_REQUIRED);
        assert_zero_writes(&state, &user, body.request_id.as_str()).await;

        let error = call(&state, &config, &user, None, &body).await.unwrap_err();
        assert_coded(&error, arkret_wire::ErrorCode::REAUTHENTICATION_REQUIRED);
        assert_zero_writes(&state, &user, body.request_id.as_str()).await;
    }

    #[tokio::test]
    async fn acceptance_records_intent_issues_record_and_replays_byte_identically() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let user = seed_account(&state).await;
        let config = fresh_config(&state);

        let body = request_body();
        let first = call(&state, &config, &user, Some(Utc::now()), &body)
            .await
            .unwrap();
        let outcome: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(outcome["status"], "accepted");
        assert_eq!(outcome["request_id"], body.request_id.as_str());
        assert!(
            outcome.get("withdrawal_window_ends_at").is_none(),
            "no withdrawal window is configured, so the field MUST be omitted"
        );

        // Durable effects: local status truth, issuer-ledger record with the
        // trigger-source reason_code, and the intent marked issued.
        let mut repo = state.repository().await.unwrap();
        let reloaded = repo.user().lookup(user.id).await.unwrap().unwrap();
        assert_eq!(reloaded.status, AccountStatus::ErasurePending);
        let head = repo
            .account_status_ledger()
            .current(
                owning_station_id_for(&state.arkret_config).as_str(),
                &user.id.to_string(),
            )
            .await
            .unwrap()
            .expect("erasure_pending record is signed and appended");
        assert_eq!(head.status, AccountStatus::ErasurePending);
        assert_eq!(head.reason_code.as_deref(), Some(SELF_ERASURE_REASON_CODE));
        let intent = repo
            .user_erasure_request()
            .lookup(body.request_id.as_str())
            .await
            .unwrap()
            .expect("intent row recorded");
        assert!(
            intent.record_issued_at.is_some(),
            "zero withdrawal window: the record is signed in the accepting transaction"
        );
        assert_eq!(
            intent.account_status_record_id.as_deref(),
            Some(head.account_status_record_id.to_string().as_str())
        );
        repo.cancel().await.ok();

        // Exact replay returns the first outcome byte-for-byte, even though
        // the account is now erasure_pending (the replay check precedes the
        // entry-condition check).
        let replay = call(&state, &config, &reloaded, Some(Utc::now()), &body)
            .await
            .unwrap();
        assert_eq!(replay, first);

        // A NEW request_id on the erasure_pending account fails at the
        // authentication layer with account_erased.
        let error = call(
            &state,
            &config,
            &reloaded,
            Some(Utc::now()),
            &request_body(),
        )
        .await
        .unwrap_err();
        assert_coded(&error, arkret_wire::ErrorCode::ACCOUNT_ERASED);
    }

    #[tokio::test]
    async fn same_request_id_with_different_canonical_bytes_is_duplicate_conflict() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let user = seed_account(&state).await;
        let config = fresh_config(&state);

        // Seed an intent whose recorded canonical digest differs from what
        // the typed body would produce (same request_id, different bytes).
        let body = request_body();
        let mut repo = state.repository().await.unwrap();
        repo.user_erasure_request()
            .insert(NewUserErasureRequest {
                request_id: body.request_id.to_string(),
                user_id: user.id,
                request_digest: "sha256:different-canonical-bytes".to_owned(),
                canonical_outcome: b"{}".to_vec(),
                recorded_at: Utc::now(),
                withdrawal_window_ends_at: None,
            })
            .await
            .unwrap();
        repo.save().await.unwrap();

        let error = call(&state, &config, &user, Some(Utc::now()), &body)
            .await
            .unwrap_err();
        assert_coded(&error, arkret_wire::ErrorCode::DUPLICATE_CONFLICT);

        // Another account replaying a foreign request_id is also a conflict,
        // never a cross-account replay of the stored outcome.
        let other = seed_account(&state).await;
        let error = call(&state, &config, &other, Some(Utc::now()), &body)
            .await
            .unwrap_err();
        assert_coded(&error, arkret_wire::ErrorCode::DUPLICATE_CONFLICT);
    }

    #[tokio::test]
    async fn second_request_id_with_live_intent_is_erasure_request_already_pending() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let user = seed_account(&state).await;
        let config = fresh_config(&state);

        // Seed a live intent (record not yet signed), as a deployment with a
        // withdrawal window would hold between acceptance and issuance.
        let live = request_body();
        let mut repo = state.repository().await.unwrap();
        repo.user_erasure_request()
            .insert(NewUserErasureRequest {
                request_id: live.request_id.to_string(),
                user_id: user.id,
                request_digest: live.canonical_request_digest().unwrap().to_string(),
                canonical_outcome: b"{}".to_vec(),
                recorded_at: Utc::now(),
                withdrawal_window_ends_at: None,
            })
            .await
            .unwrap();
        repo.save().await.unwrap();

        let second = request_body();
        let error = call(&state, &config, &user, Some(Utc::now()), &second)
            .await
            .unwrap_err();
        match &error {
            ArkretRouteError::CodedDetailed { code, details, .. } => {
                assert_eq!(*code, arkret_wire::ErrorCode::FAILED_PRECONDITION);
                assert_eq!(
                    details,
                    &vec![(
                        "reason_code",
                        serde_json::Value::String("erasure_request_already_pending".to_owned()),
                    )]
                );
            }
            other => panic!("expected failed_precondition with reason_code, got {other:?}"),
        }
        assert_zero_writes(&state, &user, second.request_id.as_str()).await;
    }

    #[tokio::test]
    async fn entry_conditions_follow_the_section_8_1_matrix() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let config = fresh_config(&state);

        // suspended: admitted.
        let user = seed_account(&state).await;
        let suspended = force_status(&state, &user, AccountStatus::Suspended).await;
        let accepted = call(
            &state,
            &config,
            &suspended,
            Some(Utc::now()),
            &request_body(),
        )
        .await
        .unwrap();
        let outcome: serde_json::Value = serde_json::from_slice(&accepted).unwrap();
        assert_eq!(outcome["status"], "accepted");

        // soft_logged_out: admitted.
        let user = seed_account(&state).await;
        let soft = force_status(&state, &user, AccountStatus::SoftLoggedOut).await;
        let accepted = call(&state, &config, &soft, Some(Utc::now()), &request_body())
            .await
            .unwrap();
        let outcome: serde_json::Value = serde_json::from_slice(&accepted).unwrap();
        assert_eq!(outcome["status"], "accepted");

        // locked: refused at the authentication layer with account_locked and
        // zero writes.
        let user = seed_account(&state).await;
        let locked = force_status(&state, &user, AccountStatus::Locked).await;
        let body = request_body();
        let error = call(&state, &config, &locked, Some(Utc::now()), &body)
            .await
            .unwrap_err();
        assert_coded(&error, arkret_wire::ErrorCode::ACCOUNT_LOCKED);
        assert_zero_writes(&state, &locked, body.request_id.as_str()).await;

        // deactivated: refused with account_deactivated.
        let user = seed_account(&state).await;
        let deactivated = force_status(&state, &user, AccountStatus::Deactivated).await;
        let body = request_body();
        let error = call(&state, &config, &deactivated, Some(Utc::now()), &body)
            .await
            .unwrap_err();
        assert_coded(&error, arkret_wire::ErrorCode::ACCOUNT_DEACTIVATED);
        assert_zero_writes(&state, &deactivated, body.request_id.as_str()).await;
    }

    #[tokio::test]
    async fn http_endpoint_accepts_a_fresh_browser_session_and_replays() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        state.arkret_config.erasure_request_max_auth_age = Duration::try_minutes(10);

        let mut repo = state.repository().await.unwrap();
        let clock = SystemClock::default();
        let mut rng = ChaChaRng::seed_from_u64(unique_test_nonce());
        let user = repo
            .user()
            .add(
                &mut rng,
                &clock,
                format!("erase{}", Ulid::generate().to_string().to_lowercase()),
            )
            .await
            .unwrap();
        let password = repo
            .user_password()
            .add(&mut rng, &clock, &user, 1, "hashed".to_owned(), None)
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();
        // The freshness fact: a recent password authentication on the
        // session — exactly what the login handler records.
        repo.browser_session()
            .authenticate_with_password(&mut rng, &clock, &session, &password)
            .await
            .unwrap();
        repo.save().await.unwrap();
        state
            .seed_principal_binding(&user, &format!("erasure-http-{}", unique_test_nonce()))
            .await;

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&session));

        // Without a session the gate endpoint is unauthenticated.
        let anonymous = state
            .request(
                Request::post("/_arkret/gate/account/erasure-requests").json(serde_json::json!({
                    "request_id": format!("ak:request:{}", uuid::Uuid::now_v7()),
                })),
            )
            .await;
        anonymous.assert_status(hyper::StatusCode::UNAUTHORIZED);

        let request_id = format!("ak:request:{}", uuid::Uuid::now_v7());
        let response = state
            .request(cookies.with_cookies(
                Request::post("/_arkret/gate/account/erasure-requests").json(serde_json::json!({
                    "request_id": request_id,
                })),
            ))
            .await;
        response.assert_status(hyper::StatusCode::OK);
        let first_body = response.body().to_owned();
        let outcome: serde_json::Value = serde_json::from_str(&first_body).unwrap();
        assert_eq!(outcome["status"], "accepted");
        assert_eq!(outcome["request_id"], request_id);
        assert!(outcome.get("withdrawal_window_ends_at").is_none());

        // Exact replay over HTTP is byte-identical.
        let replay = state
            .request(cookies.with_cookies(
                Request::post("/_arkret/gate/account/erasure-requests").json(serde_json::json!({
                    "request_id": request_id,
                })),
            ))
            .await;
        replay.assert_status(hyper::StatusCode::OK);
        assert_eq!(replay.body().to_owned(), first_body);

        // A distinct request_id now fails at the authentication layer:
        // the account is erasure_pending.
        let after = state
            .request(cookies.with_cookies(
                Request::post("/_arkret/gate/account/erasure-requests").json(serde_json::json!({
                    "request_id": format!("ak:request:{}", uuid::Uuid::now_v7()),
                })),
            ))
            .await;
        after.assert_status(hyper::StatusCode::UNAUTHORIZED);
        let error: arkret_wire::problem_details::Problem = after.json();
        assert_eq!(error.code(), "account_erased");
    }
}
