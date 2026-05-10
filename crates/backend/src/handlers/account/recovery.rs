//! REST API endpoints for account recovery.
//!
//! These endpoints serve as thin HTTP adapters over the business logic in
//! [`crate::handlers::account::service::recovery`]. They parse requests,
//! delegate to service functions, and map results to JSON responses.
//!
//! The principal-server cache scaffold (snapshot + ~12 cache control endpoints)
//! lives in the [`principal_cache`] submodule and is re-exported below so the
//! [`crate::server`] router keeps using `recovery::*` paths unchanged.
pub mod model;
pub mod principal_cache;

pub use model::{
    RecoveryAuthzExamples, RecoveryBackupPayloadExample, RecoveryDescribeResponse,
    RecoveryExampleScaffold, RecoveryRestoreExamples, RecoveryStatusResponse,
    ResendRecoveryResponse, StartRecoveryInput, StartRecoveryResponse,
};
pub use principal_cache::{
    get_recovery_principal_cache_failures, get_recovery_principal_cache_policy,
    get_recovery_principal_cache_queue, get_recovery_principal_cache_status,
    get_recovery_principal_cache_upstream, get_recovery_principal_snapshot,
    post_recovery_principal_cache_complete, post_recovery_principal_cache_fail,
    post_recovery_principal_cache_invalidate, post_recovery_principal_cache_refresh,
    post_recovery_principal_cache_retry, post_recovery_principal_cache_upstream_bind,
    post_recovery_principal_cache_upstream_probe,
};

use chrono::Utc;
use coauth_data::{
    flow::{FlowSession, FlowSessionStatus},
    new_id,
};
use salvo::prelude::*;
use serde_json::Value;
use ulid::Ulid;

use super::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::handlers::{
    RequesterFingerprint,
    account::service::recovery::{
        LoadAccountRecoverySessionError, ResendAccountRecoveryError, StartAccountRecoveryError,
        load_account_recovery_session, recovery_session_status, resend_account_recovery,
        start_account_recovery,
    },
    flow::{FlowExecutor, defaults::default_recovery_flow, flow_session_store_write},
};

// ── POST /api/v1/auth/recovery/start ───────────────────────────

#[endpoint]
pub async fn post_recovery_start(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<StartRecoveryResponse>, RouteError> {
    let input: StartRecoveryInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let site_config = depot.site_config()?;
    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let url_builder = depot.url_builder()?;
    let notification_language = crate::handlers::notification_language(req, depot, None);

    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let ip_address = activity_tracker.ip();

    if !site_config.account_recovery_allowed {
        return Ok(Json(StartRecoveryResponse {
            status: "error",
            id: None,
            error: Some("recovery_disabled".into()),
            flow_session_id: None,
        }));
    }

    if site_config.captcha.is_some() {
        let http_client = depot.http_client()?;
        if let Err(error) = crate::handlers::captcha::verify_token(
            activity_tracker.ip(),
            &http_client,
            url_builder.public_hostname(),
            site_config.captcha.as_ref(),
            input.captcha_token.as_deref(),
        )
        .await
        {
            tracing::warn!(error = %error, "CAPTCHA verification failed on recovery start");
            return Ok(Json(StartRecoveryResponse {
                status: "error",
                id: None,
                error: Some("captcha_failed".into()),
                flow_session_id: None,
            }));
        }
    }

    let repo = repo_factory.create().await?;

    let session = match start_account_recovery(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester,
        input.email,
        user_agent,
        ip_address,
        notification_language,
    )
    .await
    {
        Ok(session) => session,
        Err(StartAccountRecoveryError::InvalidEmail) => {
            return Ok(Json(StartRecoveryResponse {
                status: "error",
                id: None,
                error: Some("invalid_email".into()),
                flow_session_id: None,
            }));
        }
        Err(StartAccountRecoveryError::RateLimited) => {
            return Ok(Json(StartRecoveryResponse {
                status: "error",
                id: None,
                error: Some("rate_limited".into()),
                flow_session_id: None,
            }));
        }
        Err(StartAccountRecoveryError::Repository(error)) => {
            return Err(error.into());
        }
    };

    // If the flow engine is enabled, start a flow session alongside the
    // legacy recovery session so the frontend can choose the flow-based path.
    let flow_session_id = if site_config.flow_engine_enabled {
        let mut rng = make_rng();
        let (flow_def, bindings) = default_recovery_flow(&mut *rng);
        let plan = FlowExecutor::plan(flow_def, bindings);

        let now = Utc::now();
        let flow_sid = new_id(now, &mut *rng);

        let flow_session = FlowSession {
            id: flow_sid,
            flow_id: plan.flow.id,
            current_stage_index: 0,
            status: FlowSessionStatus::InProgress,
            context: Value::Object(serde_json::Map::new()),
            ip_address: None,
            user_agent: None,
            created_at: now,
            updated_at: now,
            expires_at: now + chrono::Duration::hours(1),
            completed_at: None,
        };

        flow_session_store_write()
            .await
            .insert(flow_sid, (plan, flow_session));

        Some(flow_sid.to_string())
    } else {
        None
    };

    Ok(Json(StartRecoveryResponse {
        status: "success",
        id: Some(session.id.to_string()),
        error: None,
        flow_session_id,
    }))
}

// ── GET /api/v1/auth/recovery/:id ──────────────────────────────

#[endpoint]
pub async fn get_recovery(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RecoveryStatusResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let site_config = depot.site_config()?;
    let repo_factory = depot.repo_factory()?;

    if !site_config.account_recovery_allowed {
        return Err(RouteError::BadRequest("recovery_disabled".into()));
    }

    let mut repo = repo_factory.create().await?;

    let session = match load_account_recovery_session(&mut repo, id).await {
        Ok(session) => session,
        Err(LoadAccountRecoverySessionError::NotFound) => return Err(RouteError::NotFound),
        Err(LoadAccountRecoverySessionError::Repository(error)) => return Err(error.into()),
    };
    let status = recovery_session_status(&session);

    repo.cancel().await?;

    Ok(Json(RecoveryStatusResponse {
        id: session.id.to_string(),
        email: session.email,
        status,
    }))
}

// ── POST /api/v1/auth/recovery/:id/resend ──────────────────────

#[endpoint]
pub async fn get_recovery_describe() -> Json<RecoveryDescribeResponse> {
    Json(RecoveryDescribeResponse {
        contract: "contrix.auth.recovery_bridge.v1".to_string(),
        version: "2026-05-04".to_string(),
        recovery_start_path: "/api/v1/auth/recovery/start".to_string(),
        recovery_status_path: "/api/v1/auth/recovery/{id}".to_string(),
        recovery_resend_path: "/api/v1/auth/recovery/{id}/resend".to_string(),
        recovery_principal_snapshot_path: "/api/v1/auth/recovery/principal-snapshot".to_string(),
        recovery_principal_cache_status_path: "/api/v1/auth/recovery/principal-cache/status".to_string(),
        recovery_principal_cache_refresh_path: "/api/v1/auth/recovery/principal-cache/refresh".to_string(),
        recovery_principal_cache_queue_path: "/api/v1/auth/recovery/principal-cache/queue".to_string(),
        recovery_principal_cache_complete_path: "/api/v1/auth/recovery/principal-cache/complete".to_string(),
        recovery_principal_cache_fail_path: "/api/v1/auth/recovery/principal-cache/fail".to_string(),
        recovery_principal_cache_policy_path: "/api/v1/auth/recovery/principal-cache/policy".to_string(),
        recovery_principal_cache_retry_path: "/api/v1/auth/recovery/principal-cache/retry".to_string(),
        recovery_principal_cache_invalidate_path: "/api/v1/auth/recovery/principal-cache/invalidate".to_string(),
        recovery_principal_cache_failures_path: "/api/v1/auth/recovery/principal-cache/failures".to_string(),
        recovery_principal_cache_upstream_path: "/api/v1/auth/recovery/principal-cache/upstream".to_string(),
        recovery_principal_cache_upstream_probe_path: "/api/v1/auth/recovery/principal-cache/upstream/probe".to_string(),
        recovery_principal_cache_upstream_bind_path: "/api/v1/auth/recovery/principal-cache/upstream/bind".to_string(),
        key_backup_rest_base: "/api/v1/keys/backups".to_string(),
        key_backup_schema: "cx.schema.key_backup.v1".to_string(),
        device_message_schema: "cx.schema.device_message.v1".to_string(),
        principal_recovery_contract_stack_path: "/api/v1/recovery/contract-stack".to_string(),
        principal_recovery_stack_bundle_path: "/api/v1/recovery/stack-bundle".to_string(),
        principal_recovery_discovery_path: "/api/v1/recovery/discovery".to_string(),
        principal_recovery_readiness_path: "/api/v1/recovery/readiness".to_string(),
        principal_device_messages_describe_path: "/api/v1/device_messages/describe".to_string(),
        principal_key_backups_describe_path: "/api/v1/keys/backups/describe".to_string(),
        principal_restore_state_describe_path: "/api/v1/keys/backups/restore-state/describe".to_string(),
        principal_restore_state_export_path: "/api/v1/keys/backups/restore-state/export".to_string(),
        principal_restore_state_import_path: "/api/v1/keys/backups/restore-state/import".to_string(),
        principal_restore_state_durability_path: "/api/v1/keys/backups/restore-state/durability".to_string(),
        principal_restore_state_checkpoint_collection_path: "/api/v1/keys/backups/restore-state/checkpoints".to_string(),
        principal_restore_start_path: "/api/v1/keys/backups/{backup_id}/restore/start".to_string(),
        principal_restore_describe_path: "/api/v1/keys/backups/{backup_id}/restore/describe".to_string(),
        principal_restore_ticket_collection_path: "/api/v1/keys/backups/restore-tickets".to_string(),
        principal_restore_ticket_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}".to_string(),
        principal_restore_ticket_advance_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/advance".to_string(),
        principal_restore_ticket_resume_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/resume".to_string(),
        principal_restore_ticket_cancel_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel".to_string(),
        principal_restore_ticket_retry_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/retry".to_string(),
        principal_restore_approval_status_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status".to_string(),
        principal_restore_approval_submit_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit".to_string(),
        principal_restore_executor_status_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status".to_string(),
        principal_restore_executor_enqueue_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue".to_string(),
        principal_restore_executor_start_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start".to_string(),
        principal_restore_executor_complete_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete".to_string(),
        principal_restore_result_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/result".to_string(),
        principal_restore_receipt_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt".to_string(),
        principal_restore_materialized_device_handoff_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff".to_string(),
        principal_restore_bundle_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle".to_string(),
        principal_restore_activity_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity".to_string(),
        principal_restore_timeline_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline".to_string(),
        principal_restore_audit_feed_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed".to_string(),
        principal_recovery_live_snapshot_path: "/api/v1/recovery/live-snapshot".to_string(),
        principal_authz_describe_path: "/api/v1/authz/describe".to_string(),
        principal_authz_check_path: "/api/v1/authz/check".to_string(),
        principal_policy_describe_path: "/api/v1/policies/describe".to_string(),
        principal_policy_collection_path: "/api/v1/policies".to_string(),
        principal_policy_item_path: "/api/v1/policies/{policy_id}".to_string(),
        verification_event_kinds: vec![
            "cx.key.verification.request".to_string(),
            "cx.key.verification.ready".to_string(),
            "cx.key.verification.start".to_string(),
            "cx.key.verification.accept".to_string(),
            "cx.key.verification.key".to_string(),
            "cx.key.verification.mac".to_string(),
            "cx.key.verification.done".to_string(),
            "cx.key.verification.cancel".to_string(),
        ],
        recovery_modes: vec![
            "password_recovery".to_string(),
            "flow_session_recovery".to_string(),
            "key_backup_restore_scaffold".to_string(),
        ],
        example_backup_payload: RecoveryBackupPayloadExample::scaffold(),
        recovery_restore_examples: RecoveryRestoreExamples::scaffold(),
        recovery_authz_examples: RecoveryAuthzExamples::scaffold(),
        todos: vec![
            "TODO: bind key backup restore to durable encrypted blob storage.".to_string(),
            "TODO: bind device verification messages to signed device envelopes.".to_string(),
            "TODO: bind recovery bridge to live principal recovery contract-stack aggregation instead of only publishing path templates.".to_string(),
            "TODO: bind recovery bridge to live principal device-message and key-backup describe endpoints instead of only publishing path templates.".to_string(),
            "TODO: bind recovery bridge to live principal restore-state describe/export/import endpoints instead of only publishing path templates.".to_string(),
            "TODO: bind recovery bridge to live principal restore approval queue/status endpoints instead of only publishing path templates.".to_string(),
            "TODO: bind recovery bridge to live principal restore executor queue/status endpoints instead of only publishing path templates.".to_string(),
            "TODO: bind recovery bridge to live principal restore executor start/complete endpoints instead of only publishing path templates.".to_string(),
            "TODO: bind recovery bridge to live principal restore result/receipt/handoff endpoints instead of only publishing path templates.".to_string(),
            "TODO: add recovery proofing policy and restore approvals.".to_string(),
            "TODO: bind recovery bridge restore-start and restore-ticket examples to live principal endpoints instead of static scaffold payloads.".to_string(),
            "TODO: bind recovery bridge to live principal authz/policies describe endpoints instead of only publishing static path templates.".to_string(),
            "TODO: bind recovery bridge examples to live principal authz/policy endpoints instead of static scaffold paths.".to_string(),
            "TODO: bind recovery bridge to live principal restore-describe endpoint instead of only publishing the path template.".to_string(),
        ],
    })
}

#[endpoint]
pub async fn post_recovery_resend(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendRecoveryResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let site_config = depot.site_config()?;
    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;

    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);

    if !site_config.account_recovery_allowed {
        return Ok(Json(ResendRecoveryResponse {
            status: "error",
            error: Some("recovery_disabled".into()),
        }));
    }

    let repo = repo_factory.create().await?;

    match resend_account_recovery(repo, &limiter, &mut rng, &clock, requester, id).await {
        Ok(_) => {}
        Err(ResendAccountRecoveryError::NotFound) => return Err(RouteError::NotFound),
        Err(ResendAccountRecoveryError::AlreadyConsumed) => {
            return Ok(Json(ResendRecoveryResponse {
                status: "error",
                error: Some("recovery_already_consumed".into()),
            }));
        }
        Err(ResendAccountRecoveryError::RateLimited) => {
            return Ok(Json(ResendRecoveryResponse {
                status: "error",
                error: Some("rate_limited".into()),
            }));
        }
        Err(ResendAccountRecoveryError::Repository(error)) => return Err(error.into()),
    }

    Ok(Json(ResendRecoveryResponse {
        status: "success",
        error: None,
    }))
}
