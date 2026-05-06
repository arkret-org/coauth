//! REST API endpoints for account recovery.
//!
//! These endpoints serve as thin HTTP adapters over the business logic in
//! [`crate::handlers::account::service::recovery`]. They parse requests,
//! delegate to service functions, and map results to JSON responses.
use chrono::Utc;
use coauth_data::{
    flow::{FlowSession, FlowSessionStatus},
    new_id,
};
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{LazyLock, Mutex},
    time::Duration,
};
use ulid::Ulid;
use url::Url;

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

static PRINCIPAL_RECOVERY_CACHE: LazyLock<Mutex<Value>> = LazyLock::new(|| {
    Mutex::new(json!({
        "cache_mode": "memory_snapshot_scaffold",
        "refresh_state": "idle",
        "refresh_count": 0,
        "failure_count": 0,
        "last_refresh_at": null,
        "last_failure_at": null,
        "last_failure_code": null,
        "last_reason": null,
        "in_flight_job": null,
        "queue": [],
        "failure_log": [],
        "last_upstream_probe_at": null,
        "last_upstream_probe_result": null,
        "upstream_binding": {
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        },
        "cached_snapshot": null
    }))
});

fn recovery_cache_body_string(body: &Value, key: &str, default: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(default)
        .trim()
        .to_owned()
}

fn normalize_principal_base_url(value: &str) -> Result<String, String> {
    let mut url = Url::parse(value).map_err(|_| "invalid_principal_base_url".to_owned())?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err("unsupported_principal_base_url_scheme".to_owned()),
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

async fn probe_principal_recovery_surface(
    client: &reqwest::Client,
    principal_base_url: &str,
    path: &str,
    expected_contract: &str,
    bearer_token: Option<&str>,
) -> Value {
    let url = match Url::parse(principal_base_url).and_then(|base| base.join(path.trim_start_matches('/'))) {
        Ok(url) => url,
        Err(_) => {
            return json!({
                "path": path,
                "expected_contract": expected_contract,
                "state": "invalid_probe_url"
            });
        }
    };
    let mut request = client.get(url.clone());
    if let Some(token) = bearer_token.filter(|value| !value.trim().is_empty()) {
        request = request.bearer_auth(token);
    }
    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.json::<Value>().await.unwrap_or(Value::Null);
            let actual_contract = body.get("contract").and_then(Value::as_str).unwrap_or("");
            let state = if status == 401 || status == 403 {
                "auth_required"
            } else if status >= 400 {
                "http_error"
            } else if actual_contract == expected_contract {
                "contract_ok"
            } else {
                "contract_mismatch"
            };
            json!({
                "path": path,
                "url": url.as_str(),
                "status": status,
                "state": state,
                "expected_contract": expected_contract,
                "actual_contract": actual_contract,
                "body": body
            })
        }
        Err(error) => json!({
            "path": path,
            "url": url.as_str(),
            "state": "request_error",
            "expected_contract": expected_contract,
            "error": error.to_string()
        }),
    }
}

// ── POST /api/v1/auth/recovery/start ───────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct StartRecoveryInput {
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct StartRecoveryResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// When the flow engine is enabled, the frontend should use this ID
    /// with the flow session API (`/api/v1/flow/session/:id`) instead of
    /// the legacy recovery step endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_session_id: Option<String>,
}

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

#[derive(Serialize, ToSchema)]
pub struct RecoveryStatusResponse {
    pub id: String,
    pub email: String,
    pub status: &'static str,
}

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

#[derive(Serialize, ToSchema)]
pub struct ResendRecoveryResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryDescribeResponse {
    pub contract: &'static str,
    pub version: &'static str,
    pub recovery_start_path: &'static str,
    pub recovery_status_path: &'static str,
    pub recovery_resend_path: &'static str,
    pub recovery_principal_snapshot_path: &'static str,
    pub recovery_principal_cache_status_path: &'static str,
    pub recovery_principal_cache_refresh_path: &'static str,
    pub recovery_principal_cache_queue_path: &'static str,
    pub recovery_principal_cache_complete_path: &'static str,
    pub recovery_principal_cache_fail_path: &'static str,
    pub recovery_principal_cache_policy_path: &'static str,
    pub recovery_principal_cache_retry_path: &'static str,
    pub recovery_principal_cache_invalidate_path: &'static str,
    pub recovery_principal_cache_failures_path: &'static str,
    pub recovery_principal_cache_upstream_path: &'static str,
    pub recovery_principal_cache_upstream_probe_path: &'static str,
    pub recovery_principal_cache_upstream_bind_path: &'static str,
    pub key_backup_rest_base: &'static str,
    pub key_backup_schema: &'static str,
    pub device_message_schema: &'static str,
    pub principal_recovery_contract_stack_path: &'static str,
    pub principal_recovery_stack_bundle_path: &'static str,
    pub principal_recovery_discovery_path: &'static str,
    pub principal_recovery_readiness_path: &'static str,
    pub principal_device_messages_describe_path: &'static str,
    pub principal_key_backups_describe_path: &'static str,
    pub principal_restore_state_describe_path: &'static str,
    pub principal_restore_state_export_path: &'static str,
    pub principal_restore_state_import_path: &'static str,
    pub principal_restore_state_durability_path: &'static str,
    pub principal_restore_state_checkpoint_collection_path: &'static str,
    pub principal_restore_start_path: &'static str,
    pub principal_restore_describe_path: &'static str,
    pub principal_restore_ticket_collection_path: &'static str,
    pub principal_restore_ticket_path: &'static str,
    pub principal_restore_ticket_advance_path: &'static str,
    pub principal_restore_ticket_resume_path: &'static str,
    pub principal_restore_ticket_cancel_path: &'static str,
    pub principal_restore_ticket_retry_path: &'static str,
    pub principal_restore_approval_status_path: &'static str,
    pub principal_restore_approval_submit_path: &'static str,
    pub principal_restore_executor_status_path: &'static str,
    pub principal_restore_executor_enqueue_path: &'static str,
    pub principal_restore_executor_start_path: &'static str,
    pub principal_restore_executor_complete_path: &'static str,
    pub principal_restore_result_path: &'static str,
    pub principal_restore_receipt_path: &'static str,
    pub principal_restore_materialized_device_handoff_path: &'static str,
    pub principal_restore_bundle_path: &'static str,
    pub principal_restore_activity_path: &'static str,
    pub principal_restore_timeline_path: &'static str,
    pub principal_restore_audit_feed_path: &'static str,
    pub principal_recovery_live_snapshot_path: &'static str,
    pub principal_authz_describe_path: &'static str,
    pub principal_authz_check_path: &'static str,
    pub principal_policy_describe_path: &'static str,
    pub principal_policy_collection_path: &'static str,
    pub principal_policy_item_path: &'static str,
    pub verification_event_kinds: Vec<&'static str>,
    pub recovery_modes: Vec<&'static str>,
    pub example_backup_payload: Value,
    pub recovery_restore_examples: Value,
    pub recovery_authz_examples: Value,
    pub todos: Vec<&'static str>,
}

#[endpoint]
pub async fn get_recovery_describe() -> Json<RecoveryDescribeResponse> {
    Json(RecoveryDescribeResponse {
        contract: "contrix.auth.recovery_bridge.v1",
        version: "2026-05-04",
        recovery_start_path: "/api/v1/auth/recovery/start",
        recovery_status_path: "/api/v1/auth/recovery/{id}",
        recovery_resend_path: "/api/v1/auth/recovery/{id}/resend",
        recovery_principal_snapshot_path: "/api/v1/auth/recovery/principal-snapshot",
        recovery_principal_cache_status_path: "/api/v1/auth/recovery/principal-cache/status",
        recovery_principal_cache_refresh_path: "/api/v1/auth/recovery/principal-cache/refresh",
        recovery_principal_cache_queue_path: "/api/v1/auth/recovery/principal-cache/queue",
        recovery_principal_cache_complete_path: "/api/v1/auth/recovery/principal-cache/complete",
        recovery_principal_cache_fail_path: "/api/v1/auth/recovery/principal-cache/fail",
        recovery_principal_cache_policy_path: "/api/v1/auth/recovery/principal-cache/policy",
        recovery_principal_cache_retry_path: "/api/v1/auth/recovery/principal-cache/retry",
        recovery_principal_cache_invalidate_path: "/api/v1/auth/recovery/principal-cache/invalidate",
        recovery_principal_cache_failures_path: "/api/v1/auth/recovery/principal-cache/failures",
        recovery_principal_cache_upstream_path: "/api/v1/auth/recovery/principal-cache/upstream",
        recovery_principal_cache_upstream_probe_path: "/api/v1/auth/recovery/principal-cache/upstream/probe",
        recovery_principal_cache_upstream_bind_path: "/api/v1/auth/recovery/principal-cache/upstream/bind",
        key_backup_rest_base: "/api/v1/keys/backups",
        key_backup_schema: "cx.schema.key_backup.v1",
        device_message_schema: "cx.schema.device_message.v1",
        principal_recovery_contract_stack_path: "/api/v1/recovery/contract-stack",
        principal_recovery_stack_bundle_path: "/api/v1/recovery/stack-bundle",
        principal_recovery_discovery_path: "/api/v1/recovery/discovery",
        principal_recovery_readiness_path: "/api/v1/recovery/readiness",
        principal_device_messages_describe_path: "/api/v1/device_messages/describe",
        principal_key_backups_describe_path: "/api/v1/keys/backups/describe",
        principal_restore_state_describe_path: "/api/v1/keys/backups/restore-state/describe",
        principal_restore_state_export_path: "/api/v1/keys/backups/restore-state/export",
        principal_restore_state_import_path: "/api/v1/keys/backups/restore-state/import",
        principal_restore_state_durability_path: "/api/v1/keys/backups/restore-state/durability",
        principal_restore_state_checkpoint_collection_path: "/api/v1/keys/backups/restore-state/checkpoints",
        principal_restore_start_path: "/api/v1/keys/backups/{backup_id}/restore/start",
        principal_restore_describe_path: "/api/v1/keys/backups/{backup_id}/restore/describe",
        principal_restore_ticket_collection_path: "/api/v1/keys/backups/restore-tickets",
        principal_restore_ticket_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}",
        principal_restore_ticket_advance_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/advance",
        principal_restore_ticket_resume_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/resume",
        principal_restore_ticket_cancel_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel",
        principal_restore_ticket_retry_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/retry",
        principal_restore_approval_status_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status",
        principal_restore_approval_submit_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit",
        principal_restore_executor_status_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status",
        principal_restore_executor_enqueue_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue",
        principal_restore_executor_start_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start",
        principal_restore_executor_complete_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete",
        principal_restore_result_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/result",
        principal_restore_receipt_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt",
        principal_restore_materialized_device_handoff_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff",
        principal_restore_bundle_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle",
        principal_restore_activity_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
        principal_restore_timeline_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
        principal_restore_audit_feed_path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
        principal_recovery_live_snapshot_path: "/api/v1/recovery/live-snapshot",
        principal_authz_describe_path: "/api/v1/authz/describe",
        principal_authz_check_path: "/api/v1/authz/check",
        principal_policy_describe_path: "/api/v1/policies/describe",
        principal_policy_collection_path: "/api/v1/policies",
        principal_policy_item_path: "/api/v1/policies/{policy_id}",
        verification_event_kinds: vec![
            "cx.key.verification.request",
            "cx.key.verification.ready",
            "cx.key.verification.start",
            "cx.key.verification.accept",
            "cx.key.verification.key",
            "cx.key.verification.mac",
            "cx.key.verification.done",
            "cx.key.verification.cancel",
        ],
        recovery_modes: vec![
            "password_recovery",
            "flow_session_recovery",
            "key_backup_restore_scaffold",
        ],
        example_backup_payload: serde_json::json!({
            "schema": "cx.schema.key_backup.v1",
            "backup_id": "backup-scaffold-current-device",
            "class": "mls_export",
            "encryption": {
                "alg": "xchacha20poly1305",
                "kdf": "argon2id"
            },
            "items": [
                {
                    "kind": "mls_group_state",
                    "ref": "group:default",
                    "todo": "replace scaffold payload with encrypted export blob"
                }
            ]
        }),
        recovery_restore_examples: serde_json::json!({
            "restore_start_request": {
                "backup_id": "backup-scaffold-current-device",
                "actor": "did:web:alice.example",
                "device_id": "device-web",
                "verification_event_kind": "cx.key.verification.done",
                "todo": "replace scaffold restore start with verified restore ticket handoff"
            },
            "restore_ticket_response_shape": {
                "contract": "contrix.rest.key_backup_restore_ticket.v1",
                "lifecycle_state": "authz_pending",
                "allowed_next_transitions": [
                    "authz_checked",
                    "policy_checked",
                    "approved",
                    "materialized"
                ]
            },
            "restore_ticket_advance_request": {
                "transition": "authz_checked",
                "note": "replace scaffold transition with policy-backed approval state machine"
            }
        }),
        recovery_authz_examples: serde_json::json!({
            "authz_check_request": {
                "actor": "did:web:alice.example",
                "action": "keys.backups.restore",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "resources": [
                    {
                        "kind": "blob",
                        "space_id": "cx:space:01JS0SP000000000000000000",
                        "blob_ref": "cx:blob:sha256:0123456789abcdef",
                        "object_type": "encrypted_backup",
                        "object_ref": "backup-scaffold-current-device",
                        "scope": "exact"
                    }
                ],
                "constraints": [
                    {
                        "constraint_type": "claim_based",
                        "effect": "allow",
                        "object_type_allow": ["key_backup"],
                        "facet_allow": ["recovery"],
                        "requires_claims": [
                            {
                                "claim_type": "recovery_operator",
                                "issuer": "did:web:coauth.example",
                                "organization": "example-org",
                                "status": "active",
                                "roles": ["backup_admin"]
                            }
                        ]
                    }
                ]
            },
            "policy_upsert_request": {
                "scope": "space",
                "subject_ref": "did:web:alice.example",
                "policy_type": "keys.backups.restore",
                "effect": "require_review",
                "payload": {
                    "actions": ["keys.backups.restore"],
                    "resource": {
                        "kind": "blob",
                        "space_id": "cx:space:01JS0SP000000000000000000",
                        "blob_ref": "cx:blob:sha256:0123456789abcdef",
                        "object_type": "encrypted_backup",
                        "object_ref": "backup-scaffold-current-device"
                    },
                    "constraints": [
                        {
                            "constraint_type": "approval_workflow",
                            "effect": "require_review",
                            "approval_required": true,
                            "approval_mode": "two_man_rule",
                            "approval_actor_refs": [
                                "did:web:controller.example",
                                "did:web:guardian.example"
                            ],
                            "approval_relation": "controller"
                        }
                    ]
                }
            }
        }),
        todos: vec![
            "TODO: bind key backup restore to durable encrypted blob storage.",
            "TODO: bind device verification messages to signed device envelopes.",
            "TODO: bind recovery bridge to live principal recovery contract-stack aggregation instead of only publishing path templates.",
            "TODO: bind recovery bridge to live principal device-message and key-backup describe endpoints instead of only publishing path templates.",
            "TODO: bind recovery bridge to live principal restore-state describe/export/import endpoints instead of only publishing path templates.",
            "TODO: bind recovery bridge to live principal restore approval queue/status endpoints instead of only publishing path templates.",
            "TODO: bind recovery bridge to live principal restore executor queue/status endpoints instead of only publishing path templates.",
            "TODO: bind recovery bridge to live principal restore executor start/complete endpoints instead of only publishing path templates.",
            "TODO: bind recovery bridge to live principal restore result/receipt/handoff endpoints instead of only publishing path templates.",
            "TODO: add recovery proofing policy and restore approvals.",
            "TODO: bind recovery bridge restore-start and restore-ticket examples to live principal endpoints instead of static scaffold payloads.",
            "TODO: bind recovery bridge to live principal authz/policies describe endpoints instead of only publishing static path templates.",
            "TODO: bind recovery bridge examples to live principal authz/policy endpoints instead of static scaffold paths.",
            "TODO: bind recovery bridge to live principal restore-describe endpoint instead of only publishing the path template.",
        ],
    })
}

#[endpoint]
pub async fn get_recovery_principal_snapshot() -> Json<Value> {
    let cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock")
        .clone();
    Json(json!({
        "contract": "contrix.auth.recovery_principal_snapshot.v1",
        "version": "2026-05-04-scaffold",
        "recovery_describe_path": "/api/v1/auth/recovery/describe",
        "principal_cache_status_path": "/api/v1/auth/recovery/principal-cache/status",
        "principal_cache_refresh_path": "/api/v1/auth/recovery/principal-cache/refresh",
        "principal_cache_queue_path": "/api/v1/auth/recovery/principal-cache/queue",
        "principal_cache_complete_path": "/api/v1/auth/recovery/principal-cache/complete",
        "principal_cache_fail_path": "/api/v1/auth/recovery/principal-cache/fail",
        "principal_cache_policy_path": "/api/v1/auth/recovery/principal-cache/policy",
        "principal_cache_retry_path": "/api/v1/auth/recovery/principal-cache/retry",
        "principal_cache_invalidate_path": "/api/v1/auth/recovery/principal-cache/invalidate",
        "principal_cache_failures_path": "/api/v1/auth/recovery/principal-cache/failures",
        "principal_cache_upstream_path": "/api/v1/auth/recovery/principal-cache/upstream",
        "principal_cache_upstream_probe_path": "/api/v1/auth/recovery/principal-cache/upstream/probe",
        "principal_cache_upstream_bind_path": "/api/v1/auth/recovery/principal-cache/upstream/bind",
        "principal_recovery_contract_stack_path": "/api/v1/recovery/contract-stack",
        "principal_recovery_stack_bundle_path": "/api/v1/recovery/stack-bundle",
        "principal_recovery_discovery_path": "/api/v1/recovery/discovery",
        "principal_recovery_readiness_path": "/api/v1/recovery/readiness",
        "principal_recovery_live_snapshot_path": "/api/v1/recovery/live-snapshot",
        "principal_restore_state_durability_path": "/api/v1/keys/backups/restore-state/durability",
        "principal_restore_state_checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints",
        "principal_restore_ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
        "principal_restore_bundle_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle",
        "principal_restore_activity_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
        "principal_restore_timeline_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
        "principal_restore_audit_feed_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
        "cache_state": cache,
        "principal_snapshot": {
            "contract": "contrix.rest.recovery_live_snapshot.v1",
            "path": "/api/v1/recovery/live-snapshot",
            "fetch_mode": "coauth_memory_cache_scaffold",
            "cache_hit": cache.get("cached_snapshot").is_some_and(|v| !v.is_null()),
            "todo": "TODO(coauth.recovery): replace memory cache scaffold with live principal fetch, freshness policy, and tenant-aware invalidation."
        },
        "principal_contract_stack": {
            "contract": "contrix.rest.recovery_contract_stack.v1",
            "path": "/api/v1/recovery/contract-stack",
            "fetch_mode": "coauth_memory_cache_scaffold",
            "todo": "TODO(coauth.recovery): fetch and freeze the live principal recovery contract stack instead of repeating static bridge values."
        },
        "principal_stack_bundle": {
            "contract": "contrix.rest.recovery_stack_bundle.v1",
            "path": "/api/v1/recovery/stack-bundle",
            "fetch_mode": "coauth_memory_cache_scaffold",
            "todo": "TODO(coauth.recovery): fetch the live principal recovery stack bundle instead of reconstructing it from static bridge fields."
        },
        "todos": [
            "TODO(coauth.recovery): replace principal snapshot scaffold with live HTTP fetch, cache freshness, and audience binding.",
            "TODO(coauth.recovery): add failure taxonomy and degraded-mode semantics for principal snapshot aggregation."
        ]
    }))
}

#[endpoint]
pub async fn get_recovery_principal_cache_status() -> Json<Value> {
    let cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock")
        .clone();
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_status.v1",
        "version": "2026-05-04-scaffold",
        "cache_mode": cache.get("cache_mode").cloned().unwrap_or_else(|| json!("memory_snapshot_scaffold")),
        "fetch_mode": "manual_refresh_memory_scaffold",
        "snapshot_path": "/api/v1/auth/recovery/principal-snapshot",
        "refresh_path": "/api/v1/auth/recovery/principal-cache/refresh",
        "queue_path": "/api/v1/auth/recovery/principal-cache/queue",
        "complete_path": "/api/v1/auth/recovery/principal-cache/complete",
        "fail_path": "/api/v1/auth/recovery/principal-cache/fail",
        "policy_path": "/api/v1/auth/recovery/principal-cache/policy",
        "retry_path": "/api/v1/auth/recovery/principal-cache/retry",
        "invalidate_path": "/api/v1/auth/recovery/principal-cache/invalidate",
        "failures_path": "/api/v1/auth/recovery/principal-cache/failures",
        "upstream_path": "/api/v1/auth/recovery/principal-cache/upstream",
        "upstream_probe_path": "/api/v1/auth/recovery/principal-cache/upstream/probe",
        "upstream_bind_path": "/api/v1/auth/recovery/principal-cache/upstream/bind",
        "upstream_live_snapshot_path": "/api/v1/recovery/live-snapshot",
        "upstream_contract_stack_path": "/api/v1/recovery/contract-stack",
        "upstream_binding": cache.get("upstream_binding").cloned().unwrap_or_else(|| json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })),
        "last_upstream_probe_at": cache.get("last_upstream_probe_at").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": cache.get("last_upstream_probe_result").cloned().unwrap_or(Value::Null),
        "last_refresh_at": cache.get("last_refresh_at").cloned().unwrap_or(Value::Null),
        "refresh_state": cache.get("refresh_state").cloned().unwrap_or_else(|| json!("idle")),
        "refresh_count": cache.get("refresh_count").cloned().unwrap_or_else(|| json!(0)),
        "failure_count": cache.get("failure_count").cloned().unwrap_or_else(|| json!(0)),
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "last_invalidated_at": cache.get("last_invalidated_at").cloned().unwrap_or(Value::Null),
        "last_reason": cache.get("last_reason").cloned().unwrap_or(Value::Null),
        "queue_depth": cache.get("queue").and_then(Value::as_array).map(|v| v.len()).unwrap_or(0),
        "in_flight_job": cache.get("in_flight_job").cloned().unwrap_or(Value::Null),
        "has_cached_snapshot": cache.get("cached_snapshot").is_some_and(|v| !v.is_null()),
        "failure_log_depth": cache.get("failure_log").and_then(Value::as_array).map(|v| v.len()).unwrap_or(0),
        "freshness_policy": {
            "max_stale_seconds": 300,
            "degraded_mode": "serve_last_ready_snapshot",
            "invalidate_on_audience_change": true,
            "todo": "TODO(coauth.recovery): bind freshness to principal DID, tenant, audience, and upstream ETag/version."
        },
        "failure_codes": [
            "upstream_unreachable",
            "invalid_discovery_binding",
            "cache_write_failed",
            "stale_snapshot",
            "audience_binding_changed",
            "manual_invalidation"
        ],
        "todos": [
            "TODO(coauth.recovery): replace cache status scaffold with real principal fetch/cache metadata and freshness timestamps.",
            "TODO(coauth.recovery): bind refresh state to audience, tenant, and principal-server identity.",
            "TODO(coauth.recovery): replace policy/retry/invalidate scaffold with durable cache control records."
        ]
    }))
}

#[endpoint]
pub async fn get_recovery_principal_cache_policy() -> Json<Value> {
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_policy.v1",
        "version": "2026-05-04",
        "status_path": "/api/v1/auth/recovery/principal-cache/status",
        "refresh_path": "/api/v1/auth/recovery/principal-cache/refresh",
        "retry_path": "/api/v1/auth/recovery/principal-cache/retry",
        "invalidate_path": "/api/v1/auth/recovery/principal-cache/invalidate",
        "failures_path": "/api/v1/auth/recovery/principal-cache/failures",
        "upstream_path": "/api/v1/auth/recovery/principal-cache/upstream",
        "upstream_probe_path": "/api/v1/auth/recovery/principal-cache/upstream/probe",
        "upstream_bind_path": "/api/v1/auth/recovery/principal-cache/upstream/bind",
        "freshness": {
            "max_stale_seconds": 300,
            "serve_stale_while_refreshing": true,
            "serve_stale_on_failure": true,
            "invalidate_on_principal_did_change": true,
            "invalidate_on_audience_change": true
        },
        "retry": {
            "strategy": "bounded_exponential",
            "initial_delay_ms": 500,
            "max_delay_ms": 30000,
            "max_attempts": 5,
            "jitter": "full"
        },
        "state_store": {
            "kind": "process_memory",
            "scope": "coauth_process",
            "durable": false
        },
        "failure_taxonomy": [
            "upstream_unreachable",
            "invalid_discovery_binding",
            "cache_write_failed",
            "stale_snapshot",
            "audience_binding_changed",
            "manual_invalidation"
        ],
        "remaining_gaps": [
            "tenant_overrides",
            "principal_server_etag_binding",
            "durable_retry_budget_accounting"
        ]
    }))
}

#[endpoint]
pub async fn get_recovery_principal_cache_upstream() -> Json<Value> {
    let cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock")
        .clone();
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_upstream.v1",
        "version": "2026-05-04-scaffold",
        "binding": cache.get("upstream_binding").cloned().unwrap_or_else(|| json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })),
        "last_probe_at": cache.get("last_upstream_probe_at").cloned().unwrap_or(Value::Null),
        "last_probe_result": cache.get("last_upstream_probe_result").cloned().unwrap_or(Value::Null),
        "probe_path": "/api/v1/auth/recovery/principal-cache/upstream/probe",
        "bind_path": "/api/v1/auth/recovery/principal-cache/upstream/bind",
        "expected_principal_paths": {
            "contract_stack": "/api/v1/recovery/contract-stack",
            "stack_bundle": "/api/v1/recovery/stack-bundle",
            "discovery": "/api/v1/recovery/discovery",
            "readiness": "/api/v1/recovery/readiness",
            "live_snapshot": "/api/v1/recovery/live-snapshot",
            "restore_state_durability": "/api/v1/keys/backups/restore-state/durability",
            "restore_state_checkpoints": "/api/v1/keys/backups/restore-state/checkpoints",
            "restore_tickets": "/api/v1/keys/backups/restore-tickets"
        },
        "implemented_controls": [
            "live_http_probe",
            "operator_bind",
            "probe_result_cache",
            "cache_invalidation_on_bind"
        ],
        "remaining_gaps": [
            "service_did_verification",
            "tenant_tls_policy",
            "durable_binding_store"
        ]
    }))
}

#[endpoint]
pub async fn post_recovery_principal_cache_upstream_probe(req: &mut Request) -> Json<Value> {
    let body: Value = req.parse_json().await.unwrap_or(Value::Null);
    let probed_at = Utc::now().to_rfc3339();
    let principal_base_url_input =
        recovery_cache_body_string(&body, "principal_base_url", "http://127.0.0.1:8080");
    let principal_base_url = match normalize_principal_base_url(&principal_base_url_input) {
        Ok(value) => value,
        Err(error_code) => {
            return Json(json!({
                "contract": "contrix.auth.recovery_principal_cache_upstream_probe.v1",
                "version": "2026-05-04",
                "principal_base_url": principal_base_url_input,
                "probe_state": "invalid_principal_base_url",
                "failure_code": error_code,
                "probed_at": probed_at
            }));
        }
    };
    let bearer_token = body
        .get("bearer_token")
        .or_else(|| body.get("access_token"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let probes = vec![
        probe_principal_recovery_surface(
            &client,
            &principal_base_url,
            "/api/v1/recovery/discovery",
            "contrix.rest.recovery_discovery.v1",
            bearer_token.as_deref(),
        )
        .await,
        probe_principal_recovery_surface(
            &client,
            &principal_base_url,
            "/api/v1/recovery/readiness",
            "contrix.rest.recovery_readiness.v1",
            bearer_token.as_deref(),
        )
        .await,
        probe_principal_recovery_surface(
            &client,
            &principal_base_url,
            "/api/v1/recovery/stack-bundle",
            "contrix.rest.recovery_stack_bundle.v1",
            bearer_token.as_deref(),
        )
        .await,
        probe_principal_recovery_surface(
            &client,
            &principal_base_url,
            "/api/v1/recovery/live-snapshot",
            "contrix.rest.recovery_live_snapshot.v1",
            bearer_token.as_deref(),
        )
        .await,
    ];
    let contract_ok_count = probes
        .iter()
        .filter(|probe| probe.get("state").and_then(Value::as_str) == Some("contract_ok"))
        .count();
    let auth_required_count = probes
        .iter()
        .filter(|probe| probe.get("state").and_then(Value::as_str) == Some("auth_required"))
        .count();
    let probe_state = if contract_ok_count == probes.len() {
        "contract_ok"
    } else if contract_ok_count > 0 {
        "partial_contract_ok"
    } else if auth_required_count == probes.len() {
        "auth_required"
    } else {
        "probe_failed"
    };
    let probe_result = json!({
        "principal_base_url": principal_base_url,
        "probe_state": probe_state,
        "contract_ok_count": contract_ok_count,
        "auth_required_count": auth_required_count,
        "probed_at": probed_at,
        "probes": probes
    });
    let mut cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock");
    let upstream_binding = json!({
        "principal_base_url": principal_base_url,
        "binding_state": "probe_ok",
        "probe_state": probe_state,
        "contract_ok_count": contract_ok_count,
        "auth_required_count": auth_required_count,
        "discovery_mode": "live_http_probe"
    });
    *cache = json!({
        "cache_mode": "memory_snapshot_scaffold",
        "refresh_state": cache.get("refresh_state").cloned().unwrap_or_else(|| json!("idle")),
        "refresh_count": cache.get("refresh_count").and_then(Value::as_u64).unwrap_or(0),
        "failure_count": cache.get("failure_count").and_then(Value::as_u64).unwrap_or(0),
        "last_refresh_at": cache.get("last_refresh_at").cloned().unwrap_or(Value::Null),
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "last_reason": cache.get("last_reason").cloned().unwrap_or(Value::Null),
        "in_flight_job": cache.get("in_flight_job").cloned().unwrap_or(Value::Null),
        "queue": cache.get("queue").cloned().unwrap_or_else(|| json!([])),
        "failure_log": cache.get("failure_log").cloned().unwrap_or_else(|| json!([])),
        "last_upstream_probe_at": probe_result.get("probed_at").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": probe_result.clone(),
        "upstream_binding": upstream_binding,
        "cached_snapshot": cache.get("cached_snapshot").cloned().unwrap_or(Value::Null)
    });
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_upstream_probe.v1",
        "version": "2026-05-04",
        "principal_base_url": probe_result["principal_base_url"].clone(),
        "probe_state": probe_state,
        "contract_ok_count": contract_ok_count,
        "auth_required_count": auth_required_count,
        "probed_at": probe_result["probed_at"].clone(),
        "probes": probe_result["probes"].clone(),
        "discovered_paths": {
            "contract_stack": "/api/v1/recovery/contract-stack",
            "stack_bundle": "/api/v1/recovery/stack-bundle",
            "discovery": "/api/v1/recovery/discovery",
            "readiness": "/api/v1/recovery/readiness",
            "live_snapshot": "/api/v1/recovery/live-snapshot",
            "restore_tickets": "/api/v1/keys/backups/restore-tickets"
        },
        "bind_path": "/api/v1/auth/recovery/principal-cache/upstream/bind",
        "remaining_gaps": [
            "service_did_verification",
            "durable_probe_history"
        ]
    }))
}

#[endpoint]
pub async fn post_recovery_principal_cache_upstream_bind(req: &mut Request) -> Json<Value> {
    let body: Value = req.parse_json().await.unwrap_or(Value::Null);
    let bound_at = Utc::now().to_rfc3339();
    let principal_base_url_input =
        recovery_cache_body_string(&body, "principal_base_url", "http://127.0.0.1:8080");
    let principal_base_url = match normalize_principal_base_url(&principal_base_url_input) {
        Ok(value) => value,
        Err(error_code) => {
            return Json(json!({
                "contract": "contrix.auth.recovery_principal_cache_upstream_bind.v1",
                "version": "2026-05-04",
                "principal_base_url": principal_base_url_input,
                "binding_state": "invalid_principal_base_url",
                "failure_code": error_code,
                "bound_at": bound_at
            }));
        }
    };
    let audience = recovery_cache_body_string(&body, "audience", "contrix-principal");
    let mut cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock");
    let last_probe_result = cache.get("last_upstream_probe_result").cloned().unwrap_or(Value::Null);
    let binding_state = if last_probe_result
        .get("principal_base_url")
        .and_then(Value::as_str)
        == Some(principal_base_url.as_str())
        && last_probe_result
            .get("probe_state")
            .and_then(Value::as_str)
            .is_some_and(|state| state == "contract_ok" || state == "partial_contract_ok" || state == "auth_required")
    {
        "bound_after_probe"
    } else {
        "bound_without_current_probe"
    };
    *cache = json!({
        "cache_mode": "memory_snapshot_scaffold",
        "refresh_state": "upstream_bound",
        "refresh_count": cache.get("refresh_count").and_then(Value::as_u64).unwrap_or(0),
        "failure_count": cache.get("failure_count").and_then(Value::as_u64).unwrap_or(0),
        "last_refresh_at": cache.get("last_refresh_at").cloned().unwrap_or(Value::Null),
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "last_reason": body.get("reason").cloned().unwrap_or_else(|| json!("operator_upstream_bind")),
        "in_flight_job": Value::Null,
        "queue": [],
        "failure_log": cache.get("failure_log").cloned().unwrap_or_else(|| json!([])),
        "last_upstream_probe_at": cache.get("last_upstream_probe_at").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": last_probe_result,
        "upstream_binding": {
            "principal_base_url": principal_base_url,
            "audience": audience,
            "binding_state": binding_state,
            "bound_at": bound_at,
            "discovery_mode": "live_probe_or_operator_bind"
        },
        "cached_snapshot": Value::Null
    });
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_upstream_bind.v1",
        "version": "2026-05-04",
        "principal_base_url": cache["upstream_binding"]["principal_base_url"].clone(),
        "audience": cache["upstream_binding"]["audience"].clone(),
        "binding_state": binding_state,
        "bound_at": bound_at,
        "status_path": "/api/v1/auth/recovery/principal-cache/status",
        "refresh_path": "/api/v1/auth/recovery/principal-cache/refresh",
        "upstream_path": "/api/v1/auth/recovery/principal-cache/upstream",
        "remaining_gaps": [
            "durable_tenant_config",
            "principal_service_did_proof"
        ]
    }))
}

#[endpoint]
pub async fn post_recovery_principal_cache_refresh(req: &mut Request) -> Json<Value> {
    let body: Value = req.parse_json().await.unwrap_or(Value::Null);
    let refresh_mode = body
        .get("refresh_mode")
        .cloned()
        .unwrap_or_else(|| json!("manual_scaffold"));
    let reason = body
        .get("reason")
        .cloned()
        .unwrap_or_else(|| json!("operator_requested"));
    let job_id = format!("recovery-cache-job-{}", Ulid::new());
    let refreshed_at = Utc::now().to_rfc3339();
    let mut cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock");
    let mut queue = cache
        .get("queue")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let job = json!({
        "job_id": job_id,
        "refresh_mode": refresh_mode.clone(),
        "reason": reason.clone(),
        "queued_at": refreshed_at,
        "policy_path": "/api/v1/auth/recovery/principal-cache/policy"
    });
    queue.push(job.clone());
    let in_flight_job = job.clone();
    *cache = json!({
        "cache_mode": "memory_snapshot_scaffold",
        "refresh_state": "in_flight",
        "refresh_count": cache.get("refresh_count").and_then(Value::as_u64).unwrap_or(0),
        "failure_count": cache.get("failure_count").and_then(Value::as_u64).unwrap_or(0),
        "last_refresh_at": cache.get("last_refresh_at").cloned().unwrap_or(Value::Null),
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "last_reason": reason.clone(),
        "in_flight_job": in_flight_job,
        "queue": queue,
        "failure_log": cache.get("failure_log").cloned().unwrap_or_else(|| json!([])),
        "last_upstream_probe_at": cache.get("last_upstream_probe_at").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": cache.get("last_upstream_probe_result").cloned().unwrap_or(Value::Null),
        "upstream_binding": cache.get("upstream_binding").cloned().unwrap_or_else(|| json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })),
        "cached_snapshot": {
            "contract": "contrix.auth.recovery_principal_snapshot_cache_entry.v1",
            "snapshot_contract": "contrix.rest.recovery_live_snapshot.v1",
            "snapshot_path": "/api/v1/recovery/live-snapshot",
            "contract_stack_path": "/api/v1/recovery/contract-stack",
            "ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
            "refresh_mode": refresh_mode.clone(),
            "refreshed_at": refreshed_at
        }
    });
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_refresh.v1",
        "version": "2026-05-04-scaffold",
        "refresh_state": "in_flight",
        "job_id": job_id,
        "refresh_mode": refresh_mode,
        "reason": reason,
        "queue_depth": cache.get("queue").and_then(Value::as_array).map(|v| v.len()).unwrap_or(0),
        "queued_at": refreshed_at,
        "status_path": "/api/v1/auth/recovery/principal-cache/status",
        "snapshot_path": "/api/v1/auth/recovery/principal-snapshot",
        "queue_path": "/api/v1/auth/recovery/principal-cache/queue",
        "complete_path": "/api/v1/auth/recovery/principal-cache/complete",
        "fail_path": "/api/v1/auth/recovery/principal-cache/fail",
        "policy_path": "/api/v1/auth/recovery/principal-cache/policy",
        "retry_path": "/api/v1/auth/recovery/principal-cache/retry",
        "invalidate_path": "/api/v1/auth/recovery/principal-cache/invalidate",
        "todo": "TODO(coauth.recovery): replace refresh scaffold with live principal fetch, cache population, and failure taxonomy."
    }))
}

#[endpoint]
pub async fn post_recovery_principal_cache_retry(req: &mut Request) -> Json<Value> {
    let body: Value = req.parse_json().await.unwrap_or(Value::Null);
    let retry_at = Utc::now().to_rfc3339();
    let retry_mode = body
        .get("retry_mode")
        .cloned()
        .unwrap_or_else(|| json!("manual_retry_scaffold"));
    let reason = body
        .get("reason")
        .cloned()
        .unwrap_or_else(|| json!("operator_retry_requested"));
    let retry_after_ms = body
        .get("retry_after_ms")
        .cloned()
        .unwrap_or_else(|| json!(500));
    let job_id = format!("recovery-cache-retry-{}", Ulid::new());
    let mut cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock");
    let mut queue = cache
        .get("queue")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let job = json!({
        "job_id": job_id,
        "refresh_mode": retry_mode.clone(),
        "reason": reason.clone(),
        "retry_after_ms": retry_after_ms.clone(),
        "queued_at": retry_at,
        "source_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null)
    });
    queue.push(job.clone());
    let queue_depth = queue.len();
    let cached_snapshot = cache.get("cached_snapshot").cloned().unwrap_or(Value::Null);
    *cache = json!({
        "cache_mode": "memory_snapshot_scaffold",
        "refresh_state": "retry_queued",
        "refresh_count": cache.get("refresh_count").and_then(Value::as_u64).unwrap_or(0),
        "failure_count": cache.get("failure_count").and_then(Value::as_u64).unwrap_or(0),
        "last_refresh_at": cache.get("last_refresh_at").cloned().unwrap_or(Value::Null),
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "last_reason": reason.clone(),
        "in_flight_job": job.clone(),
        "queue": queue,
        "failure_log": cache.get("failure_log").cloned().unwrap_or_else(|| json!([])),
        "last_upstream_probe_at": cache.get("last_upstream_probe_at").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": cache.get("last_upstream_probe_result").cloned().unwrap_or(Value::Null),
        "upstream_binding": cache.get("upstream_binding").cloned().unwrap_or_else(|| json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })),
        "cached_snapshot": cached_snapshot
    });
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_retry.v1",
        "version": "2026-05-04-scaffold",
        "refresh_state": "retry_queued",
        "job_id": job_id,
        "retry_mode": retry_mode,
        "retry_after_ms": retry_after_ms,
        "queue_depth": queue_depth,
        "queued_at": retry_at,
        "status_path": "/api/v1/auth/recovery/principal-cache/status",
        "queue_path": "/api/v1/auth/recovery/principal-cache/queue",
        "policy_path": "/api/v1/auth/recovery/principal-cache/policy",
        "failures_path": "/api/v1/auth/recovery/principal-cache/failures",
        "todo": "TODO(coauth.recovery): replace retry scaffold with durable retry budget, worker lease handoff, and exponential backoff enforcement."
    }))
}

#[endpoint]
pub async fn post_recovery_principal_cache_invalidate(req: &mut Request) -> Json<Value> {
    let body: Value = req.parse_json().await.unwrap_or(Value::Null);
    let invalidated_at = Utc::now().to_rfc3339();
    let reason = body
        .get("reason")
        .cloned()
        .unwrap_or_else(|| json!("manual_invalidation"));
    let mut cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock");
    *cache = json!({
        "cache_mode": "memory_snapshot_scaffold",
        "refresh_state": "invalidated",
        "refresh_count": cache.get("refresh_count").and_then(Value::as_u64).unwrap_or(0),
        "failure_count": cache.get("failure_count").and_then(Value::as_u64).unwrap_or(0),
        "last_refresh_at": cache.get("last_refresh_at").cloned().unwrap_or(Value::Null),
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "last_invalidated_at": invalidated_at,
        "last_reason": reason.clone(),
        "in_flight_job": Value::Null,
        "queue": [],
        "failure_log": cache.get("failure_log").cloned().unwrap_or_else(|| json!([])),
        "last_upstream_probe_at": cache.get("last_upstream_probe_at").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": cache.get("last_upstream_probe_result").cloned().unwrap_or(Value::Null),
        "upstream_binding": cache.get("upstream_binding").cloned().unwrap_or_else(|| json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })),
        "cached_snapshot": Value::Null
    });
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_invalidate.v1",
        "version": "2026-05-04-scaffold",
        "refresh_state": "invalidated",
        "reason": reason,
        "invalidated_at": invalidated_at,
        "status_path": "/api/v1/auth/recovery/principal-cache/status",
        "refresh_path": "/api/v1/auth/recovery/principal-cache/refresh",
        "policy_path": "/api/v1/auth/recovery/principal-cache/policy",
        "todo": "TODO(coauth.recovery): replace invalidate scaffold with audience-bound cache tombstones and stale-read prevention."
    }))
}

#[endpoint]
pub async fn get_recovery_principal_cache_queue() -> Json<Value> {
    let cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock")
        .clone();
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_queue.v1",
        "version": "2026-05-04-scaffold",
        "queue_depth": cache.get("queue").and_then(Value::as_array).map(|v| v.len()).unwrap_or(0),
        "in_flight_job": cache.get("in_flight_job").cloned().unwrap_or(Value::Null),
        "jobs": cache.get("queue").cloned().unwrap_or_else(|| json!([])),
        "retry_path": "/api/v1/auth/recovery/principal-cache/retry",
        "complete_path": "/api/v1/auth/recovery/principal-cache/complete",
        "fail_path": "/api/v1/auth/recovery/principal-cache/fail",
        "todo": "TODO(coauth.recovery): replace queue scaffold with durable refresh jobs, worker leases, and retry/backoff policy."
    }))
}

#[endpoint]
pub async fn post_recovery_principal_cache_complete(req: &mut Request) -> Json<Value> {
    let body: Value = req.parse_json().await.unwrap_or(Value::Null);
    let completed_at = Utc::now().to_rfc3339();
    let mut cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock");
    let job_id = body.get("job_id").cloned().unwrap_or_else(|| json!("unknown"));
    let refresh_count = cache
        .get("refresh_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    *cache = json!({
        "cache_mode": "memory_snapshot_scaffold",
        "refresh_state": "ready",
        "refresh_count": refresh_count,
        "failure_count": cache.get("failure_count").and_then(Value::as_u64).unwrap_or(0),
        "last_refresh_at": completed_at,
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "last_reason": body.get("reason").cloned().unwrap_or_else(|| json!("manual_complete")),
        "in_flight_job": Value::Null,
        "queue": [],
        "failure_log": cache.get("failure_log").cloned().unwrap_or_else(|| json!([])),
        "last_upstream_probe_at": cache.get("last_upstream_probe_at").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": cache.get("last_upstream_probe_result").cloned().unwrap_or(Value::Null),
        "upstream_binding": cache.get("upstream_binding").cloned().unwrap_or_else(|| json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })),
        "cached_snapshot": {
            "contract": "contrix.auth.recovery_principal_snapshot_cache_entry.v1",
            "snapshot_contract": "contrix.rest.recovery_live_snapshot.v1",
            "snapshot_path": "/api/v1/recovery/live-snapshot",
            "contract_stack_path": "/api/v1/recovery/contract-stack",
            "ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
            "refresh_mode": body.get("refresh_mode").cloned().unwrap_or_else(|| json!("manual_scaffold")),
            "refreshed_at": completed_at
        }
    });
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_complete.v1",
        "version": "2026-05-04-scaffold",
        "refresh_state": "ready",
        "job_id": job_id,
        "refresh_count": refresh_count,
        "completed_at": completed_at,
        "status_path": "/api/v1/auth/recovery/principal-cache/status",
        "snapshot_path": "/api/v1/auth/recovery/principal-snapshot",
        "todo": "TODO(coauth.recovery): replace complete scaffold with worker acknowledgements, stale-write protection, and durable cache updates."
    }))
}

#[endpoint]
pub async fn post_recovery_principal_cache_fail(req: &mut Request) -> Json<Value> {
    let body: Value = req.parse_json().await.unwrap_or(Value::Null);
    let failed_at = Utc::now().to_rfc3339();
    let mut cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock");
    let failure_count = cache
        .get("failure_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    let failure_code = body
        .get("failure_code")
        .cloned()
        .unwrap_or_else(|| json!("upstream_unreachable"));
    let mut failure_log = cache
        .get("failure_log")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    failure_log.push(json!({
        "failure_code": failure_code.clone(),
        "reason": body.get("reason").cloned().unwrap_or_else(|| json!("manual_fail")),
        "failed_at": failed_at
    }));
    *cache = json!({
        "cache_mode": "memory_snapshot_scaffold",
        "refresh_state": "failed",
        "refresh_count": cache.get("refresh_count").and_then(Value::as_u64).unwrap_or(0),
        "failure_count": failure_count,
        "last_refresh_at": cache.get("last_refresh_at").cloned().unwrap_or(Value::Null),
        "last_failure_at": failed_at,
        "last_failure_code": failure_code.clone(),
        "last_reason": body.get("reason").cloned().unwrap_or_else(|| json!("manual_fail")),
        "in_flight_job": Value::Null,
        "queue": [],
        "failure_log": failure_log,
        "last_upstream_probe_at": cache.get("last_upstream_probe_at").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": cache.get("last_upstream_probe_result").cloned().unwrap_or(Value::Null),
        "upstream_binding": cache.get("upstream_binding").cloned().unwrap_or_else(|| json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })),
        "cached_snapshot": cache.get("cached_snapshot").cloned().unwrap_or(Value::Null)
    });
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_fail.v1",
        "version": "2026-05-04-scaffold",
        "refresh_state": "failed",
        "failure_count": failure_count,
        "failure_code": failure_code,
        "failed_at": failed_at,
        "status_path": "/api/v1/auth/recovery/principal-cache/status",
        "queue_path": "/api/v1/auth/recovery/principal-cache/queue",
        "retry_path": "/api/v1/auth/recovery/principal-cache/retry",
        "failures_path": "/api/v1/auth/recovery/principal-cache/failures",
        "todo": "TODO(coauth.recovery): replace fail scaffold with durable error records, retry policy, and degraded-mode cache semantics."
    }))
}

#[endpoint]
pub async fn get_recovery_principal_cache_failures() -> Json<Value> {
    let cache = PRINCIPAL_RECOVERY_CACHE
        .lock()
        .expect("principal recovery cache lock")
        .clone();
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_failures.v1",
        "version": "2026-05-04-scaffold",
        "failure_count": cache.get("failure_count").cloned().unwrap_or_else(|| json!(0)),
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "failure_log": cache.get("failure_log").cloned().unwrap_or_else(|| json!([])),
        "retry_path": "/api/v1/auth/recovery/principal-cache/retry",
        "policy_path": "/api/v1/auth/recovery/principal-cache/policy",
        "taxonomy": [
            {
                "code": "upstream_unreachable",
                "retryable": true,
                "degraded_mode": "serve_last_ready_snapshot"
            },
            {
                "code": "invalid_discovery_binding",
                "retryable": false,
                "degraded_mode": "block_new_snapshot"
            },
            {
                "code": "cache_write_failed",
                "retryable": true,
                "degraded_mode": "serve_live_only"
            },
            {
                "code": "manual_invalidation",
                "retryable": true,
                "degraded_mode": "empty_cache_until_refresh"
            }
        ],
        "todo": "TODO(coauth.recovery): replace failure log scaffold with durable error records, alert hooks, and retry budget reconciliation."
    }))
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
