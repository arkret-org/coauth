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
    pub key_backup_rest_base: &'static str,
    pub key_backup_schema: &'static str,
    pub device_message_schema: &'static str,
    pub principal_authz_check_path: &'static str,
    pub principal_policy_collection_path: &'static str,
    pub principal_policy_item_path: &'static str,
    pub verification_event_kinds: Vec<&'static str>,
    pub recovery_modes: Vec<&'static str>,
    pub example_backup_payload: Value,
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
        key_backup_rest_base: "/api/v1/keys/backups",
        key_backup_schema: "cx.schema.key_backup.v1",
        device_message_schema: "cx.schema.device_message.v1",
        principal_authz_check_path: "/api/v1/authz/check",
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
            "TODO: add recovery proofing policy and restore approvals.",
            "TODO: bind recovery bridge examples to live principal authz/policy endpoints instead of static scaffold paths.",
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
