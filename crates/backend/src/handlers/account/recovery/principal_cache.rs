//! Recovery -> principal-server cache bridge.
//!
//! Phase 2.3 stores cache snapshots in PostgreSQL through the
//! `PrincipalCacheService`, with the in-process cache retained as a dev-mode
//! fallback when the durable table is unavailable.

use std::time::Duration;

use chrono::Utc;
use salvo::prelude::*;
use serde_json::{Value, json};
use ulid::Ulid;

use super::DepotExt;

fn principal_cache_service(
    depot: &Depot,
) -> crate::services::principal_cache::PrincipalCacheServiceHandle {
    depot
        .principal_cache_service()
        .expect("principal_cache_service not found in depot")
}

async fn recovery_cache_json_body(req: &mut Request) -> Value {
    req.parse_json::<Value>()
        .await
        .unwrap_or_else(|_| json!({}))
}

#[derive(Clone, Copy)]
enum PrincipalSnapshotFailure {
    Drift,
    FetchFailed,
    ContractMismatch,
    Unauthenticated,
}

impl PrincipalSnapshotFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Drift => "drift",
            Self::FetchFailed => "fetch_failed",
            Self::ContractMismatch => "contract_mismatch",
            Self::Unauthenticated => "unauthenticated",
        }
    }

    fn retryable(self) -> bool {
        match self {
            Self::Drift | Self::ContractMismatch => false,
            Self::FetchFailed | Self::Unauthenticated => true,
        }
    }
}

fn recovery_bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
}

fn probe_failure(probe: &Value) -> Option<PrincipalSnapshotFailure> {
    match probe.get("state").and_then(Value::as_str) {
        Some("auth_required") => Some(PrincipalSnapshotFailure::Unauthenticated),
        Some("contract_mismatch") => Some(PrincipalSnapshotFailure::ContractMismatch),
        Some("invalid_probe_url" | "request_error" | "http_error") => {
            Some(PrincipalSnapshotFailure::FetchFailed)
        }
        _ => None,
    }
}

fn snapshot_failure_from_probes(probes: &[Value]) -> Option<PrincipalSnapshotFailure> {
    if probes.iter().any(|probe| {
        matches!(
            probe_failure(probe),
            Some(PrincipalSnapshotFailure::Unauthenticated)
        )
    }) {
        return Some(PrincipalSnapshotFailure::Unauthenticated);
    }
    if probes.iter().any(|probe| {
        matches!(
            probe_failure(probe),
            Some(PrincipalSnapshotFailure::ContractMismatch)
        )
    }) {
        return Some(PrincipalSnapshotFailure::ContractMismatch);
    }
    if probes.iter().any(|probe| probe_failure(probe).is_some()) {
        return Some(PrincipalSnapshotFailure::FetchFailed);
    }
    None
}

async fn store_principal_snapshot_failure(
    principal_cache: &crate::services::principal_cache::PrincipalCacheServiceHandle,
    cache: &Value,
    failure: PrincipalSnapshotFailure,
    reason: &str,
    probes: Value,
) -> Value {
    let failed_at = Utc::now().to_rfc3339();
    let failure_count = cache
        .get("failure_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    let mut failure_log = cache
        .get("failure_log")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    failure_log.push(json!({
        "failure_code": failure.as_str(),
        "reason": reason,
        "failed_at": failed_at,
        "details": probes
    }));
    let updated_cache = json!({
        "cache_mode": cache.get("cache_mode").cloned().unwrap_or_else(|| json!("pg_recovery_principal_cache")),
        "storage": cache.get("storage").cloned().unwrap_or(Value::Null),
        "refresh_state": "failed",
        "refresh_count": cache.get("refresh_count").and_then(Value::as_u64).unwrap_or(0),
        "failure_count": failure_count,
        "last_refresh_at": cache.get("last_refresh_at").cloned().unwrap_or(Value::Null),
        "last_failure_at": failed_at,
        "last_failure_code": failure.as_str(),
        "last_reason": reason,
        "last_invalidated_at": cache.get("last_invalidated_at").cloned().unwrap_or(Value::Null),
        "etag": cache.get("etag").cloned().unwrap_or(Value::Null),
        "contract_digest": cache.get("contract_digest").cloned().unwrap_or(Value::Null),
        "drift": cache.get("drift").cloned().unwrap_or_else(|| json!({
            "state": "none",
            "last_detected_at": null
        })),
        "in_flight_job": Value::Null,
        "queue": cache.get("queue").cloned().unwrap_or_else(|| json!([])),
        "failure_log": failure_log,
        "last_upstream_probe_at": failed_at,
        "last_upstream_probe_result": probes,
        "upstream_binding": cache.get("upstream_binding").cloned().unwrap_or_else(|| json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })),
        "cached_snapshot": cache.get("cached_snapshot").cloned().unwrap_or(Value::Null)
    });
    principal_cache.store(updated_cache.clone()).await;
    updated_cache
}

fn principal_snapshot_failure_response(
    cache_state: Value,
    failure: PrincipalSnapshotFailure,
    reason: &str,
    details: Value,
) -> Json<Value> {
    Json(json!({
        "contract": "contrix.auth.recovery_principal_snapshot.v1",
        "version": "2026-05-06",
        "aggregation_state": "failed",
        "failure": {
            "code": failure.as_str(),
            "reason": reason,
            "retryable": failure.retryable(),
            "details": details
        },
        "cache_state": cache_state,
        "principal_snapshot": Value::Null,
        "principal_recovery_contract_stack_path": "/api/v1/recovery/contract-stack",
        "principal_recovery_stack_bundle_path": "/api/v1/recovery/stack-bundle",
        "principal_cache_status_path": "/api/v1/auth/recovery/principal-cache/status",
        "principal_cache_refresh_path": "/api/v1/auth/recovery/principal-cache/refresh"
    }))
}

#[endpoint]
pub async fn get_recovery_principal_snapshot(req: &mut Request, depot: &Depot) -> Json<Value> {
    let principal_cache = principal_cache_service(depot);
    let cache = principal_cache.snapshot().await;
    if cache
        .pointer("/drift/state")
        .and_then(Value::as_str)
        .is_some_and(|state| state == "detected")
    {
        let updated_cache = store_principal_snapshot_failure(
            &principal_cache,
            &cache,
            PrincipalSnapshotFailure::Drift,
            "principal cache drift must be reconciled before snapshot aggregation",
            cache.get("drift").cloned().unwrap_or(Value::Null),
        )
        .await;
        return principal_snapshot_failure_response(
            updated_cache,
            PrincipalSnapshotFailure::Drift,
            "principal cache drift must be reconciled before snapshot aggregation",
            cache.get("drift").cloned().unwrap_or(Value::Null),
        );
    }

    let principal_base_url = match cache
        .pointer("/upstream_binding/principal_base_url")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => value.to_owned(),
        None => {
            let updated_cache = store_principal_snapshot_failure(
                &principal_cache,
                &cache,
                PrincipalSnapshotFailure::FetchFailed,
                "principal upstream binding is missing",
                Value::Null,
            )
            .await;
            return principal_snapshot_failure_response(
                updated_cache,
                PrincipalSnapshotFailure::FetchFailed,
                "principal upstream binding is missing",
                Value::Null,
            );
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let bearer_token = recovery_bearer_token(req);
    let stack_bundle_probe = principal_cache
        .probe_recovery_surface(
            &client,
            &principal_base_url,
            "/api/v1/recovery/stack-bundle",
            "contrix.rest.recovery_stack_bundle.v1",
            bearer_token.as_deref(),
        )
        .await;
    let contract_stack_probe = principal_cache
        .probe_recovery_surface(
            &client,
            &principal_base_url,
            "/api/v1/recovery/contract-stack",
            "contrix.rest.recovery_contract_stack.v1",
            bearer_token.as_deref(),
        )
        .await;
    let probes = vec![stack_bundle_probe.clone(), contract_stack_probe.clone()];
    if let Some(failure) = snapshot_failure_from_probes(&probes) {
        let reason = match failure {
            PrincipalSnapshotFailure::Drift => "principal cache drift detected",
            PrincipalSnapshotFailure::FetchFailed => "failed to fetch principal recovery surfaces",
            PrincipalSnapshotFailure::ContractMismatch => {
                "principal recovery surface contract mismatch"
            }
            PrincipalSnapshotFailure::Unauthenticated => {
                "principal recovery surface requires authentication"
            }
        };
        let details = json!({
            "principal_base_url": principal_base_url,
            "probes": probes
        });
        let updated_cache = store_principal_snapshot_failure(
            &principal_cache,
            &cache,
            failure,
            reason,
            details.clone(),
        )
        .await;
        return principal_snapshot_failure_response(updated_cache, failure, reason, details);
    }

    let aggregated_at = Utc::now().to_rfc3339();
    let stack_bundle = stack_bundle_probe
        .get("body")
        .cloned()
        .unwrap_or(Value::Null);
    let contract_stack = contract_stack_probe
        .get("body")
        .cloned()
        .unwrap_or(Value::Null);
    let principal_snapshot = json!({
        "contract": "contrix.auth.recovery_principal_snapshot_aggregate.v1",
        "fetch_mode": "live_principal_cache_aggregation",
        "principal_base_url": principal_base_url,
        "aggregated_at": aggregated_at,
        "stack_bundle": stack_bundle,
        "contract_stack": contract_stack
    });
    let refresh_count = cache
        .get("refresh_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    let updated_cache = json!({
        "cache_mode": cache.get("cache_mode").cloned().unwrap_or_else(|| json!("pg_recovery_principal_cache")),
        "storage": cache.get("storage").cloned().unwrap_or(Value::Null),
        "refresh_state": "ready",
        "refresh_count": refresh_count,
        "failure_count": cache.get("failure_count").and_then(Value::as_u64).unwrap_or(0),
        "last_refresh_at": aggregated_at,
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "last_reason": "principal_snapshot_aggregated",
        "last_invalidated_at": cache.get("last_invalidated_at").cloned().unwrap_or(Value::Null),
        "etag": cache.get("etag").cloned().unwrap_or(Value::Null),
        "contract_digest": cache.get("contract_digest").cloned().unwrap_or(Value::Null),
        "drift": {
            "state": "none",
            "last_detected_at": null
        },
        "in_flight_job": Value::Null,
        "queue": [],
        "failure_log": cache.get("failure_log").cloned().unwrap_or_else(|| json!([])),
        "last_upstream_probe_at": aggregated_at,
        "last_upstream_probe_result": {
            "principal_base_url": principal_base_url,
            "probe_state": "contract_ok",
            "probed_at": aggregated_at,
            "probes": probes
        },
        "upstream_binding": cache.get("upstream_binding").cloned().unwrap_or_else(|| json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })),
        "cached_snapshot": principal_snapshot
    });
    principal_cache.store(updated_cache.clone()).await;
    Json(json!({
        "contract": "contrix.auth.recovery_principal_snapshot.v1",
        "version": "2026-05-06",
        "aggregation_state": "ready",
        "failure": Value::Null,
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
        "cache_state": updated_cache,
        "principal_snapshot": principal_snapshot,
        "principal_contract_stack": contract_stack_probe.get("body").cloned().unwrap_or(Value::Null),
        "principal_stack_bundle": stack_bundle_probe.get("body").cloned().unwrap_or(Value::Null),
        "todos": [
            "TODO(coauth.recovery): add failure taxonomy and degraded-mode semantics for principal snapshot aggregation."
        ]
    }))
}

#[endpoint]
pub async fn get_recovery_principal_cache_status(depot: &Depot) -> Json<Value> {
    let cache = principal_cache_service(depot).snapshot().await;
    let cache_mode = cache
        .get("cache_mode")
        .cloned()
        .unwrap_or_else(|| json!("memory_snapshot_scaffold"));
    let upstream_binding = cache.get("upstream_binding").cloned().unwrap_or_else(|| {
        json!({
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        })
    });
    let drift = cache.get("drift").cloned().unwrap_or_else(|| {
        json!({
            "state": "none",
            "last_detected_at": null
        })
    });
    let storage = cache.get("storage").cloned().unwrap_or_else(|| {
        json!({
            "kind": "process_memory",
            "durable": false,
            "fallback": true
        })
    });
    let freshness_policy = json!({
        "max_stale_seconds": 300,
        "degraded_mode": "serve_last_ready_snapshot",
        "invalidate_on_audience_change": true,
        "todo": "TODO(coauth.recovery): bind freshness to principal DID, tenant, audience, and upstream ETag/version."
    });
    let failure_codes = json!([
        "upstream_unreachable",
        "invalid_discovery_binding",
        "cache_write_failed",
        "stale_snapshot",
        "audience_binding_changed",
        "manual_invalidation",
        "etag_drift",
        "contract_digest_drift"
    ]);
    let todos = json!([
        "TODO(coauth.recovery): replace cache status scaffold with real principal fetch/cache metadata and freshness timestamps.",
        "TODO(coauth.recovery): bind refresh state to audience, tenant, and principal-server identity.",
        "TODO(coauth.recovery): replace manual worker endpoints with durable cache control records."
    ]);
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_status.v1",
        "version": "2026-05-04-scaffold",
        "cache_mode": cache_mode,
        "fetch_mode": "manual_refresh_pg_cache",
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
        "upstream_binding": upstream_binding,
        "last_upstream_probe_at": cache.get("last_upstream_probe_at").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": cache.get("last_upstream_probe_result").cloned().unwrap_or(Value::Null),
        "last_refresh_at": cache.get("last_refresh_at").cloned().unwrap_or(Value::Null),
        "refresh_state": cache.get("refresh_state").cloned().unwrap_or_else(|| json!("idle")),
        "refresh_count": cache.get("refresh_count").cloned().unwrap_or_else(|| json!(0)),
        "failure_count": cache.get("failure_count").cloned().unwrap_or_else(|| json!(0)),
        "last_failure_at": cache.get("last_failure_at").cloned().unwrap_or(Value::Null),
        "last_failure_code": cache.get("last_failure_code").cloned().unwrap_or(Value::Null),
        "last_invalidated_at": cache.get("last_invalidated_at").cloned().unwrap_or(Value::Null),
        "etag": cache.get("etag").cloned().unwrap_or(Value::Null),
        "contract_digest": cache.get("contract_digest").cloned().unwrap_or(Value::Null),
        "drift": drift,
        "storage": storage,
        "last_reason": cache.get("last_reason").cloned().unwrap_or(Value::Null),
        "queue_depth": cache.get("queue").and_then(Value::as_array).map(|v| v.len()).unwrap_or(0),
        "in_flight_job": cache.get("in_flight_job").cloned().unwrap_or(Value::Null),
        "has_cached_snapshot": cache.get("cached_snapshot").is_some_and(|v| !v.is_null()),
        "failure_log_depth": cache.get("failure_log").and_then(Value::as_array).map(|v| v.len()).unwrap_or(0),
        "freshness_policy": freshness_policy,
        "failure_codes": failure_codes,
        "todos": todos
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
            "kind": "pg",
            "scope": "coauth_recovery_principal_cache",
            "durable": true,
            "fallback_kind": "process_memory_dev_fallback"
        },
        "failure_taxonomy": [
            "upstream_unreachable",
            "invalid_discovery_binding",
            "cache_write_failed",
            "stale_snapshot",
            "audience_binding_changed",
            "manual_invalidation",
            "etag_drift",
            "contract_digest_drift"
        ],
        "remaining_gaps": [
            "tenant_overrides",
            "worker_retry_budget_accounting",
            "tenant_overrides"
        ]
    }))
}

#[endpoint]
pub async fn get_recovery_principal_cache_upstream(depot: &Depot) -> Json<Value> {
    let cache = principal_cache_service(depot).snapshot().await;
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
pub async fn post_recovery_principal_cache_upstream_probe(
    req: &mut Request,
    depot: &Depot,
) -> Json<Value> {
    let principal_cache = principal_cache_service(depot);
    let body = recovery_cache_json_body(req).await;
    let probed_at = Utc::now().to_rfc3339();
    let principal_base_url_input =
        principal_cache.body_string(&body, "principal_base_url", "http://127.0.0.1:8080");
    let principal_base_url =
        match principal_cache.normalize_principal_base_url(&principal_base_url_input) {
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
        principal_cache
            .probe_recovery_surface(
                &client,
                &principal_base_url,
                "/api/v1/recovery/discovery",
                "contrix.rest.recovery_discovery.v1",
                bearer_token.as_deref(),
            )
            .await,
        principal_cache
            .probe_recovery_surface(
                &client,
                &principal_base_url,
                "/api/v1/recovery/readiness",
                "contrix.rest.recovery_readiness.v1",
                bearer_token.as_deref(),
            )
            .await,
        principal_cache
            .probe_recovery_surface(
                &client,
                &principal_base_url,
                "/api/v1/recovery/stack-bundle",
                "contrix.rest.recovery_stack_bundle.v1",
                bearer_token.as_deref(),
            )
            .await,
        principal_cache
            .probe_recovery_surface(
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
    let cache = principal_cache.snapshot().await;
    let upstream_binding = json!({
        "principal_base_url": principal_base_url,
        "binding_state": "probe_ok",
        "probe_state": probe_state,
        "contract_ok_count": contract_ok_count,
        "auth_required_count": auth_required_count,
        "discovery_mode": "live_http_probe"
    });
    let updated_cache = json!({
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
    principal_cache.store(updated_cache).await;
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
pub async fn post_recovery_principal_cache_upstream_bind(
    req: &mut Request,
    depot: &Depot,
) -> Json<Value> {
    let principal_cache = principal_cache_service(depot);
    let body = recovery_cache_json_body(req).await;
    let bound_at = Utc::now().to_rfc3339();
    let principal_base_url_input =
        principal_cache.body_string(&body, "principal_base_url", "http://127.0.0.1:8080");
    let principal_base_url =
        match principal_cache.normalize_principal_base_url(&principal_base_url_input) {
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
    let audience = principal_cache.body_string(&body, "audience", "contrix-principal");
    let cache = principal_cache.snapshot().await;
    let last_probe_result = cache
        .get("last_upstream_probe_result")
        .cloned()
        .unwrap_or(Value::Null);
    let binding_state = if last_probe_result
        .get("principal_base_url")
        .and_then(Value::as_str)
        == Some(principal_base_url.as_str())
        && last_probe_result
            .get("probe_state")
            .and_then(Value::as_str)
            .is_some_and(|state| {
                state == "contract_ok" || state == "partial_contract_ok" || state == "auth_required"
            }) {
        "bound_after_probe"
    } else {
        "bound_without_current_probe"
    };
    let updated_cache = json!({
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
    principal_cache.store(updated_cache.clone()).await;
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_upstream_bind.v1",
        "version": "2026-05-04",
        "principal_base_url": updated_cache["upstream_binding"]["principal_base_url"].clone(),
        "audience": updated_cache["upstream_binding"]["audience"].clone(),
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
pub async fn post_recovery_principal_cache_refresh(
    req: &mut Request,
    depot: &Depot,
) -> Json<Value> {
    let principal_cache = principal_cache_service(depot);
    let body = recovery_cache_json_body(req).await;
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
    let cache = principal_cache.snapshot().await;
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
    let updated_cache = json!({
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
    principal_cache.store(updated_cache.clone()).await;
    Json(json!({
        "contract": "contrix.auth.recovery_principal_cache_refresh.v1",
        "version": "2026-05-04-scaffold",
        "refresh_state": "in_flight",
        "job_id": job_id,
        "refresh_mode": refresh_mode,
        "reason": reason,
        "queue_depth": updated_cache.get("queue").and_then(Value::as_array).map(|v| v.len()).unwrap_or(0),
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
pub async fn post_recovery_principal_cache_retry(req: &mut Request, depot: &Depot) -> Json<Value> {
    let principal_cache = principal_cache_service(depot);
    let body = recovery_cache_json_body(req).await;
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
    let cache = principal_cache.snapshot().await;
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
    let updated_cache = json!({
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
    principal_cache.store(updated_cache).await;
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
pub async fn post_recovery_principal_cache_invalidate(
    req: &mut Request,
    depot: &Depot,
) -> Json<Value> {
    let principal_cache = principal_cache_service(depot);
    let body = recovery_cache_json_body(req).await;
    let invalidated_at = Utc::now().to_rfc3339();
    let reason = body
        .get("reason")
        .cloned()
        .unwrap_or_else(|| json!("manual_invalidation"));
    let cache = principal_cache.snapshot().await;
    let updated_cache = json!({
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
    principal_cache.store(updated_cache).await;
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
pub async fn get_recovery_principal_cache_queue(depot: &Depot) -> Json<Value> {
    let cache = principal_cache_service(depot).snapshot().await;
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
pub async fn post_recovery_principal_cache_complete(
    req: &mut Request,
    depot: &Depot,
) -> Json<Value> {
    let principal_cache = principal_cache_service(depot);
    let body = recovery_cache_json_body(req).await;
    let completed_at = Utc::now().to_rfc3339();
    let cache = principal_cache.snapshot().await;
    let job_id = body
        .get("job_id")
        .cloned()
        .unwrap_or_else(|| json!("unknown"));
    let refresh_count = cache
        .get("refresh_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    let updated_cache = json!({
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
    principal_cache.store(updated_cache).await;
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
pub async fn post_recovery_principal_cache_fail(req: &mut Request, depot: &Depot) -> Json<Value> {
    let principal_cache = principal_cache_service(depot);
    let body = recovery_cache_json_body(req).await;
    let failed_at = Utc::now().to_rfc3339();
    let cache = principal_cache.snapshot().await;
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
    let updated_cache = json!({
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
    principal_cache.store(updated_cache).await;
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
pub async fn get_recovery_principal_cache_failures(depot: &Depot) -> Json<Value> {
    let cache = principal_cache_service(depot).snapshot().await;
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
