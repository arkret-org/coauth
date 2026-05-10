//! Admin DTOs for the coauth recovery bridge discovery surface.
//!
//! Mirrors the wire shape emitted by:
//!
//! - `GET /api/v1/auth/recovery/describe` —
//!   `RecoveryDescribeResponse` from
//!   `coauth/crates/backend/src/handlers/account/recovery/model.rs`
//!   (the recovery-bridge-side discovery contract published to the
//!   admin SPA's account-detail page).
//!
//! Round-34 (C34.2): lifted out of the inline `CoauthRecoveryBridgeDescribe`
//! decoder shim in `sodmin/src/api/coauth.rs`. The sodmin shim was
//! decoding the three `example_*` fields as opaque
//! `serde_json::Value` — silently collapsing the typed
//! `RecoveryBackupPayloadExample` / `RecoveryRestoreExamples` /
//! `RecoveryAuthzExamples` payloads the backend has been emitting since
//! the recovery-bridge contract first shipped. The shared shape now
//! carries the typed nested example structures, so a backend rename or
//! field addition surfaces as a compile error rather than a silent loss
//! of UI fidelity.
//!
//! Why this is a separate module from `recovery_admin`: that module
//! describes the **soland** recovery / restore-ticket surface which
//! sodmin renders on its own dedicated page. This module describes the
//! **coauth** recovery bridge contract that ships as part of the
//! per-account admin detail payload. They share the word "recovery" but
//! the wire shapes are completely different and live behind different
//! HTTP endpoints, so they get distinct shared types.
//!
//! Why the inner `*Example` structs do not unify with `RecoveryDescribePath`
//! in `recovery_admin`: those describe sodmin's own labeled recovery
//! paths; the coauth bridge uses positionally-named keys for every path
//! and a different example-struct shape entirely.

use serde::{Deserialize, Serialize};

/// Coauth recovery-bridge contract discovery payload bundled into the
/// per-account admin detail.
///
/// Field order mirrors `RecoveryDescribeResponse` in
/// `coauth/crates/backend/src/handlers/account/recovery/model.rs`
/// exactly so any rename or reorder lands in lock-step on both sides.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryBridgeDescribe {
    #[serde(default)]
    pub contract: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub recovery_start_path: String,
    #[serde(default)]
    pub recovery_status_path: String,
    #[serde(default)]
    pub recovery_resend_path: String,
    #[serde(default)]
    pub recovery_principal_snapshot_path: String,
    #[serde(default)]
    pub recovery_principal_cache_status_path: String,
    #[serde(default)]
    pub recovery_principal_cache_refresh_path: String,
    #[serde(default)]
    pub recovery_principal_cache_queue_path: String,
    #[serde(default)]
    pub recovery_principal_cache_complete_path: String,
    #[serde(default)]
    pub recovery_principal_cache_fail_path: String,
    #[serde(default)]
    pub recovery_principal_cache_policy_path: String,
    #[serde(default)]
    pub recovery_principal_cache_retry_path: String,
    #[serde(default)]
    pub recovery_principal_cache_invalidate_path: String,
    #[serde(default)]
    pub recovery_principal_cache_failures_path: String,
    #[serde(default)]
    pub recovery_principal_cache_upstream_path: String,
    #[serde(default)]
    pub recovery_principal_cache_upstream_probe_path: String,
    #[serde(default)]
    pub recovery_principal_cache_upstream_bind_path: String,
    #[serde(default)]
    pub key_backup_rest_base: String,
    #[serde(default)]
    pub key_backup_schema: String,
    #[serde(default)]
    pub device_message_schema: String,
    #[serde(default)]
    pub principal_recovery_contract_stack_path: String,
    #[serde(default)]
    pub principal_recovery_stack_bundle_path: String,
    #[serde(default)]
    pub principal_recovery_discovery_path: String,
    #[serde(default)]
    pub principal_recovery_readiness_path: String,
    #[serde(default)]
    pub principal_device_messages_describe_path: String,
    #[serde(default)]
    pub principal_key_backups_describe_path: String,
    #[serde(default)]
    pub principal_restore_state_describe_path: String,
    #[serde(default)]
    pub principal_restore_state_export_path: String,
    #[serde(default)]
    pub principal_restore_state_import_path: String,
    #[serde(default)]
    pub principal_restore_state_durability_path: String,
    #[serde(default)]
    pub principal_restore_state_checkpoint_collection_path: String,
    #[serde(default)]
    pub principal_restore_start_path: String,
    #[serde(default)]
    pub principal_restore_describe_path: String,
    #[serde(default)]
    pub principal_restore_ticket_collection_path: String,
    #[serde(default)]
    pub principal_restore_ticket_path: String,
    #[serde(default)]
    pub principal_restore_ticket_advance_path: String,
    #[serde(default)]
    pub principal_restore_ticket_resume_path: String,
    #[serde(default)]
    pub principal_restore_ticket_cancel_path: String,
    #[serde(default)]
    pub principal_restore_ticket_retry_path: String,
    #[serde(default)]
    pub principal_restore_approval_status_path: String,
    #[serde(default)]
    pub principal_restore_approval_submit_path: String,
    #[serde(default)]
    pub principal_restore_executor_status_path: String,
    #[serde(default)]
    pub principal_restore_executor_enqueue_path: String,
    #[serde(default)]
    pub principal_restore_executor_start_path: String,
    #[serde(default)]
    pub principal_restore_executor_complete_path: String,
    #[serde(default)]
    pub principal_restore_result_path: String,
    #[serde(default)]
    pub principal_restore_receipt_path: String,
    #[serde(default)]
    pub principal_restore_materialized_device_handoff_path: String,
    #[serde(default)]
    pub principal_restore_bundle_path: String,
    #[serde(default)]
    pub principal_restore_activity_path: String,
    #[serde(default)]
    pub principal_restore_timeline_path: String,
    #[serde(default)]
    pub principal_restore_audit_feed_path: String,
    #[serde(default)]
    pub principal_recovery_live_snapshot_path: String,
    #[serde(default)]
    pub principal_authz_describe_path: String,
    #[serde(default)]
    pub principal_authz_check_path: String,
    #[serde(default)]
    pub principal_policy_describe_path: String,
    #[serde(default)]
    pub principal_policy_collection_path: String,
    #[serde(default)]
    pub principal_policy_item_path: String,
    #[serde(default)]
    pub verification_event_kinds: Vec<String>,
    #[serde(default)]
    pub recovery_modes: Vec<String>,
    #[serde(default)]
    pub example_backup_payload: RecoveryBackupPayloadExample,
    #[serde(default)]
    pub recovery_restore_examples: RecoveryRestoreExamples,
    #[serde(default)]
    pub recovery_authz_examples: RecoveryAuthzExamples,
    #[serde(default)]
    pub todos: Vec<String>,
}

/// Example encrypted backup payload published by the recovery bridge.
///
/// `class` is renamed at the wire level (`#[serde(rename = "class")]`)
/// because `class` is a reserved word in Rust struct field syntax.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryBackupPayloadExample {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub backup_id: String,
    #[serde(default, rename = "class")]
    pub backup_class: String,
    #[serde(default)]
    pub encryption: RecoveryBackupEncryptionExample,
    #[serde(default)]
    pub items: Vec<RecoveryBackupItemExample>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryBackupEncryptionExample {
    #[serde(default)]
    pub alg: String,
    #[serde(default)]
    pub kdf: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryBackupItemExample {
    #[serde(default)]
    pub kind: String,
    #[serde(default, rename = "ref")]
    pub item_ref: String,
    #[serde(default)]
    pub todo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryRestoreExamples {
    #[serde(default)]
    pub restore_start_request: RecoveryRestoreStartRequestExample,
    #[serde(default)]
    pub restore_ticket_response_shape: RecoveryRestoreTicketResponseShapeExample,
    #[serde(default)]
    pub restore_ticket_advance_request: RecoveryRestoreTicketAdvanceRequestExample,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryRestoreStartRequestExample {
    #[serde(default)]
    pub backup_id: String,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub verification_event_kind: String,
    #[serde(default)]
    pub todo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryRestoreTicketResponseShapeExample {
    #[serde(default)]
    pub contract: String,
    #[serde(default)]
    pub lifecycle_state: String,
    #[serde(default)]
    pub allowed_next_transitions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryRestoreTicketAdvanceRequestExample {
    #[serde(default)]
    pub transition: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryAuthzExamples {
    #[serde(default)]
    pub authz_check_request: RecoveryAuthzCheckRequestExample,
    #[serde(default)]
    pub policy_upsert_request: RecoveryPolicyUpsertRequestExample,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryAuthzCheckRequestExample {
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub space_id: String,
    #[serde(default)]
    pub resources: Vec<RecoveryAuthzResourceExample>,
    #[serde(default)]
    pub constraints: Vec<RecoveryClaimConstraintExample>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryAuthzResourceExample {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub space_id: String,
    #[serde(default)]
    pub blob_ref: String,
    #[serde(default)]
    pub object_type: String,
    #[serde(default)]
    pub object_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryClaimConstraintExample {
    #[serde(default)]
    pub constraint_type: String,
    #[serde(default)]
    pub subtype: String,
    #[serde(default)]
    pub effect: String,
    #[serde(default)]
    pub object_type_allow: Vec<String>,
    #[serde(default)]
    pub facet_allow: Vec<String>,
    #[serde(default)]
    pub requires_claims: Vec<RecoveryRequiredClaimExample>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryRequiredClaimExample {
    #[serde(default)]
    pub claim_type: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryPolicyUpsertRequestExample {
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub subject_ref: String,
    #[serde(default)]
    pub policy_type: String,
    #[serde(default)]
    pub effect: String,
    #[serde(default)]
    pub payload: RecoveryPolicyPayloadExample,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryPolicyPayloadExample {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub resource: RecoveryAuthzResourceExample,
    #[serde(default)]
    pub constraints: Vec<RecoveryApprovalConstraintExample>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryApprovalConstraintExample {
    #[serde(default)]
    pub constraint_type: String,
    #[serde(default)]
    pub subtype: String,
    #[serde(default)]
    pub effect: String,
    #[serde(default)]
    pub approval_required: bool,
    #[serde(default)]
    pub approval_mode: String,
    #[serde(default)]
    pub approval_actor_refs: Vec<String>,
    #[serde(default)]
    pub approval_relation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_default_round_trips() {
        let d = RecoveryBridgeDescribe::default();
        let s = serde_json::to_string(&d).unwrap();
        let back: RecoveryBridgeDescribe = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn backup_payload_decodes_class_via_serde_rename() {
        // The wire emits `"class"` because the Rust struct field is
        // `backup_class` to dodge the keyword.
        let wire = r#"{
            "schema": "cx.schema.key_backup.v1",
            "backup_id": "backup-scaffold-current-device",
            "class": "mls_export",
            "encryption": {"alg": "xchacha20poly1305", "kdf": "argon2id"},
            "items": [{"kind": "mls_group_state", "ref": "group:default", "todo": "x"}]
        }"#;
        let p: RecoveryBackupPayloadExample = serde_json::from_str(wire).unwrap();
        assert_eq!(p.backup_class, "mls_export");
        assert_eq!(p.items[0].item_ref, "group:default");
        // Round-trip must keep the wire key as `class` not `backup_class`.
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"class\":\"mls_export\""));
        assert!(!s.contains("\"backup_class\""));
        assert!(s.contains("\"ref\":\"group:default\""));
        assert!(!s.contains("\"item_ref\""));
    }

    #[test]
    fn restore_examples_round_trip() {
        let e = RecoveryRestoreExamples {
            restore_start_request: RecoveryRestoreStartRequestExample {
                backup_id: "b".into(),
                actor: "did:web:a".into(),
                device_id: "d".into(),
                verification_event_kind: "cx.key.verification.done".into(),
                todo: "x".into(),
            },
            restore_ticket_response_shape: RecoveryRestoreTicketResponseShapeExample {
                contract: "c".into(),
                lifecycle_state: "authz_pending".into(),
                allowed_next_transitions: vec!["authz_checked".into()],
            },
            restore_ticket_advance_request: RecoveryRestoreTicketAdvanceRequestExample {
                transition: "authz_checked".into(),
                note: "n".into(),
            },
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: RecoveryRestoreExamples = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn authz_examples_resource_omits_optional_scope_when_none() {
        // `RecoveryAuthzResourceExample.scope` is the only `Option<…>`
        // on the recovery-bridge example tree — and the only one that
        // should drop off the wire when unset (the policy upsert request
        // *does* emit a top-level `scope` field that's a non-optional
        // String). Keep the assertion narrow so it actually verifies the
        // skip-when-none behavior of the resource shape.
        let r_some = RecoveryAuthzResourceExample {
            kind: "blob".into(),
            space_id: "s".into(),
            blob_ref: "b".into(),
            object_type: "ot".into(),
            object_ref: "or".into(),
            scope: Some("exact".into()),
        };
        let r_none = RecoveryAuthzResourceExample {
            scope: None,
            ..r_some.clone()
        };
        let s_some = serde_json::to_string(&r_some).unwrap();
        let s_none = serde_json::to_string(&r_none).unwrap();
        assert!(s_some.contains("\"scope\":\"exact\""));
        assert!(!s_none.contains("\"scope\""));
    }

    #[test]
    fn full_describe_decodes_backend_wire_payload_with_typed_examples() {
        // Mirrors a trimmed slice of what `recovery::get_recovery_describe`
        // actually emits — most paths elided to keep the test focused on
        // the `example_*` block where the prior sodmin shim was silently
        // dropping typed structure in favor of opaque `Value`.
        let wire = r#"{
            "contract": "contrix.auth.recovery_bridge.v1",
            "version": "2026-05-04",
            "verification_event_kinds": ["cx.key.verification.done"],
            "recovery_modes": ["password_recovery"],
            "example_backup_payload": {
                "schema": "cx.schema.key_backup.v1",
                "backup_id": "backup-scaffold-current-device",
                "class": "mls_export",
                "encryption": {"alg": "xchacha20poly1305", "kdf": "argon2id"},
                "items": [{"kind": "mls_group_state", "ref": "group:default", "todo": "x"}]
            },
            "recovery_restore_examples": {
                "restore_start_request": {
                    "backup_id": "b", "actor": "did:web:a", "device_id": "d",
                    "verification_event_kind": "cx.key.verification.done", "todo": "t"
                },
                "restore_ticket_response_shape": {
                    "contract": "c", "lifecycle_state": "authz_pending",
                    "allowed_next_transitions": ["authz_checked"]
                },
                "restore_ticket_advance_request": {"transition": "authz_checked", "note": "n"}
            },
            "recovery_authz_examples": {
                "authz_check_request": {
                    "actor": "did:web:a", "action": "act", "space_id": "s",
                    "resources": [], "constraints": []
                },
                "policy_upsert_request": {
                    "scope": "space", "subject_ref": "did:web:a",
                    "policy_type": "pt", "effect": "require_review",
                    "payload": {"actions": [], "resource": {
                        "kind": "blob", "space_id": "s", "blob_ref": "b",
                        "object_type": "ot", "object_ref": "or"
                    }, "constraints": []}
                }
            },
            "todos": []
        }"#;
        let d: RecoveryBridgeDescribe = serde_json::from_str(wire).unwrap();
        assert_eq!(d.contract, "contrix.auth.recovery_bridge.v1");
        // Typed examples — the whole point of the lift.
        assert_eq!(d.example_backup_payload.backup_class, "mls_export");
        assert_eq!(
            d.recovery_restore_examples
                .restore_ticket_response_shape
                .lifecycle_state,
            "authz_pending"
        );
        assert_eq!(
            d.recovery_authz_examples.policy_upsert_request.policy_type,
            "pt"
        );
    }
}
