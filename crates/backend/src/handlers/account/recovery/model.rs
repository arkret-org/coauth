use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, ToSchema)]
pub struct RecoveryStatusResponse {
    pub id: String,
    pub email: String,
    pub status: &'static str,
}

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
    pub example_backup_payload: RecoveryBackupPayloadExample,
    pub recovery_restore_examples: RecoveryRestoreExamples,
    pub recovery_authz_examples: RecoveryAuthzExamples,
    pub todos: Vec<&'static str>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryBackupPayloadExample {
    pub schema: &'static str,
    pub backup_id: &'static str,
    #[serde(rename = "class")]
    pub backup_class: &'static str,
    pub encryption: RecoveryBackupEncryptionExample,
    pub items: Vec<RecoveryBackupItemExample>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryBackupEncryptionExample {
    pub alg: &'static str,
    pub kdf: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryBackupItemExample {
    pub kind: &'static str,
    #[serde(rename = "ref")]
    pub item_ref: &'static str,
    pub todo: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryRestoreExamples {
    pub restore_start_request: RecoveryRestoreStartRequestExample,
    pub restore_ticket_response_shape: RecoveryRestoreTicketResponseShapeExample,
    pub restore_ticket_advance_request: RecoveryRestoreTicketAdvanceRequestExample,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryRestoreStartRequestExample {
    pub backup_id: &'static str,
    pub actor: &'static str,
    pub device_id: &'static str,
    pub verification_event_kind: &'static str,
    pub todo: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryRestoreTicketResponseShapeExample {
    pub contract: &'static str,
    pub lifecycle_state: &'static str,
    pub allowed_next_transitions: Vec<&'static str>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryRestoreTicketAdvanceRequestExample {
    pub transition: &'static str,
    pub note: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryAuthzExamples {
    pub authz_check_request: RecoveryAuthzCheckRequestExample,
    pub policy_upsert_request: RecoveryPolicyUpsertRequestExample,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryAuthzCheckRequestExample {
    pub actor: &'static str,
    pub action: &'static str,
    pub space_id: &'static str,
    pub resources: Vec<RecoveryAuthzResourceExample>,
    pub constraints: Vec<RecoveryClaimConstraintExample>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryAuthzResourceExample {
    pub kind: &'static str,
    pub space_id: &'static str,
    pub blob_ref: &'static str,
    pub object_type: &'static str,
    pub object_ref: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<&'static str>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryClaimConstraintExample {
    pub constraint_type: &'static str,
    pub subtype: &'static str,
    pub effect: &'static str,
    pub object_type_allow: Vec<&'static str>,
    pub facet_allow: Vec<&'static str>,
    pub requires_claims: Vec<RecoveryRequiredClaimExample>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryRequiredClaimExample {
    pub claim_type: &'static str,
    pub issuer: &'static str,
    pub organization: &'static str,
    pub status: &'static str,
    pub roles: Vec<&'static str>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryPolicyUpsertRequestExample {
    pub scope: &'static str,
    pub subject_ref: &'static str,
    pub policy_type: &'static str,
    pub effect: &'static str,
    pub payload: RecoveryPolicyPayloadExample,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryPolicyPayloadExample {
    pub actions: Vec<&'static str>,
    pub resource: RecoveryAuthzResourceExample,
    pub constraints: Vec<RecoveryApprovalConstraintExample>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryApprovalConstraintExample {
    pub constraint_type: &'static str,
    pub subtype: &'static str,
    pub effect: &'static str,
    pub approval_required: bool,
    pub approval_mode: &'static str,
    pub approval_actor_refs: Vec<&'static str>,
    pub approval_relation: &'static str,
}

impl RecoveryBackupPayloadExample {
    pub fn scaffold() -> Self {
        Self {
            schema: "cx.schema.key_backup.v1",
            backup_id: "backup-scaffold-current-device",
            backup_class: "mls_export",
            encryption: RecoveryBackupEncryptionExample {
                alg: "xchacha20poly1305",
                kdf: "argon2id",
            },
            items: vec![RecoveryBackupItemExample {
                kind: "mls_group_state",
                item_ref: "group:default",
                todo: "replace scaffold payload with encrypted export blob",
            }],
        }
    }
}

impl RecoveryRestoreExamples {
    pub fn scaffold() -> Self {
        Self {
            restore_start_request: RecoveryRestoreStartRequestExample {
                backup_id: "backup-scaffold-current-device",
                actor: "did:web:alice.example",
                device_id: "device-web",
                verification_event_kind: "cx.key.verification.done",
                todo: "replace scaffold restore start with verified restore ticket handoff",
            },
            restore_ticket_response_shape: RecoveryRestoreTicketResponseShapeExample {
                contract: "contrix.rest.key_backup_restore_ticket.v1",
                lifecycle_state: "authz_pending",
                allowed_next_transitions: vec![
                    "authz_checked",
                    "policy_checked",
                    "approved",
                    "materialized",
                ],
            },
            restore_ticket_advance_request: RecoveryRestoreTicketAdvanceRequestExample {
                transition: "authz_checked",
                note: "replace scaffold transition with policy-backed approval state machine",
            },
        }
    }
}

impl RecoveryAuthzExamples {
    pub fn scaffold() -> Self {
        Self {
            authz_check_request: RecoveryAuthzCheckRequestExample {
                actor: "did:web:alice.example",
                action: "keys.backups.restore",
                space_id: "cx:space:01JS0SP000000000000000000",
                resources: vec![RecoveryAuthzResourceExample {
                    kind: "blob",
                    space_id: "cx:space:01JS0SP000000000000000000",
                    blob_ref: "cx:blob:sha256:0123456789abcdef",
                    object_type: "encrypted_backup",
                    object_ref: "backup-scaffold-current-device",
                    scope: Some("exact"),
                }],
                constraints: vec![RecoveryClaimConstraintExample {
                    constraint_type: "claim_based",
                    subtype: "claim",
                    effect: "allow",
                    object_type_allow: vec!["key_backup"],
                    facet_allow: vec!["recovery"],
                    requires_claims: vec![RecoveryRequiredClaimExample {
                        claim_type: "recovery_operator",
                        issuer: "did:web:coauth.example",
                        organization: "example-org",
                        status: "active",
                        roles: vec!["backup_admin"],
                    }],
                }],
            },
            policy_upsert_request: RecoveryPolicyUpsertRequestExample {
                scope: "space",
                subject_ref: "did:web:alice.example",
                policy_type: "keys.backups.restore",
                effect: "require_review",
                payload: RecoveryPolicyPayloadExample {
                    actions: vec!["keys.backups.restore"],
                    resource: RecoveryAuthzResourceExample {
                        kind: "blob",
                        space_id: "cx:space:01JS0SP000000000000000000",
                        blob_ref: "cx:blob:sha256:0123456789abcdef",
                        object_type: "encrypted_backup",
                        object_ref: "backup-scaffold-current-device",
                        scope: None,
                    },
                    constraints: vec![RecoveryApprovalConstraintExample {
                        constraint_type: "claim_based",
                        subtype: "approval",
                        effect: "require_review",
                        approval_required: true,
                        approval_mode: "two_man_rule",
                        approval_actor_refs: vec![
                            "did:web:controller.example",
                            "did:web:guardian.example",
                        ],
                        approval_relation: "controller",
                    }],
                },
            },
        }
    }
}
