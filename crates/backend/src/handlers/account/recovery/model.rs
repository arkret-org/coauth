use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

// `RecoveryDescribeResponse` (and the entire `Recovery*Example` family
// it nests) used to live inline here. They moved to
// `coauth_admin_types::recovery_bridge_admin` in C34.2 so the sodmin
// admin SPA decodes them through the same typed shape — the prior
// sodmin shim was decoding the three `example_*` blocks as opaque
// `serde_json::Value`, silently dropping the typed structure of
// `RecoveryBackupPayloadExample` / `RecoveryRestoreExamples` /
// `RecoveryAuthzExamples`. The shared crate is the source of truth from
// here forward; this module re-exports them under the original names so
// the rest of the backend handler keeps compiling without touching every
// `use super::model::…` import site.
pub use coauth_admin_types::{
    RecoveryApprovalConstraintExample, RecoveryAuthzCheckRequestExample, RecoveryAuthzExamples,
    RecoveryAuthzResourceExample, RecoveryBackupEncryptionExample, RecoveryBackupItemExample,
    RecoveryBackupPayloadExample, RecoveryBridgeDescribe as RecoveryDescribeResponse,
    RecoveryClaimConstraintExample, RecoveryPolicyPayloadExample,
    RecoveryPolicyUpsertRequestExample, RecoveryRequiredClaimExample, RecoveryRestoreExamples,
    RecoveryRestoreStartRequestExample, RecoveryRestoreTicketAdvanceRequestExample,
    RecoveryRestoreTicketResponseShapeExample,
};

#[derive(Deserialize, ToSchema)]
pub struct StartRecoveryInput {
    pub email: String,
    /// Solved CAPTCHA token, supplied when the deployment has a CAPTCHA
    /// provider configured (`site.captcha`). Verified before the
    /// rate-limited recovery session is allocated.
    #[serde(default)]
    pub captcha_token: Option<String>,
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

/// Trait extension that produces the canonical scaffold payloads. The
/// inherent `scaffold()` constructors used to live on the inline backend
/// types; they cannot live on the shared `coauth_admin_types` shapes
/// (orphan rule), so they get promoted to a backend-side trait that the
/// recovery describe handler already imports through the prelude.
pub trait RecoveryExampleScaffold: Sized {
    fn scaffold() -> Self;
}

impl RecoveryExampleScaffold for RecoveryBackupPayloadExample {
    fn scaffold() -> Self {
        Self {
            schema: "cx.schema.key_backup.v1".to_string(),
            backup_id: "backup-scaffold-current-device".to_string(),
            backup_class: "mls_export".to_string(),
            encryption: RecoveryBackupEncryptionExample {
                alg: "xchacha20poly1305".to_string(),
                kdf: "argon2id".to_string(),
            },
            items: vec![RecoveryBackupItemExample {
                kind: "mls_group_state".to_string(),
                item_ref: "group:default".to_string(),
                todo: "replace scaffold payload with encrypted export blob".to_string(),
            }],
        }
    }
}

impl RecoveryExampleScaffold for RecoveryRestoreExamples {
    fn scaffold() -> Self {
        Self {
            restore_start_request: RecoveryRestoreStartRequestExample {
                backup_id: "backup-scaffold-current-device".to_string(),
                actor: "did:web:alice.example".to_string(),
                device_id: "device-web".to_string(),
                verification_event_kind: "cx.key.verification.done".to_string(),
                todo: "replace scaffold restore start with verified restore ticket handoff"
                    .to_string(),
            },
            restore_ticket_response_shape: RecoveryRestoreTicketResponseShapeExample {
                contract: "contrix.rest.key_backup_restore_ticket.v1".to_string(),
                lifecycle_state: "authz_pending".to_string(),
                allowed_next_transitions: vec![
                    "authz_checked".to_string(),
                    "policy_checked".to_string(),
                    "approved".to_string(),
                    "materialized".to_string(),
                ],
            },
            restore_ticket_advance_request: RecoveryRestoreTicketAdvanceRequestExample {
                transition: "authz_checked".to_string(),
                note: "replace scaffold transition with policy-backed approval state machine"
                    .to_string(),
            },
        }
    }
}

impl RecoveryExampleScaffold for RecoveryAuthzExamples {
    fn scaffold() -> Self {
        Self {
            authz_check_request: RecoveryAuthzCheckRequestExample {
                actor: "did:web:alice.example".to_string(),
                action: "keys.backups.restore".to_string(),
                space_id: "cx:space:01JS0SP000000000000000000".to_string(),
                resources: vec![RecoveryAuthzResourceExample {
                    kind: "blob".to_string(),
                    space_id: "cx:space:01JS0SP000000000000000000".to_string(),
                    blob_ref: "cx:blob:sha256:0123456789abcdef".to_string(),
                    object_type: "encrypted_backup".to_string(),
                    object_ref: "backup-scaffold-current-device".to_string(),
                    scope: Some("exact".to_string()),
                }],
                constraints: vec![RecoveryClaimConstraintExample {
                    constraint_type: "claim_based".to_string(),
                    subtype: "claim".to_string(),
                    effect: "allow".to_string(),
                    object_type_allow: vec!["key_backup".to_string()],
                    facet_allow: vec!["recovery".to_string()],
                    requires_claims: vec![RecoveryRequiredClaimExample {
                        claim_type: "recovery_operator".to_string(),
                        issuer: "did:web:coauth.example".to_string(),
                        organization: "example-org".to_string(),
                        status: "active".to_string(),
                        roles: vec!["backup_admin".to_string()],
                    }],
                }],
            },
            policy_upsert_request: RecoveryPolicyUpsertRequestExample {
                scope: "space".to_string(),
                subject_ref: "did:web:alice.example".to_string(),
                policy_type: "keys.backups.restore".to_string(),
                effect: "require_review".to_string(),
                payload: RecoveryPolicyPayloadExample {
                    actions: vec!["keys.backups.restore".to_string()],
                    resource: RecoveryAuthzResourceExample {
                        kind: "blob".to_string(),
                        space_id: "cx:space:01JS0SP000000000000000000".to_string(),
                        blob_ref: "cx:blob:sha256:0123456789abcdef".to_string(),
                        object_type: "encrypted_backup".to_string(),
                        object_ref: "backup-scaffold-current-device".to_string(),
                        scope: None,
                    },
                    constraints: vec![RecoveryApprovalConstraintExample {
                        constraint_type: "claim_based".to_string(),
                        subtype: "approval".to_string(),
                        effect: "require_review".to_string(),
                        approval_required: true,
                        approval_mode: "two_man_rule".to_string(),
                        approval_actor_refs: vec![
                            "did:web:controller.example".to_string(),
                            "did:web:guardian.example".to_string(),
                        ],
                        approval_relation: "controller".to_string(),
                    }],
                },
            },
        }
    }
}
