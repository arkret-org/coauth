//! Cokret device administration endpoints.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use chrono::{DateTime, Utc};
use coauth_data::audit::{AdminOperation, AdminOperationFilter};
use coauth_data::oauth::SessionGrantFilter;
use coauth_data::{Pagination, RepositoryAccess};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::handlers::admin::audit_helper::record_admin_operation;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::params::extract_ulid_param;
use crate::services::device_revoke::cascade_revoke_session_grants;
use crate::{AppError, JsonResult};

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceMfaState {
    Verified,
    Required,
    Unknown,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct DeviceRecord {
    /// Device identifier.
    id: String,

    /// Owning account ULID.
    account_id: Option<String>,

    /// Human-facing device label.
    display_name: Option<String>,

    /// Current device risk level.
    risk_level: DeviceRiskLevel,

    /// MFA/passkey state for this device.
    mfa_state: DeviceMfaState,

    /// When the device was registered.
    registered_at: Option<DateTime<Utc>>,

    /// When the device was revoked.
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct DeviceListResBody {
    data: Vec<DeviceRecord>,
}

#[derive(Deserialize, JsonSchema, ToSchema)]
#[serde(rename = "RevokeDeviceRequestBody")]
pub struct RevokeDeviceRequestBody {
    /// Operator-supplied reason for audit.
    pub reason: String,

    /// Optional approval proof for high-risk revocations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_proof: Option<String>,
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct DeviceRevokeOutcome {
    /// The device that was revoked.
    pub device: DeviceRecord,

    /// How many active session grants were cascade-revoked atomically.
    pub revoked_session_grants: usize,
}

struct DeviceDraft {
    id: String,
    account_id: Option<String>,
    display_name: Option<String>,
    registered_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl DeviceDraft {
    fn new(id: String) -> Self {
        Self {
            id,
            account_id: None,
            display_name: None,
            registered_at: None,
            revoked_at: None,
        }
    }

    fn into_record(self) -> DeviceRecord {
        DeviceRecord {
            id: self.id,
            account_id: self.account_id,
            display_name: self.display_name,
            risk_level: DeviceRiskLevel::Unknown,
            mfa_state: DeviceMfaState::Unknown,
            registered_at: self.registered_at,
            revoked_at: self.revoked_at,
        }
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.devices.list", skip_all)]
pub async fn list_devices(req: &mut Request, depot: &Depot) -> JsonResult<DeviceListResBody> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;

    let devices = aggregate_devices(&mut repo, None).await?;

    Ok(Json(DeviceListResBody {
        data: devices
            .into_values()
            .map(DeviceDraft::into_record)
            .collect(),
    }))
}

/// List the devices owned by a single account.
///
/// Reuses the same session-grant aggregation as the flat
/// `/_coauth/admin/devices` inventory, restricting the result to devices
/// whose owning account ULID matches the `{id}` path parameter.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.devices.list", skip_all)]
pub async fn list_account_devices(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<DeviceListResBody> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let account_id = extract_ulid_param(req)?;

    // 404 if the account does not exist, mirroring the other
    // accounts/{id}/* sub-routes.
    if repo.user().lookup(account_id).await?.is_none() {
        return Err(AppError::not_found(format!(
            "Account ID {account_id} not found"
        )));
    }

    let devices = aggregate_devices(&mut repo, Some(account_id)).await?;

    Ok(Json(DeviceListResBody {
        data: devices
            .into_values()
            .map(DeviceDraft::into_record)
            .collect(),
    }))
}

/// Aggregate device drafts from active session grants.
///
/// When `account_filter` is `Some`, only devices owned by that account ULID
/// are retained. The owning account is resolved via the browser session
/// behind each session grant, exactly as the flat inventory does.
async fn aggregate_devices(
    repo: &mut coauth_data::BoxRepository,
    account_filter: Option<Ulid>,
) -> Result<BTreeMap<String, DeviceDraft>, coauth_data::RepositoryError> {
    let mut devices = BTreeMap::<String, DeviceDraft>::new();
    let mut after = None;

    loop {
        let mut pagination = Pagination::first(100);
        if let Some(cursor) = after {
            pagination = pagination.after(cursor);
        }

        // Push the owning-account constraint down to the query layer so we
        // only page grants for the target account instead of scanning the
        // whole table and resolving each owner in memory.
        let mut filter = SessionGrantFilter::new();
        if let Some(wanted) = account_filter {
            filter = filter.for_account(wanted);
        }

        let page = repo.oauth_session_grant().list(filter, pagination).await?;
        let has_next = page.has_next_page;

        for edge in page.edges {
            after = Some(edge.cursor);
            let grant = edge.node;
            let Some(device_id) = grant.device_id.clone() else {
                continue;
            };

            // When `account_filter` is set the query already restricted the
            // page to that account, so the owner is known without a lookup.
            // Otherwise resolve it once per grant to populate the draft.
            let owner = if let Some(wanted) = account_filter {
                Some(wanted)
            } else if let Some(browser_session_id) = grant.browser_session_id {
                repo.browser_session()
                    .lookup(browser_session_id)
                    .await?
                    .map(|browser_session| browser_session.user.id)
            } else {
                None
            };

            let entry = match devices.entry(device_id.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(DeviceDraft::new(device_id)),
            };
            entry.registered_at = Some(
                entry
                    .registered_at
                    .map_or(grant.created_at, |current| current.min(grant.created_at)),
            );

            if entry.account_id.is_none()
                && let Some(owner) = owner
            {
                entry.account_id = Some(owner.to_string());
            }
        }

        if !has_next {
            break;
        }
    }

    apply_device_revocation_audit(repo, &mut devices).await?;

    Ok(devices)
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.devices.revoke", skip_all)]
pub async fn revoke_device(req: &mut Request, depot: &Depot) -> JsonResult<DeviceRevokeOutcome> {
    let device_id = req
        .param::<String>("id")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::bad_request("missing device id"))?;
    let body: RevokeDeviceRequestBody = req.parse_json().await.map_err(AppError::internal)?;
    let reason = body.reason.trim().to_owned();
    if reason.is_empty() {
        return Err(AppError::bad_request("reason is required"));
    }

    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let Some(admin_user) = admin_user.as_ref() else {
        return Err(AppError::forbidden(
            "device revocation requires an authenticated admin user for audit",
        ));
    };
    // High-risk: a supplied approval_proof MUST be a real detached JWS
    // bound to the admin DID over the canonical revocation transcript;
    // a forged/garbage proof is rejected rather than logged as a boolean.
    let approval_verification_method =
        crate::handlers::admin::v1::revocation_approval::verify_revocation_approval_proof(
            depot,
            &mut repo,
            admin_user,
            "device.revoke",
            &device_id,
            None,
            &reason,
            body.approval_proof.as_deref(),
        )
        .await?;
    let mut rng = crate::handlers::account::make_rng();

    // Cascade-revoke every active session grant tied to this device, in
    // the same repository transaction as the audit-log entry. Either both
    // succeed (`repo.save()` below) or both roll back.
    let outcome = cascade_revoke_session_grants(&mut repo, &*clock, &device_id)
        .await
        .map_err(AppError::internal)?;

    record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        Some(admin_user),
        AdminOperation::Other("device.revoke".to_owned()),
        "device",
        None,
        serde_json::json!({
            "device_id": device_id,
            "reason": reason,
            "approval_proof_present": body.approval_proof.is_some(),
            "approval_verification_method": approval_verification_method,
            "revoked_session_grants": outcome.revoked_session_grants,
            "revoked_at": outcome.revoked_at,
        }),
    )
    .await?;
    repo.save().await?;

    Ok(Json(DeviceRevokeOutcome {
        device: DeviceRecord {
            id: device_id,
            account_id: None,
            display_name: None,
            risk_level: DeviceRiskLevel::Unknown,
            mfa_state: DeviceMfaState::Unknown,
            registered_at: None,
            revoked_at: Some(outcome.revoked_at),
        },
        revoked_session_grants: outcome.revoked_session_grants,
    }))
}

/// Revoke a single device belonging to a specific account.
///
/// Same cascade as the flat `/_coauth/admin/devices/{id}/revoke` endpoint,
/// but scoped under `accounts/{id}`: the account ULID is validated and
/// recorded in the audit log alongside the device id. The device id is the
/// `{device_id}` path parameter (the account is `{id}`).
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.accounts.devices.revoke", skip_all)]
pub async fn revoke_account_device(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<DeviceRevokeOutcome> {
    let account_id = extract_ulid_param(req)?;
    let device_id = req
        .param::<String>("device_id")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::bad_request("missing device id"))?;
    let body: RevokeDeviceRequestBody = req.parse_json().await.map_err(AppError::internal)?;
    let reason = body.reason.trim().to_owned();
    if reason.is_empty() {
        return Err(AppError::bad_request("reason is required"));
    }

    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let Some(admin_user) = admin_user.as_ref() else {
        return Err(AppError::forbidden(
            "device revocation requires an authenticated admin user for audit",
        ));
    };
    if repo.user().lookup(account_id).await?.is_none() {
        return Err(AppError::not_found(format!(
            "Account ID {account_id} not found"
        )));
    }
    // High-risk: a supplied approval_proof MUST be a real detached JWS
    // bound to the admin DID over the canonical revocation transcript.
    let approval_verification_method =
        crate::handlers::admin::v1::revocation_approval::verify_revocation_approval_proof(
            depot,
            &mut repo,
            admin_user,
            "device.revoke",
            &device_id,
            Some(&account_id.to_string()),
            &reason,
            body.approval_proof.as_deref(),
        )
        .await?;
    let mut rng = crate::handlers::account::make_rng();

    // Same atomic cascade as the flat endpoint: device-revoke audit entry +
    // every active session grant for the device, committed together.
    let outcome = cascade_revoke_session_grants(&mut repo, &*clock, &device_id)
        .await
        .map_err(AppError::internal)?;

    record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        Some(admin_user),
        AdminOperation::Other("device.revoke".to_owned()),
        "device",
        None,
        serde_json::json!({
            "account_id": account_id.to_string(),
            "device_id": device_id,
            "reason": reason,
            "approval_proof_present": body.approval_proof.is_some(),
            "approval_verification_method": approval_verification_method,
            "revoked_session_grants": outcome.revoked_session_grants,
            "revoked_at": outcome.revoked_at,
        }),
    )
    .await?;
    repo.save().await?;

    Ok(Json(DeviceRevokeOutcome {
        device: DeviceRecord {
            id: device_id,
            account_id: Some(account_id.to_string()),
            display_name: None,
            risk_level: DeviceRiskLevel::Unknown,
            mfa_state: DeviceMfaState::Unknown,
            registered_at: None,
            revoked_at: Some(outcome.revoked_at),
        },
        revoked_session_grants: outcome.revoked_session_grants,
    }))
}

async fn apply_device_revocation_audit(
    repo: &mut coauth_data::BoxRepository,
    devices: &mut BTreeMap<String, DeviceDraft>,
) -> Result<(), coauth_data::RepositoryError> {
    let logs = repo
        .audit()
        .list_admin_operations(
            AdminOperationFilter::new()
                .for_resource_type("device")
                .with_limit(1000),
        )
        .await?;

    for log in logs {
        if log.operation != AdminOperation::Other("device.revoke".to_owned()) {
            continue;
        }
        let Some(device_id) = log.details.get("device_id").and_then(|v| v.as_str()) else {
            continue;
        };
        let revoked_at = log
            .details
            .get("revoked_at")
            .and_then(|v| serde_json::from_value::<DateTime<Utc>>(v.clone()).ok())
            .unwrap_or(log.created_at);

        let entry = match devices.entry(device_id.to_owned()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(DeviceDraft::new(device_id.to_owned())),
        };
        entry.revoked_at = Some(
            entry
                .revoked_at
                .map_or(revoked_at, |current| current.max(revoked_at)),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use coauth_data::Clock;
    use coauth_data::oauth::NewSessionGrant;
    use coauth_oauth_types::scope::Scope;
    use hyper::{Request, StatusCode};

    use super::*;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[test]
    fn device_draft_does_not_synthesize_device_did() {
        // A device is not a DID subject: even when the id has a `did:`
        // shape, `DeviceDraft` no longer derives any device_did (that
        // field was removed). A device only has a device_id.
        let record = DeviceDraft::new("did:web:device.example".to_owned()).into_record();

        assert_eq!(record.id, "did:web:device.example");
        assert!(record.revoked_at.is_none());
    }

    #[test]
    fn device_draft_keeps_earliest_registration_and_latest_revoke() {
        let first = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let second = Utc.timestamp_opt(1_700_100_000, 0).unwrap();
        let mut draft = DeviceDraft::new("device-1".to_owned());

        draft.registered_at = Some(second);
        draft.registered_at = Some(draft.registered_at.unwrap().min(first));
        draft.revoked_at = Some(first);
        draft.revoked_at = Some(draft.revoked_at.unwrap().max(second));

        let record = draft.into_record();
        assert_eq!(record.registered_at, Some(first));
        assert_eq!(record.revoked_at, Some(second));
    }

    #[tokio::test]
    async fn device_inventory_lists_and_revokes_persisted_session_grant_devices() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*state.clock, "device-admin-alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(
                &mut rng,
                &*state.clock,
                &user,
                Some("test-agent".to_owned()),
            )
            .await
            .unwrap();
        let scope: Scope = "urn:cokret:principal-server:session.bind".parse().unwrap();
        let grant = repo
            .oauth_session_grant()
            .add(
                &mut rng,
                &*state.clock,
                NewSessionGrant {
                    grant_id: cokret_core::GrantId::new(
                        "ck:grant:0196419b-0000-7000-8000-000000000203".to_owned(),
                    )
                    .unwrap(),
                    browser_session_id: Some(browser_session.id),
                    issuer: "did:web:auth.example",
                    subject: "did:web:alice.example",
                    device_id: Some("device-1"),
                    applet_id: None,
                    effective_scope: None,
                    registration_epoch: None,
                    service_did: None,
                    capability_grant_refs: Vec::new(),
                    audience: "https://principal.example/api",
                    scope,
                    grant_jwt: "device-1.jwt",
                    session_public_key: "{\"kty\":\"OKP\"}",
                    expires_at: state.clock.now() + chrono::Duration::try_minutes(5).unwrap(),
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let response = state
            .request(
                Request::get("/_coauth/admin/devices")
                    .bearer(&token)
                    .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"][0]["id"], "device-1");
        assert_eq!(body["data"][0]["account_id"], user.id.to_string());
        assert!(body["data"][0]["registered_at"].is_string());
        assert_eq!(body["data"][0]["revoked_at"], serde_json::Value::Null);

        let response = state
            .request(
                Request::post("/_coauth/admin/devices/device-1/revoke")
                    .bearer(&token)
                    .json(serde_json::json!({ "reason": "lost device" })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["device"]["id"], "device-1");
        assert_eq!(body["revoked_session_grants"], 1);

        let mut repo = state.repository().await.unwrap();
        let revoked = repo
            .oauth_session_grant()
            .lookup(grant.id)
            .await
            .unwrap()
            .unwrap();
        assert!(revoked.revoked_at.is_some());
        repo.cancel().await.unwrap();
    }
}
