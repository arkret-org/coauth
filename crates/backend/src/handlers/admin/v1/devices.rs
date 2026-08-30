//! Arkret device administration endpoints.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use chrono::{DateTime, Utc};
use coauth_admin_types::{
    DeviceListResBody, DeviceMfaState, DeviceRecord, DeviceRevokeOutcome, DeviceRiskLevel,
    RevokeDeviceRequestBody,
};
use coauth_data::audit::{AdminOperation, AdminOperationFilter};
use coauth_data::oauth::SessionGrantFilter;
use coauth_data::{Pagination, RepositoryAccess};
use salvo::prelude::*;
use ulid::Ulid;

use crate::handlers::admin::audit_helper::record_admin_operation;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::params::extract_ulid_param;
use crate::services::device_revoke::cascade_revoke_session_grants;
use crate::{AppError, JsonResult};

const DESTRUCTIVE_REASON_MAX_CHARS: usize = 512;

fn validate_destructive_reason(reason: &str) -> Result<String, AppError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::bad_request("reason is required"));
    }
    if reason.chars().count() > DESTRUCTIVE_REASON_MAX_CHARS {
        return Err(AppError::bad_request(
            "reason must not exceed 512 characters",
        ));
    }
    if reason.chars().any(char::is_control) {
        return Err(AppError::bad_request("reason must be a single line"));
    }

    let lower = reason.to_ascii_lowercase();
    const SENSITIVE_MARKERS: &[&str] = &[
        "-----begin private key",
        "authorization:",
        "bearer ey",
        "password=",
        "secret=",
        "token=",
    ];
    if SENSITIVE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return Err(AppError::bad_request(
            "reason must not contain credentials or secrets",
        ));
    }
    Ok(reason.to_owned())
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
    let reason = validate_destructive_reason(&body.reason)?;

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
    let reason = validate_destructive_reason(&body.reason)?;

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
    use hyper::{Request, StatusCode};

    use super::*;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[test]
    fn destructive_reason_policy_rejects_secrets_and_multiline_text() {
        assert!(validate_destructive_reason("SEC-1234 lost device").is_ok());
        assert!(validate_destructive_reason("first\nsecond").is_err());
        assert!(validate_destructive_reason("token=secret-value").is_err());
        assert!(validate_destructive_reason(&"x".repeat(513)).is_err());
    }

    #[test]
    fn device_draft_does_not_synthesize_device_did() {
        // A device is not a DID subject. `DeviceDraft` no longer derives any
        // device DID; a device only has its typed device id.
        let record = DeviceDraft::new("ak:device:0196419b-0000-7000-8000-000000000006".to_owned())
            .into_record();

        assert_eq!(record.id, "ak:device:0196419b-0000-7000-8000-000000000006");
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
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
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
        let device_id = "ak:device:0196419b-0000-7000-8000-000000000006";
        let grant_config = coauth_config::ArkretConfig {
            deployment_profile: coauth_config::DeploymentProfileConfig::PersonalNode,
            principal_method: coauth_config::PrincipalMethodConfig::DidWeb,
            runtime_service_identity: coauth_config::RuntimeServiceIdentity::fixture(
                "did:web:auth.example",
            ),
            // Session-grant audiences are Station core DIDs.
            admin_audience: Some("ak:did_core:web:principal.example.com".to_owned()),
            ..coauth_config::ArkretConfig::default()
        };
        let session_private = coauth_keystore::PrivateKey::generate_ed25519(&mut rng);
        let session_public = coauth_jose::jwk::PublicJsonWebKey::new(
            coauth_jose::jwk::JsonWebKeyPublicParameters::from(&session_private),
        );
        let principal_id = "ak:did_core:web:alice.example";
        let station_id =
            crate::handlers::arkret::required_audience_for(&state.url_builder, &grant_config);
        let account_id = arkret_wire::AccountId::new(
            arkret_identifiers::DidCoreId::new(principal_id).unwrap(),
            arkret_identifiers::DidCoreId::new(station_id).unwrap(),
        );
        // The revoke cascade selects grants active at the wall clock, so the
        // seeded grant has to be minted against the same clock; one minted at
        // the mock epoch is already years expired.
        let grant_clock = coauth_data::SystemClock::default();
        let material = crate::handlers::arkret::issue_session_grant(
            &mut rng,
            &grant_clock,
            &state.url_builder,
            &grant_config,
            &state.key_store,
            &browser_session,
            session_public,
            principal_id,
            &account_id,
            arkret_identifiers::DeviceId::new(device_id.to_owned()).unwrap(),
            vec![
                crate::handlers::arkret::STATION_SESSION_BIND_SCOPE.to_owned(),
                format!("urn:arkret:client:device:{device_id}"),
            ],
        )
        .unwrap();
        let grant = crate::handlers::arkret::persist_session_grant(
            &mut repo,
            &mut rng,
            &grant_clock,
            &browser_session,
            &material,
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
        assert_eq!(body["data"][0]["id"], device_id);
        assert_eq!(body["data"][0]["account_id"], user.id.to_string());
        assert!(body["data"][0]["registered_at"].is_string());
        assert_eq!(body["data"][0]["revoked_at"], serde_json::Value::Null);

        let response = state
            .request(
                Request::post(format!("/_coauth/admin/devices/{device_id}/revoke"))
                    .bearer(&token)
                    .json(serde_json::json!({ "reason": "lost device" })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["device"]["id"], device_id);
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
