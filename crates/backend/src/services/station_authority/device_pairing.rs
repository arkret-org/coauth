//! Actual issuer-owned device-pairing stage, resolution and terminal status.
use arkret_models_collaboration::device_pairing::{
    DevicePairingBootstrap, DevicePairingCode, DevicePairingNonce, DevicePairingRequestId,
    DevicePairingResolveRequestBody, DevicePairingStageRequestBody, DevicePairingStageResponseBody,
    DevicePairingState, DevicePairingStatusRequestBody, DevicePairingStatusResponseBody,
};
use arkret_wire::Hash;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::Duration;
use coauth_data::{
    DevicePairingAdmissionState, DevicePairingStageInsert, NewDevicePairingPendingRecord,
};
use rand_core::RngCore;
use salvo::http::StatusCode;

use crate::handlers::arkret::ArkretRouteError;

const PAIRING_TTL: Duration = Duration::minutes(10);
const PAIRING_TOMBSTONE_RETENTION: Duration = Duration::hours(24);
const PAIRING_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub(crate) fn mint_pairing_code(rng: &mut (impl RngCore + ?Sized)) -> DevicePairingCode {
    let mut bytes = [0_u8; 8];
    rng.fill_bytes(&mut bytes);
    let code: String = bytes
        .into_iter()
        .map(|byte| PAIRING_CODE_ALPHABET[usize::from(byte & 31)] as char)
        .collect();
    DevicePairingCode::new(code).expect("closed pairing-code alphabet")
}

pub(crate) fn mint_nonce(rng: &mut (impl RngCore + ?Sized)) -> DevicePairingNonce {
    let mut bytes = [0_u8; 32];
    rng.fill_bytes(&mut bytes);
    DevicePairingNonce::new(Base64UrlUnpadded::encode_string(&bytes))
        .expect("32-byte base64url nonce")
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct DevicePairingToken {
    r: DevicePairingRequestId,
    c: DevicePairingCode,
}

pub(crate) fn parse_device_pairing_token(
    token: &str,
) -> Result<(DevicePairingRequestId, DevicePairingCode), ArkretRouteError> {
    let bytes = Base64UrlUnpadded::decode_vec(token).map_err(|_| internal_not_found())?;
    let value: DevicePairingToken =
        serde_json::from_slice(&bytes).map_err(|_| internal_not_found())?;
    let canonical =
        arkret_canonical::canonical_json_bytes(&value).map_err(|_| internal_not_found())?;
    if canonical != bytes {
        return Err(internal_not_found());
    }
    Ok((value.r, value.c))
}

pub(crate) fn valid_stage_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~:-".contains(&byte))
}

pub(crate) async fn stage(
    body: DevicePairingStageRequestBody,
    stage_idempotency_key: String,
    context: &super::Context<'_>,
) -> Result<Vec<u8>, ArkretRouteError> {
    if !valid_stage_idempotency_key(&stage_idempotency_key) {
        return Err(internal_not_found());
    }
    let canonical_request = arkret_canonical::canonical_json_bytes(&body)?;
    let stage_request_digest = Hash::new(arkret_canonical::sha256_digest(&canonical_request))?;
    let clock = crate::handlers::make_clock();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let expires_at = now + PAIRING_TTL;
    let gate_audience_uri = context.account_authority_origin.clone();
    let mut rng = crate::handlers::make_rng();
    let mut repo = context.repository_factory.create().await?;

    for _ in 0..8 {
        let device_pairing_request_id = DevicePairingRequestId::new(format!(
            "device_pairing_request:{}",
            uuid::Uuid::now_v7()
        ))?;
        let pairing_code = mint_pairing_code(&mut *rng);
        let server_nonce = mint_nonce(&mut *rng);
        let outcome = DevicePairingStageResponseBody {
            device_pairing_request_id: device_pairing_request_id.clone(),
            pairing_code: pairing_code.clone(),
            gate_audience_uri: gate_audience_uri.clone(),
            server_nonce: server_nonce.clone(),
            expires_at,
        };
        let bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
        let inserted = repo
            .account_handoff()
            .insert_device_pairing_stage(NewDevicePairingPendingRecord {
                stage_idempotency_key: stage_idempotency_key.clone(),
                stage_request_digest: stage_request_digest.clone(),
                stage_outcome: bytes.clone(),
                device_pairing_request_id,
                pairing_code,
                new_device_public_key: body.new_device_public_key.clone(),
                client_nonce: body.client_nonce.clone(),
                display_name: body.display_name.clone(),
                device_metadata: body.device_metadata.clone(),
                gate_audience_uri: gate_audience_uri.clone(),
                server_nonce,
                expires_at,
                retained_until: expires_at + PAIRING_TOMBSTONE_RETENTION,
                created_at: now,
            })
            .await?;
        match inserted {
            DevicePairingStageInsert::Inserted => {
                repo.save().await?;
                return Ok(bytes);
            }
            DevicePairingStageInsert::Replay(bytes) => {
                repo.cancel().await.ok();
                return Ok(bytes);
            }
            DevicePairingStageInsert::DuplicateConflict => {
                repo.cancel().await.ok();
                return Err(duplicate_conflict());
            }
            DevicePairingStageInsert::IdentifierCollision => {}
        }
    }

    repo.cancel().await.ok();
    Err(ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE,
        "could not mint a unique live device-pairing credential",
    ))
}

pub(crate) async fn resolve(
    context: &super::Context<'_>,
    body: DevicePairingResolveRequestBody,
) -> Result<Vec<u8>, ArkretRouteError> {
    let (request_id, pairing_code) = parse_device_pairing_token(body.pairing_token.as_str())?;
    let now = arkret_canonical::normalize_timestamp_canonical(crate::handlers::make_clock().now());
    let mut repo = context.repository_factory.read().await?;
    let record = repo
        .account_handoff()
        .get_device_pairing_stage(&request_id)
        .await?
        .filter(|record| {
            record.pairing_code == pairing_code
                && record.state == DevicePairingState::ReadyForClaim
                && record.admission.is_none()
                && record.expires_at > now
        })
        .ok_or_else(internal_not_found)?;
    let station_origin = context
        .config
        .owning_station()
        .map(|station| station.endpoint.origin().ascii_serialization())
        .ok_or_else(internal_not_found)?;
    let outcome = DevicePairingBootstrap {
        arkret_base_url: station_origin,
        device_pairing_request_id: record.device_pairing_request_id,
        pairing_code: record.pairing_code,
        new_device_public_key: record.new_device_public_key,
        client_nonce: record.client_nonce,
        gate_audience_uri: record.gate_audience_uri,
        server_nonce: record.server_nonce,
        display_name: record.display_name,
        device_metadata: record.device_metadata,
        expires_at: record.expires_at,
    };
    let bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
    repo.cancel().await.ok();
    Ok(bytes)
}
pub(crate) async fn status(
    context: &super::Context<'_>,
    body: DevicePairingStatusRequestBody,
) -> Result<Vec<u8>, ArkretRouteError> {
    let now = arkret_canonical::normalize_timestamp_canonical(crate::handlers::make_clock().now());
    let mut repo = context.repository_factory.read().await?;
    let record = repo
        .account_handoff()
        .get_device_pairing_stage(&body.device_pairing_request_id)
        .await?
        .filter(|record| record.pairing_code == body.pairing_code)
        .ok_or_else(internal_not_found)?;
    if record
        .admission
        .as_ref()
        .is_some_and(|admission| admission.state != DevicePairingAdmissionState::Completed)
    {
        repo.cancel().await.ok();
        return Err(internal_not_found());
    }
    let public_state = if record.state != DevicePairingState::Authorized && record.expires_at <= now
    {
        DevicePairingState::Expired
    } else {
        record.state
    };
    let authorized = public_state == DevicePairingState::Authorized;
    let outcome = DevicePairingStatusResponseBody {
        state: public_state,
        device_id: authorized.then_some(record.authorized_device_id).flatten(),
        authorized_event_ref: authorized.then_some(record.authorized_event_ref).flatten(),
    };
    outcome.validate().map_err(|_| internal_not_found())?;
    let bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
    repo.cancel().await.ok();
    Ok(bytes)
}
fn duplicate_conflict() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
        "Idempotency-Key was reused with a different canonical stage request",
    )
}

fn internal_not_found() -> ArkretRouteError {
    ArkretRouteError::NotFound
}
