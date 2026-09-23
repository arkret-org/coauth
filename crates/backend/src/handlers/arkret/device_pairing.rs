//! Account Authority-owned device-pairing stage, finalize and code-claim boundary.

use std::collections::BTreeSet;

use arkret_identity::{
    DidBindingPurpose, RealmAuthorityFreshness, RealmAuthorityKeyMap, verify_realm_authority_bundle,
};
use arkret_models_collaboration::device_pairing::{
    AccountDevicePairOutcome, AccountDevicePairRequestBody, DevicePairingBootstrap,
    DevicePairingCode, DevicePairingCodeClaimOutcome, DevicePairingCodeClaimRequestBody,
    DevicePairingFinalizeOutcome, DevicePairingFinalizeRequestBody, DevicePairingNonce,
    DevicePairingRequestId, DevicePairingResolveRequestBody, DevicePairingStageOutcome,
    DevicePairingStageRequestBody, DevicePairingState, DevicePairingStatusOutcome,
    DevicePairingStatusRequestBody, DevicePairingTargetKeyAlgorithm, DevicePairingTargetProof,
};
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_models_identity::{
    AccountHandoffAllowedOperation, SessionGrantCredentialClass, SessionGrantHolderBinding,
    SignedSessionGrantClaims,
};
use arkret_signatures::device_pairing::{
    ServerDevicePairingChallenge, verify_server_device_pairing_target_proof,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthorityCommitStatus, AuthorityRejectionStatus, Base64UrlString,
    CommitStreamRef, CommittedEventRef, DidUrl, Hash,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::Duration;
use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
use coauth_data::{
    Clock as _, DevicePairingAdmissionCommit, DevicePairingAdmissionReserve,
    DevicePairingAdmissionState, DevicePairingFinalizeCommit, DevicePairingPendingRecord,
    DevicePairingStageInsert, NewDevicePairingAdmission, NewDevicePairingPendingRecord,
    RepositoryAccess,
};
use coauth_jose::jwt::Jwt;
use rand_core::RngCore;
use salvo::prelude::*;

use super::account_handoff::{proof_invalid, random_opaque};
use super::session_grant::acquire_private_current_device_binding;
use super::{ArkretCanonicalJson, ArkretRouteError, authenticate_account_handoff};
use crate::handlers::common::{DepotExt as _, extract_bound_activity_tracker};
use crate::services::did_binding;
use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};
use crate::services::peer_protocol_client::{
    InternalAuthorityChannel, PeerProtocolClient, PeerProtocolClientError,
};

const PAIRING_TTL: Duration = Duration::minutes(10);
const PAIRING_TOMBSTONE_RETENTION: Duration = Duration::hours(24);
const PAIRING_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const PRIVATE_EVENT_ADMISSION_PATH: &str = "/_soland/account-authority/events/admit";

fn mint_pairing_code(rng: &mut (impl RngCore + ?Sized)) -> DevicePairingCode {
    let mut bytes = [0_u8; 8];
    rng.fill_bytes(&mut bytes);
    let code: String = bytes
        .into_iter()
        .map(|byte| PAIRING_CODE_ALPHABET[usize::from(byte & 31)] as char)
        .collect();
    DevicePairingCode::new(code).expect("closed pairing-code alphabet")
}

fn mint_nonce(rng: &mut (impl RngCore + ?Sized)) -> DevicePairingNonce {
    DevicePairingNonce::new(random_opaque(rng, 32)).expect("32-byte base64url nonce")
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct DevicePairingToken {
    r: DevicePairingRequestId,
    c: DevicePairingCode,
}

fn parse_device_pairing_token(
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

fn valid_stage_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~:-".contains(&byte))
}

/// `ak.open.device_pairing.command.stage.v1`.
#[handler]
pub async fn stage_device_pairing(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let body: DevicePairingStageRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    // A direct public ingress is intentionally not retry-safe. In a combined
    // deployment it still enters the same Authority-owned ledger, with a
    // fresh private key that cannot accidentally deduplicate a later public
    // invocation.
    let internal_key = format!("direct:{}", uuid::Uuid::now_v7());
    stage_device_pairing_with_key(body, internal_key, depot).await
}

async fn stage_device_pairing_with_key(
    body: DevicePairingStageRequestBody,
    stage_idempotency_key: String,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let canonical_request = arkret_canonical::canonical_json_bytes(&body)?;
    let stage_request_digest = Hash::new(arkret_canonical::sha256_digest(&canonical_request))?;
    let clock = crate::handlers::make_clock();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let expires_at = now + PAIRING_TTL;
    let gate_audience_uri = depot
        .url_builder()?
        .http_base()
        .origin()
        .ascii_serialization();
    let mut rng = crate::handlers::make_rng();
    let mut repo = depot.repo().await?;

    for _ in 0..8 {
        let device_pairing_request_id = DevicePairingRequestId::new(format!(
            "device_pairing_request:{}",
            uuid::Uuid::now_v7()
        ))?;
        let pairing_code = mint_pairing_code(&mut *rng);
        let server_nonce = mint_nonce(&mut *rng);
        let outcome = DevicePairingStageOutcome {
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
                new_device_pubkey: body.new_device_pubkey.clone(),
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
                return Ok(ArkretCanonicalJson(bytes));
            }
            DevicePairingStageInsert::Replay(bytes) => {
                repo.cancel().await.ok();
                return Ok(ArkretCanonicalJson(bytes));
            }
            DevicePairingStageInsert::DuplicateConflict => {
                repo.cancel().await.ok();
                return Err(duplicate_conflict());
            }
            DevicePairingStageInsert::IdentifierCollision => continue,
        }
    }

    repo.cancel().await.ok();
    Err(ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE,
        "could not mint a unique live device-pairing credential",
    ))
}

/// Implementation-private owning-Station adapter for the public stage
/// operation. This is not an Arkret operation and carries no protocol selector.
#[handler]
pub async fn private_stage_device_pairing_adapter(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    authenticate_private_pairing_adapter(req, depot)?;
    let body: DevicePairingStageRequestBody =
        req.parse_json().await.map_err(|_| internal_not_found())?;
    let idempotency_key = super::account_status::required_header(req, "idempotency-key")?;
    if !valid_stage_idempotency_key(&idempotency_key) {
        return Err(internal_not_found());
    }
    stage_device_pairing_with_key(body, idempotency_key, depot).await
}

/// Implementation-private owning-Station adapter for the public resolve
/// operation. It reads the Account Authority's sole pairing ledger.
#[handler]
pub async fn private_resolve_device_pairing_adapter(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    authenticate_private_pairing_adapter(req, depot)?;
    let body: DevicePairingResolveRequestBody =
        req.parse_json().await.map_err(|_| internal_not_found())?;
    let (request_id, pairing_code) = parse_device_pairing_token(body.pairing_token.as_str())?;
    let now = arkret_canonical::normalize_timestamp_canonical(crate::handlers::make_clock().now());
    let mut repo = depot.repo().await?;
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
    let station_origin = depot
        .arkret_config()?
        .owning_station()
        .map(|station| station.endpoint.origin().ascii_serialization())
        .ok_or_else(internal_not_found)?;
    let outcome = DevicePairingBootstrap {
        arkret_base_url: station_origin,
        device_pairing_request_id: record.device_pairing_request_id,
        pairing_code: record.pairing_code,
        new_device_pubkey: record.new_device_pubkey,
        client_nonce: record.client_nonce,
        gate_audience_uri: record.gate_audience_uri,
        server_nonce: record.server_nonce,
        display_name: record.display_name,
        device_metadata: record.device_metadata,
        expires_at: record.expires_at,
    };
    let bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
    repo.cancel().await.ok();
    Ok(ArkretCanonicalJson(bytes))
}

/// Implementation-private owning-Station adapter for the public status
/// operation. Non-terminal journal state remains non-enumerating.
#[handler]
pub async fn private_device_pairing_status_adapter(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    authenticate_private_pairing_adapter(req, depot)?;
    let body: DevicePairingStatusRequestBody =
        req.parse_json().await.map_err(|_| internal_not_found())?;
    let now = arkret_canonical::normalize_timestamp_canonical(crate::handlers::make_clock().now());
    let mut repo = depot.repo().await?;
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
    let outcome = DevicePairingStatusOutcome {
        state: public_state,
        device_id: authorized.then_some(record.authorized_device_id).flatten(),
        authorized_event_ref: authorized.then_some(record.authorized_event_ref).flatten(),
    };
    outcome.validate().map_err(|_| internal_not_found())?;
    let bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
    repo.cancel().await.ok();
    Ok(ArkretCanonicalJson(bytes))
}

fn authenticate_private_pairing_adapter(
    req: &Request,
    depot: &Depot,
) -> Result<(), ArkretRouteError> {
    let token = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .ok_or_else(internal_not_found)?;
    crate::handlers::arkret::station_internal_channel_caller(&depot.arkret_config()?, token)
        .map(|_| ())
        .ok_or_else(internal_not_found)
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

/// `ak.gate.account.command.finalize_device_pairing.v1`.
#[handler]
pub async fn finalize_device_pairing(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let (handoff, dpop) = authenticate_account_handoff(
        req,
        depot,
        AccountHandoffAllowedOperation::FinalizeDevicePairing,
    )
    .await?;
    let requester = extract_bound_activity_tracker(req, depot).requester_fingerprint();
    depot
        .limiter()?
        .check_device_pairing(requester, handoff.local_account_id, &dpop.jkt)
        .await
        .map_err(|_| ArkretRouteError::rate_limited("device pairing is rate limited", 60_000))?;
    let body: DevicePairingFinalizeRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    let request_digest = Hash::new(arkret_canonical::canonical_sha256(&body)?)?;
    let clock = crate::handlers::make_clock();
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());

    let mut repo = depot.repo().await?;
    let user = repo
        .user()
        .lookup(handoff.local_account_id)
        .await?
        .ok_or(ArkretRouteError::NotFound)?;
    let binding = repo
        .principal_did()
        .get_for_user_and_audience(&user, &handoff.audience_id)
        .await?
        .ok_or(ArkretRouteError::NotFound)?;
    let record = repo
        .account_handoff()
        .get_device_pairing_stage(&body.device_pairing_request_id)
        .await?;
    let Some(record) = record else {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::NotFound);
    };
    if body.target_proof.account_id != binding.account_id {
        repo.account_handoff()
            .record_device_pairing_failure(&body.device_pairing_request_id, now)
            .await?;
        repo.save().await?;
        return Err(proof_invalid(
            "device pairing target proof account_id does not match the authenticated handoff",
        ));
    }
    if record.pairing_code != body.pairing_code
        || (record.state == DevicePairingState::Staged && record.expires_at <= now)
    {
        repo.account_handoff()
            .record_device_pairing_failure(&body.device_pairing_request_id, now)
            .await?;
        repo.save().await?;
        return Err(ArkretRouteError::NotFound);
    }

    if record.state == DevicePairingState::Staged {
        let challenge = ServerDevicePairingChallenge {
            client_nonce: record.client_nonce.clone(),
            device_pairing_request_id: record.device_pairing_request_id.clone(),
            expires_at: record.expires_at,
            gate_audience_uri: record.gate_audience_uri.clone(),
            pairing_code: record.pairing_code.clone(),
            server_nonce: record.server_nonce.clone(),
            display_name: record.display_name.clone(),
            device_metadata: record.device_metadata.clone(),
        };
        if let Err(error) = verify_server_device_pairing_target_proof(
            &record.new_device_pubkey,
            &challenge,
            &binding.account_id,
            &body.target_proof,
            now,
        ) {
            repo.account_handoff()
                .record_device_pairing_failure(&body.device_pairing_request_id, now)
                .await?;
            repo.save().await?;
            return Err(proof_invalid(format!(
                "device pairing target proof is invalid: {error}"
            )));
        }
    }

    let outcome = DevicePairingFinalizeOutcome {
        device_pairing_request_id: body.device_pairing_request_id.clone(),
        state: DevicePairingState::ReadyForClaim,
        expires_at: record.expires_at,
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;
    let result = repo
        .account_handoff()
        .finalize_device_pairing(
            &body.device_pairing_request_id,
            &body.pairing_code,
            &binding.account_id,
            &body.target_proof,
            &request_digest,
            &canonical_outcome,
            now,
        )
        .await?;
    match result {
        DevicePairingFinalizeCommit::Committed(bytes) => {
            repo.save().await?;
            Ok(ArkretCanonicalJson(bytes))
        }
        DevicePairingFinalizeCommit::Replay(bytes) => {
            repo.cancel().await.ok();
            Ok(ArkretCanonicalJson(bytes))
        }
        DevicePairingFinalizeCommit::DuplicateConflict => {
            repo.save().await?;
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "device pairing request was already finalized with different canonical content",
            ))
        }
        DevicePairingFinalizeCommit::NotFound => {
            repo.save().await?;
            Err(ArkretRouteError::NotFound)
        }
    }
}

/// `ak.gate.account.command.pair_device.v1`.
#[handler]
pub async fn pair_device(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let authenticated = authenticate_current_device(req, depot, "device pairing").await?;
    let body: AccountDevicePairRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    let canonical_request = arkret_canonical::canonical_json_bytes(&body)?;
    let request_digest = Hash::new(arkret_canonical::sha256_digest(&canonical_request))?;
    let now = arkret_canonical::normalize_timestamp_canonical(crate::handlers::make_clock().now());

    let requester = extract_bound_activity_tracker(req, depot).requester_fingerprint();
    depot
        .limiter()?
        .check_device_pairing(
            requester,
            authenticated.local_account_id,
            authenticated.device_id.as_str(),
        )
        .await
        .map_err(|_| ArkretRouteError::rate_limited("device pairing is rate limited", 60_000))?;

    // A fenced retry is classified solely by the durable intent and holder.
    // It must not re-run mutable pending/proof checks or the EventWrite gate.
    let existing = {
        let mut repo = depot.repo().await?;
        let record = repo
            .account_handoff()
            .get_device_pairing_stage(&body.device_pairing_request_id)
            .await?;
        repo.cancel().await.ok();
        record
    };
    let Some(record) = existing else {
        return Err(ArkretRouteError::NotFound);
    };
    if let Some(admission) = record.admission.clone() {
        if admission.approving_account_id != authenticated.account_id
            || admission.approving_device_id != authenticated.device_id
            || admission.canonical_request_digest != request_digest
        {
            return Err(pairing_duplicate_conflict());
        }
        if admission.state == DevicePairingAdmissionState::Completed {
            return Ok(ArkretCanonicalJson(
                admission
                    .terminal_outcome_bytes
                    .ok_or_else(pairing_temporarily_unavailable)?,
            ));
        }
        return resume_device_pairing_admission(admission, depot, now).await;
    }

    let validated = match validate_pairing_intent(&record, &body, &authenticated, now) {
        Ok(validated) => validated,
        Err(error) => {
            let mut repo = depot.repo().await?;
            repo.account_handoff()
                .record_device_pairing_failure(&body.device_pairing_request_id, now)
                .await?;
            repo.save().await?;
            return Err(error);
        }
    };

    let intent_digest = Hash::new(arkret_canonical::canonical_sha256(&serde_json::json!({
        "operation_id": arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE_V1,
        "account_id": &authenticated.account_id,
        "device_id": &authenticated.device_id,
        "request": &body,
    }))?)?;
    let current_binding = acquire_private_current_device_binding(
        depot,
        &authenticated.account_id,
        authenticated.device_id.clone(),
        arkret_wire::DeviceRevocationAdmissionAction::EventWrite,
        Some(&authenticated.device_binding),
        None,
        intent_digest,
        now,
    )
    .await?;
    if current_binding != authenticated.device_binding {
        return Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::DEVICE_REVOKED,
            "device pairing approver is no longer the current accepted device",
        ));
    }

    let authority = load_current_realm_authority(depot, &validated.event.realm_id, now).await?;
    let config = depot.arkret_config()?;
    let target_station_id = super::owning_station_id_for(&config);
    if authority.verified.current_service_id() != &target_station_id
        || authority.bundle.current_service_id != target_station_id
    {
        return Err(pairing_temporarily_unavailable());
    }
    let expected_stream = CommitStreamRef::from_scope(
        &validated.event.scope_ref,
        Some(validated.event.realm_id.clone()),
    )
    .map_err(|_| proof_invalid("authorize Event has an invalid commit stream"))?;
    if authority.bundle.realm_stream_head.stream_ref != expected_stream {
        return Err(proof_invalid(
            "authorize Event does not target the current principal-control stream",
        ));
    }

    let authorize_event_bytes = arkret_canonical::canonical_json_bytes(&body.authorize_event)?;
    let admission = NewDevicePairingAdmission {
        device_pairing_request_id: body.device_pairing_request_id.clone(),
        pairing_code: body.pairing_code.clone(),
        approving_account_id: authenticated.account_id,
        approving_device_id: authenticated.device_id,
        canonical_request_digest: request_digest,
        canonical_request_bytes: canonical_request,
        authorize_event_bytes,
        authorize_event_id: validated.event.event_id.clone(),
        target_station_id,
        target_authority_generation: authority.bundle.current_generation,
        target_stream_head: authority.bundle.realm_stream_head,
    };
    let reserved = {
        let mut repo = depot.repo().await?;
        let result = repo
            .account_handoff()
            .reserve_device_pairing_admission(admission, now)
            .await?;
        match result {
            DevicePairingAdmissionReserve::Started(_)
            | DevicePairingAdmissionReserve::Resume(_) => repo.save().await?,
            _ => {
                repo.cancel().await.ok();
            }
        }
        result
    };
    match reserved {
        DevicePairingAdmissionReserve::Started(admission)
        | DevicePairingAdmissionReserve::Resume(admission) => {
            resume_device_pairing_admission(admission, depot, now).await
        }
        DevicePairingAdmissionReserve::Replay(bytes) => Ok(ArkretCanonicalJson(bytes)),
        DevicePairingAdmissionReserve::DuplicateConflict => Err(pairing_duplicate_conflict()),
        DevicePairingAdmissionReserve::NotFound => Err(ArkretRouteError::NotFound),
    }
}

struct ValidatedPairingIntent<'a> {
    event: &'a arkret_wire::Event,
}

fn validate_pairing_intent<'a>(
    record: &DevicePairingPendingRecord,
    body: &'a AccountDevicePairRequestBody,
    authenticated: &AuthenticatedCurrentDevice,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ValidatedPairingIntent<'a>, ArkretRouteError> {
    if record.state != DevicePairingState::ReadyForClaim
        || record.expires_at <= now
        || record.pairing_code != body.pairing_code
        || record.account_id.as_ref() != Some(&authenticated.account_id)
    {
        return Err(ArkretRouteError::NotFound);
    }
    if record.new_device_pubkey != body.new_device_pubkey
        || record.display_name.as_ref().map(|value| value.as_str()) != body.display_name.as_deref()
        || arkret_canonical::canonical_json_bytes(&record.device_metadata)?
            != arkret_canonical::canonical_json_bytes(&body.device_metadata)?
    {
        return Err(proof_invalid(
            "pair request does not reproduce the staged device material",
        ));
    }
    body.authorize_event.validate().map_err(|error| {
        proof_invalid(format!("authorize Event submission is invalid: {error}"))
    })?;
    arkret_schema::validate_event_for_submit(&body.authorize_event.event)
        .map_err(|error| proof_invalid(format!("authorize Event schema is invalid: {error}")))?;
    let event = &body.authorize_event.event;
    let digest_suite = arkret_canonical::digest_suite(event.event_id.digest_suite_code().as_str())
        .map_err(|error| {
            proof_invalid(format!("authorize Event digest suite is invalid: {error}"))
        })?;
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| proof_invalid(format!("authorize Event id is invalid: {error}")))?;
    if event.actor_id.as_account_id() != Some(&authenticated.account_id)
        || event.realm_id != authenticated.principal_control_realm_id
    {
        return Err(proof_invalid(
            "authorize Event actor or principal-control Realm does not match the approver",
        ));
    }
    let payload = DeviceAuthorizePayload::try_from(event)
        .map_err(|error| proof_invalid(error.to_string()))?;
    if payload.authorization_binding_kind != DeviceAuthorizationBindingKind::AcceptedDevice
        || !matches!(
            &payload.authorized_by,
            DeviceOrPrincipalRef::DeviceId(device_id) if device_id == &authenticated.device_id
        )
    {
        return Err(proof_invalid(
            "authorize Event is not bound to the approving accepted device",
        ));
    }
    let target_proof = DevicePairingTargetProof {
        account_id: authenticated.account_id.clone(),
        device_id: payload.device_id.clone(),
        device_public_key_did: arkret_wire::DidKey::new(
            payload.device_public_key_did.as_str().to_owned(),
        )
        .map_err(|error| proof_invalid(error.to_string()))?,
        hpke_key: payload.hpke_key.clone(),
        algorithms: payload.algorithms.clone(),
        device_key_algorithm: DevicePairingTargetKeyAlgorithm::Ed25519,
        authorization_binding_kind: payload.authorization_binding_kind,
        pairing_challenge_transcript_digest: payload
            .pairing_challenge_transcript_digest
            .clone()
            .ok_or_else(|| proof_invalid("authorize Event omits the pairing transcript digest"))?,
        device_signature: payload.device_signature.clone(),
    };
    let stored_proof = record
        .target_proof
        .as_ref()
        .ok_or_else(|| proof_invalid("finalized pairing request has no target proof"))?;
    if arkret_canonical::canonical_json_bytes(&target_proof)?
        != arkret_canonical::canonical_json_bytes(stored_proof)?
    {
        return Err(proof_invalid(
            "authorize Event target proof is not byte-equivalent to finalize",
        ));
    }
    let challenge = ServerDevicePairingChallenge {
        client_nonce: record.client_nonce.clone(),
        device_pairing_request_id: record.device_pairing_request_id.clone(),
        expires_at: record.expires_at,
        gate_audience_uri: record.gate_audience_uri.clone(),
        pairing_code: record.pairing_code.clone(),
        server_nonce: record.server_nonce.clone(),
        display_name: record.display_name.clone(),
        device_metadata: record.device_metadata.clone(),
    };
    verify_server_device_pairing_target_proof(
        &record.new_device_pubkey,
        &challenge,
        &authenticated.account_id,
        &target_proof,
        now,
    )
    .map_err(|error| proof_invalid(format!("device pairing target proof is invalid: {error}")))?;
    Ok(ValidatedPairingIntent { event })
}

struct CurrentRealmAuthority {
    bundle: arkret_wire::RealmAuthorityBundle,
    verified: arkret_identity::VerifiedRealmAuthority,
}

async fn load_current_realm_authority(
    depot: &Depot,
    realm_id: &arkret_wire::RealmId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<CurrentRealmAuthority, ArkretRouteError> {
    let nonce = Base64UrlString::new(random_opaque(&mut *crate::handlers::make_rng(), 32))
        .map_err(|_| pairing_temporarily_unavailable())?;
    let request = AuthorityBundleRequest {
        realm_id: realm_id.clone(),
        nonce: nonce.clone(),
    };
    let config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let keyring = depot.keyring()?;
    let client = PeerProtocolClient::new_for_owning_station(&config, &http_client, &keyring)
        .map_err(map_pairing_peer_error)?;
    let bundle = client
        .get_realm_authority_bundle(&request)
        .await
        .map_err(map_pairing_peer_error)?;
    let keys = resolve_realm_authority_keys(depot, &bundle, None, now).await?;
    let freshness = RealmAuthorityFreshness::new(now, nonce, Duration::minutes(5))
        .map_err(|_| pairing_temporarily_unavailable())?;
    let verified = verify_realm_authority_bundle(&bundle, &freshness, &keys)
        .map_err(|_| pairing_temporarily_unavailable())?;
    Ok(CurrentRealmAuthority { bundle, verified })
}

async fn resolve_realm_authority_keys(
    depot: &Depot,
    bundle: &arkret_wire::RealmAuthorityBundle,
    extra: Option<&DidUrl>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RealmAuthorityKeyMap, ArkretRouteError> {
    let mut methods = BTreeSet::new();
    methods.insert(bundle.genesis_commit.signature.verification_method.clone());
    for transition in &bundle.authority_transitions {
        methods.insert(
            transition
                .change_commit
                .signature
                .verification_method
                .clone(),
        );
        methods.insert(
            transition
                .handoff
                .old_authority_signature
                .verification_method
                .clone(),
        );
        methods.insert(
            transition
                .handoff
                .new_authority_acceptance_signature
                .verification_method
                .clone(),
        );
    }
    if let Some(extra) = extra {
        methods.insert(extra.clone());
    }
    let config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let url_builder = depot.url_builder()?;
    let keyring = depot.keyring()?;
    let resolver = depot.did_resolver_service()?;
    let store = depot.verified_did_binding_store()?;
    let mut repo = depot.repo().await?;
    let mut keys = RealmAuthorityKeyMap::new();
    for method in methods {
        let controller = method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(pairing_temporarily_unavailable)?;
        let authority = did_binding::authority_document(
            &http_client,
            &url_builder,
            &config,
            &keyring,
            &mut repo,
            resolver.as_ref(),
            store.as_ref(),
            controller,
            DidBindingPurpose::Service,
            did_binding::high_risk_freshness(),
            now,
        )
        .await
        .map_err(|_| pairing_temporarily_unavailable())?;
        let key = arkret_identity::resolve_verification_method_key_from_document(
            authority.accepted.document(),
            method.as_str(),
        )
        .map_err(|_| pairing_temporarily_unavailable())?;
        keys.insert(&method, key.public_key);
    }
    repo.cancel().await.ok();
    Ok(keys)
}

async fn resume_device_pairing_admission(
    admission: coauth_data::DevicePairingAdmissionRecord,
    depot: &Depot,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let event_submission: arkret_wire::EventAdmissionSubmission =
        arkret_canonical::canonical::from_canonical_json_slice(&admission.authorize_event_bytes)
            .map_err(|_| pairing_temporarily_unavailable())?;
    let event_bytes = arkret_canonical::canonical_json_bytes(&event_submission)?;
    if event_bytes != admission.authorize_event_bytes
        || event_submission.event.event_id != admission.authorize_event_id
    {
        return Err(pairing_temporarily_unavailable());
    }

    let commit = if admission.state == DevicePairingAdmissionState::CommitRecorded {
        arkret_canonical::canonical::from_canonical_json_slice::<arkret_wire::RealmCommit>(
            admission
                .recorded_commit_bytes
                .as_deref()
                .ok_or_else(pairing_temporarily_unavailable)?,
        )
        .map_err(|_| pairing_temporarily_unavailable())?
    } else {
        let config = depot.arkret_config()?;
        let http_client = depot.http_client()?;
        let station = config
            .owning_station()
            .ok_or_else(pairing_temporarily_unavailable)?;
        let channel = InternalAuthorityChannel::new(
            &station.endpoint,
            &http_client,
            station.internal_authority_shared_secret(),
            admission.target_station_id.clone(),
        )
        .map_err(map_pairing_peer_error)?;
        let peer_outcome: arkret_wire::AuthoritySubmitOutcome = channel
            .post_private_json(
                "private_pairing_event_admission",
                PRIVATE_EVENT_ADMISSION_PATH,
                &event_submission,
                Some(admission.authorize_event_id.as_str()),
            )
            .await
            .map_err(map_pairing_peer_error)?;
        let commit = match &peer_outcome {
            arkret_wire::AuthoritySubmitOutcome::Accepted { status, commit }
                if matches!(
                    status,
                    AuthorityCommitStatus::Committed | AuthorityCommitStatus::Duplicate
                ) =>
            {
                commit.clone()
            }
            arkret_wire::AuthoritySubmitOutcome::Accepted { .. } => {
                return Err(pairing_temporarily_unavailable());
            }
            arkret_wire::AuthoritySubmitOutcome::Rejected {
                status: AuthorityRejectionStatus::Rejected,
                reason_code,
            } => {
                tracing::warn!(
                    request_id = admission.authorize_event_id.as_str(),
                    reason_code,
                    "owning Station terminally rejected frozen device-pairing Event"
                );
                let mut repo = depot.repo().await?;
                let abandoned = repo
                    .account_handoff()
                    .abandon_pending_device_pairing_admission(
                        &device_pairing_request_id_from_admission(&admission)?,
                        &admission.canonical_request_digest,
                    )
                    .await?;
                if abandoned {
                    repo.save().await?;
                } else {
                    repo.cancel().await.ok();
                }
                return Err(pairing_failed_precondition());
            }
            arkret_wire::AuthoritySubmitOutcome::Rejected {
                status: AuthorityRejectionStatus::RetryableUnavailable,
                ..
            } => return Err(pairing_temporarily_unavailable()),
        };
        verify_recorded_pairing_commit(&admission, &event_submission, &commit, depot, now).await?;
        let commit_bytes = arkret_canonical::canonical_json_bytes(&commit)?;
        let commit_digest = Hash::new(arkret_canonical::sha256_digest(&commit_bytes))?;
        let request_id = device_pairing_request_id_from_admission(&admission)?;
        let mut repo = depot.repo().await?;
        let accepted = repo
            .account_handoff()
            .record_device_pairing_commit(
                &request_id,
                &admission.canonical_request_digest,
                &commit_bytes,
                &commit_digest,
                now,
            )
            .await?;
        if !accepted {
            repo.cancel().await.ok();
            return Err(pairing_temporarily_unavailable());
        }
        repo.save().await?;
        commit
    };

    let authorized_event_ref = CommittedEventRef {
        event_id: commit.event_ref.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    let payload = DeviceAuthorizePayload::try_from(&event_submission.event)
        .map_err(|_| pairing_temporarily_unavailable())?;
    let outcome = AccountDevicePairOutcome {
        device_id: payload.device_id.clone(),
        authorized_event_ref: authorized_event_ref.clone(),
        device_grant: None,
        key_backup_hint: None,
    };
    let outcome_bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
    let request_id = device_pairing_request_id_from_admission(&admission)?;
    let mut repo = depot.repo().await?;
    let completed = repo
        .account_handoff()
        .complete_device_pairing_admission(
            &request_id,
            &admission.canonical_request_digest,
            &payload.device_id,
            &authorized_event_ref,
            &outcome_bytes,
            now,
        )
        .await?;
    match completed {
        DevicePairingAdmissionCommit::Completed(bytes)
        | DevicePairingAdmissionCommit::Replay(bytes) => {
            repo.save().await?;
            Ok(ArkretCanonicalJson(bytes))
        }
        DevicePairingAdmissionCommit::DuplicateConflict => {
            repo.cancel().await.ok();
            Err(pairing_duplicate_conflict())
        }
        DevicePairingAdmissionCommit::NotReady => {
            repo.cancel().await.ok();
            Err(pairing_temporarily_unavailable())
        }
    }
}

fn device_pairing_request_id_from_admission(
    admission: &coauth_data::DevicePairingAdmissionRecord,
) -> Result<DevicePairingRequestId, ArkretRouteError> {
    let request: AccountDevicePairRequestBody =
        arkret_canonical::canonical::from_canonical_json_slice(&admission.canonical_request_bytes)
            .map_err(|_| pairing_temporarily_unavailable())?;
    Ok(request.device_pairing_request_id)
}

async fn verify_recorded_pairing_commit(
    admission: &coauth_data::DevicePairingAdmissionRecord,
    submission: &arkret_wire::EventAdmissionSubmission,
    commit: &arkret_wire::RealmCommit,
    depot: &Depot,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), ArkretRouteError> {
    if commit.realm_id != submission.event.realm_id
        || commit.event_ref != admission.authorize_event_id
        || commit.stream_ref != admission.target_stream_head.stream_ref
        || commit.stream_position
            != admission
                .target_stream_head
                .stream_position
                .saturating_add(1)
        || commit.previous_commit_ref.as_ref() != Some(&admission.target_stream_head.commit_id)
        || commit.governance_generation != admission.target_authority_generation
    {
        return Err(pairing_temporarily_unavailable());
    }
    let authority = load_current_realm_authority(depot, &commit.realm_id, now).await?;
    if authority.verified.current_service_id() != &admission.target_station_id
        || authority.verified.current_generation() != admission.target_authority_generation
    {
        return Err(pairing_temporarily_unavailable());
    }
    let keys = resolve_realm_authority_keys(
        depot,
        &authority.bundle,
        Some(&commit.signature.verification_method),
        now,
    )
    .await?;
    authority
        .verified
        .verify_commit(commit, &keys)
        .map_err(|_| pairing_temporarily_unavailable())?;
    Ok(())
}

fn map_pairing_peer_error(error: PeerProtocolClientError) -> ArkretRouteError {
    match error {
        PeerProtocolClientError::Status { .. }
        | PeerProtocolClientError::Http(_)
        | PeerProtocolClientError::Response(_)
        | PeerProtocolClientError::BaseUrlNotConfigured
        | PeerProtocolClientError::InternalChannelNotConfigured(_)
        | PeerProtocolClientError::InvalidUrl(_)
        | PeerProtocolClientError::NoSigningKey
        | PeerProtocolClientError::Sign
        | PeerProtocolClientError::Canonical(_) => pairing_temporarily_unavailable(),
    }
}

fn pairing_temporarily_unavailable() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE,
        "device pairing terminal admission is temporarily unavailable",
    )
}

fn pairing_failed_precondition() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::PRECONDITION_FAILED,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        "owning Station rejected the device authorization",
    )
}

fn pairing_duplicate_conflict() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
        "device pairing request was reused with different canonical content or holder",
    )
}

struct AuthenticatedCurrentDevice {
    account_id: arkret_wire::AccountId,
    local_account_id: coauth_data::Ulid,
    device_id: arkret_identifiers::DeviceId,
    device_binding: arkret_models_identity::SessionGrantDeviceBinding,
    principal_control_realm_id: arkret_wire::RealmId,
}

/// `ak.gate.account.read.claim_device_pairing_code.v1`.
#[handler]
pub async fn claim_device_pairing_code(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let authenticated =
        authenticate_current_device(req, depot, "device pairing code claim").await?;
    let requester = extract_bound_activity_tracker(req, depot).requester_fingerprint();
    depot
        .limiter()?
        .check_device_pairing(
            requester,
            authenticated.local_account_id,
            authenticated.device_id.as_str(),
        )
        .await
        .map_err(|_| ArkretRouteError::rate_limited("device pairing is rate limited", 60_000))?;
    let body: DevicePairingCodeClaimRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;

    let intent_digest = Hash::new(arkret_canonical::canonical_sha256(&serde_json::json!({
        "operation_id": "ak.gate.account.read.claim_device_pairing_code.v1",
        "account_id": &authenticated.account_id,
        "device_id": &authenticated.device_id,
        "request": &body,
    }))?)?;
    let now = arkret_canonical::normalize_timestamp_canonical(crate::handlers::make_clock().now());
    acquire_private_current_device_binding(
        depot,
        &authenticated.account_id,
        authenticated.device_id.clone(),
        arkret_wire::DeviceRevocationAdmissionAction::DevicePairingCodeClaim,
        Some(&authenticated.device_binding),
        None,
        intent_digest,
        now,
    )
    .await?;

    let mut repo = depot.repo().await?;
    let Some(record) = repo
        .account_handoff()
        .get_device_pairing_by_code(&body.pairing_code, now)
        .await?
    else {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::NotFound);
    };

    let usable = record.state == DevicePairingState::ReadyForClaim
        && record.expires_at > now
        && record.admission.is_none()
        && record.account_id.as_ref() == Some(&authenticated.account_id)
        && record.target_proof.is_some();
    if !usable {
        repo.account_handoff()
            .record_device_pairing_failure(&record.device_pairing_request_id, now)
            .await?;
        repo.save().await?;
        return Err(ArkretRouteError::NotFound);
    }

    let challenge = ServerDevicePairingChallenge {
        client_nonce: record.client_nonce.clone(),
        device_pairing_request_id: record.device_pairing_request_id.clone(),
        expires_at: record.expires_at,
        gate_audience_uri: record.gate_audience_uri.clone(),
        pairing_code: record.pairing_code.clone(),
        server_nonce: record.server_nonce.clone(),
        display_name: record.display_name.clone(),
        device_metadata: record.device_metadata.clone(),
    };
    let target_proof = record
        .target_proof
        .clone()
        .expect("usable pairing record has a target proof");
    if verify_server_device_pairing_target_proof(
        &record.new_device_pubkey,
        &challenge,
        &authenticated.account_id,
        &target_proof,
        now,
    )
    .is_err()
    {
        repo.account_handoff()
            .record_device_pairing_failure(&record.device_pairing_request_id, now)
            .await?;
        repo.save().await?;
        return Err(ArkretRouteError::NotFound);
    }

    let outcome = DevicePairingCodeClaimOutcome {
        device_pairing_request_id: record.device_pairing_request_id.clone(),
        bootstrap: DevicePairingBootstrap {
            arkret_base_url: depot
                .url_builder()?
                .http_base()
                .as_str()
                .trim_end_matches('/')
                .to_owned(),
            device_pairing_request_id: record.device_pairing_request_id,
            pairing_code: record.pairing_code,
            new_device_pubkey: record.new_device_pubkey,
            client_nonce: record.client_nonce,
            gate_audience_uri: record.gate_audience_uri,
            server_nonce: record.server_nonce,
            display_name: record.display_name,
            device_metadata: record.device_metadata,
            expires_at: record.expires_at,
        },
        target_proof,
    };
    let bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
    repo.cancel().await.ok();
    Ok(ArkretCanonicalJson(bytes))
}

async fn authenticate_current_device(
    req: &Request,
    depot: &Depot,
    operation: &str,
) -> Result<AuthenticatedCurrentDevice, ArkretRouteError> {
    let grant_jwt = crate::services::dpop::dpop_authorization_token(req).ok_or_else(|| {
        ArkretRouteError::Unauthorized(format!(
            "Authorization: DPoP <session_grant> is required for {operation}"
        ))
    })?;
    let claims = Jwt::<SignedSessionGrantClaims>::try_from(grant_jwt)
        .map_err(|_| ArkretRouteError::Unauthorized("session grant is not parseable".to_owned()))?
        .payload()
        .clone();
    claims.validate().map_err(|error| {
        ArkretRouteError::Unauthorized(format!("invalid session grant: {error}"))
    })?;
    if claims.credential_class != SessionGrantCredentialClass::Standard
        || !matches!(
            claims.holder_binding,
            SessionGrantHolderBinding::HumanDevice { .. }
        )
    {
        return Err(ArkretRouteError::Unauthorized(format!(
            "{operation} requires a Standard human SessionGrant"
        )));
    }
    let device_binding = claims.device_binding.clone().ok_or_else(|| {
        ArkretRouteError::Unauthorized(format!("{operation} requires an accepted device binding"))
    })?;
    let dpop_header = dpop_header_from_request(req)
        .ok_or_else(|| ArkretRouteError::Unauthorized(format!("{operation} requires DPoP")))?;
    let clock = crate::handlers::make_clock();
    let now = clock.now();
    let htu = dpop_htu(&depot.url_builder()?.http_base(), req);
    let dpop = DpopVerifier::verify_without_replay(
        &dpop_header,
        req.method().as_str(),
        &htu,
        now,
        Some(grant_jwt),
    )
    .map_err(|error| ArkretRouteError::Unauthorized(format!("invalid DPoP proof: {error}")))?;
    let expected_jkt = claims
        .session_public_key
        .thumbprint_sha256()
        .map_err(|error| ArkretRouteError::Unauthorized(format!("invalid session key: {error}")))?;
    DpopVerifier::require_matching_jkt(&dpop.jkt, &expected_jkt)
        .map_err(|error| ArkretRouteError::Unauthorized(format!("invalid DPoP holder: {error}")))?;

    let mut repo = depot.repo().await?;
    let grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(grant_jwt)
        .await?
        .ok_or_else(|| ArkretRouteError::Unauthorized("session grant is not active".to_owned()))?;
    if !grant.is_active(&*clock)
        || grant.grant_id != claims.grant_id
        || grant.issuer_id != claims.issuer_id
        || grant.subject_id != claims.account_id.principal_id
        || grant.audience_id != claims.audience_id
        || grant.device_id.as_deref() != Some(device_binding.device_id.as_str())
    {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::Unauthorized(
            "session grant is not active for this device".to_owned(),
        ));
    }
    let consumed = repo
        .dpop_replay()
        .consume_jti(crate::services::dpop::dpop_replay_record(
            &dpop.claims.jti,
            now,
        ))
        .await?;
    if !consumed {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::Unauthorized(
            "device pairing code-claim DPoP JTI was already consumed".to_owned(),
        ));
    }
    let local_account_id = grant.local_account_id.as_str().parse().map_err(|error| {
        ArkretRouteError::Internal(
            format!("invalid local account id in session grant: {error}").into(),
        )
    })?;
    let user = repo.user().lookup(local_account_id).await?.ok_or_else(|| {
        ArkretRouteError::Unauthorized("session account is unavailable".to_owned())
    })?;
    let principal_binding = repo
        .principal_did()
        .get_for_user_and_audience(&user, claims.audience_id.as_str())
        .await?
        .filter(|binding| binding.account_id == claims.account_id)
        .ok_or_else(|| {
            ArkretRouteError::Unauthorized(
                "session grant does not match the durable principal binding".to_owned(),
            )
        })?;
    let authenticated = AuthenticatedCurrentDevice {
        account_id: claims.account_id,
        local_account_id,
        device_id: device_binding.device_id.clone(),
        device_binding,
        principal_control_realm_id: principal_binding.principal_control_realm_id,
    };
    repo.save().await?;
    Ok(authenticated)
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use rand_core::{CryptoRng, Error, RngCore};

    use super::{
        mint_nonce, mint_pairing_code, parse_device_pairing_token, valid_stage_idempotency_key,
    };

    struct ZeroRng;

    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ZeroRng {}

    #[test]
    fn minted_pairing_material_uses_the_closed_wire_alphabets() {
        let mut rng = ZeroRng;
        assert_eq!(mint_pairing_code(&mut rng).as_str(), "AAAAAAAA");
        assert_eq!(
            mint_nonce(&mut rng).as_str(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
    }

    #[test]
    fn pairing_token_accepts_only_canonical_closed_shape() {
        let canonical = br#"{"c":"ABCDEFGH","r":"device_pairing_request:01999999-0000-7000-8000-00000000feed"}"#;
        let token = Base64UrlUnpadded::encode_string(canonical);
        let (request_id, code) = parse_device_pairing_token(&token).expect("canonical token");
        assert_eq!(
            request_id.as_str(),
            "device_pairing_request:01999999-0000-7000-8000-00000000feed"
        );
        assert_eq!(code.as_str(), "ABCDEFGH");

        let noncanonical = br#"{"r":"device_pairing_request:01999999-0000-7000-8000-00000000feed", "c":"ABCDEFGH"}"#;
        assert!(
            parse_device_pairing_token(&Base64UrlUnpadded::encode_string(noncanonical)).is_err()
        );
        let extra = br#"{"c":"ABCDEFGH","r":"device_pairing_request:01999999-0000-7000-8000-00000000feed","x":1}"#;
        assert!(parse_device_pairing_token(&Base64UrlUnpadded::encode_string(extra)).is_err());
    }

    #[test]
    fn stage_idempotency_key_uses_the_registered_closed_alphabet() {
        assert!(valid_stage_idempotency_key("station:ingress_01.retry-2~x"));
        assert!(!valid_stage_idempotency_key(""));
        assert!(!valid_stage_idempotency_key("contains space"));
        assert!(!valid_stage_idempotency_key(&"a".repeat(129)));
    }

    #[test]
    fn canonical_internal_pairing_routes_are_not_exposed() {
        let source = include_str!("device_pairing.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let routers = include_str!("../../server/routers.rs")
            .split_once("mod private_tcb_surface_tests")
            .unwrap()
            .0;
        for removed in [
            "stage_device_pairing_internal",
            "resolve_device_pairing_internal",
            "device_pairing_status_internal",
            "gate/account/device-pairing/stages",
            "gate/account/device-pairing/resolutions",
            "gate/account/device-pairing/status-queries",
        ] {
            assert!(!production.contains(removed));
            assert!(!routers.contains(removed));
        }
        let private_adapters = production
            .split_once("pub async fn private_stage_device_pairing_adapter")
            .unwrap()
            .1
            .split_once("fn duplicate_conflict")
            .unwrap()
            .0;
        assert!(private_adapters.contains("authenticate_private_pairing_adapter"));
        for forbidden in [
            "ServiceOperationId",
            "arkret-operation",
            "source-service-id",
            "SignatureVerificationPolicy",
        ] {
            assert!(!private_adapters.contains(forbidden));
        }
    }

    #[test]
    fn code_claim_orders_auth_rate_gate_lookup_and_failure_budget() {
        let source = include_str!("device_pairing.rs");
        let claim_and_rest = source
            .split_once("pub async fn claim_device_pairing_code")
            .expect("code-claim handler")
            .1;
        let claim = claim_and_rest
            .split_once("async fn authenticate_current_device")
            .expect("code-claim authentication helper")
            .0;
        let auth = claim
            .find("authenticate_current_device(req, depot")
            .unwrap();
        let rate = claim.find(".check_device_pairing(").unwrap();
        let gate = claim
            .find("acquire_private_current_device_binding(")
            .unwrap();
        let lookup = claim.find(".get_device_pairing_by_code(").unwrap();
        let budget = claim.find(".record_device_pairing_failure(").unwrap();
        assert!(auth < rate && rate < gate && gate < lookup && lookup < budget);
        assert!(claim.contains("DeviceRevocationAdmissionAction::DevicePairingCodeClaim"));
        assert!(!claim.contains("DeviceRevocationAdmissionAction::EventWrite"));
    }

    #[test]
    fn pair_device_uses_one_private_journal_and_one_event_commit() {
        let source = include_str!("device_pairing.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let pair = source
            .split_once("pub async fn pair_device")
            .expect("pair-device handler")
            .1
            .split_once("struct ValidatedPairingIntent")
            .expect("pair-device helper boundary")
            .0;
        let auth = pair.find("authenticate_current_device(req, depot").unwrap();
        let rate = pair.find(".check_device_pairing(").unwrap();
        let ledger = pair.find(".get_device_pairing_stage(").unwrap();
        let event_write = pair
            .find("DeviceRevocationAdmissionAction::EventWrite")
            .unwrap();
        let authority = pair.find("load_current_realm_authority(").unwrap();
        let reserve = pair.find(".reserve_device_pairing_admission(").unwrap();
        assert!(auth < rate && rate < ledger && ledger < event_write);
        assert!(event_write < authority && authority < reserve);

        let resume = source
            .split_once("async fn resume_device_pairing_admission")
            .expect("resume helper")
            .1
            .split_once("fn device_pairing_request_id_from_admission")
            .expect("resume helper boundary")
            .0;
        let frozen_decode = resume.find("admission.authorize_event_bytes").unwrap();
        let peer_submit = resume.find(".post_private_json(").unwrap();
        let commit_recorded = resume.find(".record_device_pairing_commit(").unwrap();
        let local_complete = resume.find(".complete_device_pairing_admission(").unwrap();
        assert!(frozen_decode < peer_submit);
        assert!(peer_submit < commit_recorded && commit_recorded < local_complete);
        assert!(!resume.contains("peer_outcome_bytes"));
        assert!(!production.contains("station_accepted"));

        let routers = include_str!("../../server/routers.rs");
        assert!(routers.contains("gate/account/device-pair"));
        assert!(!routers.contains("device-pairing/authorize-event"));
    }

    #[test]
    fn fenced_pairing_is_hidden_and_terminal_replay_precedes_network_work() {
        let source = include_str!("device_pairing.rs");
        let pair = source
            .split_once("pub async fn pair_device")
            .unwrap()
            .1
            .split_once("struct ValidatedPairingIntent")
            .unwrap()
            .0;
        let terminal = pair.find("terminal_outcome_bytes").unwrap();
        let current_gate = pair
            .find("DeviceRevocationAdmissionAction::EventWrite")
            .unwrap();
        assert!(
            terminal < current_gate,
            "completed retry must return stored bytes"
        );

        let claim = source
            .split_once("pub async fn claim_device_pairing_code")
            .unwrap()
            .1
            .split_once("async fn authenticate_current_device")
            .unwrap()
            .0;
        assert!(claim.contains("record.admission.is_none()"));
    }
}
