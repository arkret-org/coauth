//! Account Authority-owned device-pairing stage, finalize and code-claim boundary.

use arkret_identity::DidBindingPurpose;
use arkret_models_collaboration::device_pairing::{
    DevicePairingBootstrap, DevicePairingCode, DevicePairingCodeClaimOutcome,
    DevicePairingCodeClaimRequestBody, DevicePairingFinalizeOutcome,
    DevicePairingFinalizeRequestBody, DevicePairingNonce, DevicePairingRequestId,
    DevicePairingResolveRequestBody, DevicePairingStageOutcome, DevicePairingStageRequestBody,
    DevicePairingState, DevicePairingStatusOutcome, DevicePairingStatusRequestBody,
};
use arkret_models_identity::{
    AccountHandoffAllowedOperation, SessionGrantCredentialClass, SessionGrantHolderBinding,
    SignedSessionGrantClaims,
};
use arkret_signatures::device_pairing::{
    ServerDevicePairingChallenge, verify_server_device_pairing_target_proof,
};
use arkret_signatures::http_signature::{
    Component, SignatureVerificationPolicy, parse_signature_input,
    verify_signed_canonical_json_message,
};
use arkret_wire::{DidUrl, Hash};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::Duration;
use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
use coauth_data::{
    Clock as _, DevicePairingFinalizeCommit, DevicePairingStageInsert,
    NewDevicePairingPendingRecord, RepositoryAccess,
};
use coauth_jose::jwt::Jwt;
use rand_core::RngCore;
use salvo::prelude::*;

use super::account_handoff::{proof_invalid, random_opaque};
use super::session_grant::acquire_human_device_binding;
use super::{ArkretCanonicalJson, ArkretRouteError, authenticate_account_handoff};
use crate::arkret_key_bridge::sdk_verifying_key_from_jose_verifying_key;
use crate::handlers::common::{DepotExt as _, extract_bound_activity_tracker};
use crate::services::did_binding;
use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

const PAIRING_TTL: Duration = Duration::minutes(10);
const PAIRING_TOMBSTONE_RETENTION: Duration = Duration::hours(24);
const PAIRING_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

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

/// `ak.gate.account.command.stage_device_pairing.v1`.
#[handler]
pub async fn stage_device_pairing_internal(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let body: DevicePairingStageRequestBody =
        req.parse_json().await.map_err(|_| internal_not_found())?;
    let canonical_body =
        arkret_canonical::canonical_json_bytes(&body).map_err(|_| internal_not_found())?;
    authenticate_internal_pairing_request(
        req,
        depot,
        &canonical_body,
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_STAGE_DEVICE_PAIRING_V1,
        true,
    )
    .await?;
    let idempotency_key = super::account_status::required_header(req, "idempotency-key")?;
    if !valid_stage_idempotency_key(&idempotency_key) {
        return Err(internal_not_found());
    }
    stage_device_pairing_with_key(body, idempotency_key, depot).await
}

/// `ak.gate.account.read.resolve_device_pairing.v1`.
#[handler]
pub async fn resolve_device_pairing_internal(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let body: DevicePairingResolveRequestBody =
        req.parse_json().await.map_err(|_| internal_not_found())?;
    let canonical_body =
        arkret_canonical::canonical_json_bytes(&body).map_err(|_| internal_not_found())?;
    authenticate_internal_pairing_request(
        req,
        depot,
        &canonical_body,
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_READ_RESOLVE_DEVICE_PAIRING_V1,
        false,
    )
    .await?;
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

/// `ak.gate.account.read.device_pairing_status.v1`.
#[handler]
pub async fn device_pairing_status_internal(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let body: DevicePairingStatusRequestBody =
        req.parse_json().await.map_err(|_| internal_not_found())?;
    let canonical_body =
        arkret_canonical::canonical_json_bytes(&body).map_err(|_| internal_not_found())?;
    authenticate_internal_pairing_request(
        req,
        depot,
        &canonical_body,
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_READ_DEVICE_PAIRING_STATUS_V1,
        false,
    )
    .await?;
    let now = arkret_canonical::normalize_timestamp_canonical(crate::handlers::make_clock().now());
    let mut repo = depot.repo().await?;
    let record = repo
        .account_handoff()
        .get_device_pairing_stage(&body.device_pairing_request_id)
        .await?
        .filter(|record| {
            record.pairing_code == body.pairing_code
                && record.state == DevicePairingState::ReadyForClaim
                && record.expires_at > now
        })
        .ok_or_else(internal_not_found)?;
    let outcome = DevicePairingStatusOutcome {
        state: record.state,
        device_id: None,
        authorized_event_ref: None,
    };
    outcome.validate().map_err(|_| internal_not_found())?;
    let bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
    repo.cancel().await.ok();
    Ok(ArkretCanonicalJson(bytes))
}

async fn authenticate_internal_pairing_request(
    req: &Request,
    depot: &Depot,
    canonical_body: &[u8],
    operation_id: &str,
    require_idempotency_key: bool,
) -> Result<(), ArkretRouteError> {
    let config = depot.arkret_config()?;
    let owning_station_id = super::owning_station_id_for(&config);
    let owning_station_did = super::owning_station_did_for(&config);
    let source_id = super::account_status::required_header(req, "source-service-id")?;
    let destination_id = super::account_status::required_header(req, "destination-service-id")?;
    let selected_operation = super::account_status::required_header(req, "arkret-operation")?;
    if source_id != owning_station_id.as_str()
        || destination_id != owning_station_id.as_str()
        || selected_operation != operation_id
    {
        return Err(internal_not_found());
    }
    let source_trust_domain = config
        .owning_station()
        .and_then(|station| station.trust_domain.as_deref())
        .ok_or_else(internal_not_found)?;
    let destination_trust_domain = config
        .trust_domain
        .as_deref()
        .ok_or_else(internal_not_found)?;
    if super::account_status::required_header(req, "source-trust-domain")? != source_trust_domain
        || super::account_status::required_header(req, "destination-trust-domain")?
            != destination_trust_domain
    {
        return Err(internal_not_found());
    }

    let signature_input = req
        .headers()
        .get("signature-input")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_signature_input(value).ok())
        .ok_or_else(internal_not_found)?;
    let key_id = DidUrl::new(signature_input.key_id.clone()).map_err(|_| internal_not_found())?;
    let source_did = key_id
        .as_str()
        .rsplit_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(internal_not_found)?;
    if source_did != owning_station_did.as_str() {
        return Err(internal_not_found());
    }

    let mut repo = depot.repo().await?;
    let authority = did_binding::authority_document(
        &depot.http_client()?,
        &depot.url_builder()?,
        &config,
        &depot.keyring()?,
        &mut repo,
        depot.did_resolver_service()?.as_ref(),
        depot.verified_did_binding_store()?.as_ref(),
        source_did,
        DidBindingPurpose::Service,
        did_binding::high_risk_freshness(),
        crate::handlers::make_clock().now(),
    )
    .await
    .map_err(|_| internal_not_found())?;
    let resolved_key = arkret_identity::resolve_verification_method_key_from_document(
        authority.accepted.document(),
        key_id.as_str(),
    )
    .map_err(|_| internal_not_found())?;
    let public_key = ed25519_dalek::VerifyingKey::from_bytes(
        &resolved_key
            .public_key
            .ed25519_bytes()
            .map_err(|_| internal_not_found())?,
    )
    .map_err(|_| internal_not_found())?;

    let public_base_url = depot.url_builder()?.http_base();
    let authority_header = public_base_url
        .host_str()
        .map(|host| {
            public_base_url
                .port()
                .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"))
        })
        .ok_or_else(internal_not_found)?;
    let target_uri = public_base_url
        .join(req.uri().path().trim_start_matches('/'))
        .map_err(|_| internal_not_found())?;
    let mut covered = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header("arkret-operation".to_owned()),
        Component::Header("source-service-id".to_owned()),
        Component::Header("destination-service-id".to_owned()),
        Component::Header("source-trust-domain".to_owned()),
        Component::Header("destination-trust-domain".to_owned()),
        Component::Header("content-digest".to_owned()),
    ];
    if require_idempotency_key {
        covered.push(Component::Header("idempotency-key".to_owned()));
    }
    let policy = SignatureVerificationPolicy::new(covered)
        .require_content_digest(true)
        .max_clock_skew_seconds(30)
        .max_validity_window_seconds(300);
    let sdk_public_key =
        sdk_verifying_key_from_jose_verifying_key(&public_key).map_err(|_| internal_not_found())?;
    let headers = req.headers().iter().filter_map(|(name, value)| {
        value
            .to_str()
            .ok()
            .map(|value| (name.as_str().to_owned(), value.to_owned()))
    });
    verify_signed_canonical_json_message(
        req.method().as_str(),
        target_uri.as_str(),
        &authority_header,
        req.uri().path(),
        headers,
        req.headers().contains_key("content-encoding"),
        canonical_body,
        &sdk_public_key,
        &policy,
        crate::handlers::make_clock().now().timestamp(),
    )
    .map_err(|_| internal_not_found())?;
    repo.cancel().await.ok();
    Ok(())
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

struct AuthenticatedCodeClaim {
    account_id: arkret_wire::AccountId,
    local_account_id: coauth_data::Ulid,
    device_id: arkret_identifiers::DeviceId,
    device_binding: arkret_models_identity::SessionGrantDeviceBinding,
}

/// `ak.gate.account.read.claim_device_pairing_code.v1`.
#[handler]
pub async fn claim_device_pairing_code(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let authenticated = authenticate_code_claim(req, depot).await?;
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
    acquire_human_device_binding(
        depot,
        &authenticated.account_id,
        authenticated.device_id.clone(),
        arkret_wire::DeviceRevocationGateActionClass::DevicePairingCodeClaim,
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

async fn authenticate_code_claim(
    req: &Request,
    depot: &Depot,
) -> Result<AuthenticatedCodeClaim, ArkretRouteError> {
    let grant_jwt = crate::services::dpop::dpop_authorization_token(req).ok_or_else(|| {
        ArkretRouteError::Unauthorized("Authorization: DPoP <session_grant> is required".to_owned())
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
        return Err(ArkretRouteError::Unauthorized(
            "device pairing code claim requires a Standard human SessionGrant".to_owned(),
        ));
    }
    let device_binding = claims.device_binding.clone().ok_or_else(|| {
        ArkretRouteError::Unauthorized(
            "device pairing code claim requires an accepted device binding".to_owned(),
        )
    })?;
    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        ArkretRouteError::Unauthorized("device pairing code claim requires DPoP".to_owned())
    })?;
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
    let authenticated = AuthenticatedCodeClaim {
        account_id: claims.account_id,
        local_account_id: grant.local_account_id.as_str().parse().map_err(|error| {
            ArkretRouteError::Internal(
                format!("invalid local account id in session grant: {error}").into(),
            )
        })?,
        device_id: device_binding.device_id.clone(),
        device_binding,
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
    fn internal_pairing_routes_authenticate_before_touching_the_pairing_ledger() {
        let source = include_str!("device_pairing.rs");
        for (name, next) in [
            (
                "pub async fn stage_device_pairing_internal",
                "pub async fn resolve_device_pairing_internal",
            ),
            (
                "pub async fn resolve_device_pairing_internal",
                "pub async fn device_pairing_status_internal",
            ),
            (
                "pub async fn device_pairing_status_internal",
                "async fn authenticate_internal_pairing_request",
            ),
        ] {
            let body = source
                .split_once(name)
                .expect("internal pairing handler")
                .1
                .split_once(next)
                .expect("next handler boundary")
                .0;
            let auth = body
                .find("authenticate_internal_pairing_request(")
                .expect("service signature authentication");
            let ledger = body
                .find("stage_device_pairing_with_key(")
                .or_else(|| body.find(".account_handoff()"))
                .expect("pairing ledger access");
            assert!(
                auth < ledger,
                "{name} must authenticate before ledger access"
            );
        }

        let verifier = source
            .split_once("async fn authenticate_internal_pairing_request")
            .expect("internal verifier")
            .1
            .split_once("fn duplicate_conflict")
            .expect("verifier boundary")
            .0;
        for covered in [
            "arkret-operation",
            "source-service-id",
            "destination-service-id",
            "source-trust-domain",
            "destination-trust-domain",
            "content-digest",
            "idempotency-key",
        ] {
            assert!(verifier.contains(covered), "missing covered {covered}");
        }
        assert!(
            verifier.contains("let source_trust_domain = config")
                && verifier.contains(".owning_station()")
                && verifier.contains("station.trust_domain.as_deref()"),
            "source trust domain must come from the verified owning Station entry"
        );
        assert!(
            verifier.contains("let destination_trust_domain = config")
                && verifier.contains(".trust_domain")
                && verifier.contains("destination_trust_domain"),
            "destination trust domain must come from the Account Authority deployment"
        );
        assert!(
            verifier.contains(".max_clock_skew_seconds(30)")
                && verifier.contains(".max_validity_window_seconds(300)"),
            "service signature freshness must keep the canonical 30s skew / 300s lifetime"
        );
    }

    #[test]
    fn router_wires_only_the_three_registered_internal_pairing_paths() {
        let routers = include_str!("../../server/routers.rs");
        for path in [
            "gate/account/device-pairing/stages",
            "gate/account/device-pairing/resolutions",
            "gate/account/device-pairing/status-queries",
        ] {
            assert!(routers.contains(path), "missing {path}");
        }
        assert!(!routers.contains("open/device-pairing/internal"));
    }

    #[test]
    fn code_claim_orders_auth_rate_gate_lookup_and_failure_budget() {
        let source = include_str!("device_pairing.rs");
        let claim_and_rest = source
            .split_once("pub async fn claim_device_pairing_code")
            .expect("code-claim handler")
            .1;
        let claim = claim_and_rest
            .split_once("async fn authenticate_code_claim")
            .expect("code-claim authentication helper")
            .0;
        let auth = claim.find("authenticate_code_claim(req, depot)").unwrap();
        let rate = claim.find(".check_device_pairing(").unwrap();
        let gate = claim.find("acquire_human_device_binding(").unwrap();
        let lookup = claim.find(".get_device_pairing_by_code(").unwrap();
        let budget = claim.find(".record_device_pairing_failure(").unwrap();
        assert!(auth < rate && rate < gate && gate < lookup && lookup < budget);
        assert!(claim.contains("DeviceRevocationGateActionClass::DevicePairingCodeClaim"));
        assert!(!claim.contains("DeviceRevocationGateActionClass::EventWrite"));
    }
}
