//! Account Authority-owned device-pairing stage, finalize and code-claim boundary.

use arkret_models_collaboration::device_pairing::{
    DevicePairingBootstrap, DevicePairingCode, DevicePairingCodeClaimOutcome,
    DevicePairingCodeClaimRequestBody, DevicePairingFinalizeOutcome,
    DevicePairingFinalizeRequestBody, DevicePairingNonce, DevicePairingRequestId,
    DevicePairingStageOutcome, DevicePairingStageRequestBody, DevicePairingState,
};
use arkret_models_identity::{
    AccountHandoffAllowedOperation, SessionGrantCredentialClass, SessionGrantHolderBinding,
    SignedSessionGrantClaims,
};
use arkret_signatures::device_pairing::{
    ServerDevicePairingChallenge, verify_server_device_pairing_target_proof,
};
use arkret_wire::Hash;
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
use crate::handlers::common::{DepotExt as _, extract_bound_activity_tracker};
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
        let inserted = repo
            .account_handoff()
            .insert_device_pairing_stage(NewDevicePairingPendingRecord {
                device_pairing_request_id: device_pairing_request_id.clone(),
                pairing_code: pairing_code.clone(),
                new_device_pubkey: body.new_device_pubkey.clone(),
                client_nonce: body.client_nonce.clone(),
                display_name: body.display_name.clone(),
                device_metadata: body.device_metadata.clone(),
                gate_audience_uri: gate_audience_uri.clone(),
                server_nonce: server_nonce.clone(),
                expires_at,
                retained_until: expires_at + PAIRING_TOMBSTONE_RETENTION,
                created_at: now,
            })
            .await?;
        if inserted == DevicePairingStageInsert::IdentifierCollision {
            continue;
        }
        let outcome = DevicePairingStageOutcome {
            device_pairing_request_id,
            pairing_code,
            gate_audience_uri,
            server_nonce,
            expires_at,
        };
        let bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
        repo.save().await?;
        return Ok(ArkretCanonicalJson(bytes));
    }

    repo.cancel().await.ok();
    Err(ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::TEMPORARILY_UNAVAILABLE,
        "could not mint a unique live device-pairing credential",
    ))
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
    use rand_core::{CryptoRng, Error, RngCore};

    use super::{mint_nonce, mint_pairing_code};

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
