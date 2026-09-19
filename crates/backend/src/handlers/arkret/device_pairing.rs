//! Account Authority-owned device-pairing stage and finalize boundary.

use arkret_models_collaboration::device_pairing::{
    DevicePairingCode, DevicePairingFinalizeOutcome, DevicePairingFinalizeRequestBody,
    DevicePairingNonce, DevicePairingRequestId, DevicePairingStageOutcome,
    DevicePairingStageRequestBody, DevicePairingState,
};
use arkret_models_identity::AccountHandoffAllowedOperation;
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
use rand_core::RngCore;
use salvo::prelude::*;

use super::account_handoff::{proof_invalid, random_opaque};
use super::{ArkretCanonicalJson, ArkretRouteError, authenticate_account_handoff};
use crate::handlers::common::{DepotExt as _, extract_bound_activity_tracker};

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
}
