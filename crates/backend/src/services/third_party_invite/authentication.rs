//! Authentication of the registered IVS transcripts. No substitute wire proofs.
use arkret_signatures::PublicKeyMaterial;

use super::{InviteError, *};

pub(crate) async fn verify_activation(
    http: &reqwest::Client,
    config: &coauth_config::ArkretConfig,
    request: &ThirdPartyInviteActivationRequestBody,
    now: DateTime<Utc>,
) -> Result<(), InviteError> {
    let a = &request.acceptance_attestation;
    if request.provisioning_id != a.provisioning_id {
        return Err(InviteError::NotFound);
    }
    let owning = config
        .runtime_owning_station_identity
        .get()
        .ok_or(InviteError::NotFound)?;
    if a.verification_id != owning.station_id
        || a.station_id != owning.station_id
        || a.inviter_account_id.station_id != owning.station_id
        || a.observed_at > now
    {
        return Err(InviteError::NotFound);
    }
    let station = config.owning_station().ok_or(InviteError::NotFound)?;
    let verified = crate::services::station_trust::verify_station_identity(
        http,
        &station.endpoint,
        Some(&a.station_id),
        None,
    )
    .await
    .map_err(|_| InviteError::NotFound)?;
    let method = a.signature.verification_method.as_str();
    arkret_identity::validate_verification_method_relationship(
        &verified.current_document,
        &a.signature.verification_method,
        &verified.did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|_| InviteError::NotFound)?;
    let key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &verified.current_document,
        method,
    )
    .map_err(|_| InviteError::NotFound)?;
    arkret_signatures::proof::verify_ed25519_detached_jws_payload_proof(
        &a.signature,
        &a.proof_binding_bytes().map_err(|_| InviteError::NotFound)?,
        &PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_bytes().to_vec(),
        },
    )
    .map_err(|_| InviteError::NotFound)?;
    // Only a verified attestation may receive a reason describing its window.
    if a.expires_at <= a.observed_at || a.expires_at > a.invite_expires_at {
        return Err(InviteError::AcceptanceStale);
    }
    a.validate().map_err(|_| InviteError::NotFound)?;
    a.validate_freshness(Utc::now())
        .map_err(|_| InviteError::AcceptanceStale)?;
    Ok(())
}
