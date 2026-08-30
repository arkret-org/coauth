use arkret_identifiers::{Did, Hash, project_did_to_core_id};
use arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding;
use arkret_models_identity::SessionGrantDeviceBinding;
use arkret_wire::{
    AccountId, DeviceId, DeviceRevocationGateActionClass, DeviceRevocationGateCheckRequestBody,
    DeviceRevocationGateDecision,
};
use chrono::{DateTime, Utc};
use salvo::prelude::{Depot, StatusCode};

use crate::handlers::arkret::{
    ArkretRouteError, owning_station_did_for, owning_station_id_for, trust_domain_for,
};
use crate::handlers::common::DepotExt as _;
use crate::services::did_binding_proof::verify_detached_jws_against_method;
use crate::services::peer_protocol_client::PeerProtocolClient;

pub(crate) async fn acquire_human_device_binding(
    depot: &Depot,
    account_id: &AccountId,
    device_id: DeviceId,
    action_class: DeviceRevocationGateActionClass,
    expected_binding: Option<&SessionGrantDeviceBinding>,
    accepted_device_possession_proof: Option<arkret_wire::AcceptedDevicePossessionProof>,
    intent_digest: Hash,
    now: DateTime<Utc>,
) -> Result<SessionGrantDeviceBinding, ArkretRouteError> {
    let config = depot.arkret_config()?;
    let destination = config
        .stations
        .iter()
        .find(|server| {
            crate::services::station_trust::effective_audience_shared(server)
                .is_some_and(|audience_id| audience_id == account_id.station_id)
        })
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::BAD_REQUEST,
                arkret_wire::ErrorCode::AUDIENCE_UNKNOWN,
                "principal authority has no configured origin Station",
            )
        })?;
    let (expected_device_authorize_event_id, expected_device_generation_ref) = expected_binding
        .map_or(
            (None, None),
            SessionGrantDeviceBinding::as_expected_gate_binding,
        );
    let request = DeviceRevocationGateCheckRequestBody {
        account_id: account_id.clone(),
        device_id,
        expected_device_authorize_event_id,
        expected_device_generation_ref,
        action_class,
        intent_digest,
        accepted_device_possession_proof,
        requested_at: arkret_canonical::normalize_timestamp_canonical(now),
    };
    request.validate().map_err(gate_protocol_error)?;

    let source_id = owning_station_id_for(&config);
    let trust_domain =
        arkret_identifiers::TrustDomainId::new(trust_domain_for(&depot.url_builder()?, &config))
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let identity = KeyPackagesClaimServiceBinding {
        source_id,
        destination_id: account_id.station_id.clone(),
    };
    let http_client = depot.http_client()?;
    let key_store = depot.key_store()?;
    let client = PeerProtocolClient::new(
        Some(&destination.endpoint),
        &http_client,
        &key_store,
        owning_station_did_for(&config),
        identity,
        trust_domain.clone(),
        trust_domain,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let outcome = client
        .post_device_revocation_gate_check(&request)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    verify_gate_receipt(depot, &outcome).await?;

    match outcome.decision_receipt.decision {
        DeviceRevocationGateDecision::Allow => {
            SessionGrantDeviceBinding::from_gate_outcome(&outcome, &request, now)
                .map_err(gate_protocol_error)
        }
        DeviceRevocationGateDecision::AuthorityMismatch => Err(ArkretRouteError::coded(
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::DEVICE_UNAUTHORIZED,
            "device is not currently authorized for this principal",
        )),
        DeviceRevocationGateDecision::RevocationPending => Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::DEVICE_REVOCATION_PENDING,
            "device revocation is pending",
        )),
        DeviceRevocationGateDecision::Revoked
        | DeviceRevocationGateDecision::GenerationMismatch => Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::DEVICE_REVOKED,
            "device authorization is revoked or generation-fenced",
        )),
    }
}

async fn verify_gate_receipt(
    depot: &Depot,
    outcome: &arkret_wire::DeviceRevocationGateCheckOutcome,
) -> Result<(), ArkretRouteError> {
    let receipt = &outcome.decision_receipt;
    let (controller, _) = receipt
        .verification_method
        .as_str()
        .split_once('#')
        .ok_or_else(|| gate_protocol_error("gate receipt verification method has no fragment"))?;
    let controller =
        Did::new(controller.to_owned()).map_err(|error| gate_protocol_error(error.to_string()))?;
    let controller_core = project_did_to_core_id(&controller)
        .map_err(|error| gate_protocol_error(error.to_string()))?;
    if controller_core != receipt.account_id.station_id {
        return Err(gate_protocol_error(
            "gate receipt signer is not the origin Station",
        ));
    }

    let http_client = depot.http_client()?;
    let document = if controller.as_str().starts_with("did:webvh:") {
        let resolver = depot.did_resolver_service()?;
        crate::services::did_resolver::resolve_verified_webvh_service_document_at(
            &http_client,
            resolver.resolver_egress_policy(),
            &controller,
            receipt.proof.created_at,
        )
        .await
        .map_err(|error| gate_protocol_error(error.to_string()))?
    } else {
        let config = depot.arkret_config()?;
        let key_store = depot.key_store()?;
        let url_builder = depot.url_builder()?;
        let resolver = depot.did_resolver_service()?;
        let binding_store = depot.verified_did_binding_store()?;
        let mut repo = depot.repo().await?;
        let resolution = crate::services::did_binding::authority_document(
            &http_client,
            &url_builder,
            &config,
            &key_store,
            &mut repo,
            resolver.as_ref(),
            binding_store.as_ref(),
            controller.as_str(),
            arkret_identity::DidBindingPurpose::Controller,
            crate::services::did_binding::controller_freshness(),
            receipt.proof.created_at,
        )
        .await
        .map_err(|error| gate_protocol_error(error.to_string()))?;
        repo.save()
            .await
            .map_err(|error| gate_protocol_error(error.to_string()))?;
        resolution.document
    };
    receipt
        .verify_proof_with(|proof, binding| {
            verify_detached_jws_against_method(
                &proof.jws,
                binding,
                &document.verification_method,
                proof.verification_method.as_str(),
            )
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
        })
        .map_err(gate_protocol_error)
}

fn gate_protocol_error(error: impl ToString) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::BAD_GATEWAY,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        format!(
            "device revocation gate verification failed: {}",
            error.to_string()
        ),
    )
}
