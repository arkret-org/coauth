use arkret_identifiers::{DidFullId, Hash, project_full_id_to_core_id};
use arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding;
use arkret_models_identity::SessionGrantDeviceBinding;
use arkret_wire::{
    DeviceId, DeviceRevocationGateActionClass, DeviceRevocationGateCheckRequestBody,
    DeviceRevocationGateDecision, PrincipalAuthorityKey,
};
use chrono::{DateTime, Utc};
use salvo::prelude::{Depot, StatusCode};

use crate::handlers::arkret::{ArkretRouteError, issuer_did_for, service_id_for, trust_domain_for};
use crate::handlers::common::DepotExt as _;
use crate::services::did_binding_proof::verify_detached_jws_with_sdk;
use crate::services::peer_protocol_client::PeerProtocolClient;

pub(crate) fn operation_intent_digest(
    operation: &coauth_data::SessionGrantOperation,
) -> Result<Hash, ArkretRouteError> {
    Hash::new(format!(
        "sha256:{}",
        hex::encode(operation.canonical_intent_digest)
    ))
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}

pub(crate) async fn acquire_human_device_binding(
    depot: &Depot,
    principal_authority: &PrincipalAuthorityKey,
    device_id: DeviceId,
    action_class: DeviceRevocationGateActionClass,
    expected_binding: Option<&SessionGrantDeviceBinding>,
    intent_digest: Hash,
    now: DateTime<Utc>,
) -> Result<Option<SessionGrantDeviceBinding>, ArkretRouteError> {
    let config = depot.arkret_config()?;
    let destination = config
        .principal_servers
        .iter()
        .find(|server| {
            crate::services::resolved_principal_audiences::effective_audience_shared(server)
                .is_some_and(|audience| audience == principal_authority.principal_server_id)
        })
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::BAD_REQUEST,
                arkret_wire::ErrorCode::AUDIENCE_UNKNOWN,
                "principal authority has no configured origin Principal Server",
            )
        })?;
    let (expected_device_authorize_event_id, expected_device_generation_ref) = expected_binding
        .map(SessionGrantDeviceBinding::as_expected_gate_binding)
        .unwrap_or((None, None));
    let request = DeviceRevocationGateCheckRequestBody {
        principal_authority: principal_authority.clone(),
        device_id,
        expected_device_authorize_event_id,
        expected_device_generation_ref,
        action_class,
        intent_digest,
        requested_at: arkret_canonical::normalize_timestamp_canonical(now),
    };
    request.validate().map_err(gate_protocol_error)?;

    let source_service_id = service_id_for(&config);
    let trust_domain =
        arkret_identifiers::TrustDomainId::new(trust_domain_for(&depot.url_builder()?, &config))
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let identity = KeyPackagesClaimServiceBinding {
        source_service_id: source_service_id.into(),
        destination_service_id: principal_authority.principal_server_id.clone().into(),
    };
    let http_client = depot.http_client()?;
    let key_store = depot.key_store()?;
    let client = PeerProtocolClient::new(
        Some(&destination.endpoint),
        &http_client,
        &key_store,
        issuer_did_for(&config),
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
        DeviceRevocationGateDecision::Allow | DeviceRevocationGateDecision::AuthorityMismatch => {
            SessionGrantDeviceBinding::from_gate_outcome(&outcome, &request, now)
                .map_err(gate_protocol_error)
        }
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
    let controller = DidFullId::new(controller.to_owned())
        .map_err(|error| gate_protocol_error(error.to_string()))?;
    let controller_core = project_full_id_to_core_id(&controller)
        .map_err(|error| gate_protocol_error(error.to_string()))?;
    if controller_core != receipt.principal_authority.principal_server_id {
        return Err(gate_protocol_error(
            "gate receipt signer is not the origin Principal Server",
        ));
    }

    let http_client = depot.http_client()?;
    let document = if controller.as_str().starts_with("did:webvh:") {
        crate::services::did_resolver::resolve_verified_webvh_document_at(
            &http_client,
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
            let verified_method =
                verify_detached_jws_with_sdk(&proof.jws, binding, &document.verification_method)
                    .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))?;
            if verified_method != proof.verification_method.as_str() {
                return Err(arkret_wire::Error::Protocol(
                    "gate receipt proof verified under a different method".to_owned(),
                ));
            }
            Ok(())
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
