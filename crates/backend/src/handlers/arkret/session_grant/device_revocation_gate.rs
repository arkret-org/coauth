use arkret_identifiers::Hash;
use arkret_models_identity::SessionGrantDeviceBinding;
use arkret_wire::{
    AcceptedDevicePossessionProof, AccountId, DeviceId, DeviceRevocationAdmissionInput,
    DeviceRevocationDeniedAction, EventId, RealmCommitId,
};
use chrono::{DateTime, Utc};
use salvo::prelude::{Depot, StatusCode};

use crate::handlers::arkret::ArkretRouteError;
use crate::handlers::common::DepotExt as _;
use crate::services::peer_protocol_client::{InternalAuthorityChannel, PeerProtocolClientError};

const PRIVATE_CURRENT_DEVICE_PATH: &str = "/_soland/account-authority/current-device/check";

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateCurrentDeviceRequest {
    account_id: AccountId,
    device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_device_authorize_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_device_generation_ref: Option<u64>,
    action_class: DeviceRevocationDeniedAction,
    intent_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_device_possession_proof: Option<AcceptedDevicePossessionProof>,
    requested_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrivateCurrentDeviceDecision {
    Allow,
    RevocationPending,
    Revoked,
    AuthorityMismatch,
    GenerationMismatch,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateCurrentDeviceResponse {
    account_id: AccountId,
    device_id: DeviceId,
    #[serde(default)]
    authorization_event_id: Option<EventId>,
    #[serde(default)]
    device_generation_ref: Option<u64>,
    action_class: DeviceRevocationDeniedAction,
    intent_digest: Hash,
    #[serde(default)]
    accepted_device_possession_proof_digest: Option<Hash>,
    decision: PrivateCurrentDeviceDecision,
    linearization_seq: u64,
    linearized_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    #[serde(default)]
    accepted_commit_id: Option<RealmCommitId>,
}

/// Resolve and linearize the current-device decision through the owning
/// Station's private TCB adapter. The adapter response is consumed here and
/// never exposed as an Arkret receipt or canonical operation outcome.
pub(crate) async fn acquire_private_current_device_binding(
    depot: &Depot,
    account_id: &AccountId,
    device_id: DeviceId,
    action_class: DeviceRevocationDeniedAction,
    expected_binding: Option<&SessionGrantDeviceBinding>,
    accepted_device_possession_proof: Option<arkret_wire::AcceptedDevicePossessionProof>,
    intent_digest: Hash,
    now: DateTime<Utc>,
) -> Result<SessionGrantDeviceBinding, ArkretRouteError> {
    let config = depot.arkret_config()?;
    // The origin Station of this exact account is selected from explicit
    // deployment configuration only (`service-http-binding.md` §2.2.3): a
    // configured entry whose configured identity equals the account's
    // `station_id`. No `describe` probe, no "first configured Station", and no
    // value read out of a response body may stand in for it.
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
            SessionGrantDeviceBinding::as_expected_revocation_binding,
        );
    let request = PrivateCurrentDeviceRequest {
        account_id: account_id.clone(),
        device_id,
        expected_device_authorize_event_id,
        expected_device_generation_ref,
        action_class,
        intent_digest,
        accepted_device_possession_proof,
        requested_at: arkret_canonical::normalize_timestamp_canonical(now),
    };
    validate_private_request(&request).map_err(gate_protocol_error)?;

    let http_client = depot.http_client()?;
    // `PeerProtocolClientError` deliberately has no `From` for
    // `ArkretRouteError`: `account_register.rs::map_peer_error` maps the same
    // type onto registry codes, so a blanket `?` conversion here would be the
    // wrong default. The gate treats a transport-level failure as internal.
    let channel = InternalAuthorityChannel::new(
        &destination.endpoint,
        &http_client,
        destination.internal_authority_shared_secret(),
        account_id.station_id.clone(),
    )
    .map_err(map_peer_gate_error)?;
    let outcome: PrivateCurrentDeviceResponse = channel
        .post_private_json(
            "private_current_device_check",
            PRIVATE_CURRENT_DEVICE_PATH,
            &request,
            None,
        )
        .await
        .map_err(map_peer_gate_error)?;
    validate_private_response(&channel, &request, &outcome, now).map_err(gate_protocol_error)?;

    match outcome.decision {
        PrivateCurrentDeviceDecision::Allow => Ok(SessionGrantDeviceBinding {
            device_id: outcome.device_id,
            authorization_event_id: outcome
                .authorization_event_id
                .ok_or_else(|| gate_protocol_error("allow omitted authorization Event"))?,
            model_generation_ref: outcome
                .device_generation_ref
                .ok_or_else(|| gate_protocol_error("allow omitted device generation"))?,
        }),
        PrivateCurrentDeviceDecision::AuthorityMismatch => Err(ArkretRouteError::coded(
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::DEVICE_UNAUTHORIZED,
            "device is not currently authorized for this principal",
        )),
        PrivateCurrentDeviceDecision::RevocationPending => Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::DEVICE_REVOCATION_PENDING,
            "device revocation is pending",
        )),
        PrivateCurrentDeviceDecision::Revoked
        | PrivateCurrentDeviceDecision::GenerationMismatch => Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::DEVICE_REVOKED,
            "device authorization is revoked or generation-fenced",
        )),
    }
}

fn map_peer_gate_error(error: PeerProtocolClientError) -> ArkretRouteError {
    match error {
        PeerProtocolClientError::Status {
            status,
            problem: Some(problem),
        } if (400..500).contains(&status) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
            let code = arkret_wire::ErrorCode::from_wire(problem.code()).map_or(
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                arkret_wire::ErrorCode::as_str,
            );
            ArkretRouteError::coded(status, code, problem.detail)
        }
        PeerProtocolClientError::Status { status, .. } if (400..500).contains(&status) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
            ArkretRouteError::coded(
                status,
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                "origin Station rejected the device revocation gate request",
            )
        }
        PeerProtocolClientError::Status { .. }
        | PeerProtocolClientError::Http(_)
        | PeerProtocolClientError::BaseUrlNotConfigured => ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            "origin Station device revocation gate is unavailable",
        ),
        PeerProtocolClientError::Response(error) => ArkretRouteError::coded(
            StatusCode::BAD_GATEWAY,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            format!("origin Station returned an invalid device revocation gate response: {error}"),
        ),
        // A gap in the registered internal channel configuration fails closed.
        // The gate never downgrades to an unauthenticated or signature-only
        // call to reach the Station anyway.
        PeerProtocolClientError::InternalChannelNotConfigured(error) => ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            format!("device revocation gate channel is unavailable: {error}"),
        ),
        other => ArkretRouteError::Internal(Box::new(other)),
    }
}

fn validate_private_request(request: &PrivateCurrentDeviceRequest) -> Result<(), String> {
    DeviceRevocationAdmissionInput {
        account_id: request.account_id.clone(),
        device_id: request.device_id.clone(),
        expected_device_authorize_event_id: request.expected_device_authorize_event_id.clone(),
        expected_device_generation_ref: request.expected_device_generation_ref,
        action_class: request.action_class,
        intent_digest: request.intent_digest.clone(),
        accepted_device_possession_proof: request.accepted_device_possession_proof.clone(),
        requested_at: request.requested_at,
    }
    .validate()
    .map_err(|error| error.to_string())
}

fn validate_private_response(
    channel: &InternalAuthorityChannel<'_>,
    request: &PrivateCurrentDeviceRequest,
    response: &PrivateCurrentDeviceResponse,
    now: DateTime<Utc>,
) -> Result<(), String> {
    if &response.account_id.station_id != channel.destination_service_id()
        || response.account_id != request.account_id
        || response.device_id != request.device_id
        || response.action_class != request.action_class
        || response.intent_digest != request.intent_digest
    {
        return Err("private current-device response does not bind the request/channel".to_owned());
    }
    let expected_proof_digest = request
        .accepted_device_possession_proof
        .as_ref()
        .map(AcceptedDevicePossessionProof::proof_digest)
        .transpose()
        .map_err(|error| error.to_string())?;
    if response.accepted_device_possession_proof_digest != expected_proof_digest {
        return Err(
            "private current-device response does not bind the possession proof".to_owned(),
        );
    }
    let has_binding = matches!(
        (&response.authorization_event_id, response.device_generation_ref),
        (Some(_), Some(generation)) if generation > 0
    );
    if has_binding != (response.decision == PrivateCurrentDeviceDecision::Allow)
        || response.accepted_commit_id.is_some()
            != (response.decision == PrivateCurrentDeviceDecision::Allow)
    {
        return Err("private current-device response has an invalid decision witness".to_owned());
    }
    if response.decision == PrivateCurrentDeviceDecision::Allow
        && request.expected_device_authorize_event_id.is_some()
        && (response.authorization_event_id != request.expected_device_authorize_event_id
            || response.device_generation_ref != request.expected_device_generation_ref)
    {
        return Err("private current-device allow changed the expected binding".to_owned());
    }
    if response.linearization_seq == 0
        || response.expires_at <= response.linearized_at
        || response.expires_at - response.linearized_at > chrono::Duration::seconds(30)
        || now >= response.expires_at
    {
        return Err(
            "private current-device response is stale or has an invalid lifetime".to_owned(),
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn core_id(value: &str) -> arkret_identifiers::DidCoreId {
        arkret_identifiers::DidCoreId::new(value.to_owned()).expect("test service core id")
    }

    fn channel_to<'a>(
        endpoint: &'a url::Url,
        http_client: &'a reqwest::Client,
        destination: &str,
    ) -> InternalAuthorityChannel<'a> {
        InternalAuthorityChannel::new(
            endpoint,
            http_client,
            Some("configured-internal-channel-credential"),
            core_id(destination),
        )
        .expect("configured internal channel")
    }

    fn allow_response(station_id: &str) -> PrivateCurrentDeviceResponse {
        let linearized_at = chrono::DateTime::<chrono::Utc>::from_timestamp(1_800_000_000, 0)
            .expect("test timestamp");
        PrivateCurrentDeviceResponse {
            account_id: AccountId::new(
                core_id("ak:did_core:web:alice.example"),
                core_id(station_id),
            ),
            device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001")
                .expect("test device id"),
            authorization_event_id: Some(
                arkret_wire::EventId::new("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e")
                    .expect("test event id"),
            ),
            device_generation_ref: Some(1),
            action_class: DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
            intent_digest: Hash::new(format!("sha256:{}", "a".repeat(64)))
                .expect("test intent digest"),
            accepted_device_possession_proof_digest: None,
            decision: PrivateCurrentDeviceDecision::Allow,
            linearization_seq: 1,
            linearized_at,
            expires_at: linearized_at + chrono::Duration::seconds(30),
            accepted_commit_id: Some(
                RealmCommitId::new("ak:realm_commit:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e")
                    .expect("test RealmCommit id"),
            ),
        }
    }

    /// A missing channel credential is a configuration gap, not permission to
    /// call the origin Station unauthenticated.
    #[test]
    fn internal_channel_without_a_configured_credential_fails_closed() {
        let endpoint = url::Url::parse("https://station.example/").expect("test endpoint");
        let http_client = crate::reqwest_client();
        // `InternalAuthorityChannel` is deliberately not `Debug` (it holds a
        // credential), so destructure rather than using `expect_err`.
        let Err(error) = InternalAuthorityChannel::new(
            &endpoint,
            &http_client,
            None,
            core_id("ak:did_core:web:station.example"),
        ) else {
            panic!("an unconfigured channel must not be usable");
        };
        assert!(matches!(
            &error,
            PeerProtocolClientError::InternalChannelNotConfigured(_)
        ));
        assert!(matches!(
            map_peer_gate_error(error),
            ArkretRouteError::Coded {
                status: StatusCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));
    }

    /// The channel is the private adapter's authenticity source, so the answer
    /// must be about the exact account whose configured origin Station this
    /// channel was opened to.
    #[test]
    fn private_response_for_another_station_is_rejected() {
        let endpoint = url::Url::parse("https://station.example/").expect("test endpoint");
        let http_client = crate::reqwest_client();
        let channel = channel_to(&endpoint, &http_client, "ak:did_core:web:station.example");
        let response = allow_response("ak:did_core:web:station.example");
        let request = PrivateCurrentDeviceRequest {
            account_id: response.account_id.clone(),
            device_id: response.device_id.clone(),
            expected_device_authorize_event_id: None,
            expected_device_generation_ref: None,
            action_class: response.action_class,
            intent_digest: response.intent_digest.clone(),
            accepted_device_possession_proof: None,
            requested_at: response.linearized_at,
        };
        validate_private_response(&channel, &request, &response, response.linearized_at)
            .expect("a response bound to the configured origin Station is accepted");
        let error = validate_private_response(
            &channel,
            &request,
            &allow_response("ak:did_core:web:other-station.example"),
            response.linearized_at,
        )
        .expect_err("a response bound to another Station must be rejected");
        assert!(error.contains("request/channel"));
    }

    #[test]
    fn peer_problem_4xx_keeps_status_and_registered_code() {
        let error = map_peer_gate_error(PeerProtocolClientError::Status {
            status: 400,
            problem: Some(Box::new(arkret_wire::Problem::new(
                arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                400,
                "accepted-device possession proof is invalid",
            ))),
        });
        assert!(matches!(
            error,
            ArkretRouteError::Coded {
                status: StatusCode::BAD_REQUEST,
                code: arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                ..
            }
        ));
    }

    #[test]
    fn peer_5xx_fails_closed_as_service_unavailable() {
        let error = map_peer_gate_error(PeerProtocolClientError::Status {
            status: 503,
            problem: None,
        });
        assert!(matches!(
            error,
            ArkretRouteError::Coded {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));
    }
}
