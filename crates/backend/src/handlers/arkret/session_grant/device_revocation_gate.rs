use arkret_identifiers::Hash;
use arkret_models_identity::SessionGrantDeviceBinding;
use arkret_wire::{
    AccountId, DeviceId, DeviceRevocationGateActionClass, DeviceRevocationGateCheckRequestBody,
    DeviceRevocationGateDecision,
};
use chrono::{DateTime, Utc};
use salvo::prelude::{Depot, StatusCode};

use crate::handlers::arkret::ArkretRouteError;
use crate::handlers::common::DepotExt as _;
use crate::services::peer_protocol_client::{InternalAuthorityChannel, PeerProtocolClientError};

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
    let outcome = channel
        .post_device_revocation_gate_check(&request)
        .await
        .map_err(map_peer_gate_error)?;
    ensure_receipt_answers_this_channel(&channel, &outcome)?;

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
            StatusCode::BAD_GATEWAY,
            arkret_wire::ErrorCode::UPSTREAM_UNAVAILABLE,
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

/// Bind the decision receipt to the registered internal channel it arrived on.
///
/// `crypto-media/device-lifecycle.md` §2.2: the receipt is delivered only on
/// the registered deployment-internal authenticated channel between the
/// Account Authority this exact account is bound to and its origin Station,
/// and that channel — not a detached proof — supplies its authenticity and
/// integrity. The receipt therefore carries neither `proof` nor
/// `verification_method` (the SDK wire type rejects either member), and a
/// receipt that did not arrive on this channel is rejected. There is no
/// "verify it when a proof is present, pass it through otherwise" path.
///
/// What remains here is the binding check the channel cannot make for us: the
/// answer must be about the exact account whose configured origin Station this
/// channel was opened to. Every other non-signature check — complete
/// `AccountId`, `device_id`, `action_class`, `intent_digest`, the closed
/// decision branches, `linearization_seq`, the ≤30 second window, exact replay
/// and the `accepted_device_possession_proof_digest` comparison — runs in the
/// SDK's `validate_for_request` / `session_grant_admission` and is unchanged.
fn ensure_receipt_answers_this_channel(
    channel: &InternalAuthorityChannel<'_>,
    outcome: &arkret_wire::DeviceRevocationGateCheckOutcome,
) -> Result<(), ArkretRouteError> {
    if &outcome.decision_receipt.account_id.station_id != channel.destination_service_id() {
        return Err(gate_protocol_error(
            "gate receipt is not bound to the configured origin Station of this channel",
        ));
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

    fn allow_receipt(station_id: &str) -> arkret_wire::DeviceRevocationGateCheckOutcome {
        let linearized_at = chrono::DateTime::<chrono::Utc>::from_timestamp(1_800_000_000, 0)
            .expect("test timestamp");
        arkret_wire::DeviceRevocationGateCheckOutcome {
            decision_receipt: arkret_wire::DeviceRevocationGateDecisionReceipt {
                account_id: AccountId::new(
                    core_id("ak:did_core:web:alice.example"),
                    core_id(station_id),
                ),
                device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001")
                    .expect("test device id"),
                target_device_authorize_event_id: Some(
                    arkret_wire::EventId::new(
                        "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
                    )
                    .expect("test event id"),
                ),
                target_device_generation_ref: Some(1),
                action_class: DeviceRevocationGateActionClass::SessionGrantIssue,
                intent_digest: Hash::new(format!("sha256:{}", "a".repeat(64)))
                    .expect("test intent digest"),
                accepted_device_possession_proof_digest: None,
                decision: DeviceRevocationGateDecision::Allow,
                linearization_seq: 1,
                linearized_at,
                expires_at: linearized_at + chrono::Duration::seconds(30),
                accepted_commit_id: None,
            },
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

    /// The channel is the receipt's only authenticity source, so the answer
    /// must be about the exact account whose configured origin Station this
    /// channel was opened to.
    #[test]
    fn receipt_for_another_station_is_rejected() {
        let endpoint = url::Url::parse("https://station.example/").expect("test endpoint");
        let http_client = crate::reqwest_client();
        let channel = channel_to(&endpoint, &http_client, "ak:did_core:web:station.example");
        ensure_receipt_answers_this_channel(
            &channel,
            &allow_receipt("ak:did_core:web:station.example"),
        )
        .expect("a receipt bound to the configured origin Station is accepted");
        let error = ensure_receipt_answers_this_channel(
            &channel,
            &allow_receipt("ak:did_core:web:other-station.example"),
        )
        .expect_err("a receipt bound to another Station must be rejected");
        assert!(matches!(error, ArkretRouteError::Coded { .. }));
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
    fn peer_5xx_is_an_attributable_upstream_failure() {
        let error = map_peer_gate_error(PeerProtocolClientError::Status {
            status: 503,
            problem: None,
        });
        assert!(matches!(
            error,
            ArkretRouteError::Coded {
                status: StatusCode::BAD_GATEWAY,
                code: arkret_wire::ErrorCode::UPSTREAM_UNAVAILABLE,
                ..
            }
        ));
    }
}
