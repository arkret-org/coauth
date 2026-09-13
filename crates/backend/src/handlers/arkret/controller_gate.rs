//! Durable Account Authority controller-lifecycle gate issuance.

use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::agent_signer_evidence::{
    AgentDetachedJws, ControllerAccountEligibility, ControllerAccountGateAttestation,
    ControllerAccountGateAttestationIssueOutcome, ControllerAccountGateAttestationIssueRequestBody,
    ControllerAccountGateBasis, ControllerAccountStatus,
};
use arkret_wire::{DidUrl, NonEmptyString};
use chrono::{Duration, Timelike as _};
use coauth_data::account_handoff::{
    ControllerGateAttestationCommit, ControllerGateAttestationReserve,
    NewControllerGateAttestationIssuance,
};
use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
use coauth_data::{Clock as _, RepositoryAccess as _};
use salvo::prelude::*;

use super::{ArkretRouteError, owning_station_id_for};
use crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes;
use crate::handlers::common::DepotExt;

const GATE_TTL: Duration = Duration::minutes(5);
const REPLAY_RETENTION: Duration = Duration::days(7);
const GATE_OPERATION_ID: &str =
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_CONTROLLER_GATE_ATTESTATION_V1;

pub struct ControllerGateCanonicalJson(Vec<u8>);

impl Scribe for ControllerGateCanonicalJson {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.0)
            .expect("canonical controller gate outcome is writable");
    }
}

/// `POST /_arkret/gate/account/controller-gate-attestations`.
#[handler]
pub async fn issue_controller_gate_attestation(
    req: &mut Request,
    depot: &Depot,
) -> Result<ControllerGateCanonicalJson, ArkretRouteError> {
    let canonical_body = req
        .payload()
        .await
        .map_err(|_| schema_violation("invalid controller gate attestation request"))?
        .to_vec();
    let request: ControllerAccountGateAttestationIssueRequestBody =
        serde_json::from_slice(&canonical_body)
            .map_err(|_| schema_violation("invalid controller gate attestation request"))?;

    let canonical_intent = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|error| schema_violation(error.to_string()))?;
    let canonical_intent_digest =
        arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(&canonical_intent))?;
    let clock = crate::handlers::make_clock();
    let now = clock
        .now()
        .with_nanosecond(0)
        .ok_or_else(|| ArkretRouteError::Internal("invalid clock precision".into()))?;

    let mut repo = depot.repo().await?;
    authenticate_internal_channel_caller(req, depot, &request)
        .inspect_err(|_| tracing::warn!("controller gate Agent Authority authentication failed"))?;
    let binding = repo
        .principal_did()
        .get_by_principal_id_and_audience(
            request.principal_id.as_str(),
            request.agent_authority_id.as_str(),
        )
        .await?
        .filter(|binding| binding.accepted_id == request.agent_authority_id)
        .ok_or_else(|| {
            tracing::warn!("controller gate principal binding unavailable for Agent Authority");
            not_found()
        })?;
    let user = repo
        .user()
        .lookup(binding.user_id)
        .await?
        .ok_or_else(not_found)?;

    let reserve = repo
        .account_handoff()
        .reserve_controller_gate_attestation(NewControllerGateAttestationIssuance {
            request_id: request.request_id.clone(),
            canonical_intent_digest: canonical_intent_digest.clone(),
            principal_id: request.principal_id.clone(),
            agent_authority_id: request.agent_authority_id.clone(),
            retained_until: now + REPLAY_RETENTION,
            now,
        })
        .await?;
    match reserve {
        ControllerGateAttestationReserve::Replay(record) => {
            let bytes = record.canonical_outcome.ok_or_else(indeterminate)?;
            repo.cancel().await.ok();
            return Ok(ControllerGateCanonicalJson(bytes));
        }
        ControllerGateAttestationReserve::Conflict(_) => {
            repo.cancel().await.ok();
            return Err(duplicate_conflict());
        }
        ControllerGateAttestationReserve::Indeterminate(_) => {
            repo.cancel().await.ok();
            return Err(indeterminate());
        }
        ControllerGateAttestationReserve::Reserved(_) => {}
    }

    let (status, eligibility) = controller_status(user.status);
    let authority_did = super::owning_station_did_for(&depot.arkret_config()?);
    let authority_id = owning_station_id_for(&depot.arkret_config()?);
    let key_store = depot.key_store()?;
    // The attestation is signed as the owning Station, and soland verifies it
    // by resolving `verification_method` out of the Station's DID document.
    // That document authorizes exactly one method for this Account Authority,
    // holding the designated Account Authority key. Selecting "an Ed25519
    // key" by algorithm returned whichever key sat last in the keystore and
    // wrote its `kid` as the fragment - a method that exists in no DID
    // document, so the attestation could never verify.
    let signing_seed = key_store.account_authority_seed().map_err(|error| {
        ArkretRouteError::Internal(format!("Account Authority signing key: {error}").into())
    })?;
    let signing_key_id =
        crate::services::peer_protocol_client::ACCOUNT_AUTHORITY_VERIFICATION_METHOD_FRAGMENT;
    let expires_at = now + GATE_TTL;
    let basis = ControllerAccountGateBasis::AccountBindingDefault {
        binding_version: binding.binding_version,
        binding_frontier_digest: binding.binding_frontier_digest,
    };
    let basis_digest =
        arkret_identifiers::Hash::new(arkret_canonical::canonical_sha256(&serde_json::json!({
            "principal_id": &request.principal_id,
            "accepted_id": &request.agent_authority_id,
            "status": status,
            "basis": &basis,
        }))?)?;
    let mut attestation = ControllerAccountGateAttestation {
        schema: NonEmptyString::new(
            arkret_wire::SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1.to_owned(),
        )
        .map_err(|error| ArkretRouteError::Internal(std::io::Error::other(error).into()))?,
        principal_id: request.principal_id.clone(),
        eligibility,
        status,
        basis,
        basis_digest,
        authority_id,
        verification_method: DidUrl::new(format!("{authority_did}#{signing_key_id}"))
            .map_err(|error| ArkretRouteError::Internal(std::io::Error::other(error).into()))?,
        issued_at: now,
        expires_at,
        proof: AgentDetachedJws {
            kind: NonEmptyString::new("detached_jws".to_owned())
                .map_err(|error| ArkretRouteError::Internal(std::io::Error::other(error).into()))?,
            jws: NonEmptyString::new("pending".to_owned())
                .map_err(|error| ArkretRouteError::Internal(std::io::Error::other(error).into()))?,
        },
    };
    let sdk_signing_key = sdk_signing_key_from_seed_bytes(&signing_seed);
    arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
        &mut attestation,
        &sdk_signing_key,
    )
    .map_err(|_| ArkretRouteError::Internal("controller gate signing failed".into()))?;
    let outcome = ControllerAccountGateAttestationIssueOutcome {
        request_id: request.request_id.clone(),
        controller_account_gate_attestation: attestation,
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;
    let outcome_digest =
        arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(&canonical_outcome))?;
    let committed = repo
        .account_handoff()
        .commit_controller_gate_attestation(
            &request.request_id,
            &canonical_intent_digest,
            &canonical_outcome,
            &outcome_digest,
            expires_at,
            now,
        )
        .await?;
    let response = match committed {
        ControllerGateAttestationCommit::Committed(record)
        | ControllerGateAttestationCommit::Replay(record) => {
            record.canonical_outcome.ok_or_else(indeterminate)?
        }
        ControllerGateAttestationCommit::Conflict(_) => return Err(duplicate_conflict()),
        ControllerGateAttestationCommit::Indeterminate(_) => return Err(indeterminate()),
    };
    repo.save().await?;
    Ok(ControllerGateCanonicalJson(response))
}

/// Authenticate the caller on the registered deployment-internal channel
/// (`sync/service-http-binding.md` §2.2.3).
///
/// The internal identity comes only from verifying the credential configured
/// for this exact Account Authority / Station edge. `Source-Service-ID`,
/// `Destination-Service-ID`, a path segment, a `DidCoreId`/URL in the body and
/// any caller-supplied key MUST NOT decide the identity or supply a
/// verification key; when those redundant transport inputs are present they are
/// compared verbatim against the authenticated facts and any disagreement is a
/// rejection. The channel is the complete authentication contract for this
/// operation and replaces the RFC 9421 request signature, so the request body
/// no longer carries a service-resolution carrier.
///
/// The verified caller MUST equal `agent_authority_id`; the caller's verbatim
/// equality with the principal's current `AcceptedAtServiceBinding.service_id`
/// is enforced by the binding lookup in the handler, which resolves the
/// principal only under that exact accepted service id.
///
/// The *response* attestation keeps its signature, its verification method's
/// public DID assertion authorization, its TTL and its exact replay: it leaves
/// this relationship and enters the external Agent evidence chain.
fn authenticate_internal_channel_caller(
    req: &Request,
    depot: &Depot,
    request: &ControllerAccountGateAttestationIssueRequestBody,
) -> Result<(), ArkretRouteError> {
    let config = depot.arkret_config()?;
    let credential = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(not_found)?;
    let authenticated_caller = super::station_internal_channel_caller_for_request(
        &config,
        credential,
        req.headers(),
        GATE_OPERATION_ID,
    )
    .ok_or_else(not_found)?;
    if authenticated_caller != request.agent_authority_id.as_str() {
        return Err(not_found());
    }
    Ok(())
}

#[cfg(test)]
fn validate_redundant_channel_headers(
    headers: &http::HeaderMap,
    source_service_id: &str,
    destination_service_id: &str,
    source_trust_domain: Option<&str>,
    destination_trust_domain: Option<&str>,
) -> Result<(), ArkretRouteError> {
    let redundant = [
        ("source-service-id", Some(source_service_id)),
        ("destination-service-id", Some(destination_service_id)),
        ("arkret-operation", Some(GATE_OPERATION_ID)),
        ("source-trust-domain", source_trust_domain),
        ("destination-trust-domain", destination_trust_domain),
    ];
    for (header, expected) in redundant {
        if let Some(value) = headers.get(header) {
            let observed = value.to_str().map_err(|_| not_found())?;
            if !expected.is_some_and(|expected| observed == expected) {
                return Err(not_found());
            }
        }
    }
    Ok(())
}

fn controller_status(
    status: AccountStatus,
) -> (ControllerAccountStatus, ControllerAccountEligibility) {
    match status {
        AccountStatus::Active => (
            ControllerAccountStatus::Active,
            ControllerAccountEligibility::Active,
        ),
        AccountStatus::SoftLoggedOut => (
            ControllerAccountStatus::SoftLoggedOut,
            ControllerAccountEligibility::Inactive,
        ),
        AccountStatus::Locked => (
            ControllerAccountStatus::Locked,
            ControllerAccountEligibility::Inactive,
        ),
        AccountStatus::Suspended => (
            ControllerAccountStatus::Suspended,
            ControllerAccountEligibility::Inactive,
        ),
        AccountStatus::Deactivated => (
            ControllerAccountStatus::Deactivated,
            ControllerAccountEligibility::Inactive,
        ),
        AccountStatus::ErasurePending => (
            ControllerAccountStatus::ErasurePending,
            ControllerAccountEligibility::Inactive,
        ),
    }
}

#[track_caller]
fn not_found() -> ArkretRouteError {
    tracing::warn!(location = %std::panic::Location::caller(), "controller gate verification rejected");
    ArkretRouteError::coded(
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
        "controller gate unavailable",
    )
}

fn duplicate_conflict() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
        "request_id was reused with a different controller gate intent",
    )
}

fn indeterminate() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        "controller gate issuance is indeterminate",
    )
}

fn schema_violation(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "ak:did_core:web:agent-authority.example";
    const DESTINATION: &str = "ak:did_core:web:station.example";
    const SOURCE_DOMAIN: &str = "ak:trust_domain:agent-authority.example";
    const DESTINATION_DOMAIN: &str = "ak:trust_domain:station.example";

    fn canonical_headers() -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert("source-service-id", SOURCE.parse().unwrap());
        headers.insert("destination-service-id", DESTINATION.parse().unwrap());
        headers.insert("arkret-operation", GATE_OPERATION_ID.parse().unwrap());
        headers.insert("source-trust-domain", SOURCE_DOMAIN.parse().unwrap());
        headers.insert(
            "destination-trust-domain",
            DESTINATION_DOMAIN.parse().unwrap(),
        );
        headers
    }

    fn validate(headers: &http::HeaderMap) -> Result<(), ArkretRouteError> {
        validate_redundant_channel_headers(
            headers,
            SOURCE,
            DESTINATION,
            Some(SOURCE_DOMAIN),
            Some(DESTINATION_DOMAIN),
        )
    }

    #[test]
    fn redundant_internal_channel_headers_match_registered_facts_verbatim() {
        assert!(validate(&canonical_headers()).is_ok());

        for (name, wrong) in [
            ("source-service-id", "ak:did_core:web:other-station.example"),
            (
                "destination-service-id",
                "ak:did_core:web:other-auth.example",
            ),
            ("source-trust-domain", "ak:trust_domain:wrong.example"),
            ("destination-trust-domain", "ak:trust_domain:wrong.example"),
            (
                "arkret-operation",
                arkret_wire::ServiceOperationId::PEER_DEVICE_REVOCATIONS_COMMAND_CHECK_V1,
            ),
        ] {
            let mut headers = canonical_headers();
            headers.insert(name, wrong.parse().unwrap());
            assert!(validate(&headers).is_err(), "{name} mismatch must reject");
        }

        let mut whitespace_changed = canonical_headers();
        whitespace_changed.insert("source-service-id", format!(" {SOURCE}").parse().unwrap());
        assert!(validate(&whitespace_changed).is_err());
    }

    #[test]
    fn a_present_redundant_header_requires_the_corresponding_configuration() {
        let headers = canonical_headers();
        assert!(
            validate_redundant_channel_headers(
                &headers,
                SOURCE,
                DESTINATION,
                None,
                Some(DESTINATION_DOMAIN),
            )
            .is_err()
        );
        assert!(
            validate_redundant_channel_headers(
                &headers,
                SOURCE,
                DESTINATION,
                Some(SOURCE_DOMAIN),
                None,
            )
            .is_err()
        );
    }
}
