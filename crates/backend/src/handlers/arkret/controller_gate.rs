//! Durable Account Authority controller-lifecycle gate issuance.

use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::agent_signer_evidence::{
    AgentDetachedJws, ControllerAccountEligibility, ControllerAccountGateAttestation,
    ControllerAccountGateAttestationIssueOutcome, ControllerAccountGateAttestationIssueRequestBody,
    ControllerAccountGateBasis, ControllerAccountStatus,
};
use arkret_signatures::http_signature::{
    Component, ContentDigest, Ed25519PublicKey, SignatureVerificationPolicy, parse_signature_input,
    verify_signed_canonical_json_message,
};
use arkret_wire::{DidUrl, NonEmptyString};
use chrono::{Duration, Timelike as _};
use coauth_data::account_handoff::{
    ControllerGateAttestationCommit, ControllerGateAttestationReserve,
    NewControllerGateAttestationIssuance,
};
use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
use coauth_data::{Clock as _, RepositoryAccess as _};
use coauth_jose::constraints::Constrainable as _;
use salvo::prelude::*;

use super::{ArkretRouteError, service_id_for};
use crate::handlers::common::DepotExt;

const GATE_TTL: Duration = Duration::minutes(5);
const REPLAY_RETENTION: Duration = Duration::days(7);
const GATE_OPERATION_ID: &str =
    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_CONTROLLER_GATE_ATTESTATION;

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
        arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(&canonical_intent))
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let clock = crate::handlers::make_clock();
    let now = clock
        .now()
        .with_nanosecond(0)
        .ok_or_else(|| ArkretRouteError::Internal("invalid clock precision".into()))?;

    let mut repo = depot.repo().await?;
    authenticate_agent_authority_request(req, depot, &mut repo, &request, &canonical_body, now)
        .await?;
    let binding = repo
        .principal_did()
        .get_by_did_and_audience(
            request.principal_id.as_str(),
            request.agent_authority_service_id.as_str(),
        )
        .await?
        .filter(|binding| binding.accepted_service_id == request.agent_authority_service_id)
        .ok_or_else(not_found)?;
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
            agent_authority_service_id: request.agent_authority_service_id.clone(),
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
    let authority_full_id = super::issuer_did_for(&depot.arkret_config()?);
    let authority_service_id = service_id_for(&depot.arkret_config()?);
    let key_store = depot.key_store()?;
    let signing_jwk = key_store
        .signing_key_for_algorithm(&coauth_iana::jose::JsonWebSignatureAlg::Ed25519)
        .ok_or_else(|| ArkretRouteError::Internal("no Ed25519 service signing key".into()))?;
    let signing_key_id = signing_jwk
        .kid()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ArkretRouteError::Internal("Ed25519 service signing key has no kid".into())
        })?;
    let signing_key = match signing_jwk.params() {
        coauth_keystore::PrivateKey::OkpEd25519(key) => key.as_ref(),
        _ => {
            return Err(ArkretRouteError::Internal(
                "invalid Ed25519 service signing key".into(),
            ));
        }
    };
    let expires_at = now + GATE_TTL;
    let basis = ControllerAccountGateBasis::AccountBindingDefault {
        binding_version: binding.binding_version,
        binding_frontier_digest: binding.binding_frontier_digest,
    };
    let basis_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&serde_json::json!({
            "principal_id": &request.principal_id,
            "accepted_service_id": &request.agent_authority_service_id,
            "status": status,
            "basis": &basis,
        }))
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
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
        authority_service_id,
        verification_method: DidUrl::new(format!("{authority_full_id}#{signing_key_id}"))
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
    arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
        &mut attestation,
        signing_key,
    )
    .map_err(|_| ArkretRouteError::Internal("controller gate signing failed".into()))?;
    let outcome = ControllerAccountGateAttestationIssueOutcome {
        request_id: request.request_id.clone(),
        controller_account_gate_attestation: attestation,
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let outcome_digest =
        arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(&canonical_outcome))
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
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

async fn authenticate_agent_authority_request(
    req: &Request,
    depot: &Depot,
    repo: &mut coauth_data::BoxRepository,
    request: &ControllerAccountGateAttestationIssueRequestBody,
    canonical_body: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), ArkretRouteError> {
    let config = depot.arkret_config()?;
    request
        .agent_authority_service_resolution
        .validate_shape(&request.agent_authority_service_id, now)
        .map_err(|_| not_found())?;

    let full_id = &request
        .agent_authority_service_resolution
        .service_resolution_record
        .record
        .full_id;
    let resolved = crate::services::did_binding::authority_document(
        &depot.http_client()?,
        &depot.url_builder()?,
        &config,
        &depot.key_store()?,
        repo,
        depot.did_resolver_service()?.as_ref(),
        depot.verified_did_binding_store()?.as_ref(),
        full_id.as_str(),
        arkret_identity::DidBindingPurpose::Controller,
        crate::services::did_binding::controller_freshness(),
        now,
    )
    .await
    .map_err(|_| not_found())?;
    let resolved_document = serde_json::to_value(&resolved.document).map_err(|_| not_found())?;
    let carried_document = serde_json::to_value(
        &request
            .agent_authority_service_resolution
            .normalized_did_document,
    )
    .map_err(|_| not_found())?;
    let resolved_evidence = resolved.accepted.evidence_receipt();
    let carried_evidence = serde_json::to_value(
        request
            .agent_authority_service_resolution
            .method_history_evidence
            .evidence(),
    )
    .map_err(|_| not_found())?;
    if arkret_canonical::canonical_sha256(&resolved_document).map_err(|_| not_found())?
        != arkret_canonical::canonical_sha256(&carried_document).map_err(|_| not_found())?
        || arkret_canonical::canonical_sha256(&resolved_evidence).map_err(|_| not_found())?
            != arkret_canonical::canonical_sha256(&carried_evidence).map_err(|_| not_found())?
    {
        return Err(not_found());
    }

    let resolution = &request.agent_authority_service_resolution;
    arkret_signatures::service_resolution::verify_authenticated_service_resolution(
        resolution,
        &request.agent_authority_service_id,
        now,
    )
    .map_err(|_| not_found())?;

    let signature_input = req
        .headers()
        .get("signature-input")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_signature_input(value).ok())
        .ok_or_else(not_found)?;
    let key_id = DidUrl::new(signature_input.key_id.clone()).map_err(|_| not_found())?;
    let key_controller = key_id
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(not_found)?;
    if key_controller != full_id.as_str() {
        return Err(not_found());
    }
    let resolved_key = arkret_identity::resolve_verification_method_key_from_document(
        &resolution.normalized_did_document,
        key_id.as_str(),
    )
    .map_err(|_| not_found())?;
    let key_bytes = resolved_key
        .public_key
        .ed25519_bytes()
        .map_err(|_| not_found())?;
    let public_key = Ed25519PublicKey::from_bytes(&key_bytes).map_err(|_| not_found())?;

    let source = required_header(req, "source-service-id")?;
    let destination = required_header(req, "destination-service-id")?;
    let operation = required_header(req, "arkret-operation-id")?;
    let request_id = required_header(req, "arkret-request-id")?;
    let local_service_id = service_id_for(&config);
    if source != request.agent_authority_service_id.as_str()
        || destination != local_service_id.as_str()
        || operation != GATE_OPERATION_ID
        || request_id != request.request_id.as_str()
    {
        return Err(not_found());
    }
    let public_base = depot.url_builder()?.http_base();
    let authority = public_base
        .host_str()
        .map(|host| match public_base.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        })
        .ok_or_else(not_found)?;
    let target_uri = public_base
        .join(req.uri().path().trim_start_matches('/'))
        .map_err(|_| not_found())?;
    let headers = req.headers().iter().filter_map(|(name, value)| {
        value
            .to_str()
            .ok()
            .map(|value| (name.as_str().to_owned(), value.to_owned()))
    });
    let policy = SignatureVerificationPolicy::new(vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Path,
        Component::Header("content-digest".to_owned()),
        Component::Header("source-service-id".to_owned()),
        Component::Header("destination-service-id".to_owned()),
        Component::Header("arkret-operation-id".to_owned()),
        Component::Header("arkret-request-id".to_owned()),
    ])
    .require_content_digest(true)
    .max_clock_skew_seconds(300)
    .max_validity_window_seconds(300);
    verify_signed_canonical_json_message(
        req.method().as_str(),
        target_uri.as_str(),
        &authority,
        req.uri().path(),
        headers,
        req.headers().contains_key("content-encoding"),
        canonical_body,
        &public_key,
        &policy,
        now.timestamp(),
    )
    .map_err(|_| not_found())?;
    let parsed_digest = ContentDigest::parse(required_header(req, "content-digest")?.as_str())
        .map_err(|_| not_found())?;
    arkret_signatures::http_signature::verify_content_digest(&parsed_digest, canonical_body)
        .map_err(|_| not_found())?;
    Ok(())
}

fn required_header(req: &Request, name: &str) -> Result<String, ArkretRouteError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(not_found)
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

fn not_found() -> ArkretRouteError {
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
