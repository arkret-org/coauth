//! Durable Account Authority controller-lifecycle gate issuance.

use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::agent_signer_evidence::{
    AgentDetachedJws, ControllerAccountEligibility, ControllerAccountGateAttestation,
    ControllerAccountGateBasis, ControllerAccountGateIssuanceInput,
    ControllerAccountGateIssuanceResult, ControllerAccountStatus,
};
use arkret_wire::{DidUrl, NonEmptyString};
use chrono::{Duration, Timelike as _};
use coauth_data::account_handoff::{
    ControllerGateAttestationCommit, ControllerGateAttestationReserve,
    NewControllerGateAttestationIssuance,
};
use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
use coauth_data::{
    AccountStatusLedgerRepository as _, Clock as _, LocalAccountId, RepositoryAccess as _,
};
use salvo::prelude::*;

use super::{ArkretRouteError, owning_station_id_for};
use crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes;
use crate::handlers::common::DepotExt;

const GATE_TTL: Duration = Duration::minutes(5);
const REPLAY_RETENTION: Duration = Duration::days(7);

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

/// Deployment-private controller-gate attestation issuance adapter.
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
    let request: ControllerAccountGateIssuanceInput = serde_json::from_slice(&canonical_body)
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

    // Exact replay above is independent of today's user, binding and ledger.
    // New issuance holds the actual user, binding and stable ledger head cut.
    let candidate = repo
        .principal_did()
        .get_by_principal_id_and_audience(
            request.principal_id.as_str(),
            request.agent_authority_id.as_str(),
        )
        .await?
        .ok_or_else(not_found)?;
    let authority_id = owning_station_id_for(&depot.arkret_config()?);
    let local_account = LocalAccountId::new(candidate.user_id.to_string())
        .map_err(|_| schema_violation("invalid private account coordinate"))?;
    // Publication appends under this head lock before mutating the account.
    // Use the same order, including the no-record serialization point.
    let current = repo
        .account_status_ledger()
        .current_for_gate(authority_id.as_str(), local_account.as_str())
        .await?;
    let user = repo
        .user()
        .lookup_for_gate(candidate.user_id)
        .await?
        .ok_or_else(not_found)?;
    let binding = repo
        .principal_did()
        .get_by_principal_id_and_audience_for_gate(
            request.principal_id.as_str(),
            request.agent_authority_id.as_str(),
        )
        .await?
        .ok_or_else(not_found)?;
    if binding != candidate
        || binding.user_id != user.id
        || binding.accepted_id != request.agent_authority_id
        || binding.audience_id != request.agent_authority_id
        || binding.principal_id != request.principal_id
        || binding.account_id.principal_id != request.principal_id
        || binding.account_id.station_id != authority_id
        || binding.binding_receipt.account_authority_id != authority_id
    {
        return Err(not_found());
    }
    let basis = default_basis_for_locked_head(
        binding.binding_version,
        binding.binding_receipt_digest.clone(),
        &binding.account_id,
        &binding.principal_control_realm_id,
        &authority_id,
        user.status,
        current.as_ref(),
    )?;

    let (status, eligibility) = controller_status(user.status);
    let authority_did = super::owning_station_did_for(&depot.arkret_config()?);
    let keyring = depot.keyring()?;
    // The attestation is signed as the owning Station, and soland verifies it
    // by resolving `verification_method` out of the Station's DID document.
    // That document authorizes exactly one method for this Account Authority,
    // holding the designated Account Authority key. Selecting "an Ed25519
    // key" by algorithm returned whichever key sat last in the keyring and
    // wrote its `kid` as the fragment - a method that exists in no DID
    // document, so the attestation could never verify.
    let signing_seed = keyring.account_authority_seed().map_err(|error| {
        ArkretRouteError::Internal(format!("Account Authority signing key: {error}").into())
    })?;
    let signing_key_id =
        crate::services::peer_protocol_client::ACCOUNT_AUTHORITY_VERIFICATION_METHOD_FRAGMENT;
    let expires_at = now + GATE_TTL;
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
    sign_controller_gate_with_sdk(&mut attestation, &sdk_signing_key)?;
    let outcome = ControllerAccountGateIssuanceResult {
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

/// Lifecycle §3.1 installs the initial active record in the binding's own
/// transaction. That genesis is the baseline, not a stricter successor.
/// Successors (including a later return to active) cannot be relabelled as it.
/// No registered Event/checkpoint source is available for the strict branch;
/// record identity and digest must never be cast into those wire members.
fn default_basis_for_locked_head(
    binding_version: u64,
    binding_receipt_digest: arkret_identifiers::Hash,
    account: &arkret_wire::AccountId,
    pcr: &arkret_identifiers::RealmId,
    authority: &arkret_identifiers::DidCoreId,
    user_status: AccountStatus,
    current: Option<&arkret_models_collaboration::account_status::AccountStatusRecord>,
) -> Result<ControllerAccountGateBasis, ArkretRouteError> {
    let is_initial = current.is_none_or(|head| {
        head.status_seq == 1
            && head.previous_account_status_record_id.is_none()
            && head.status == AccountStatus::Active
            && head.account_id == *account
            && head.principal_control_realm_id == *pcr
            && head.account_authority_id == *authority
            && head.binding_version == binding_version
    });
    if !is_initial || user_status != AccountStatus::Active {
        return Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "controller gate accepted status checkpoint unavailable",
        ));
    }
    Ok(ControllerAccountGateBasis::AccountBindingDefault {
        binding_version,
        binding_receipt_digest,
    })
}

fn sign_controller_gate_with_sdk(
    attestation: &mut ControllerAccountGateAttestation,
    signing_key: &crate::arkret_key_bridge::SdkSigningKey,
) -> Result<(), ArkretRouteError> {
    arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
        attestation,
        signing_key,
    )
    .map_err(|error| {
        ArkretRouteError::Internal(Box::new(std::io::Error::other(format!(
            "controller gate signing failed: {error}"
        ))))
    })
}

/// Authenticate the caller on the registered deployment-internal channel
/// (`sync/service-http-binding.md` §2.2.3).
///
/// The internal identity comes only from verifying the credential configured
/// for this exact Account Authority / Station edge. Request identity headers,
/// path fields and body fields do not decide that identity. The fixed route and
/// matched peer configuration provide the remaining binding. The channel is the complete
/// authentication contract for this operation and replaces the RFC 9421 request signature, so the
/// request body no longer carries a service-resolution carrier.
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
    request: &ControllerAccountGateIssuanceInput,
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
    let authenticated_caller =
        super::station_internal_channel_caller(&config, credential).ok_or_else(not_found)?;
    if authenticated_caller != request.agent_authority_id.as_str() {
        return Err(not_found());
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
    use arkret_identifiers::{DidCoreId, Hash};
    use arkret_signatures::PublicKeyMaterial;
    use arkret_signatures::agent_evidence::verify_controller_account_gate_attestation;

    use super::*;

    fn digest(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn attestation() -> ControllerAccountGateAttestation {
        ControllerAccountGateAttestation {
            schema: NonEmptyString::new(
                arkret_wire::SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1.to_owned(),
            )
            .unwrap(),
            principal_id: DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
            eligibility: ControllerAccountEligibility::Active,
            status: ControllerAccountStatus::Active,
            basis: ControllerAccountGateBasis::AccountBindingDefault {
                binding_version: 7,
                binding_receipt_digest: digest(0x11),
            },
            basis_digest: digest(0x22),
            authority_id: DidCoreId::new("ak:did_core:web:authority.example").unwrap(),
            verification_method: DidUrl::new("did:web:authority.example#account-authority")
                .unwrap(),
            issued_at: "2026-09-16T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-09-16T00:05:00.000Z".parse().unwrap(),
            proof: AgentDetachedJws {
                kind: NonEmptyString::new(arkret_wire::proof_kind::DETACHED_JWS.to_owned())
                    .unwrap(),
                jws: NonEmptyString::new("pending".to_owned()).unwrap(),
            },
        }
    }

    #[test]
    fn gate_default_requires_exact_initial_binding_and_never_masks_a_successor() {
        use arkret_models_collaboration::account_status::{
            AccountStatusRecord, UnsignedAccountStatusRecord,
        };
        let now = "2026-09-16T00:00:00.000Z".parse().unwrap();
        let account = arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
            DidCoreId::new("ak:did_core:web:authority.example").unwrap(),
        );
        let pcr = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x61; 32],
        ));
        let sign = |status, seq, previous| -> AccountStatusRecord {
            arkret_signatures::account_status::sign_account_status_record(
                UnsignedAccountStatusRecord {
                    schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
                    account_authority_id: account.station_id.clone(),
                    account_id: account.clone(),
                    principal_control_realm_id: pcr.clone(),
                    binding_version: 7,
                    status_seq: seq,
                    previous_account_status_record_id: previous,
                    status,
                    reason_code: None,
                    reason: None,
                    issued_at: now,
                    effective_at: now,
                    expires_at: None,
                },
                DidUrl::new("did:web:authority.example#account-status").unwrap(),
                &sdk_signing_key_from_seed_bytes(&[41; 32]),
            )
            .unwrap()
        };
        let basis = |current, status| {
            default_basis_for_locked_head(
                7,
                digest(0x11),
                &account,
                &pcr,
                &account.station_id,
                status,
                current,
            )
        };
        assert!(basis(None, AccountStatus::Active).is_ok());
        let initial = sign(AccountStatus::Active, 1, None);
        assert_eq!(
            basis(Some(&initial), AccountStatus::Active).unwrap(),
            ControllerAccountGateBasis::AccountBindingDefault {
                binding_version: 7,
                binding_receipt_digest: digest(0x11)
            }
        );
        let inactive = sign(
            AccountStatus::Suspended,
            2,
            Some(initial.account_status_record_id.clone()),
        );
        assert!(basis(Some(&inactive), AccountStatus::Suspended).is_err());
        let resumed = sign(
            AccountStatus::Active,
            3,
            Some(inactive.account_status_record_id.clone()),
        );
        assert!(basis(Some(&resumed), AccountStatus::Active).is_err());
        let mut foreign = initial.clone();
        foreign.account_id.station_id = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(basis(Some(&foreign), AccountStatus::Active).is_err());
        let mut wrong_version = initial.clone();
        wrong_version.binding_version += 1;
        assert!(basis(Some(&wrong_version), AccountStatus::Active).is_err());
        let mut wrong_pcr = initial.clone();
        wrong_pcr.principal_control_realm_id = arkret_wire::RealmId::from_event_id(
            &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x62; 32]),
        );
        assert!(basis(Some(&wrong_pcr), AccountStatus::Active).is_err());
        assert!(basis(None, AccountStatus::Locked).is_err());
    }

    #[test]
    fn production_controller_gate_signer_uses_sdk_carrier_and_binds_basis_digest() {
        let signing_key = sdk_signing_key_from_seed_bytes(&[41; 32]);
        let mut gate = attestation();
        sign_controller_gate_with_sdk(&mut gate, &signing_key).unwrap();
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        let now = "2026-09-16T00:02:00.000Z".parse().unwrap();

        verify_controller_account_gate_attestation(
            &gate,
            &gate.principal_id,
            &gate.authority_id,
            &public_key,
            now,
        )
        .unwrap();

        let mut tampered = gate;
        tampered.basis_digest = digest(0x23);
        assert!(
            verify_controller_account_gate_attestation(
                &tampered,
                &tampered.principal_id,
                &tampered.authority_id,
                &public_key,
                now,
            )
            .is_err()
        );
    }
}

// Exercise the registered issuer route against the PostgreSQL authority ledger.
#[cfg(test)]
mod controller_gate_http_regression {
    use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
    use coauth_data::{RepositoryAccess as _, UserPatch};
    use hyper::{Request, StatusCode};

    use super::*;
    use crate::handlers::test_utils::{TEST_STATION_AUDIENCE, TestState, setup, unique_test_nonce};

    #[tokio::test]
    async fn internal_gate_initial_binding_succeeds_strict_successor_refuses_and_original_replays()
    {
        setup();
        // For Root acceptance DATABASE_URL must be explicitly configured and
        // COAUTH_SKIP_POSTGRES_TESTS must be absent. This fixture must fail if
        // the existing opt-out is enabled instead of silently returning early.
        let pool = coauth_storage_postgres::test_utils::setup_test_pool()
            .await
            .expect("actual PostgreSQL is required for this HTTP regression");
        let mut state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        // TestState's existing registered Station pin is zTestStation. Give
        // the owning AA that same real DID identity, not another Station.
        state.arkret_config.runtime_owning_station_identity =
            coauth_config::RuntimeOwningStationIdentity::fixture(
                "did:webvh:zTestStation:principal.example",
            );
        const TOKEN: &str = "public-controller-gate-http-fixture-token";
        state.arkret_config.stations[0].internal_authority_shared_secret =
            Some(TOKEN.to_owned().into());
        assert_eq!(
            crate::handlers::arkret::station_internal_channel_caller(&state.arkret_config, TOKEN)
                .as_deref(),
            Some(TEST_STATION_AUDIENCE)
        );
        assert_eq!(
            crate::handlers::arkret::owning_station_id_for(&state.arkret_config).as_str(),
            TEST_STATION_AUDIENCE
        );
        let mut rng = state.rng();
        let mut setup_repo = state.repository().await.unwrap();
        let user = setup_repo
            .user()
            .add(
                &mut rng,
                state.clock.as_ref(),
                format!("controller-gate-{}", unique_test_nonce()),
            )
            .await
            .unwrap();
        setup_repo.save().await.unwrap();
        let principal = state
            .seed_principal_binding(&user, &format!("gate-{}", unique_test_nonce()))
            .await;
        let original_request = ControllerAccountGateIssuanceInput {
            request_id: arkret_wire::RequestId::new_v7_at(
                chrono::Utc::now().timestamp_millis() as u64
            ),
            principal_id: arkret_wire::DidCoreId::new(principal.clone()).unwrap(),
            agent_authority_id: arkret_wire::DidCoreId::new(TEST_STATION_AUDIENCE).unwrap(),
        };
        let request = |body: &ControllerAccountGateIssuanceInput, credential: &str| {
            Request::post("/_coauth/internal/controller-gate-attestations")
                .header("Authorization", format!("Bearer {credential}"))
                .header("Content-Type", "application/json")
                .body(serde_json::to_string(body).unwrap())
                .unwrap()
        };
        let unauthenticated = state
            .request(request(&original_request, "wrong-public-fixture-token"))
            .await;
        assert_eq!(unauthenticated.status(), StatusCode::NOT_FOUND);
        let first = state.request(request(&original_request, TOKEN)).await;
        assert_eq!(first.status(), StatusCode::OK);
        let original_bytes = first.body().clone();
        let accepted: ControllerAccountGateIssuanceResult =
            serde_json::from_str(&original_bytes).unwrap();
        assert_eq!(accepted.request_id, original_request.request_id);
        assert!(matches!(
            &accepted.controller_account_gate_attestation.basis,
            ControllerAccountGateBasis::AccountBindingDefault { .. }
        ));
        let aa_signer =
            sdk_signing_key_from_seed_bytes(&state.keyring.account_authority_seed().unwrap());
        arkret_signatures::agent_evidence::verify_controller_account_gate_attestation(
            &accepted.controller_account_gate_attestation,
            &original_request.principal_id,
            &original_request.agent_authority_id,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: aa_signer.verifying_key().to_bytes().to_vec(),
            },
            accepted.controller_account_gate_attestation.issued_at,
        )
        .unwrap();
        // Produce a real immutable signed issuer successor with the existing
        // lifecycle API, atomically mutate user status, then issue a new ID.
        let mut transition = state.repository().await.unwrap();
        let current_user = transition.user().lookup(user.id).await.unwrap().unwrap();
        let binding = transition
            .principal_did()
            .get_by_principal_id_and_audience(&principal, TEST_STATION_AUDIENCE)
            .await
            .unwrap()
            .unwrap();
        crate::services::account_status_publication::author_and_enqueue_transition(
            &mut transition,
            &mut rng,
            state.clock.as_ref(),
            state.station_admin.as_ref(),
            &state.keyring,
            TEST_STATION_AUDIENCE,
            &current_user,
            &binding,
            AccountStatus::Suspended,
            None,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        transition
            .user()
            .patch(
                state.clock.as_ref(),
                current_user,
                UserPatch {
                    status: Some(AccountStatus::Suspended),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        transition.save().await.unwrap();
        let fresh_request = ControllerAccountGateIssuanceInput {
            request_id: arkret_wire::RequestId::new_v7_at(
                chrono::Utc::now().timestamp_millis() as u64
            ),
            ..original_request.clone()
        };
        let denied = state.request(request(&fresh_request, TOKEN)).await;
        assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
        let problem: arkret_wire::problem_details::Problem =
            serde_json::from_str(denied.body()).unwrap();
        assert_eq!(problem.code(), arkret_wire::ErrorCode::FAILED_PRECONDITION);
        use diesel_async::RunQueryDsl as _;
        #[derive(diesel::QueryableByName)]
        struct Rows {
            #[diesel(sql_type=diesel::sql_types::BigInt)]
            count: i64,
        }
        let mut conn = pool.get().await.unwrap();
        let count = diesel::sql_query("SELECT count(*) AS count FROM controller_gate_attestation_issuances WHERE request_id=$1")
            .bind::<diesel::sql_types::Uuid,_>(fresh_request.request_id.uuid())
            .get_result::<Rows>(&mut conn).await.unwrap().count;
        assert_eq!(
            count, 0,
            "rejected new issuance cannot persist a reservation or outcome"
        );
        drop(conn);
        let replay = state.request(request(&original_request, TOKEN)).await;
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(replay.body(), &original_bytes);
    }
}
