//! `POST /_arkret/gate/account/device-enroll`
//! (`ak.gate.account.command.enroll_device`) — managed-DID `service_attested`
//! device enrollment (device-lifecycle §5.4, key-management §5.0.6).
//!
//! coauth signs exactly one shape: a `service_attested` `ak.device.authorize`
//! for **the calling user's own device**, under the user's principal DID. It
//! never acts as a general signing oracle and never contacts soland — the
//! signed Event is returned to the client (inkson) which submits it to
//! `/_arkret/self/events`.
//!
//! Flow:
//! 1. Resolve the caller's OAuth access token to a `User` (end-user bearer, NOT the
//!    server-to-server `require_session_grant_caller` path).
//! 2. Resolve that user's principal DID for the targeted principal server.
//! 3. Use the client-supplied `device_id` (this session's id) so the projected `device_public_key`
//!    lands under the id the session and recovery look up.
//! 4. Assemble the B-model `ak.device.authorize` envelope: `actor_id` = principal DID, `realm_id` =
//!    principal-control realm, `executed_by` = enrollment authority DID, `authorization_ref` = the
//!    exact service DID URL verified at binding time, and payload carries the
//!    `enrollment_authority_binding`.
//! 5. Sign the proof with the persistent enrollment key (VM mapped to `executed_by`) and return the
//!    full Event JSON.
#[cfg(test)]
use arkret_canonical::ed25519_pubkey_to_did_key_multibase;
use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
use arkret_models_identity::{
    AccountDeviceEnrollOutcome, AccountDeviceEnrollRequestBody, SessionGrantBootstrapBinding,
    SessionGrantCredentialClass, SignedSessionGrantClaims, device_bootstrap_device_key_digest,
    founding_batch_digest,
};
use arkret_signatures::{SignEventOptions, sign_event};
use arkret_wire::Event;
use chrono::{DateTime, Utc};
use coauth_data::user::PrincipalDidRepository as _;
use salvo::prelude::*;

use super::ArkretRouteError;
use crate::handlers::common::DepotExt;
use crate::services::device_enrollment_authority::enrollment_authority;
use crate::services::resolved_principal_audiences::{
    self, ResolvedPrincipalAudiences, effective_audience,
};

/// Extract the `Authorization: Bearer <token>` value (the caller's
/// `ak.session.grant`), or a 401.
pub(super) fn bearer_token_from_request(req: &Request) -> Result<String, ArkretRouteError> {
    let header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| ArkretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let value = header
        .to_str()
        .map_err(|_| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))
}

/// Decode `device_public_key` (multibase or base64) into the raw 32-byte key.
pub(super) fn decode_device_public_key(input: &str) -> Result<[u8; 32], ArkretRouteError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ArkretRouteError::BadRequest(
            "device_public_key is empty".to_owned(),
        ));
    }

    // A canonical multibase `z…` carries the `0xed01` ed25519-pub multicodec
    // prefix. Raw base64url is also allowed and can legitimately begin with
    // the character `z`, so a failed multibase parse must fall through to the
    // raw-key decoder instead of making the first character a format tag.
    if trimmed.starts_with('z')
        && let Ok(raw) = arkret_canonical::decode_ed25519_multibase(trimmed)
    {
        return Ok(raw);
    }

    // Otherwise treat as base64 (standard or URL-safe, padded or not) of the
    // raw 32-byte key.
    let raw = decode_base64_any(trimmed).ok_or_else(|| {
        ArkretRouteError::BadRequest(
            "device_public_key must be multibase (z…) or base64".to_owned(),
        )
    })?;
    raw.try_into().map_err(|raw: Vec<u8>| {
        ArkretRouteError::BadRequest(format!(
            "device_public_key must decode to 32 bytes, got {}",
            raw.len()
        ))
    })
}

fn decode_base64_any(input: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding as _};
    Base64::decode_vec(input)
        .or_else(|_| Base64Unpadded::decode_vec(input))
        .or_else(|_| Base64Url::decode_vec(input))
        .or_else(|_| Base64UrlUnpadded::decode_vec(input))
        .ok()
}

pub(super) fn truncate_to_seconds(when: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp(when.timestamp(), 0).unwrap_or(when)
}

pub struct DeviceEnrollCanonicalJson(Vec<u8>);

impl Scribe for DeviceEnrollCanonicalJson {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.0)
            .expect("canonical JSON response body is writable");
    }
}

/// Resolve the configured Principal Server selected by the authenticated
/// session grant. The grant audience is already holder-bound and persisted by
/// coauth, so it is the authoritative discriminator in multi-server
/// deployments; the enrollment request body does not need a second audience
/// field.
fn principal_audience_for_grant(
    arkret_config: &coauth_config::ArkretConfig,
    resolved: &ResolvedPrincipalAudiences,
    grant_audience: &str,
) -> Result<String, ArkretRouteError> {
    if arkret_config.principal_servers.is_empty() {
        return Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            "no principal server is configured for device enrollment",
        ));
    }

    arkret_config
        .principal_servers
        .iter()
        .filter_map(|server| effective_audience(server, resolved))
        .find(|audience| audience.as_str() == grant_audience)
        .map(|audience| audience.to_string())
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::BAD_REQUEST,
                arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
                "session grant audience is not a configured principal server",
            )
        })
}

/// `POST /_arkret/gate/account/device-enroll`
/// (`ak.gate.account.command.enroll_device`).
#[handler]
pub async fn device_enroll_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<DeviceEnrollCanonicalJson, ArkretRouteError> {
    use coauth_data::RepositoryAccess;
    use coauth_jose::jwt::Jwt;

    use crate::services::dpop::{
        DpopVerifier, dpop_header_from_request, dpop_htu, dpop_replay_record,
    };

    let arkret_config = depot.arkret_config()?;
    let url_builder = depot.url_builder()?;
    let clock = crate::handlers::make_clock();

    // 1. Durable-session auth: the caller presents its `ak.session.grant` (`Authorization: Bearer`)
    //    plus a grant-binding `DPoP` proof bound to the grant's `cnf.jkt`. This is the same
    //    proof-of-possession path as session-grant refresh / logout (device-lifecycle §5.4
    //    grant-binding proof), NOT the short-lived OAuth access token: device enrollment is retried
    //    on every connect for the whole life of the session, and the access token may already have
    //    expired on a later boot while the durable grant is still valid. The grant `subject` IS the
    //    principal DID, and the DB lookup below proves coauth issued it.
    let grant_jwt = bearer_token_from_request(req)?;
    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
            "session-grant grant-binding DPoP proof required",
        )
    })?;

    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    let body: AccountDeviceEnrollRequestBody = serde_json::from_value(raw_body.clone())
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    body.validate()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;

    // Read `cnf.jkt` from the grant payload; the persisted row is the source of
    // truth (no JWT signature check here — the DB lookup authenticates it).
    let jwt: Jwt<'_, SignedSessionGrantClaims> = Jwt::try_from(grant_jwt.as_str())
        .map_err(|_| ArkretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let grant_payload = jwt.payload().clone();
    grant_payload
        .validate()
        .map_err(|error| ArkretRouteError::BadRequest(format!("invalid grant_jwt: {error}")))?;
    let expected_jkt = grant_payload.cnf.jkt.clone();

    let mut repo = depot.repo().await?;
    let grant_row = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&grant_jwt)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
                "no session grant matches the presented bearer",
            )
        })?;
    let expected_device_scope = format!("urn:arkret:client:device:{}", body.device_id.as_str());
    let (
        bootstrap_transaction_id,
        bootstrap_principal_id,
        bootstrap_device_id,
        bootstrap_device_key_digest,
        bootstrap_holder_jkt,
        bootstrap_request_digest,
        bootstrap_founding_digest,
        bootstrap_founding_event_ids,
        allowed_operation_ids,
        bootstrap_expires_at,
    ) = match grant_payload.bootstrap_binding.as_ref() {
        Some(SessionGrantBootstrapBinding::Founding {
            transaction_id,
            principal_id,
            device_id,
            device_key_digest,
            holder_jkt,
            canonical_request_digest,
            founding_batch_digest,
            founding_event_ids,
            allowed_operation_ids,
            bootstrap_transaction_expires_at,
            ..
        }) => (
            transaction_id,
            principal_id,
            device_id,
            device_key_digest,
            holder_jkt,
            canonical_request_digest,
            founding_batch_digest,
            founding_event_ids,
            allowed_operation_ids,
            bootstrap_transaction_expires_at,
        ),
        _ => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
                "device enrollment requires a closed device_bootstrap binding",
            ));
        }
    };
    if grant_payload.credential_class != SessionGrantCredentialClass::DeviceBootstrap
        || grant_payload.holder_binding.is_some()
        || bootstrap_principal_id != &grant_payload.subject
        || bootstrap_device_id != &body.device_id
        || bootstrap_holder_jkt != &grant_payload.cnf.jkt
        || bootstrap_request_digest != &request_digest
        || !allowed_operation_ids.iter().any(|operation| {
            operation == arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ENROLL_DEVICE
        })
        || grant_payload
            .device_binding
            .as_ref()
            .is_some_and(|binding| binding.device_id != body.device_id)
        || grant_row.device_id.as_deref() != Some(body.device_id.as_str())
        || !grant_payload
            .scopes
            .iter()
            .any(|scope| scope == &expected_device_scope)
        || !grant_row
            .scope
            .iter()
            .any(|scope| scope.as_str() == expected_device_scope)
    {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "session grant holder/device binding does not authorize this enrollment device",
        ));
    }
    repo.cancel().await.ok();

    // 2. Proof-of-possession: the caller MUST hold the key the grant is bound to.
    let dpop_now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let verification =
        DpopVerifier::verify_without_replay(&dpop_header, &htm, &htu, dpop_now, Some(&grant_jwt))
            .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::INVALID_SIGNATURE,
                error.to_string(),
            )
        })?;
    DpopVerifier::require_matching_jkt(&verification.jkt, &expected_jkt).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::INVALID_SIGNATURE,
            error.to_string(),
        )
    })?;

    // 3. The principal DID is the grant subject. Bind the event proof to the configured principal
    //    server and require the grant to target it.
    let principal_id = grant_payload.subject.clone();
    let _audience = principal_audience_for_grant(
        &arkret_config,
        resolved_principal_audiences::shared(),
        grant_payload.audience.as_str(),
    )?;

    // 4. Re-derive every bootstrap identity value from the complete client-authored preimage. The
    //    account authority is not an Event author: it may validate and append one proof only.
    let device_id = body.device_id.clone();
    let preimage = &body.authorize_event_preimage;
    let payload: DeviceAuthorizePayload = serde_json::from_value(
        serde_json::to_value(&preimage.payload)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
    )
    .map_err(|error| {
        ArkretRouteError::BadRequest(format!("invalid device authorize payload: {error}"))
    })?;
    let device_public_key = decode_device_public_key(payload.device_public_key.as_str())?;
    let derived_device_key_digest = device_bootstrap_device_key_digest(device_public_key)
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let derived_founding_digest = founding_batch_digest(bootstrap_founding_event_ids)
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let expected_realm_id = arkret_models_identity::principal_control_realm_id(&principal_id);
    if preimage.realm_id.as_str() != expected_realm_id
        || preimage.actor_id != principal_id
        || preimage.prev_refs.first() != bootstrap_founding_event_ids.first()
        || Some(&preimage.event_id) != bootstrap_founding_event_ids.get(1)
        || &derived_device_key_digest != bootstrap_device_key_digest
        || &derived_founding_digest != bootstrap_founding_digest
    {
        return Err(ArkretRouteError::coded(
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "device authorize preimage does not match the founding bootstrap transaction",
        ));
    }

    let bootstrap_transaction_id =
        arkret_wire::ProtocolOpaqueId::new(bootstrap_transaction_id.clone())
            .map_err(|error| ArkretRouteError::BadRequest(error.to_owned()))?;

    // Replay is decided before signing. A retry must return the exact first proof bytes, not a
    // newly-created equivalent signature. The current request has already reauthenticated the
    // holder and revalidated every immutable bootstrap binding above.
    let mut repo = depot.repo().await?;
    let reservation = repo
        .account_handoff()
        .reserve_device_bootstrap_enrollment(
            coauth_data::DeviceBootstrapEnrollmentReservationInput {
                transaction_id: &bootstrap_transaction_id,
                principal_id: &principal_id,
                device_id: &device_id,
                request_digest: &request_digest,
                now: clock.now(),
            },
        )
        .await?;
    let transaction = match &reservation {
        coauth_data::DeviceBootstrapEnrollmentReserve::Reserved(transaction)
        | coauth_data::DeviceBootstrapEnrollmentReserve::RequiresDecision(transaction)
        | coauth_data::DeviceBootstrapEnrollmentReserve::Replay(transaction)
        | coauth_data::DeviceBootstrapEnrollmentReserve::Conflict(transaction)
        | coauth_data::DeviceBootstrapEnrollmentReserve::Cancelled(transaction)
        | coauth_data::DeviceBootstrapEnrollmentReserve::Expired(transaction) => transaction,
        coauth_data::DeviceBootstrapEnrollmentReserve::NotFound => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "device bootstrap credential has no durable issuer transaction",
            ));
        }
    };
    let binding_matches = transaction.principal_id == principal_id
        && transaction.device_id == device_id
        && transaction.device_key_digest == derived_device_key_digest
        && transaction.holder_jkt == expected_jkt
        && transaction.canonical_request_digest == request_digest
        && transaction.founding_batch_digest == derived_founding_digest
        && transaction.founding_event_ids == *bootstrap_founding_event_ids
        && transaction.bootstrap_grant_id == grant_payload.grant_id;
    if !binding_matches {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::BOOTSTRAP_IDEMPOTENCY_CONFLICT,
            "founding device enrollment conflicts with the durable bootstrap transaction",
        ));
    }
    let enrollment_authority_did = match reservation {
        coauth_data::DeviceBootstrapEnrollmentReserve::Reserved(_) => {
            if !grant_row.is_active(&*clock) || *bootstrap_expires_at <= clock.now() {
                repo.cancel().await.ok();
                return Err(ArkretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    arkret_wire::ErrorCode::GRANT_ALREADY_CONSUMED,
                    "session grant or bootstrap authorization is no longer active",
                ));
            }
            if !repo
                .dpop_replay()
                .consume_jti(dpop_replay_record(&verification.claims.jti, dpop_now))
                .await?
            {
                repo.cancel().await.ok();
                return Err(ArkretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    arkret_wire::ErrorCode::INVALID_SIGNATURE,
                    "DPoP JTI was already consumed",
                ));
            }
            let Some(browser_session_id) = grant_row.browser_session_id else {
                repo.cancel().await.ok();
                return Err(ArkretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
                    "device enrollment requires a browser-bound session grant",
                ));
            };
            let browser_session = repo
                .browser_session()
                .lookup(browser_session_id)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        "session grant references missing browser session",
                    ))
                })?;
            if browser_session.finished_at.is_some() {
                repo.cancel().await.ok();
                return Err(ArkretRouteError::coded(
                    StatusCode::UNAUTHORIZED,
                    arkret_wire::ErrorCode::SESSION_LOGGED_OUT,
                    "browser session is logged out",
                ));
            }
            let principal_binding = repo
                .principal_did()
                .get_by_did_and_audience(
                    grant_payload.subject.as_str(),
                    grant_payload.audience.as_str(),
                )
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .filter(|binding| binding.user_id == browser_session.user.id)
                .ok_or_else(|| {
                    ArkretRouteError::coded(
                        StatusCode::NOT_FOUND,
                        arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
                        "principal_unknown",
                    )
                })?;
            if preimage.executed_by.as_str() != principal_binding.enrollment_authority_did.as_str()
                || preimage.authorization_ref.as_str() != principal_binding.enrollment_authority_ref
            {
                repo.cancel().await.ok();
                return Err(ArkretRouteError::coded(
                    StatusCode::FORBIDDEN,
                    arkret_wire::ErrorCode::FAILED_PRECONDITION,
                    "device authorize preimage does not match the enrollment authority binding",
                ));
            }
            principal_binding.enrollment_authority_did
        }
        coauth_data::DeviceBootstrapEnrollmentReserve::RequiresDecision(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
                "bootstrap deadline requires a Principal Server decision receipt",
            ));
        }
        coauth_data::DeviceBootstrapEnrollmentReserve::Replay(transaction) => {
            let bytes = transaction.canonical_enrollment_outcome.ok_or_else(|| {
                ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                    "replayed device-bootstrap transaction has no canonical outcome",
                ))
            })?;
            let stored: AccountDeviceEnrollOutcome =
                serde_json::from_slice(&bytes).map_err(|error| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        format!("stored device-enroll outcome is invalid: {error}"),
                    ))
                })?;
            stored.validate_against(&body).map_err(|error| {
                ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                    format!("stored device-enroll outcome failed validation: {error}"),
                ))
            })?;
            repo.cancel().await.ok();
            return Ok(DeviceEnrollCanonicalJson(bytes));
        }
        coauth_data::DeviceBootstrapEnrollmentReserve::Conflict(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::BOOTSTRAP_IDEMPOTENCY_CONFLICT,
                "founding device enrollment conflicts with the durable bootstrap transaction",
            ));
        }
        coauth_data::DeviceBootstrapEnrollmentReserve::Cancelled(_) => {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::BOOTSTRAP_TRANSACTION_CANCELLED,
                "device bootstrap transaction is cancelled",
            ));
        }
        coauth_data::DeviceBootstrapEnrollmentReserve::Expired(_) => {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::GONE,
                arkret_wire::ErrorCode::BOOTSTRAP_TRANSACTION_EXPIRED,
                "device bootstrap transaction is expired",
            ));
        }
        coauth_data::DeviceBootstrapEnrollmentReserve::NotFound => unreachable!("handled above"),
    };

    // 5. Materialize the exact proof-free Event and append only the persistent enrollment authority
    //    proof. `validate_against` below proves signing did not rewrite the preimage.
    let key_store = depot.key_store()?;
    let authority = enrollment_authority(&key_store)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    if authority.did() != enrollment_authority_did.as_str() {
        return Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            "configured enrollment authority does not match the verified DID delegation",
        ));
    }
    let authority_did = enrollment_authority_did;
    let mut event: Event = preimage.clone().into_event();

    // 5. Sign the proof with the persistent enrollment key; the VM maps to `executed_by`
    //    (device-lifecycle §5.4). The authorization is a portable identity fact, so its proof omits
    //    service-specific domain/audience. The authenticated enrollment request and the principal
    //    binding still constrain issuance to `audience`; downstream federation independently
    //    verifies the DID designation and this authority proof.
    let signer = authority.signer();
    sign_event(
        &mut event,
        &signer,
        authority.verification_method(),
        SignEventOptions::new().with_created_at(clock.now()),
    )
    .map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "failed to sign device-enroll event: {error}"
        )))
    })?;

    let mut outcome = AccountDeviceEnrollOutcome {
        bootstrap_transaction_id: bootstrap_transaction_id.clone(),
        principal_id,
        device_id,
        authority_did,
        authorized_event_id: event.event_id.clone(),
        authorized_event_digest: arkret_identifiers::Hash::new(
            event
                .event_digest()
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        )
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
        authorized_event: event,
        outcome_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
            .expect("placeholder outcome digest has a valid wire shape"),
    };
    outcome.outcome_digest = outcome
        .recompute_outcome_digest()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    outcome
        .validate_against(&body)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let commit = repo
        .account_handoff()
        .commit_device_bootstrap_enrollment(coauth_data::DeviceBootstrapEnrollmentInput {
            transaction_id: &bootstrap_transaction_id,
            principal_id: &outcome.principal_id,
            device_id: &outcome.device_id,
            request_digest: &request_digest,
            authorized_event_id: &outcome.authorized_event_id,
            authorized_event_digest: &outcome.authorized_event_digest,
            canonical_outcome: &canonical_outcome,
            outcome_digest: &outcome.outcome_digest,
            now: clock.now(),
        })
        .await?;
    match commit {
        coauth_data::DeviceBootstrapEnrollmentCommit::Committed(transaction) => {
            repo.save().await?;
            Ok(DeviceEnrollCanonicalJson(
                transaction.canonical_enrollment_outcome.ok_or_else(|| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        "committed device-bootstrap transaction has no canonical outcome",
                    ))
                })?,
            ))
        }
        coauth_data::DeviceBootstrapEnrollmentCommit::RequiresDecision(_) => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::BOOTSTRAP_DECISION_INDETERMINATE,
                "bootstrap deadline requires a Principal Server decision receipt",
            ))
        }
        coauth_data::DeviceBootstrapEnrollmentCommit::Replay(transaction) => {
            repo.cancel().await.ok();
            Ok(DeviceEnrollCanonicalJson(
                transaction.canonical_enrollment_outcome.ok_or_else(|| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        "replayed device-bootstrap transaction has no canonical outcome",
                    ))
                })?,
            ))
        }
        coauth_data::DeviceBootstrapEnrollmentCommit::Conflict(_) => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::BOOTSTRAP_IDEMPOTENCY_CONFLICT,
                "founding device enrollment conflicts with the durable bootstrap outcome",
            ))
        }
        coauth_data::DeviceBootstrapEnrollmentCommit::Cancelled(_) => {
            repo.save().await?;
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::BOOTSTRAP_TRANSACTION_CANCELLED,
                "device bootstrap transaction is cancelled",
            ))
        }
        coauth_data::DeviceBootstrapEnrollmentCommit::Expired(_) => {
            repo.save().await?;
            Err(ArkretRouteError::coded(
                StatusCode::GONE,
                arkret_wire::ErrorCode::BOOTSTRAP_TRANSACTION_EXPIRED,
                "device bootstrap transaction is expired",
            ))
        }
        coauth_data::DeviceBootstrapEnrollmentCommit::NotFound => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "device bootstrap credential has no durable issuer transaction",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal_server(name: &str, endpoint: &str) -> coauth_config::PrincipalServerConfig {
        coauth_config::PrincipalServerConfig {
            name: name.to_owned(),
            endpoint: url::Url::parse(endpoint).expect("valid endpoint"),
            session_grant_introspection_bearer: Some("test-introspection".to_owned()),
            embedded_webvh_registration_bearer: Some("test-registration".to_owned()),
        }
    }

    #[test]
    fn raw_base64url_key_starting_with_z_is_not_misclassified_as_multibase() {
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        let raw = [0xcc_u8; 32];
        let encoded = Base64UrlUnpadded::encode_string(&raw);
        assert!(encoded.starts_with('z'));
        assert_eq!(decode_device_public_key(&encoded).unwrap(), raw);
    }

    #[test]
    fn canonical_ed25519_multibase_key_still_decodes() {
        let raw = [0x5a_u8; 32];
        let encoded = ed25519_pubkey_to_did_key_multibase(&raw);
        assert_eq!(decode_device_public_key(&encoded).unwrap(), raw);
    }

    #[test]
    fn grant_audience_selects_the_matching_principal_server() {
        let alpha = principal_server("alpha", "https://alpha.example/");
        let beta = principal_server("beta", "https://beta.example/");
        let config = coauth_config::ArkretConfig {
            principal_servers: vec![alpha.clone(), beta.clone()],
            ..Default::default()
        };
        let resolved = ResolvedPrincipalAudiences::new();
        resolved.insert_for_test(&alpha.endpoint, "did:web:alpha.example");
        resolved.insert_for_test(&beta.endpoint, "did:web:beta.example");

        assert_eq!(
            principal_audience_for_grant(&config, &resolved, "did:web:beta.example").unwrap(),
            "did:web:beta.example"
        );
    }

    #[test]
    fn unknown_grant_audience_fails_closed() {
        let alpha = principal_server("alpha", "https://alpha.example/");
        let config = coauth_config::ArkretConfig {
            principal_servers: vec![alpha.clone()],
            ..Default::default()
        };
        let resolved = ResolvedPrincipalAudiences::new();
        resolved.insert_for_test(&alpha.endpoint, "did:web:alpha.example");

        assert!(principal_audience_for_grant(&config, &resolved, "did:web:other.example").is_err());
    }
}
