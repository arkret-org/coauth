//! `POST /_cokret/gate/account/device-enroll`
//! (`ck.gate.account.command.enroll_device`) — managed-DID `service_attested`
//! device enrollment (device-lifecycle §5.4, key-management §5.0.6).
//!
//! coauth signs exactly one shape: a `service_attested` `ck.device.authorize`
//! for **the calling user's own device**, under the user's principal DID. It
//! never acts as a general signing oracle and never contacts soland — the
//! signed Event is returned to the client (yougen) which submits it to
//! `/_cokret/self/events`.
//!
//! Flow:
//! 1. Resolve the caller's OAuth access token to a `User` (end-user bearer, NOT the
//!    server-to-server `require_session_grant_caller` path).
//! 2. Resolve that user's principal DID for the targeted principal server.
//! 3. Use the client-supplied `device_id` (this session's id) so the projected `device_public_key`
//!    lands under the id the session and recovery look up.
//! 4. Assemble the B-model `ck.device.authorize` envelope: `actor_id` = principal DID, `realm_id` =
//!    principal-control realm, `executed_by` = enrollment authority DID, `authorization_ref` =
//!    `"{principal}#enrollment-authority"`, payload carries the `enrollment_authority_binding`.
//! 5. Sign the proof with the persistent enrollment key (VM mapped to `executed_by`) and return the
//!    full Event JSON.

use chrono::{DateTime, Utc};
use cokret_core::error::{
    ERROR_CODE_AUDIENCE_MISMATCH, ERROR_CODE_DID_PROOF_REQUIRED, ERROR_CODE_FAILED_PRECONDITION,
    ERROR_CODE_GRANT_ALREADY_CONSUMED, ERROR_CODE_INVALID_PARAM, ERROR_CODE_INVALID_SIGNATURE,
    ERROR_CODE_SERVICE_UNAVAILABLE, ERROR_CODE_SESSION_GRANT_NOT_FOUND,
    ERROR_CODE_SESSION_LOGGED_OUT,
};
use cokret_core::{
    AccountDeviceEnrollOutcome, AccountDeviceEnrollRequestBody, Audience, DeviceAuthorizePayload,
    DeviceEnrollmentAuthorityBinding, DeviceOrPrincipalRef, Did, Event, EventId, EventRequirements,
    Hlc, RealmId, ed25519_pubkey_to_did_key_multibase,
};
use cokret_signatures::{SignEventOptions, sign_event};
use salvo::prelude::*;

use super::{CokretRouteError, SessionGrantPayload};
use crate::handlers::common::DepotExt;
use crate::services::device_enrollment_authority::enrollment_authority;

const DEVICE_AUTHORIZE_KIND: &str = "ck.device.authorize";
const ENROLLMENT_AUTHORITY_SERVICE_FRAGMENT: &str = "#enrollment-authority";
const ENROLLMENT_BINDING_KIND: &str = "service_attested";

/// Extract the `Authorization: Bearer <token>` value (the caller's
/// `ck.session.grant`), or a 401.
fn bearer_token_from_request(req: &Request) -> Result<String, CokretRouteError> {
    let header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| CokretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let value = header
        .to_str()
        .map_err(|_| CokretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| CokretRouteError::Unauthorized("invalid authorization header".to_owned()))
}

/// Decode `device_public_key` (multibase or base64) into the raw 32-byte key.
fn decode_device_public_key(input: &str) -> Result<[u8; 32], CokretRouteError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CokretRouteError::BadRequest(
            "device_public_key is empty".to_owned(),
        ));
    }

    // Multibase `z…` carries the `0xed01` ed25519-pub multicodec prefix.
    if trimmed.starts_with('z') {
        return cokret_core::decode_ed25519_multibase(trimmed).map_err(|error| {
            CokretRouteError::BadRequest(format!("invalid multibase device_public_key: {error}"))
        });
    }

    // Otherwise treat as base64 (standard or URL-safe, padded or not) of the
    // raw 32-byte key.
    let raw = decode_base64_any(trimmed).ok_or_else(|| {
        CokretRouteError::BadRequest(
            "device_public_key must be multibase (z…) or base64".to_owned(),
        )
    })?;
    raw.try_into().map_err(|raw: Vec<u8>| {
        CokretRouteError::BadRequest(format!(
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

/// Truncate to whole seconds so the SDK serializes `created_at`/`not_before` in
/// the canonical `YYYY-MM-DDTHH:MM:SSZ` form the principal server enforces
/// (`validate_timestamp_canonical` rejects fractional seconds).
fn truncate_to_seconds(when: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp(when.timestamp(), 0).unwrap_or(when)
}

/// Generate a fresh HLC string (`<unix_ms>-<logical>-<node>`) in the
/// 26-char form the SDK `Hlc` validator accepts.
fn fresh_hlc(now: DateTime<Utc>, rng: &mut (dyn rand_core::RngCore + Send)) -> Hlc {
    let unix_ms = u64::try_from(now.timestamp_millis().max(0)).unwrap_or(0);
    let node = rng.next_u32();
    // 12 hex (48-bit ms) + 4 hex logical + 8 hex node = 26 with separators.
    let value = format!(
        "{:012x}-{:04x}-{:08x}",
        unix_ms & 0xFFFF_FFFF_FFFF,
        0u16,
        node
    );
    Hlc::new(value).expect("generated HLC is well-formed")
}

fn enforce_device_authorize_inception_key_window(
    grant_payload: &SessionGrantPayload,
    raw_body: &serde_json::Value,
    now: DateTime<Utc>,
) -> Result<(), CokretRouteError> {
    let request_anchor =
        crate::services::inception_key_window::device_authorize_request_anchor(raw_body);
    let grant_anchor =
        crate::services::inception_key_window::scope_details_anchor(&grant_payload.scope_details);
    let anchor = request_anchor.or(grant_anchor);
    let requires_gate = anchor.is_some()
        || matches!(
            grant_payload.proof_kind,
            Some(
                cokret_core::SessionGrantProofKind::DidBoundSignature
                    | cokret_core::SessionGrantProofKind::PairedDeviceProof
            )
        );
    if !requires_gate {
        return Ok(());
    }
    crate::services::inception_key_window::enforce_inception_key_window_rfc3339(anchor, now)
        .map_err(inception_key_window_error)
}

fn inception_key_window_error(
    error: crate::services::inception_key_window::InceptionKeyWindowError,
) -> CokretRouteError {
    CokretRouteError::coded(
        StatusCode::FORBIDDEN,
        ERROR_CODE_FAILED_PRECONDITION,
        format!("reason_code={}; {error}", error.reason_code()),
    )
}

fn enforce_service_attested_device_authorize_provenance(
    event: &Event,
    payload: &DeviceAuthorizePayload,
) -> Result<(), CokretRouteError> {
    payload
        .validate_service_attested_provenance(
            event.executed_by.as_ref(),
            event.authorization_ref.as_deref(),
            event.created_at,
        )
        .map_err(|error| service_attested_provenance_error(error.to_string()))
}

fn service_attested_provenance_error(message: impl std::fmt::Display) -> CokretRouteError {
    CokretRouteError::coded(
        StatusCode::FORBIDDEN,
        ERROR_CODE_FAILED_PRECONDITION,
        format!("reason_code=service_attested_provenance_required; {message}"),
    )
}

/// Single configured principal-server audience, or an error when the
/// deployment has zero / multiple (the request body carries no audience, so
/// disambiguation is impossible — fail closed).
fn sole_principal_audience(
    cokret_config: &coauth_config::CokretConfig,
) -> Result<String, CokretRouteError> {
    match cokret_config.principal_servers.as_slice() {
        [server] => Ok(server.audience.clone()),
        [] => Err(CokretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            ERROR_CODE_SERVICE_UNAVAILABLE,
            "no principal server is configured for device enrollment",
        )),
        _ => Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_INVALID_PARAM,
            "multiple principal servers configured; device-enroll cannot pick one",
        )),
    }
}

/// `POST /_cokret/gate/account/device-enroll`
/// (`ck.gate.account.command.enroll_device`).
#[handler]
pub async fn device_enroll_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<AccountDeviceEnrollOutcome>, CokretRouteError> {
    use coauth_data::RepositoryAccess;
    use coauth_jose::jwt::Jwt;

    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let cokret_config = depot.cokret_config()?;
    let url_builder = depot.url_builder()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    // 1. Durable-session auth: the caller presents its `ck.session.grant` (`Authorization: Bearer`)
    //    plus a `DPoP` holder proof bound to the grant's `cnf.jkt`. This is the same
    //    proof-of-possession path as session-grant refresh / logout (device-lifecycle §5.4 holder
    //    proof), NOT the short-lived OAuth access token: device enrollment is retried on every
    //    connect for the whole life of the session, and the access token may already have expired
    //    on a later boot while the durable grant is still valid. The grant `subject` IS the
    //    principal DID, and the DB lookup below proves coauth issued it.
    let grant_jwt = bearer_token_from_request(req)?;
    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_DID_PROOF_REQUIRED,
            "session-grant holder proof (DPoP) required",
        )
    })?;

    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;
    let body: AccountDeviceEnrollRequestBody = serde_json::from_value(raw_body.clone())
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;

    // Read `cnf.jkt` from the grant payload; the persisted row is the source of
    // truth (no JWT signature check here — the DB lookup authenticates it).
    let jwt: Jwt<'_, SessionGrantPayload> = Jwt::try_from(grant_jwt.as_str())
        .map_err(|_| CokretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let grant_payload = jwt.payload().clone();
    enforce_device_authorize_inception_key_window(&grant_payload, &raw_body, clock.now())?;
    let expected_jkt = grant_payload
        .cnf
        .as_ref()
        .map(|cnf| cnf.jkt.clone())
        .ok_or_else(|| {
            CokretRouteError::BadRequest("grant_jwt is not DPoP-bound (cnf.jkt missing)".to_owned())
        })?;

    let mut repo = depot.repo().await?;
    let grant_row = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&grant_jwt)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            CokretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                ERROR_CODE_SESSION_GRANT_NOT_FOUND,
                "no session grant matches the presented bearer",
            )
        })?;
    if grant_row.revoked_at.is_some() {
        repo.cancel().await.ok();
        return Err(CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_GRANT_ALREADY_CONSUMED,
            "session grant has been revoked",
        ));
    }
    if grant_row.expires_at <= clock.now() {
        repo.cancel().await.ok();
        return Err(CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_SESSION_GRANT_NOT_FOUND,
            "session grant has expired",
        ));
    }
    let Some(browser_session_id) = grant_row.browser_session_id else {
        repo.cancel().await.ok();
        return Err(CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_SESSION_GRANT_NOT_FOUND,
            "device enrollment requires a browser-bound session grant",
        ));
    };
    let browser_session = repo
        .browser_session()
        .lookup(browser_session_id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                "session grant references missing browser session",
            ))
        })?;
    if browser_session.finished_at.is_some() {
        repo.cancel().await.ok();
        return Err(CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_SESSION_LOGGED_OUT,
            "browser session is logged out",
        ));
    }
    repo.cancel().await.ok();

    // 2. Proof-of-possession: the caller MUST hold the key the grant is bound to.
    let verifier = depot
        .dpop_verifier()
        .unwrap_or_else(|_| DpopVerifier::shared());
    let dpop_now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let verification = verifier
        .verify(&dpop_header, &htm, &htu, dpop_now, Some(&grant_jwt))
        .await
        .map_err(|error| {
            CokretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                ERROR_CODE_INVALID_SIGNATURE,
                error.to_string(),
            )
        })?;
    DpopVerifier::require_matching_jkt(&verification.jkt, &expected_jkt).map_err(|error| {
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_INVALID_SIGNATURE,
            error.to_string(),
        )
    })?;

    // 3. The principal DID is the grant subject. Bind the event proof to the configured principal
    //    server and require the grant to target it.
    let principal_id = Did::new(grant_payload.subject.clone()).map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "grant subject is not a valid principal DID: {error}"
        )))
    })?;
    let audience = sole_principal_audience(&cokret_config)?;
    if grant_payload.audience != audience {
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_AUDIENCE_MISMATCH,
            "session grant was not issued for this principal server",
        ));
    }

    // 3. This session's device id (client-supplied; soland projects the device_public_key under it,
    //    matching the id the session/recovery uses). Already a typed `DeviceId` (validated on
    //    deserialize) from the SDK request body.
    let device_id = body.device_id.clone();
    let device_public_key = decode_device_public_key(&body.device_public_key)?;
    let device_public_key_multibase = ed25519_pubkey_to_did_key_multibase(&device_public_key);

    // 4. Assemble the B-model envelope.
    let authority = enrollment_authority();
    let authority_did = Did::new(authority.did().to_owned()).map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "enrollment authority DID is invalid: {error}"
        )))
    })?;
    let authorization_ref = format!(
        "{}{ENROLLMENT_AUTHORITY_SERVICE_FRAGMENT}",
        principal_id.as_str()
    );
    let realm_id_string = cokret::auth::principal_control_realm_id(&principal_id);
    let realm_id = RealmId::new(realm_id_string).map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "derived principal-control realm id is invalid: {error}"
        )))
    })?;

    let now = truncate_to_seconds(clock.now());
    let not_before = body
        .not_before
        .as_ref()
        .cloned()
        .map(truncate_to_seconds)
        .unwrap_or_else(|| now.clone());

    let payload = DeviceAuthorizePayload {
        principal_id: principal_id.clone(),
        device_id: device_id.as_str().to_owned(),
        device_public_key: device_public_key_multibase,
        device_key_algorithm: None,
        authorized_by: DeviceOrPrincipalRef::Did(authority_did.clone()),
        scopes: None,
        not_before,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        bootstrap_binding: None,
        enrollment_authority_binding: Some(DeviceEnrollmentAuthorityBinding {
            kind: ENROLLMENT_BINDING_KIND.to_owned(),
            authority_did: authority_did.clone(),
            authorization_ref: authorization_ref.clone(),
        }),
        recovery_session_id: None,
    };

    let content = serde_json::to_value(&payload).map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "failed to serialize device-enroll payload: {error}"
        )))
    })?;

    let mut event = Event {
        event_id: EventId::new(cokret_core::identifiers::new_prefixed_uuid7("ck:event:")).map_err(
            |error| {
                CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                    format!("failed to mint event id: {error}"),
                ))
            },
        )?,
        kind: DEVICE_AUTHORIZE_KIND.into(),
        realm_id,
        actor_id: principal_id.clone(),
        actor_seq: body.actor_seq,
        created_at: now,
        hlc: fresh_hlc(now, &mut *rng),
        prev_refs: Vec::new(),
        effective_scope: None,
        refs: Vec::new(),
        preconditions: Vec::new(),
        effects: Vec::new(),
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        requirements: EventRequirements::default(),
        redacts: None,
        content,
        executed_by: Some(authority_did.clone()),
        authorization_ref: Some(authorization_ref.clone()),
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        unsigned: std::collections::BTreeMap::new(),
        proofs: Vec::new(),
    };

    enforce_service_attested_device_authorize_provenance(&event, &payload)?;

    // 5. Sign the proof with the persistent enrollment key; the VM maps to `executed_by`
    //    (device-lifecycle §5.4). Bind the proof to the target principal server
    //    (`domain`/`audience` = its service DID) so the submitting client's domain-binding check
    //    passes and the binding is audience-scoped.
    let signer = authority.signer();
    sign_event(
        &mut event,
        &signer,
        authority.verification_method(),
        SignEventOptions::new()
            .with_created_at(now)
            .with_domain(audience.clone())
            .with_audience(Audience::Single(audience.clone())),
    )
    .map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "failed to sign device-enroll event: {error}"
        )))
    })?;

    Ok(Json(AccountDeviceEnrollOutcome {
        principal_id,
        device_id,
        authority_did,
        authorized_event: event,
    }))
}
