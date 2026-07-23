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
use std::sync::{Mutex, OnceLock};

use arkret_canonical::ed25519_pubkey_to_did_key_multibase;
use arkret_hlc::HlcGenerator;
use arkret_identifiers::{EventId, Hlc, RealmId};
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_models_identity::{
    AccountDeviceEnrollOutcome, AccountDeviceEnrollRequestBody, DeviceEnrollmentAuthorityBinding,
    DeviceEnrollmentAuthorityBindingKind, SignedSessionGrantClaims,
};
use arkret_signatures::{SignEventOptions, sign_event};
use arkret_wire::{Audience, Event, EventRequirements, NonEmptyString};
use chrono::{DateTime, Utc};
use coauth_data::user::PrincipalDidRepository as _;
use salvo::prelude::*;

use super::ArkretRouteError;
use crate::handlers::common::DepotExt;
use crate::services::device_enrollment_authority::enrollment_authority;
use crate::services::resolved_principal_audiences::{
    self, ResolvedPrincipalAudiences, effective_audience,
};

const DEVICE_AUTHORIZE_KIND: &str = "ak.device.authorize";

/// Extract the `Authorization: Bearer <token>` value (the caller's
/// `ak.session.grant`), or a 401.
fn bearer_token_from_request(req: &Request) -> Result<String, ArkretRouteError> {
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
fn decode_device_public_key(input: &str) -> Result<[u8; 32], ArkretRouteError> {
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
    if trimmed.starts_with('z') {
        if let Ok(raw) = arkret_canonical::decode_ed25519_multibase(trimmed) {
            return Ok(raw);
        }
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

/// Truncate to whole seconds so the SDK serializes `created_at`/`not_before` in
/// the canonical `YYYY-MM-DDTHH:MM:SSZ` form the principal server enforces
/// (`validate_timestamp_canonical` rejects fractional seconds).
fn truncate_to_seconds(when: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp(when.timestamp(), 0).unwrap_or(when)
}

static DEVICE_ENROLL_HLC: OnceLock<Mutex<HlcGenerator>> = OnceLock::new();

fn fresh_hlc(
    authority: &crate::services::device_enrollment_authority::EnrollmentAuthority,
    realm_id: &RealmId,
    device_id: &arkret_identifiers::DeviceId,
    now: DateTime<Utc>,
) -> Result<Hlc, ArkretRouteError> {
    let unix_ms = u64::try_from(now.timestamp_millis().max(0)).unwrap_or(0);
    let secret = authority.hlc_node_secret();
    let clock = DEVICE_ENROLL_HLC.get_or_init(|| {
        Mutex::new(HlcGenerator::with_initial_time(
            realm_id.as_str(),
            device_id.as_str(),
            &secret,
            0,
        ))
    });
    clock
        .lock()
        .map_err(|_| {
            ArkretRouteError::Internal(Box::new(std::io::Error::other(
                "device enrollment HLC lock poisoned",
            )))
        })?
        .try_generate_for_scope_at(realm_id.as_str(), device_id.as_str(), &secret, unix_ms)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}

fn enforce_service_attested_device_authorize_provenance(
    event: &Event,
    payload: &DeviceAuthorizePayload,
) -> Result<(), ArkretRouteError> {
    payload
        .validate_service_attested_provenance(
            event.executed_by.as_ref(),
            event.authorization_ref.as_deref(),
            event.created_at,
        )
        .map_err(|error| service_attested_provenance_error(error.to_string()))
}

fn service_attested_provenance_error(message: impl std::fmt::Display) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::FORBIDDEN,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        format!("reason_code=service_attested_provenance_required; {message}"),
    )
}

fn device_enroll_prev_refs(
    actor_seq: u64,
    bootstrap_create_event_id: Option<EventId>,
) -> Result<Vec<EventId>, ArkretRouteError> {
    match (actor_seq, bootstrap_create_event_id) {
        (0, _) => Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::INVALID_PARAM,
            "actor_seq must be the next positive principal control sequence",
        )),
        (1, Some(create_event_id)) => Ok(vec![create_event_id]),
        (1, None) => Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::INVALID_PARAM,
            "bootstrap_create_event_id is required for first-device enrollment",
        )),
        (..) => Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::INVALID_PARAM,
            "device-enroll is restricted to actor_seq=1 founding-device enrollment",
        )),
    }
}

/// Single configured principal-server audience, or an error when the
/// deployment has zero / multiple (the request body carries no audience, so
/// disambiguation is impossible — fail closed).
fn sole_principal_audience(
    arkret_config: &coauth_config::ArkretConfig,
    resolved: &ResolvedPrincipalAudiences,
) -> Result<String, ArkretRouteError> {
    match arkret_config.principal_servers.as_slice() {
        // Fail closed when the sole server omits `audience` and its describe
        // probe has not yet landed, rather than enrolling against an unknown
        // principal-server audience.
        // This is deliberate fail-closed behavior; see
        // `services::resolved_principal_audiences`. Do not substitute an
        // unverified default audience.
        [server] => effective_audience(server, resolved)
            .map(|audience| audience.to_string())
            .ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
                    "principal server audience is not yet resolved from /_arkret/describe",
                )
            }),
        [] => Err(ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
            "no principal server is configured for device enrollment",
        )),
        _ => Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::INVALID_PARAM,
            "multiple principal servers configured; device-enroll cannot pick one",
        )),
    }
}

/// `POST /_arkret/gate/account/device-enroll`
/// (`ak.gate.account.command.enroll_device`).
#[handler]
pub async fn device_enroll_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<AccountDeviceEnrollOutcome>, ArkretRouteError> {
    use coauth_data::RepositoryAccess;
    use coauth_jose::jwt::Jwt;

    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

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
    if grant_row.revoked_at.is_some() {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::GRANT_ALREADY_CONSUMED,
            "session grant has been revoked",
        ));
    }
    if grant_row.expires_at <= clock.now() {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
            "session grant has expired",
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
        .get_by_did_and_audience(grant_payload.subject.as_str(), &grant_payload.audience)
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
    let enrollment_authority_did = principal_binding.enrollment_authority_did;
    let authorization_ref = principal_binding.enrollment_authority_ref;
    let service_account_id = principal_binding.user_id;
    repo.cancel().await.ok();

    // 2. Proof-of-possession: the caller MUST hold the key the grant is bound to.
    let verifier = depot.dpop_verifier()?;
    let dpop_now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let verification = verifier
        .verify(&dpop_header, &htm, &htu, dpop_now, Some(&grant_jwt))
        .await
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
    let audience = sole_principal_audience(&arkret_config, resolved_principal_audiences::shared())?;
    if grant_payload.audience != audience {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
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
    let realm_id_string = arkret_models_identity::principal_control_realm_id(&principal_id);
    let realm_id = RealmId::new(realm_id_string).map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "derived principal-control realm id is invalid: {error}"
        )))
    })?;

    let now = truncate_to_seconds(clock.now());
    let not_before = body.not_before.map_or_else(|| now, truncate_to_seconds);
    let prev_refs =
        device_enroll_prev_refs(body.actor_seq, body.bootstrap_create_event_id.clone())?;

    let payload = DeviceAuthorizePayload {
        principal_id: principal_id.clone(),
        device_id: device_id.clone(),
        device_public_key: NonEmptyString::new(device_public_key_multibase)
            .expect("encoded Ed25519 public key is non-empty"),
        hpke_key: NonEmptyString::new(body.hpke_key.clone())
            .map_err(|error| ArkretRouteError::BadRequest(format!("invalid hpke_key: {error}")))?,
        algorithms: body
            .algorithms
            .iter()
            .cloned()
            .map(NonEmptyString::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ArkretRouteError::BadRequest(format!("invalid algorithm: {error}")))?,
        device_key_algorithm: None,
        authorized_by: DeviceOrPrincipalRef::Did(authority_did.clone()),
        scopes: None,
        not_before,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(DeviceEnrollmentAuthorityBinding {
            kind: DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
            authority_did: authority_did.clone(),
            authorization_ref: NonEmptyString::new(authorization_ref.clone())
                .expect("principal enrollment authority reference is non-empty"),
        }),
        recovery_session_id: None,
    };

    let content = serde_json::to_value(&payload).map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "failed to serialize device-enroll payload: {error}"
        )))
    })?;
    let content = serde_json::from_value(content).map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "device-enroll payload must serialize as an object: {error}"
        )))
    })?;

    let hlc = fresh_hlc(&authority, &realm_id, &device_id, now)?;
    let mut event = Event {
        event_id: EventId::new(arkret_identifiers::new_prefixed_uuid7("ak:event:")).map_err(
            |error| {
                ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                    format!("failed to mint event id: {error}"),
                ))
            },
        )?,
        kind: DEVICE_AUTHORIZE_KIND.into(),
        realm_id,
        actor_id: principal_id.clone(),
        actor_seq: body.actor_seq,
        created_at: now,
        hlc: Some(hlc),
        prev_refs,
        effective_scope: None,
        refs: Vec::new(),
        causal_refs: Vec::new(),
        preconditions: Vec::new(),
        effects: Vec::new(),
        seal_ref: None,
        conflict_keys_digest: None,
        auth_context: None,
        seal_basis: None,
        requirements: EventRequirements::default(),
        redacts: None,
        payload: content,
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
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "failed to sign device-enroll event: {error}"
        )))
    })?;

    let mut repo = depot.repo().await?;
    if !repo
        .account_handoff()
        .claim_first_device_enrollment(
            service_account_id,
            &audience,
            &principal_id,
            &device_id,
            clock.now(),
        )
        .await?
    {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "founding device enrollment requires a verified identity-creation receipt and no existing device",
        ));
    }
    repo.save().await?;

    Ok(Json(AccountDeviceEnrollOutcome {
        principal_id,
        device_id,
        authority_did,
        authorized_event: event,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_id(value: &str) -> EventId {
        EventId::new(value).expect("valid event id")
    }

    #[test]
    fn first_device_requires_and_uses_bootstrap_create_predecessor() {
        let create = event_id("ak:event:01964137-0000-7000-8000-000000000001");
        assert_eq!(
            device_enroll_prev_refs(1, Some(create.clone())).expect("bootstrap refs"),
            vec![create]
        );
        assert!(device_enroll_prev_refs(1, None).is_err());
    }

    #[test]
    fn later_device_is_rejected_by_the_founding_device_endpoint() {
        let create = event_id("ak:event:01964137-0000-7000-8000-000000000001");
        assert!(device_enroll_prev_refs(2, Some(create)).is_err());
        assert!(device_enroll_prev_refs(0, None).is_err());
        assert!(device_enroll_prev_refs(2, None).is_err());
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
}
