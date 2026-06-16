//! `POST /_cokret/gate/account/device-authorize` — restricted enrollment
//! signing oracle (decision 0002 B model, device-lifecycle §5.4).
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
use cokret_core::{
    Audience, DeviceAuthorizePayload, DeviceEnrollmentAuthorityBinding, DeviceOrPrincipalRef, Did,
    Event, EventId, EventRequirements, Hlc, RealmId, ed25519_pubkey_to_did_key_multibase,
};
use cokret_signatures::{SignEventOptions, sign_event};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::CokretRouteError;
use crate::handlers::common::DepotExt;
use crate::salvo_utils::user_authorization::UserAuthorization;
use crate::services::device_enrollment_authority::enrollment_authority;

const DEVICE_AUTHORIZE_KIND: &str = "ck.device.authorize";
const ENROLLMENT_AUTHORITY_SERVICE_FRAGMENT: &str = "#enrollment-authority";
const ENROLLMENT_BINDING_KIND: &str = "service_attested";

/// Request body for `POST /_cokret/gate/account/device-authorize`.
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizeRequestBody {
    /// This session's `device_id` (`ck:device:<uuid>`). The enrollment authority
    /// signs the `ck.device.authorize` for exactly this id so the projected
    /// `device_public_key` lands under the same id the session (and recovery)
    /// looks up.
    pub device_id: String,
    /// The device's 32-byte Ed25519 public key, encoded as multibase
    /// (`z<base58btc(0xed01||key)>`) or standard/URL-safe base64.
    pub device_public_key: String,
    /// The principal's current device-stream `actor_seq`, as observed by the
    /// client from soland. coauth does not re-derive it.
    pub actor_seq: u64,
    /// Optional `not_before` (RFC3339). Defaults to now.
    #[serde(default)]
    pub not_before: Option<DateTime<Utc>>,
}

/// Response: the signed `ck.device.authorize` Event, ready for the client to
/// submit to soland `/_cokret/self/events`.
#[derive(Debug, Serialize)]
pub struct DeviceAuthorizeOutcome {
    /// The principal DID the device was authorized under.
    pub principal_id: String,
    /// The derived self-certifying device id.
    pub device_id: String,
    /// The enrollment authority DID (`executed_by` / `authorized_by`).
    pub authority_did: String,
    /// The fully-signed Event envelope.
    pub event: Event,
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
            "no_principal_server",
            "no principal server is configured for device enrollment",
        )),
        _ => Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            "ambiguous_principal_server",
            "multiple principal servers configured; device-authorize cannot pick one",
        )),
    }
}

/// `POST /_cokret/gate/account/device-authorize`.
#[handler]
pub async fn device_authorize_endpoint(
    req: &mut Request,
    depot: &mut Depot,
) -> Result<Json<DeviceAuthorizeOutcome>, CokretRouteError> {
    use oauth_types::scope::OPENID;

    let cokret_config = depot.cokret_config()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    // 1. End-user bearer → session → user. This is the human access-token path (userinfo-style),
    //    distinct from the server-to-server `require_session_grant_caller`.
    let user_authorization = UserAuthorization::<()>::extract_from_request(req)
        .await
        .map_err(|_| CokretRouteError::Unauthorized("invalid authorization".to_owned()))?;

    let body: DeviceAuthorizeRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;

    let mut repo = depot.repo().await?;
    let session = user_authorization
        .protected(&mut repo, &clock, &[&OPENID])
        .await
        .map_err(|_| CokretRouteError::Unauthorized("invalid or expired session".to_owned()))?;
    let Some(user_id) = session.user_id else {
        return Err(CokretRouteError::Unauthorized(
            "session is not bound to a user".to_owned(),
        ));
    };
    let user = repo
        .user()
        .lookup(user_id)
        .await
        .map_err(CokretRouteError::from)?
        .ok_or_else(|| CokretRouteError::Unauthorized("unknown user".to_owned()))?;

    // 2. Resolve the user's principal DID for the targeted principal server.
    let audience = sole_principal_audience(&cokret_config)?;
    let principal_did_row = repo
        .principal_did()
        .get_for_user_and_audience(&user, &audience)
        .await
        .map_err(CokretRouteError::from)?
        .ok_or_else(|| {
            CokretRouteError::coded(
                StatusCode::CONFLICT,
                "principal_did_not_minted",
                "no principal DID has been minted for this user yet",
            )
        })?;
    repo.cancel().await.ok();

    let principal_id = Did::new(principal_did_row.did.clone()).map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "stored principal DID is invalid: {error}"
        )))
    })?;

    // 3. This session's device id (client-supplied; soland projects the
    //    device_public_key under it, matching the id the session/recovery uses).
    let device_id = cokret_core::DeviceId::new(body.device_id.clone()).map_err(|error| {
        CokretRouteError::BadRequest(format!("device_id must be a ck:device id: {error}"))
    })?;
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

    let not_before = body.not_before.unwrap_or_else(|| clock.now());

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
            "failed to serialize device-authorize payload: {error}"
        )))
    })?;

    let now = clock.now();
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
        authorization_ref: Some(authorization_ref),
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        unsigned: std::collections::BTreeMap::new(),
        proofs: Vec::new(),
    };

    // 5. Sign the proof with the persistent enrollment key; the VM maps to `executed_by`
    //    (device-lifecycle §5.4). Bind the proof to the target principal server
    //    (`domain`/`audience` = its service DID) so the submitting client's
    //    domain-binding check passes and the binding is audience-scoped.
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
            "failed to sign device-authorize event: {error}"
        )))
    })?;

    Ok(Json(DeviceAuthorizeOutcome {
        principal_id: principal_id.into_string(),
        device_id: device_id.as_str().to_owned(),
        authority_did: authority_did.into_string(),
        event,
    }))
}
