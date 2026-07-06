use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use coauth_jose::jwt::Jwt;
use cokret_core::canonical::{canonical_json_bytes, canonical_sha256};
use cokret_core::error::{
    ERROR_CODE_AUDIENCE_MISMATCH, ERROR_CODE_DID_PROOF_REQUIRED, ERROR_CODE_GRANT_ALREADY_CONSUMED,
    ERROR_CODE_INVALID_PARAM, ERROR_CODE_INVALID_SIGNATURE, ERROR_CODE_SESSION_GRANT_NOT_FOUND,
    ERROR_CODE_SESSION_LOGGED_OUT, REASON_PROOF_INVALID,
};
use cokret_core::{
    DeviceId, Hash, SessionGrantProofKind, SessionGrantRefreshOutcome, SessionGrantRefreshProof,
    SessionGrantRefreshRequestBody,
};
use salvo::prelude::*;
use serde::Serialize;
use sha2::Digest as _;

use super::*;
use crate::handlers::cokret::*;
use crate::services::device_signing_directory::resolve_authorized_device_signing_key;
use crate::services::third_party_invite::NonceStore;

const SOFT_LOGOUT_RESTORE_OPERATION: &str = "resume_soft_logged_out_session";
const SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS: i64 = 300;
const SOFT_LOGOUT_DID_PROOF_REPLAY_REASON: &str = "did_proof_replay_window_exceeded";

#[derive(Debug, Serialize)]
struct SoftLogoutDidProofClaims<'a> {
    pub principal_id: &'a str,
    pub device_id: &'a str,
    pub audience: &'a str,
    pub challenge: &'a str,
    pub request_canonical_digest: &'a str,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SoftLogoutRestoreRequestDigest<'a> {
    pub operation: &'static str,
    pub grant_jwt_hash: String,
    pub principal_id: &'a str,
    pub device_id: &'a str,
    pub audience: &'a str,
    pub grant_binding_key_id: &'a str,
}

fn shared_soft_logout_did_proof_nonce_store() -> &'static Arc<NonceStore> {
    static STORE: OnceLock<Arc<NonceStore>> = OnceLock::new();
    STORE.get_or_init(|| Arc::new(NonceStore::new()))
}

fn did_proof_required(message: impl Into<String>) -> CokretRouteError {
    CokretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        ERROR_CODE_DID_PROOF_REQUIRED,
        message,
    )
}

fn did_proof_invalid(message: impl Into<String>) -> CokretRouteError {
    CokretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        REASON_PROOF_INVALID,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn did_proof_replay_window_exceeded(message: impl Into<String>) -> CokretRouteError {
    CokretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        REASON_PROOF_INVALID,
        format!(
            "reason_code={}; {}",
            SOFT_LOGOUT_DID_PROOF_REPLAY_REASON,
            message.into()
        ),
    )
}

fn required_soft_logout_proof(
    body: &SessionGrantRefreshRequestBody,
) -> Result<&SessionGrantRefreshProof, CokretRouteError> {
    body.proof.as_ref().ok_or_else(|| {
        did_proof_required("human soft logout recovery requires a fresh device DID proof")
    })
}

fn required_proof_str<'a>(
    value: &'a Option<String>,
    field: &str,
) -> Result<&'a str, CokretRouteError> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| did_proof_required(format!("soft logout DID proof requires {field}")))
}

fn required_proof_timestamp(
    value: &Option<DateTime<Utc>>,
    field: &str,
) -> Result<DateTime<Utc>, CokretRouteError> {
    value
        .as_ref()
        .copied()
        .ok_or_else(|| did_proof_required(format!("soft logout DID proof requires {field}")))
}

fn required_proof_hash<'a>(
    value: &'a Option<Hash>,
    field: &str,
) -> Result<&'a str, CokretRouteError> {
    value
        .as_ref()
        .map(cokret_core::Hash::as_str)
        .ok_or_else(|| did_proof_required(format!("soft logout DID proof requires {field}")))
}

fn validate_soft_logout_proof_kind(
    proof_kind: Option<SessionGrantProofKind>,
) -> Result<(), CokretRouteError> {
    let proof_kind = proof_kind
        .ok_or_else(|| did_proof_required("soft logout DID proof requires proof_kind"))?;
    match proof_kind {
        SessionGrantProofKind::DidBoundSignature | SessionGrantProofKind::PairedDeviceProof => {
            Ok(())
        }
        other => Err(did_proof_invalid(format!(
            "unsupported soft logout DID proof_kind {other:?}"
        ))),
    }
}

fn require_soft_logout_bound_device_id<'a>(
    presented_device_id: Option<&'a str>,
    persisted_device_id: Option<&'a str>,
) -> Result<&'a str, CokretRouteError> {
    let presented = presented_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            did_proof_required("soft logout recovery requires the presented device_id")
        })?;
    DeviceId::new(presented.to_owned()).map_err(|error| {
        CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_INVALID_PARAM,
            format!("device_id is not a protocol device identifier: {error}"),
        )
    })?;

    let persisted = persisted_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            did_proof_required("session grant has no device_id binding for soft logout recovery")
        })?;
    if presented != persisted {
        return Err(did_proof_invalid(
            "presented device_id does not match the persisted session grant binding",
        ));
    }

    Ok(persisted)
}

fn validate_soft_logout_did_proof_window(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), CokretRouteError> {
    let freshness_secs = (expires_at - issued_at).num_seconds();
    if freshness_secs <= 0 || freshness_secs > SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS {
        return Err(did_proof_replay_window_exceeded(format!(
            "DID proof expires_at - issued_at must be within 1..={SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS} seconds"
        )));
    }

    let skew_secs = (issued_at - now).num_seconds().abs();
    if skew_secs > SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS {
        return Err(did_proof_replay_window_exceeded(format!(
            "DID proof issued_at is outside the {SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS} second receiver skew window"
        )));
    }

    if now >= expires_at {
        return Err(did_proof_replay_window_exceeded(
            "DID proof has expired and cannot restore a soft-logged-out session",
        ));
    }

    Ok(())
}

fn session_grant_jwt_hash(grant_jwt: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(grant_jwt.as_bytes()))
    )
}

fn soft_logout_restore_request_canonical_digest(
    grant_jwt: &str,
    principal_id: &str,
    device_id: &str,
    audience: &str,
    grant_binding_key_id: &str,
) -> Result<String, CokretRouteError> {
    canonical_sha256(&SoftLogoutRestoreRequestDigest {
        operation: SOFT_LOGOUT_RESTORE_OPERATION,
        grant_jwt_hash: session_grant_jwt_hash(grant_jwt),
        principal_id,
        device_id,
        audience,
        grant_binding_key_id,
    })
    .map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "soft logout restore request canonicalization failed: {error}"
        )))
    })
}

fn verification_method_did(verification_method: &str) -> &str {
    let without_fragment = verification_method
        .split_once('#')
        .map_or(verification_method, |(did, _)| did);
    without_fragment
        .split_once('?')
        .map_or(without_fragment, |(did, _)| did)
}

/// Verify an EdDSA detached compact JWS (`protected..signature`) over
/// `payload_bytes` against a bare Ed25519 multibase verifying key (the
/// device signing key resolved from the Principal Server directory). Returns
/// the `kid` (verification method) from the protected header on success.
///
/// The signing input is recomputed from the wire bytes per RFC 7515 §5.2 as
/// `b64u(protected) "." b64u(payload_bytes)`, so no JWS library state intervenes
/// between the directory-resolved key and the SDK Ed25519 verifier
/// (`cokret_signatures::proof::verify_detached_ed25519_signature`).
fn verify_detached_jws_with_device_key(
    detached_jws: &str,
    payload_bytes: &[u8],
    device_multibase: &str,
) -> Result<String, String> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use cokret_signatures::proof::{PublicKeyMaterial, verify_detached_ed25519_signature};

    let mut parts = detached_jws.split('.');
    let header_b64u = parts.next().ok_or("missing protected header")?;
    let payload_segment = parts.next().ok_or("missing payload segment")?;
    let signature_b64u = parts.next().ok_or("missing signature segment")?;
    if parts.next().is_some() {
        return Err("too many JWS segments".to_owned());
    }
    if !payload_segment.is_empty() {
        return Err("detached JWS payload segment must be empty".to_owned());
    }

    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64u)
        .map_err(|error| format!("invalid header b64url: {error}"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|error| format!("invalid protected header: {error}"))?;
    if header.get("alg").and_then(serde_json::Value::as_str) != Some("EdDSA") {
        return Err("protected header alg must be EdDSA".to_owned());
    }
    let verification_method = header
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("protected header missing kid")?
        .to_owned();

    // RFC 7515 §5.2 signing input over the attached payload bytes.
    let payload_b64u = Base64UrlUnpadded::encode_string(payload_bytes);
    let mut signing_input = String::with_capacity(header_b64u.len() + 1 + payload_b64u.len());
    signing_input.push_str(header_b64u);
    signing_input.push('.');
    signing_input.push_str(&payload_b64u);

    let material = PublicKeyMaterial::Ed25519Multibase {
        value: device_multibase.to_owned(),
    };
    if verify_detached_ed25519_signature(&material, signing_input.as_bytes(), signature_b64u) {
        Ok(verification_method)
    } else {
        Err("Ed25519 signature did not verify against the authorized device key".to_owned())
    }
}

async fn verify_soft_logout_did_proof(
    http_client: &reqwest::Client,
    cokret_config: &coauth_config::CokretConfig,
    body: &SessionGrantRefreshRequestBody,
    prior_grant: &coauth_data::SessionGrant,
    device_id: &str,
    now: DateTime<Utc>,
) -> Result<(), CokretRouteError> {
    let proof = required_soft_logout_proof(body)?;
    validate_soft_logout_proof_kind(proof.proof_kind)?;

    let challenge = required_proof_str(&proof.challenge, "challenge")?;
    let proof_audience = required_proof_str(&proof.audience, "audience")?;
    let request_canonical_digest =
        required_proof_hash(&proof.request_canonical_digest, "request_canonical_digest")?;
    let proof_jws = required_proof_str(&proof.signature, "signature")?;
    let issued_at = required_proof_timestamp(&proof.issued_at, "issued_at")?;
    let expires_at = required_proof_timestamp(&proof.expires_at, "expires_at")?;

    if proof_audience != prior_grant.audience {
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_AUDIENCE_MISMATCH,
            "soft logout DID proof audience must match the session grant audience",
        ));
    }

    validate_soft_logout_did_proof_window(issued_at, expires_at, now)?;

    let claims = SoftLogoutDidProofClaims {
        principal_id: &prior_grant.subject,
        device_id,
        audience: proof_audience,
        challenge,
        request_canonical_digest,
        issued_at,
        expires_at,
    };
    let payload = canonical_json_bytes(&claims).map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "soft logout DID proof canonicalization failed: {error}"
        )))
    })?;

    // Device-identity source of truth is the Principal Server's device directory,
    // NOT the principal DID document. The device signing key was authorized by a
    // `ck.device.authorize` event and projected into soland's device directory; a
    // `ck.device.revoke` masks it. Resolve the authorized, non-revoked key for
    // this human `(principal, device)` and verify the detached DID-proof JWS
    // against it. Agent runtimes use the separate `agent_key_proof` branch.
    // The directory only surfaces verified, non-revoked devices, so a resolved
    // key is itself proof the device is currently authorized.
    let resolved = resolve_authorized_device_signing_key(
        http_client,
        cokret_config,
        &prior_grant.audience,
        &prior_grant.subject,
        device_id,
    )
    .await
    .map_err(|error| did_proof_invalid(format!("device signing key resolution failed: {error}")))?;

    let verification_method =
        verify_detached_jws_with_device_key(proof_jws, &payload, &resolved.multibase)
            .map_err(|error| did_proof_invalid(format!("DID proof JWS invalid: {error}")))?;
    if let Some(expected_method) = proof
        .verification_method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && expected_method != verification_method.as_str()
    {
        return Err(did_proof_invalid(
            "DID proof verification_method does not match the detached JWS kid",
        ));
    }
    // The kid principal MUST still be the session-grant subject, so a proof
    // signed under a different principal's device key cannot restore this
    // session. The kid may carry either the principal DID prefix
    // (`{principal}#{device}`) or the bare device `did:key`; accept either, but
    // when it is principal-prefixed it MUST match the subject.
    let kid_principal = verification_method_did(&verification_method);
    let kid_is_principal_prefixed =
        kid_principal.starts_with("did:webvh:") || kid_principal.starts_with("did:web:");
    if kid_is_principal_prefixed && kid_principal != prior_grant.subject {
        return Err(did_proof_invalid(
            "DID proof verification_method principal does not match the session grant subject",
        ));
    }
    if !kid_is_principal_prefixed
        && !kid_principal.starts_with("did:key:")
        && verification_method.as_str() != resolved.device_signing_key_did
    {
        return Err(did_proof_invalid(
            "DID proof verification_method does not match the authorized device signing key",
        ));
    }

    let expected_digest = soft_logout_restore_request_canonical_digest(
        &body.grant_jwt,
        &prior_grant.subject,
        device_id,
        proof_audience,
        &verification_method,
    )?;
    if request_canonical_digest != expected_digest {
        return Err(did_proof_invalid(
            "DID proof request_canonical_digest does not match the presented restore request",
        ));
    }

    let replay_key = format!(
        "{}|{}|{}|{}|{}|{}",
        SOFT_LOGOUT_RESTORE_OPERATION,
        prior_grant.subject,
        device_id,
        proof_audience,
        challenge,
        request_canonical_digest
    );
    shared_soft_logout_did_proof_nonce_store()
        .check_and_record(&replay_key, expires_at, now)
        .map_err(|_| did_proof_invalid("DID proof challenge has already been used"))?;

    Ok(())
}

// ── DPoP-bound session-grant refresh + debug seed ──────────────
//
// These two handlers were added in G3.C1 to complete the device-bound
// session-grant story: `refresh_session_grant` rotates an existing
// DPoP-bound grant onto a new access token (keeping `cnf.jkt` constant),
// and `debug_issue_dpop_grant` is the cotest harness seam that mints a
// fully signed grant without going through OIDC.

/// `POST /_cokret/gate/account/session-grants/refresh` — exchange a near-expiry
/// DPoP-bound session grant for a fresh one. The caller MUST present:
///
/// * A `DPoP` header that proves possession of the same key the existing grant is bound to
///   (`cnf.jkt` on the old grant must match the new proof's `jkt`).
/// * A request body carrying the prior grant JWT, the bound `device_id`, and a fresh human-device
///   DID proof over the soft-logout restore transcript.
///
/// On success the old grant is revoked (single-use semantics — its
/// `revoked_at` is persisted) and a new grant is issued with the same
/// `cnf.jkt`, a rotated id, and a fresh expiry.
#[handler]
pub async fn refresh_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantRefreshOutcome>, CokretRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    // 1. DPoP proof must be present — the refresh endpoint is the canonical proof-of-possession
    //    check.
    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        // The grant-binding DPoP proof authorizes this operation; its absence is
        // an auth failure, not a malformed body.
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_DID_PROOF_REQUIRED,
            "session-grant grant-binding DPoP proof required",
        )
    })?;

    let body: SessionGrantRefreshRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;

    if body.grant_jwt.trim().is_empty() {
        return Err(CokretRouteError::BadRequest("missing grant_jwt".to_owned()));
    }

    // 2. Parse + load the existing grant. We never verify the JWT signature here — the persisted
    //    row IS the source of truth — but we DO read the `cnf.jkt` claim out of the JWT payload to
    //    bind the proof.
    let jwt: Jwt<'_, SessionGrantPayload> = Jwt::try_from(body.grant_jwt.as_str())
        .map_err(|_| CokretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let prior_payload = jwt.payload().clone();
    let expected_jkt = prior_payload
        .cnf
        .as_ref()
        .map(|cnf| cnf.jkt.clone())
        .ok_or_else(|| {
            CokretRouteError::BadRequest("grant_jwt is not DPoP-bound (cnf.jkt missing)".to_owned())
        })?;

    let mut repo = depot.repo().await?;
    let prior_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&body.grant_jwt)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            CokretRouteError::coded(
                StatusCode::NOT_FOUND,
                ERROR_CODE_SESSION_GRANT_NOT_FOUND,
                "no session grant matches the presented grant_jwt",
            )
        })?;

    // Single-use enforcement: a previously consumed grant can never be rotated
    // again. Re-use of a consumed grant is a credential-compromise signal (the
    // wire code is `grant_already_consumed`; this protocol rotates DPoP-bound
    // session grants, not OAuth refresh tokens — see account-lifecycle §4.1).
    if prior_grant.revoked_at.is_some() {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_GRANT_ALREADY_CONSUMED,
            "session grant already consumed; its rotation chain cannot continue",
        ));
    }

    // 3. Verify the DPoP proof against this exact endpoint, with the prior grant_jwt as the bound
    //    access token (so `ath` MUST match).
    let verifier = depot.dpop_verifier()?;
    let now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let verification = verifier
        .verify(&dpop_header, &htm, &htu, now, Some(&body.grant_jwt))
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

    // 4. Resolve the underlying browser session so the new grant lives under the same
    //    authentication context.
    let browser_session_id = prior_grant.browser_session_id.ok_or_else(|| {
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            ERROR_CODE_SESSION_GRANT_NOT_FOUND,
            "session-grant refresh requires a browser-bound session grant",
        )
    })?;
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

    // The browser session is the authentication context the grant chain hangs
    // off. Logout finishes it (sets `finished_at`) but does NOT eagerly revoke
    // outstanding grants — so without this check a logged-out device that still
    // holds the DPoP key could keep rotating its grant and stay signed in
    // forever, defeating logout. Refuse rotation once the session is finished:
    // re-authentication (a fresh browser session) is then required.
    if browser_session.finished_at.is_some() {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_SESSION_LOGGED_OUT,
            "underlying browser session is logged out; rotation chain cannot be resumed",
        ));
    }

    // 5. Mint a new grant with the same subject + scope + audience. The
    // audience MUST NOT change across rotation: a client holding a grant for
    // one Principal Server must not be able to rotate it into a grant for a
    // different audience (which it could then exchange there). Ignore any
    // client-supplied audience; reject an explicit mismatch defensively.
    if let Some(requested) = body.audience.as_deref()
        && requested != prior_grant.audience
    {
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_AUDIENCE_MISMATCH,
            "session-grant rotation MUST NOT change the bound audience",
        ));
    }

    let device_id = require_soft_logout_bound_device_id(
        body.device_id.as_ref().map(DeviceId::as_str),
        prior_grant.device_id.as_deref(),
    )?;
    verify_soft_logout_did_proof(
        &http_client,
        &cokret_config,
        &body,
        &prior_grant,
        device_id,
        now,
    )
    .await?;

    // 5. Single-use rotation gate (CAS). Atomically consume the prior grant
    // BEFORE minting its successor: `revoke_if_active` sets `revoked_at` only
    // if it is still NULL and reports whether THIS call won. Two concurrent
    // rotations of the same parent contend on the row lock, so exactly one
    // wins and the loser is rejected with `grant_already_consumed` — without
    // this, both could read the parent active and each insert an active child,
    // violating single-use rotation (account-lifecycle §4.1). Doing the consume
    // first (rather than after the insert) means the loser never mints a grant
    // it would have to throw away, and the consume + insert commit atomically
    // in this one transaction.
    let consumed = repo
        .oauth_session_grant()
        .revoke_if_active(&*clock, prior_grant.id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
    if !consumed {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_GRANT_ALREADY_CONSUMED,
            "session grant already consumed; its rotation chain cannot continue",
        ));
    }

    // 6. Mint a new grant with the same subject + scope + audience.
    let audience = prior_grant.audience.clone();
    let scopes: Vec<String> = prior_grant
        .scope
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    let new_material = issue_session_grant_for_audience(
        &*clock,
        &cokret_config,
        &key_store,
        &browser_session,
        verification.jwk.clone(),
        audience,
        scopes,
        Some(&prior_grant.subject),
        Some(verification.jkt.clone()),
    )
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    let persisted = persist_session_grant(
        &mut repo,
        &mut rng,
        &*clock,
        &browser_session,
        &new_material,
    )
    .await
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantRefreshOutcome {
        grant_id: persisted.grant_id,
        grant_jwt: new_material.grant_jwt,
        session_public_key: new_material.session_public_key,
        expires_at: new_material.expires_at_timestamp,
        audience: new_material.audience,
        scopes: new_material.scopes,
        dpop_jkt: verification.jkt,
        // The prior grant was atomically consumed by the CAS above.
        previous_grant_id: prior_grant.grant_id,
    }))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    const DEVICE_ID: &str = "ck:device:0196419b-0000-7000-8000-000000000001";
    const OTHER_DEVICE_ID: &str = "ck:device:0196419b-0000-7000-8000-000000000002";

    fn ts(seconds: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(seconds, 0).expect("test timestamp must be valid")
    }

    fn assert_coded(error: CokretRouteError, expected_code: &'static str) -> String {
        match error {
            CokretRouteError::Coded { code, message, .. } => {
                assert_eq!(code, expected_code);
                message
            }
            other => panic!("expected coded error, got {other:?}"),
        }
    }

    #[test]
    fn soft_logout_proof_window_rejects_more_than_300_seconds() {
        let issued_at = ts(1_700_000_000);
        let err = validate_soft_logout_did_proof_window(
            issued_at,
            issued_at + Duration::seconds(SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS + 1),
            issued_at,
        )
        .expect_err("oversized DID proof replay window must fail closed");

        let message = assert_coded(err, REASON_PROOF_INVALID);
        assert!(message.contains(SOFT_LOGOUT_DID_PROOF_REPLAY_REASON));
    }

    #[test]
    fn soft_logout_proof_window_rejects_expired_proof() {
        let issued_at = ts(1_700_000_000);
        let expires_at = issued_at + Duration::seconds(SOFT_LOGOUT_DID_PROOF_MAX_WINDOW_SECS);
        let err = validate_soft_logout_did_proof_window(issued_at, expires_at, expires_at)
            .expect_err("expired DID proof must fail closed");

        let message = assert_coded(err, REASON_PROOF_INVALID);
        assert!(message.contains(SOFT_LOGOUT_DID_PROOF_REPLAY_REASON));
    }

    #[test]
    fn soft_logout_proof_kind_is_required() {
        let err = validate_soft_logout_proof_kind(None)
            .expect_err("missing proof_kind must require proof context");

        assert_coded(err, ERROR_CODE_DID_PROOF_REQUIRED);
    }

    #[test]
    fn soft_logout_proof_kind_rejects_unrelated_branches() {
        let err = validate_soft_logout_proof_kind(Some(SessionGrantProofKind::AgentKeyProof))
            .expect_err("agent_key_proof must not restore a human soft-logged-out session");

        assert_coded(err, REASON_PROOF_INVALID);
    }

    #[test]
    fn soft_logout_device_binding_requires_presented_device_id() {
        let err = require_soft_logout_bound_device_id(None, Some(DEVICE_ID))
            .expect_err("missing presented device_id must require DID proof context");

        assert_coded(err, ERROR_CODE_DID_PROOF_REQUIRED);
    }

    #[test]
    fn soft_logout_device_binding_requires_persisted_session_grant_device() {
        let err = require_soft_logout_bound_device_id(Some(DEVICE_ID), None)
            .expect_err("legacy unbound grant must not be recoverable");

        assert_coded(err, ERROR_CODE_DID_PROOF_REQUIRED);
    }

    #[test]
    fn soft_logout_device_binding_rejects_device_mismatch() {
        let err = require_soft_logout_bound_device_id(Some(OTHER_DEVICE_ID), Some(DEVICE_ID))
            .expect_err("presented device_id must match the grant binding");

        assert_coded(err, REASON_PROOF_INVALID);
    }

    #[test]
    fn soft_logout_device_binding_accepts_persisted_match() {
        let device_id = require_soft_logout_bound_device_id(Some(DEVICE_ID), Some(DEVICE_ID))
            .expect("matching device bindings should pass");

        assert_eq!(device_id, DEVICE_ID);
    }

    #[test]
    fn soft_logout_restore_request_digest_binds_device_and_grant_binding_key() {
        let base = soft_logout_restore_request_canonical_digest(
            "grant.jwt.value",
            "did:web:alice.example",
            DEVICE_ID,
            "did:web:auth.example",
            "did:web:alice.example#device-key-1",
        )
        .expect("request digest should compute");
        assert!(base.starts_with("sha256:"));

        let other_device = soft_logout_restore_request_canonical_digest(
            "grant.jwt.value",
            "did:web:alice.example",
            OTHER_DEVICE_ID,
            "did:web:auth.example",
            "did:web:alice.example#device-key-1",
        )
        .expect("request digest should compute");
        let other_grant_binding_key = soft_logout_restore_request_canonical_digest(
            "grant.jwt.value",
            "did:web:alice.example",
            DEVICE_ID,
            "did:web:auth.example",
            "did:web:alice.example#other-device-key",
        )
        .expect("request digest should compute");

        assert_ne!(base, other_device);
        assert_ne!(base, other_grant_binding_key);
    }
}
