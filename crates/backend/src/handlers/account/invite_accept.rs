// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 — 3PID invite verifier HTTP surface.
//!
//! Wires `services::third_party_invite::verify_invite` to a public
//! HTTP endpoint so cotest's `invites/third-party` scenario (and
//! production claimants) can drive the two-step proof chain over the
//! wire.
//!
//! ## Route
//!
//! `POST /_coauth/self/invites/3pid/verify`
//!
//! This is the **pure verifier** form: the handler takes the two JWS
//! proofs + the presenter DID, runs `verify_invite`, and on success
//! returns a JSON summary of the verified invite. It does NOT forward
//! to soland — that's the consumer's job (typically yougen), which
//! then submits a separate `ck.invite.claim` via soland's existing
//! invite-acceptance reducer per the contract in
//! `cotest/e2e/scenarios/invites/third-party.md` Phase C.
//!
//! Splitting "verify" from "accept" lets us exercise the verifier in
//! isolation, gives us a stable success contract for replay-defence
//! tests (the `jti` is persisted in the shared `NonceStore` even when
//! the caller never makes the follow-up claim), and matches the
//! responsibility split the round-4 spec already draws between
//! coauth (proof checking) and soland (reducer / state machine).
//!
//! ## Error mapping
//!
//! On `Err(InviteVerificationError::*)` the handler returns
//! `error.http_status()` with a body matching coauth's standard
//! envelope:
//!
//! ```json
//! { "error": "<error.code()>", "message": "<error.to_string()>" }
//! ```
//!
//! The `error` field carries the stable wire code (`subject_proof_invalid`,
//! `proof_expired`, etc.) and `message` carries human-readable context
//! for operators. The status code is one of:
//!
//! - `401 Unauthorized` — `verification_proof_invalid` / `subject_proof_invalid`
//! - `403 Forbidden` — `subject_id_mismatch`
//! - `410 Gone` — `proof_expired`
//!
//! ## Replay defence
//!
//! The `NonceStore` that tracks accepted `jti` values is a
//! process-global `OnceLock<Arc<NonceStore>>` — see
//! [`shared_nonce_store`]. Single-process semantics are fine while
//! coauth runs as a single replica (which is the deployment topology
//! the round-4 spec already assumes); multi-replica deployment would
//! need to back this with a small DB table — see the doc comment on
//! `NonceStore` in `services::third_party_invite`.

use std::sync::{Arc, OnceLock};

use chrono::Utc;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{DepotExt, RouteError};
use crate::services::third_party_invite::{InviteRequest, NonceStore, VerifierCtx, verify_invite};

// ── Request / response shapes ──────────────────────────────────

/// Body of `POST /_coauth/self/invites/3pid/verify`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyInviteRequestBody {
    /// Verification-service proof JWS (compact serialization). Signed
    /// by the trusted 3PID verification service.
    pub binding_proof_jws: String,
    /// Subject proof JWS (compact serialization) signed by the
    /// inviter's actor key.
    pub subject_proof_jws: String,
    /// The DID currently presenting this invite. MUST match the
    /// `inviter_did` claim in the subject proof. Sourced from the
    /// caller's request context (DPoP / OAuth subject); echoed in the
    /// body for now because the verifier endpoint accepts both
    /// browser-session and cotest harness traffic.
    pub presenter_did: String,
}

/// Success payload returned on `verify_invite` Ok.
#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyInviteOutcome {
    /// Always `true` on this branch — `false` is never produced
    /// because non-Ok branches return a 4xx instead.
    pub verified: bool,
    /// SHA-256 (hex) of the normalized 3PID, as carried in both proofs.
    pub three_pid_hash: String,
    /// Inviter DID asserted by the subject proof — already checked to
    /// match `presenter_did`.
    pub inviter_did: String,
    /// DID the invitee promised to claim under.
    pub invitee_promise_did: String,
    /// `jti` of the verification-service proof; the caller may persist
    /// this for downstream audit linkage.
    pub verification_proof_jti: String,
    /// RFC 3339 string. Earliest of the two proofs' `exp` claims.
    pub effective_expires_at: String,
}

/// Error envelope mirroring coauth's other 4xx bodies but with a
/// machine-readable code + human-readable message. We render this
/// explicitly (instead of going through `RouteError`) because the
/// status / code mapping is dictated by the `InviteVerificationError`
/// variant, not by `RouteError`'s built-in shapes.
#[derive(Debug, Serialize, ToSchema)]
struct VerifyErrorBody {
    error: &'static str,
    message: String,
}

// ── Shared NonceStore (process-global) ─────────────────────────

/// Shared replay store. Lazily constructed on first use.
///
/// Held behind an `Arc` so the verifier context can take a `&NonceStore`
/// reference into it without cloning the underlying `HashMap`. The
/// store itself uses internal locking, so concurrent verify calls are
/// fine.
fn shared_nonce_store() -> &'static Arc<NonceStore> {
    static STORE: OnceLock<Arc<NonceStore>> = OnceLock::new();
    STORE.get_or_init(|| Arc::new(NonceStore::new()))
}

// ── Salvo handler ──────────────────────────────────────────────

/// `POST /_coauth/self/invites/3pid/verify`
///
/// Runs the two-step `verify_invite` proof chain (verification-service
/// proof + subject proof + cross-checks). On success returns a JSON
/// summary; on failure returns the status code dictated by
/// `InviteVerificationError::http_status()`.
///
/// When the deployment has an empty verification-service allowlist
/// (`cokret.verification_service_did` / `cokret.verification_service_dids`
/// both unset) the route returns `503 verifier_not_configured` — there's
/// no trusted `iss` set to compare the binding proof against, so we
/// cannot safely run the verifier.
#[endpoint]
#[tracing::instrument(name = "handlers.account.invite_accept.verify", skip_all, err)]
pub async fn post_verify_invite(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let body: VerifyInviteRequestBody = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid_request_body".into()))?;

    if body.binding_proof_jws.trim().is_empty()
        || body.subject_proof_jws.trim().is_empty()
        || body.presenter_did.trim().is_empty()
    {
        return Err(RouteError::BadRequest("missing_required_fields".into()));
    }

    let cokret_config = depot.cokret_config()?;
    let http_client = depot.http_client()?;
    let url_builder = depot.url_builder()?;
    let key_store = depot.key_store()?;
    let did_resolver = depot.did_resolver_service()?;

    // The verifier requires both an expected `iss` (the trusted 3PID
    // verification service DID) and an expected `aud` (this coauth
    // deployment's own service DID). The latter is derived from the
    // resolver so it tracks any deployment override; the former MUST
    // come from configuration.
    // SEC-07a — the trusted `iss` set comes from the explicit allowlist.
    // Empty == no verifier configured -> fail closed.
    let expected_iss_allowlist = cokret_config.verification_service_allowlist();
    if expected_iss_allowlist.is_empty() {
        warn!(
            "POST /_coauth/self/invites/3pid/verify called but no verification-service DID is configured \
             (cokret.verification_service_did / cokret.verification_service_dids); \
             returning 503 verifier_not_configured"
        );
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
        res.render(Json(VerifyErrorBody {
            error: "verifier_not_configured",
            message: "no cokret verification-service DID allowlist is set in this deployment"
                .into(),
        }));
        return Ok(());
    }
    let expected_aud = did_resolver.service_did(&cokret_config);

    let mut repo = depot.repo().await?;
    let nonce_store = shared_nonce_store();
    let now = Utc::now();

    let invite_request = InviteRequest {
        binding_proof_jws: body.binding_proof_jws,
        subject_proof_jws: body.subject_proof_jws,
        presenter_did: body.presenter_did,
    };

    let mut ctx = VerifierCtx {
        expected_verification_service_dids: &expected_iss_allowlist,
        expected_audience: expected_aud.as_str(),
        now,
        nonce_store: nonce_store.as_ref(),
        did_resolver: did_resolver.as_ref(),
        http_client: &http_client,
        url_builder: &url_builder,
        cokret_config: &cokret_config,
        key_store: &key_store,
        repo: &mut repo,
    };

    match verify_invite(&invite_request, &mut ctx).await {
        Ok(verified) => {
            res.status_code(StatusCode::OK);
            res.render(Json(VerifyInviteOutcome {
                verified: true,
                three_pid_hash: verified.three_pid_hash,
                inviter_did: verified.inviter_did,
                invitee_promise_did: verified.invitee_promise_did,
                verification_proof_jti: verified.verification_proof_jti,
                effective_expires_at: verified.effective_expires_at.to_rfc3339(),
            }));
            Ok(())
        }
        Err(err) => {
            let status = StatusCode::from_u16(err.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            res.status_code(status);
            res.render(Json(VerifyErrorBody {
                error: err.code(),
                message: err.to_string(),
            }));
            Ok(())
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::third_party_invite::InviteVerificationError;

    /// Tripwire: when `InviteVerificationError` variants get re-mapped
    /// to different HTTP status codes, the handler must follow. We
    /// don't instantiate the verifier here — the variant→status
    /// mapping is the contract and `services::third_party_invite`'s
    /// own tests cover the table directly. This test just exercises
    /// the `StatusCode::from_u16` conversion path so a typo in the
    /// handler's status mapping is caught locally.
    #[test]
    fn handler_renders_each_error_variant_with_its_documented_status() {
        let cases = [
            (
                InviteVerificationError::VerificationProofInvalid("x".into()),
                StatusCode::UNAUTHORIZED,
                "verification_proof_invalid",
            ),
            (
                InviteVerificationError::SubjectProofInvalid("x".into()),
                StatusCode::UNAUTHORIZED,
                "subject_proof_invalid",
            ),
            (
                InviteVerificationError::ProofExpired("x".into()),
                StatusCode::GONE,
                "proof_expired",
            ),
            (
                InviteVerificationError::SubjectIdMismatch {
                    presenter: "did:web:a".into(),
                    subject: "did:web:b".into(),
                },
                StatusCode::FORBIDDEN,
                "subject_id_mismatch",
            ),
        ];
        for (err, expected_status, expected_code) in cases {
            let actual_status = StatusCode::from_u16(err.http_status())
                .expect("variant http_status MUST be a valid status code");
            assert_eq!(actual_status, expected_status, "status for {expected_code}");
            assert_eq!(err.code(), expected_code);
        }
    }

    #[test]
    fn shared_nonce_store_is_a_singleton() {
        let a = shared_nonce_store();
        let b = shared_nonce_store();
        // Same `Arc` instance — `Arc::ptr_eq` confirms `OnceLock` did
        // not initialise twice.
        assert!(Arc::ptr_eq(a, b));
    }
}
