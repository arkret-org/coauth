// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 (2026-05-20, spec a77b995) — 3PID invite engine.
//!
//! Replaces the previous plaintext email / SMS invite pathway with the
//! `ak.schema.invite.v1` `third_party_invite` shape. Two wire modes are
//! supported:
//!
//! - `offline_token`: the OOB code is a high-entropy (`≥128 bits`) opaque token. The wire carries
//!   `token_commitment = sha256(token | salt)` + `token_salt_id` (opaque) + `token_entropy_bits`.
//!   The plaintext token is delivered out-of-band; servers verify by hashing the claimant's token
//!   against the stored salt and constant-time-comparing the commitment.
//!
//! - `lookup`: the OOB code is a short human-typeable string indexed into a server-private lookup
//!   table. The wire carries `lookup_table_ref` + `pepper_id` (both opaque). The plaintext code is
//!   delivered out-of-band; servers HMAC-pepper the claimant's input and look it up in the table.
//!   **3 wrong attempts invalidate the record** (terminal state `invalidated_by_rate_limit`).
//!
//! **Plaintext 3PID values (email addresses / phone numbers) MUST NEVER
//! appear on the wire.** This is enforced at the type level: the
//! [`ThirdPartyInviteRecord`] does not carry the plaintext value — only
//! commitment / lookup_table_ref + pepper_id. The plaintext is consumed
//! by the local mint code and then dropped.
//!
//! ## State machine
//!
//! Wire states (`ak.schema.invite.v1` §state enum):
//!
//! ```text
//!                ┌─────────┐
//!                │ pending │
//!                └─┬───────┘
//!                  │
//!     ┌────────────┼────────────┬──────────────┬──────────────────────┐
//!     ▼            ▼            ▼              ▼                      ▼
//! claimed     send_failed   revoked_by_      revoked_by_         invalidated_
//!                           capability_loss  inviter_left        by_rate_limit
//! ```
//!
//! All five non-`pending` states are terminal. On any terminal state,
//! the engine schedules a **zeroize-within-24h** task that drops the
//! stored salt (offline_token mode) or pepper (lookup mode) so the
//! invite can never be replayed — see [`schedule_terminal_zeroize`].
//!
//! ## Invite verifier
//!
//! [`verify_invite`] performs the two-step proof chain that gates an
//! incoming `ak.invite.claim`:
//!
//! 1. **Verification-service proof** — a signed JWT issued by the trusted 3PID verification
//!    service. Claims `iss` / `aud` / `sub` / `exp` / `nbf` / `nonce` are checked against
//!    [`VerifierCtx`]; signature is verified against the resolved DID's JWKS via
//!    [`did_binding_proof::verify_verification_service_proof`].
//! 2. **Subject proof** — a signed JWS by the inviter actor key over the canonical tuple
//!    `(verification_proof_jti, 3pid_hash, invitee_promise_did, expires_at)`. The signing key is
//!    resolved via the configured [`DidResolverService`]. The signed payload's `inviter_did` MUST
//!    equal `ctx.expected_presenter_did` to reject cross-presenter attacks.
//!
//! Replay defence: every accepted `jti` is recorded in
//! [`NonceStore`] (an in-memory `Mutex<HashMap>`) and kept until the
//! proof's `exp` passes. A duplicate `jti` within that window is
//! rejected with [`InviteVerificationError::VerificationProofInvalid`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arkret_core::{Did, ThirdPartyInvite, ThirdPartyInviteOobKind, ThirdPartyInviteTerminalState};
use chrono::{DateTime, Utc};
use coauth_config::ArkretConfig;
use coauth_data::{BoxRepository, UrlBuilder};
use coauth_jose::jwk::PublicJsonWebKeySet;
use coauth_jose::jwt::Jwt;
use coauth_keystore::Keystore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::handlers::arkret::VerificationMethod;
use crate::services::did_binding_proof::verify_verification_service_proof;
use crate::services::did_resolver::DidResolverService;

/// Minimum entropy (in bits) required for offline_token mode invites.
/// Mirrors `ak.schema.invite.v1` `third_party_invite.token_entropy_bits`
/// minimum.
pub const OFFLINE_TOKEN_MIN_ENTROPY_BITS: u32 = 128;

/// Maximum lookup-mode verification failures before the entry is moved to
/// [`ThirdPartyInviteTerminalState::InvalidatedByRateLimit`]. Mirrors
/// `services::oob_code::LOOKUP_STRIKE_LIMIT`.
pub const LOOKUP_RATE_LIMIT_FAILURES: u8 = 3;

/// Window after the terminal state in which the engine MUST scrub the
/// stored salt (offline_token mode) or pepper (lookup mode). Round 4
/// requirement.
pub const TERMINAL_ZEROIZE_WITHIN: Duration = Duration::from_hours(24);

/// Errors raised by the 3PID invite engine.
#[derive(Debug, Error)]
pub enum ThirdPartyInviteError {
    #[error("invite wire shape rejected: {0}")]
    InvalidWire(String),
    #[error("invite is in a terminal state ({0:?}) and cannot accept this transition")]
    AlreadyTerminal(ThirdPartyInviteTerminalState),
    #[error("invite token_entropy_bits {actual} < {min} (offline_token mode)")]
    InsufficientEntropy { actual: u32, min: u32 },
    #[error("invite rate limit exceeded ({attempts} failed attempts)")]
    RateLimitExceeded { attempts: u8 },
}

/// Internal (server-side) representation of an in-flight 3PID invite.
///
/// **Never serialise this struct to the wire — it MAY hold the
/// per-invite salt or pepper. Use [`ThirdPartyInvite`] (from the SDK)
/// for the wire shape; that struct only carries commitments and opaque
/// `*_id` references.**
#[derive(Debug, Clone)]
pub struct ThirdPartyInviteRecord {
    /// Wire form. The only thing that ever leaves coauth's address
    /// space.
    pub wire: ThirdPartyInvite,
    /// Server-private salt bytes (offline_token mode only). Stored
    /// indexed by [`ThirdPartyInvite::token_salt_id`]. MUST be zeroized
    /// on terminal transitions.
    pub server_private_salt: Option<Vec<u8>>,
    /// Server-private pepper bytes (lookup mode only). Stored indexed
    /// by [`ThirdPartyInvite::pepper_id`]. MUST be zeroized on terminal
    /// transitions.
    pub server_private_pepper: Option<Vec<u8>>,
    /// Wall-clock state-machine state.
    pub terminal_state: Option<ThirdPartyInviteTerminalState>,
    /// When the row entered the terminal state, used to schedule
    /// zeroize within 24h.
    pub terminal_at: Option<DateTime<Utc>>,
    /// Number of lookup-mode verification failures observed so far.
    /// Ignored for offline_token mode.
    pub lookup_failures: u8,
}

impl ThirdPartyInviteRecord {
    /// Build a record from the wire shape. Validates the
    /// offline_token / lookup field-population invariants and the
    /// `≥128 bit` entropy floor.
    pub fn from_wire(
        wire: ThirdPartyInvite,
        server_private_salt: Option<Vec<u8>>,
        server_private_pepper: Option<Vec<u8>>,
    ) -> Result<Self, ThirdPartyInviteError> {
        wire.validate_minimal()
            .map_err(|e| ThirdPartyInviteError::InvalidWire(e.to_string()))?;

        match wire.oob_code_kind {
            ThirdPartyInviteOobKind::OfflineToken => {
                let bits = wire.token_entropy_bits.unwrap_or(0);
                if bits < OFFLINE_TOKEN_MIN_ENTROPY_BITS {
                    return Err(ThirdPartyInviteError::InsufficientEntropy {
                        actual: bits,
                        min: OFFLINE_TOKEN_MIN_ENTROPY_BITS,
                    });
                }
                if server_private_pepper.is_some() {
                    return Err(ThirdPartyInviteError::InvalidWire(
                        "offline_token mode must not carry a pepper".into(),
                    ));
                }
            }
            ThirdPartyInviteOobKind::Lookup => {
                if server_private_salt.is_some() {
                    return Err(ThirdPartyInviteError::InvalidWire(
                        "lookup mode must not carry a salt".into(),
                    ));
                }
            }
        }

        Ok(Self {
            wire,
            server_private_salt,
            server_private_pepper,
            terminal_state: None,
            terminal_at: None,
            lookup_failures: 0,
        })
    }

    /// Returns `true` when the record is in any terminal state.
    pub fn is_terminal(&self) -> bool {
        self.terminal_state.is_some()
    }

    /// Drive a transition to a terminal state. Idempotent — re-applying
    /// the same terminal state is a no-op. Distinct terminal states
    /// MUST NOT chain; the second call returns
    /// [`ThirdPartyInviteError::AlreadyTerminal`].
    pub fn transition_terminal(
        &mut self,
        state: ThirdPartyInviteTerminalState,
        now: DateTime<Utc>,
    ) -> Result<(), ThirdPartyInviteError> {
        match self.terminal_state {
            None => {
                self.terminal_state = Some(state);
                self.terminal_at = Some(now);
                // Schedule the zeroize task. In the production handler
                // this is dispatched to `coauth-tasks`; here we just
                // mark the intent — the actual scrub happens via
                // [`Self::zeroize_secrets`] when the task fires.
                Ok(())
            }
            Some(existing) if existing == state => Ok(()),
            Some(existing) => Err(ThirdPartyInviteError::AlreadyTerminal(existing)),
        }
    }

    /// Record a wrong-attempt in lookup mode. Returns `true` when the
    /// strike limit has been reached and the caller MUST also drive
    /// `transition_terminal(InvalidatedByRateLimit, now)`.
    pub fn record_lookup_failure(&mut self) -> Result<bool, ThirdPartyInviteError> {
        if !matches!(self.wire.oob_code_kind, ThirdPartyInviteOobKind::Lookup) {
            return Err(ThirdPartyInviteError::InvalidWire(
                "record_lookup_failure called on non-lookup invite".into(),
            ));
        }
        self.lookup_failures = self.lookup_failures.saturating_add(1);
        Ok(self.lookup_failures >= LOOKUP_RATE_LIMIT_FAILURES)
    }

    /// Drop server-private salt / pepper bytes. MUST be called within
    /// `TERMINAL_ZEROIZE_WITHIN` of [`Self::transition_terminal`] when
    /// the engine moves the record off the hot path. Tests assert that
    /// the bytes are observably scrubbed.
    pub fn zeroize_secrets(&mut self) {
        if let Some(mut salt) = self.server_private_salt.take() {
            salt.zeroize();
        }
        if let Some(mut pepper) = self.server_private_pepper.take() {
            pepper.zeroize();
        }
    }

    /// Whether the engine MUST schedule a zeroize for this record at
    /// (or before) `terminal_at + TERMINAL_ZEROIZE_WITHIN`.
    pub fn zeroize_due_at(&self) -> Option<DateTime<Utc>> {
        self.terminal_at
            .map(|t| t + chrono::Duration::from_std(TERMINAL_ZEROIZE_WITHIN).expect("24h fits"))
    }
}

/// Helper: build a `token_commitment` for the offline_token mode wire
/// shape. The commitment is `sha256(token | salt)` rendered as
/// `sha256:<hex>` to match the `ak.schema.invite.v1` pattern.
#[must_use]
pub fn offline_token_commitment(token: &[u8], salt: &[u8]) -> String {
    let mut buf = Vec::with_capacity(token.len() + salt.len());
    buf.extend_from_slice(token);
    buf.extend_from_slice(salt);
    arkret_canonical::sha256_digest(buf)
}

/// Helper: schedule a zeroize task for a terminal record. Today this
/// returns the `due_at` instant — the call-site posts a `coauth-tasks`
/// job that runs `zeroize_secrets` at or before `due_at`.
///
/// Note: the wiring to the production `coauth-tasks` queue is not yet
/// in place; today this only computes the deadline and call-sites are
/// expected to schedule their own job. The terminal_at + 24h policy is
/// documented in `oob_code.rs`.
pub fn schedule_terminal_zeroize(rec: &ThirdPartyInviteRecord) -> Option<DateTime<Utc>> {
    rec.zeroize_due_at()
}

// ───────────────────────────── Invite verifier ─────────────────────────────

/// Subject-proof JWT claims. Issued by the inviter (NOT the verification
/// service) to bind their DID to a specific 3PID + verification proof.
///
/// The canonical signed message is `(verification_proof_jti, 3pid_hash,
/// invitee_promise_did, expires_at)`, packed into a JWT payload and
/// signed with the inviter's actor key via the resolver-returned
/// verification method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectProofClaims {
    /// Discriminator. MUST equal `ak.invite.subject_proof.v1`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Inviter actor DID — the entity claiming to present this invite.
    /// Verified against [`VerifierCtx::expected_presenter_did`].
    pub inviter_did: String,
    /// `jti` of the verification-service proof this subject proof
    /// references. Ties the two halves of the chain together.
    pub verification_proof_jti: String,
    /// SHA-256 (hex) of the normalized 3PID, identical to the
    /// `sub` claim in the verification-service proof.
    #[serde(rename = "3pid_hash")]
    pub three_pid_hash: String,
    /// DID the invitee promises to claim under. The wire `subject_id`
    /// of the invite-claim event MUST match this value.
    pub invitee_promise_did: String,
    /// Unix-epoch (seconds) expiry. Past this point the proof MUST be
    /// rejected with `proof_expired`.
    pub expires_at: i64,
}

/// Constant for the subject-proof type discriminator. Kept as a
/// `const` so callers can re-use it without typos.
pub const SUBJECT_PROOF_KIND: &str = "ak.invite.subject_proof.v1";

/// Inputs to [`verify_invite`].
///
/// Two JWS strings:
/// - `binding_proof_jws`: the verification-service proof (signed by the 3PID verification service).
/// - `subject_proof_jws`: the inviter's binding signature (signed by the inviter actor key).
#[derive(Debug, Clone)]
pub struct InviteRequest {
    /// Verification-service proof JWS (compact serialization).
    pub binding_proof_jws: String,
    /// Subject proof JWS (compact serialization) from the inviter.
    pub subject_proof_jws: String,
    /// The DID currently presenting this invite (typically extracted
    /// from the request bearer / DPoP signer). MUST match the inviter
    /// DID embedded in the subject proof; mismatch is
    /// `subject_id_mismatch`.
    pub presenter_did: String,
}

/// Context passed to [`verify_invite`]. Carries the dependencies the
/// pure verifier needs to perform key resolution + signature checks +
/// nonce-store updates.
pub struct VerifierCtx<'a> {
    /// SEC-07a — explicit allowlist of trusted verification-service DIDs
    /// (`spec/v1/zh/sync/third-party-invites.md` §2.1 Allowlist MUST). The
    /// `iss` of the verification-service proof MUST be a member of this set;
    /// any other issuer is rejected *before* the subject proof is examined,
    /// so a valid `subject_proof` can never admit an off-allowlist verifier
    /// (§4.3 step 2a).
    pub expected_verification_service_ids: &'a [String],
    /// Expected `aud` of the verification-service proof — the local
    /// coauth service DID.
    pub expected_audience: &'a str,
    /// Wall-clock "now" used for `exp` / `nbf` evaluation. Injected so
    /// tests can pin a deterministic value.
    pub now: DateTime<Utc>,
    /// Replay store. Records every accepted `jti` until its `exp`
    /// passes; duplicate `jti` within that window is rejected.
    pub nonce_store: &'a NonceStore,
    /// DID resolver used to look up the inviter's actor key.
    pub did_resolver: &'a dyn DidResolverService,
    /// Shared services the resolver needs.
    pub http_client: &'a reqwest::Client,
    pub url_builder: &'a UrlBuilder,
    pub arkret_config: &'a ArkretConfig,
    pub key_store: &'a Keystore,
    pub repo: &'a mut BoxRepository,
}

/// Successful verification output. Returned to the caller (typically an
/// invite-acceptance handler) so it can map onto the downstream
/// `ak.invite.create` / accept Move.
#[derive(Debug, Clone)]
pub struct VerifiedInvite {
    /// SHA-256 hex of the normalized 3PID, as carried in both proofs.
    pub three_pid_hash: String,
    /// Inviter DID asserted by the subject proof — already verified
    /// to match `ctx.expected_presenter_did`.
    pub inviter_did: String,
    /// DID the invitee promised to claim under.
    pub invitee_promise_did: String,
    /// `jti` of the verification-service proof. The caller MAY persist
    /// this for downstream audit linkage.
    pub verification_proof_jti: String,
    /// Earliest of the two proofs' `exp` claims — used by the caller
    /// to schedule downstream timeouts.
    pub effective_expires_at: DateTime<Utc>,
}

/// Discrete error variants returned by [`verify_invite`]. Each variant
/// maps onto a specific HTTP status code at the handler layer (see
/// [`InviteVerificationError::http_status`]).
#[derive(Debug, Error)]
pub enum InviteVerificationError {
    /// Verification-service proof failed validation: malformed JWT,
    /// signature mismatch, wrong `iss` / `aud` / `sub`, missing
    /// claims, or replayed `jti`. Maps to HTTP `401 Unauthorized`.
    #[error("verification_proof_invalid: {0}")]
    VerificationProofInvalid(String),

    /// Subject proof failed validation: malformed JWS, signature
    /// mismatch against the resolved inviter key, wrong kind, or
    /// canonical-message mismatch with the verification-service
    /// proof. Maps to HTTP `401 Unauthorized`.
    #[error("subject_proof_invalid: {0}")]
    SubjectProofInvalid(String),

    /// Either proof's `exp` is in the past. Maps to HTTP `410 Gone`.
    #[error("proof_expired: {0}")]
    ProofExpired(String),

    /// `inviter_did` in the subject proof doesn't match the actor
    /// presenting the invite (e.g. token theft + replay by a third
    /// party). Maps to HTTP `403 Forbidden`.
    #[error("subject_id_mismatch: presenter={presenter} subject={subject}")]
    SubjectIdMismatch { presenter: String, subject: String },
}

impl InviteVerificationError {
    /// Variant → wire error code (stable, machine-readable). Handlers
    /// use this as the `error` field in the JSON 4xx body.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::VerificationProofInvalid(_) => "verification_proof_invalid",
            Self::SubjectProofInvalid(_) => "subject_proof_invalid",
            Self::ProofExpired(_) => "proof_expired",
            Self::SubjectIdMismatch { .. } => "subject_id_mismatch",
        }
    }

    /// Variant → recommended HTTP status code for the rejection.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::VerificationProofInvalid(_) | Self::SubjectProofInvalid(_) => 401,
            Self::ProofExpired(_) => 410,
            Self::SubjectIdMismatch { .. } => 403,
        }
    }
}

/// In-memory nonce / jti replay store.
///
/// Stores `jti -> exp` until the wall-clock time passes `exp`, at
/// which point the entry is pruned (on the next insert). Replay
/// rejection is for the lifetime of the entry: if a `jti` has already
/// been accepted and its `exp` is still in the future, a second
/// `verify_invite` call with the same `jti` fails with
/// [`InviteVerificationError::VerificationProofInvalid`].
///
/// **Single-replica acceptable for now.** A multi-replica coauth
/// deployment would need to back this with the shared DB (a small
/// `invite_proof_seen_jti` table with `(jti, expires_at)` and a
/// partial unique index on `jti`). The current setup is intentional —
/// the cross-replica coordination cost outweighs the marginal benefit
/// while the deployment topology is still single-process.
#[derive(Debug, Default, Clone)]
pub struct NonceStore {
    inner: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceReplayError;

impl NonceStore {
    /// Build an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `jti` with its `exp`, returning `Err` if `jti` is already
    /// recorded and its `exp` has not yet passed.
    ///
    /// Shared single-use primitive — also used by the DID-binding
    /// control-proof verifier (`did_binding_proof::validate_control_proof`)
    /// to consume the proof nonce after a successful verify.
    pub fn check_and_record(
        &self,
        jti: &str,
        exp: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), NonceReplayError> {
        let mut guard = self.inner.lock().expect("nonce store mutex poisoned");
        // Prune expired entries opportunistically.
        guard.retain(|_, e| *e > now);
        if let Some(existing_exp) = guard.get(jti)
            && *existing_exp > now
        {
            return Err(NonceReplayError);
        }
        guard.insert(jti.to_owned(), exp);
        Ok(())
    }

    /// Test helper: number of live (non-pruned) entries.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

/// Verify a 3PID invite-claim request.
///
/// Performs (in order):
///
/// 1. **Verification-service proof** — parse JWT, verify signature via resolved JWKS, check `iss` /
///    `aud` / `sub` / `exp` / `nbf`, reject replayed `jti`.
/// 2. **Subject proof** — parse JWT, verify signature via the inviter's DID-document JWKS, check
///    kind / `inviter_did` / cross-link to the verification proof.
/// 3. **Cross-checks** — `inviter_did` MUST equal `req.presenter_did`; both proofs MUST share the
///    same `three_pid_hash`; expiries MUST be in the future.
///
/// On success returns a [`VerifiedInvite`] and persists the
/// verification proof's `jti` to the replay store.
pub async fn verify_invite(
    req: &InviteRequest,
    ctx: &mut VerifierCtx<'_>,
) -> Result<VerifiedInvite, InviteVerificationError> {
    // Step 1: verification-service proof.
    let verification = verify_verification_service_proof(
        ctx.http_client,
        ctx.url_builder,
        ctx.arkret_config,
        ctx.key_store,
        ctx.repo,
        ctx.did_resolver,
        &req.binding_proof_jws,
        ctx.expected_verification_service_ids,
        ctx.expected_audience,
        ctx.now,
    )
    .await
    .map_err(map_verification_service_error)?;

    let verification_exp =
        DateTime::<Utc>::from_timestamp(verification.exp, 0).ok_or_else(|| {
            InviteVerificationError::VerificationProofInvalid("exp claim out of range".into())
        })?;
    if verification_exp <= ctx.now {
        return Err(InviteVerificationError::ProofExpired(format!(
            "verification proof exp {} <= now {}",
            verification_exp, ctx.now
        )));
    }

    // Replay check + record. Must happen *after* we know the proof is
    // otherwise valid; recording an unverified jti would let an
    // attacker poison the store with garbage entries.
    ctx.nonce_store
        .check_and_record(&verification.jti, verification_exp, ctx.now)
        .map_err(|_| {
            InviteVerificationError::VerificationProofInvalid(format!(
                "jti {} already used",
                verification.jti
            ))
        })?;

    // Step 2: subject proof.
    let subject_claims = verify_subject_proof(
        ctx.http_client,
        ctx.url_builder,
        ctx.arkret_config,
        ctx.key_store,
        ctx.repo,
        ctx.did_resolver,
        &req.subject_proof_jws,
    )
    .await?;

    // Step 3: cross-checks.
    if subject_claims.inviter_did != req.presenter_did {
        return Err(InviteVerificationError::SubjectIdMismatch {
            presenter: req.presenter_did.clone(),
            subject: subject_claims.inviter_did.clone(),
        });
    }
    if subject_claims.verification_proof_jti != verification.jti {
        return Err(InviteVerificationError::SubjectProofInvalid(
            "verification_proof_jti mismatch with binding proof jti".into(),
        ));
    }
    if subject_claims.three_pid_hash != verification.sub {
        return Err(InviteVerificationError::SubjectProofInvalid(
            "3pid_hash in subject proof does not match verification proof sub".into(),
        ));
    }
    let subject_exp =
        DateTime::<Utc>::from_timestamp(subject_claims.expires_at, 0).ok_or_else(|| {
            InviteVerificationError::SubjectProofInvalid("expires_at out of range".into())
        })?;
    if subject_exp <= ctx.now {
        return Err(InviteVerificationError::ProofExpired(format!(
            "subject proof expires_at {} <= now {}",
            subject_exp, ctx.now
        )));
    }

    let effective_expires_at = std::cmp::min(verification_exp, subject_exp);

    Ok(VerifiedInvite {
        three_pid_hash: verification.sub,
        inviter_did: subject_claims.inviter_did,
        invitee_promise_did: subject_claims.invitee_promise_did,
        verification_proof_jti: verification.jti,
        effective_expires_at,
    })
}

/// Parse + signature-verify the subject proof against the inviter's
/// resolved DID document.
async fn verify_subject_proof(
    http_client: &reqwest::Client,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    repo: &mut BoxRepository,
    did_resolver: &dyn DidResolverService,
    subject_proof_jws: &str,
) -> Result<SubjectProofClaims, InviteVerificationError> {
    if subject_proof_jws.trim().is_empty() {
        return Err(InviteVerificationError::SubjectProofInvalid(
            "empty JWS".into(),
        ));
    }
    let jwt: Jwt<'_, SubjectProofClaims> = Jwt::try_from(subject_proof_jws).map_err(|e| {
        InviteVerificationError::SubjectProofInvalid(format!("could not parse JWS: {e}"))
    })?;
    let claims = jwt.payload();
    if claims.kind != SUBJECT_PROOF_KIND {
        return Err(InviteVerificationError::SubjectProofInvalid(format!(
            "kind discriminator mismatch: expected {SUBJECT_PROOF_KIND}, got {}",
            claims.kind
        )));
    }
    // Reject DIDs that don't pass the SDK's round-4 regex before any
    // network I/O — matches did_binding_proof.rs.
    if Did::new(claims.inviter_did.clone()).is_err() {
        return Err(InviteVerificationError::SubjectProofInvalid(format!(
            "inviter_did {:?} fails round-4 DID regex",
            claims.inviter_did
        )));
    }

    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            arkret_config,
            key_store,
            repo,
            &claims.inviter_did,
        )
        .await
        .map_err(|e| {
            InviteVerificationError::SubjectProofInvalid(format!(
                "could not resolve inviter DID: {e}"
            ))
        })?;
    ensure_subject_proof_identity_fact(&resolution)?;

    let keys: Vec<_> = resolution
        .document
        .verification_method
        .iter()
        .map(VerificationMethod::public_jwk)
        .collect::<Result<_, _>>()
        .map_err(|error| {
            InviteVerificationError::SubjectProofInvalid(format!(
                "inviter DID document verificationMethod is invalid: {error}"
            ))
        })?;
    if keys.is_empty() {
        return Err(InviteVerificationError::SubjectProofInvalid(
            "inviter DID document has no verificationMethod entries".into(),
        ));
    }
    let jwks = PublicJsonWebKeySet::new(keys);
    if jwt.verify_with_jwks(&jwks).is_err() {
        return Err(InviteVerificationError::SubjectProofInvalid(
            "JWS signature did not verify against any inviter DID key".into(),
        ));
    }

    Ok(claims.clone())
}

fn ensure_subject_proof_identity_fact(
    resolution: &crate::services::did_resolver::DidResolution,
) -> Result<(), InviteVerificationError> {
    if let Some(rejection) = resolution.identity_fact_rejection() {
        return Err(InviteVerificationError::SubjectProofInvalid(format!(
            "did_resolver_not_full_identity_fact: {}",
            rejection.as_str()
        )));
    }
    Ok(())
}

/// Map a verification-service-proof error onto the public
/// [`InviteVerificationError`] enum. `proof_expired` is split out so
/// the handler can return `410 Gone` instead of `401`.
fn map_verification_service_error(
    err: crate::services::did_binding_proof::VerificationProofError,
) -> InviteVerificationError {
    use crate::services::did_binding_proof::VerificationProofError as E;
    match err {
        E::Expired(msg) => InviteVerificationError::ProofExpired(msg),
        E::ResolverNotFullIdentityFact(rejection) => {
            InviteVerificationError::VerificationProofInvalid(format!(
                "did_resolver_not_full_identity_fact: {}",
                rejection.as_str()
            ))
        }
        other => InviteVerificationError::VerificationProofInvalid(other.to_string()),
    }
}

/// Compute the SHA-256 hex hash of a normalized 3PID value. The
/// normalization step is conservative (lowercase + trim) — callers
/// that need a stricter normalization should pre-process before
/// hashing.
#[must_use]
pub fn three_pid_hash(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    let mut h = Sha256::new();
    h.update(normalized.as_bytes());
    hex::encode(h.finalize())
}

// Re-export the verification-service proof claims for callers
// (invite-acceptance handlers may want to inspect the `nonce` claim
// before persisting audit metadata).
#[doc(hidden)]
pub use crate::services::did_binding_proof::VerificationProofError;
pub use crate::services::did_binding_proof::VerificationServiceProofClaims as VerificationProofClaims;

#[cfg(test)]
mod tests {
    use arkret_core::Hash;

    use super::*;

    fn build_wire_offline() -> ThirdPartyInvite {
        ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::OfflineToken,
            token_commitment: Some(Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap()),
            token_salt_id: Some("salt-1".to_owned()),
            token_entropy_bits: Some(128),
            lookup_table_ref: None,
            pepper_id: None,
            max_claims: 1,
            verification_service_id: Did::new("did:web:auth.example").unwrap(),
            verification_public_key: "z6MkAuthKey".to_owned(),
        }
    }

    fn build_wire_lookup() -> ThirdPartyInvite {
        ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::Lookup,
            token_commitment: None,
            token_salt_id: None,
            token_entropy_bits: None,
            lookup_table_ref: Some("lkup-1".to_owned()),
            pepper_id: Some("pepper-1".to_owned()),
            max_claims: 1,
            verification_service_id: Did::new("did:web:auth.example").unwrap(),
            verification_public_key: "z6MkAuthKey".to_owned(),
        }
    }

    #[test]
    fn from_wire_accepts_well_formed_offline_invite() {
        let wire = build_wire_offline();
        let rec = ThirdPartyInviteRecord::from_wire(wire, Some(b"salt".to_vec()), None).unwrap();
        assert_eq!(
            rec.wire.oob_code_kind,
            ThirdPartyInviteOobKind::OfflineToken
        );
        assert!(rec.server_private_salt.is_some());
        assert!(rec.server_private_pepper.is_none());
        assert!(!rec.is_terminal());
    }

    #[test]
    fn from_wire_rejects_low_entropy_offline_invite() {
        let mut wire = build_wire_offline();
        wire.token_entropy_bits = Some(64);
        let err = ThirdPartyInviteRecord::from_wire(wire, Some(b"salt".to_vec()), None);
        // The SDK's `validate_minimal()` rejects entropy<128 first, so
        // we accept either path (the engine surfaces the SDK's
        // protocol error or our explicit `InsufficientEntropy`).
        assert!(err.is_err());
    }

    #[test]
    fn from_wire_rejects_mode_field_mixup() {
        let mut wire = build_wire_offline();
        wire.lookup_table_ref = Some("oops".to_owned());
        let err = ThirdPartyInviteRecord::from_wire(wire, Some(b"salt".to_vec()), None);
        assert!(err.is_err());
    }

    #[test]
    fn from_wire_accepts_well_formed_lookup_invite() {
        let wire = build_wire_lookup();
        let rec = ThirdPartyInviteRecord::from_wire(wire, None, Some(b"pep".to_vec())).unwrap();
        assert_eq!(rec.wire.oob_code_kind, ThirdPartyInviteOobKind::Lookup);
        assert!(rec.server_private_pepper.is_some());
    }

    #[test]
    fn transition_terminal_is_idempotent_for_same_state() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_offline(), Some(b"salt".to_vec()), None)
                .unwrap();
        let now = Utc::now();
        rec.transition_terminal(ThirdPartyInviteTerminalState::Claimed, now)
            .unwrap();
        // Same state again — no error.
        rec.transition_terminal(ThirdPartyInviteTerminalState::Claimed, now)
            .unwrap();
        assert_eq!(
            rec.terminal_state,
            Some(ThirdPartyInviteTerminalState::Claimed)
        );
    }

    #[test]
    fn transition_terminal_rejects_distinct_second_terminal() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_offline(), Some(b"salt".to_vec()), None)
                .unwrap();
        let now = Utc::now();
        rec.transition_terminal(ThirdPartyInviteTerminalState::Claimed, now)
            .unwrap();
        let err = rec
            .transition_terminal(ThirdPartyInviteTerminalState::RevokedByInviterLeft, now)
            .unwrap_err();
        assert!(matches!(err, ThirdPartyInviteError::AlreadyTerminal(_)));
    }

    #[test]
    fn record_lookup_failure_triggers_at_three_strikes() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_lookup(), None, Some(b"pep".to_vec()))
                .unwrap();
        assert!(!rec.record_lookup_failure().unwrap());
        assert!(!rec.record_lookup_failure().unwrap());
        assert!(rec.record_lookup_failure().unwrap()); // third strike → true
    }

    #[test]
    fn record_lookup_failure_rejects_on_offline_invite() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_offline(), Some(b"salt".to_vec()), None)
                .unwrap();
        let err = rec.record_lookup_failure().unwrap_err();
        assert!(matches!(err, ThirdPartyInviteError::InvalidWire(_)));
    }

    #[test]
    fn zeroize_secrets_scrubs_salt_and_pepper() {
        let mut rec = ThirdPartyInviteRecord::from_wire(
            build_wire_offline(),
            Some(b"hot_salt".to_vec()),
            None,
        )
        .unwrap();
        assert!(rec.server_private_salt.is_some());
        rec.zeroize_secrets();
        assert!(rec.server_private_salt.is_none());
    }

    #[test]
    fn zeroize_due_at_is_24h_from_terminal() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_offline(), Some(b"salt".to_vec()), None)
                .unwrap();
        let now = Utc::now();
        rec.transition_terminal(ThirdPartyInviteTerminalState::Claimed, now)
            .unwrap();
        let due = rec.zeroize_due_at().unwrap();
        let delta = (due - now).num_hours();
        assert_eq!(delta, 24, "zeroize MUST be due exactly 24h after terminal");
    }

    #[test]
    fn offline_token_commitment_matches_canonical_form() {
        let c = offline_token_commitment(b"correct horse battery staple", b"some-salt");
        assert!(c.starts_with("sha256:"));
        assert_eq!(c.len(), "sha256:".len() + 64);
        // Hex digits only.
        assert!(c["sha256:".len()..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn five_terminal_states_are_all_reachable() {
        let now = Utc::now();
        for state in [
            ThirdPartyInviteTerminalState::Claimed,
            ThirdPartyInviteTerminalState::SendFailed,
            ThirdPartyInviteTerminalState::RevokedByCapabilityLoss,
            ThirdPartyInviteTerminalState::RevokedByInviterLeft,
            ThirdPartyInviteTerminalState::InvalidatedByRateLimit,
        ] {
            let mut rec = ThirdPartyInviteRecord::from_wire(
                build_wire_offline(),
                Some(b"salt".to_vec()),
                None,
            )
            .unwrap();
            rec.transition_terminal(state, now).unwrap();
            assert_eq!(rec.terminal_state, Some(state));
        }
    }

    // ─────────── verifier tests (pure parts) ───────────

    #[test]
    fn three_pid_hash_normalizes_input() {
        let a = three_pid_hash("Bob@Example.COM ");
        let b = three_pid_hash("bob@example.com");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // SHA-256 hex
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn nonce_store_rejects_duplicate_jti_before_expiry() {
        let store = NonceStore::new();
        let now = Utc::now();
        let exp = now + chrono::Duration::minutes(10);
        store.check_and_record("jti-1", exp, now).unwrap();
        assert_eq!(store.len(), 1);
        let again = store.check_and_record("jti-1", exp, now);
        assert!(again.is_err(), "duplicate jti must reject");
    }

    #[test]
    fn nonce_store_allows_jti_reuse_after_expiry() {
        let store = NonceStore::new();
        let now = Utc::now();
        let exp = now + chrono::Duration::seconds(1);
        store.check_and_record("jti-1", exp, now).unwrap();
        // Simulate time passing past exp.
        let later = exp + chrono::Duration::seconds(1);
        let new_exp = later + chrono::Duration::minutes(10);
        store
            .check_and_record("jti-1", new_exp, later)
            .expect("post-expiry re-use must succeed (entry is pruned)");
    }

    #[test]
    fn invite_verification_error_code_and_status_map_correctly() {
        let cases = [
            (
                InviteVerificationError::VerificationProofInvalid("x".into()),
                "verification_proof_invalid",
                401u16,
            ),
            (
                InviteVerificationError::SubjectProofInvalid("x".into()),
                "subject_proof_invalid",
                401,
            ),
            (
                InviteVerificationError::ProofExpired("x".into()),
                "proof_expired",
                410,
            ),
            (
                InviteVerificationError::SubjectIdMismatch {
                    presenter: "did:web:a".into(),
                    subject: "did:web:b".into(),
                },
                "subject_id_mismatch",
                403,
            ),
        ];
        for (err, code, status) in cases {
            assert_eq!(err.code(), code);
            assert_eq!(err.http_status(), status);
        }
    }

    #[test]
    fn subject_proof_kind_constant_is_stable() {
        // Tripwire: any rename of the kind discriminator is a wire break.
        assert_eq!(SUBJECT_PROOF_KIND, "ak.invite.subject_proof.v1");
    }

    #[test]
    fn degraded_resolution_cannot_back_invite_capability_proofs() {
        let resolution = crate::services::did_resolver::DidResolution {
            document: crate::handlers::arkret::DidDocument {
                id: "did:webvh:ztest:resolver.example:users:alice".to_owned(),
                also_known_as: Vec::new(),
                verification_method: Vec::new(),
                authentication: Vec::new(),
                assertion_method: Vec::new(),
                capability_delegation: Vec::new(),
                service: Vec::new(),
                metadata: None,
            },
            source: crate::services::did_resolver::DidResolutionSource::DelegatedResolver,
            verified_local_binding: false,
            key_log_head: None,
            method_evidence: serde_json::json!({"resolver_state": "webvh_cache_only_degraded"}),
            identity_fact_rejection: Some(
                crate::services::did_resolver::DidResolutionIdentityFactRejection::CacheOnlyDegraded,
            ),
        };

        let subject_err = ensure_subject_proof_identity_fact(&resolution)
            .expect_err("degraded resolver must not back subject proof success");
        assert!(matches!(
            subject_err,
            InviteVerificationError::SubjectProofInvalid(ref msg)
                if msg.contains("cache_only_degraded")
        ));

        let verification_err = map_verification_service_error(
            crate::services::did_binding_proof::VerificationProofError::ResolverNotFullIdentityFact(
                crate::services::did_resolver::DidResolutionIdentityFactRejection::CacheOnlyDegraded,
            ),
        );
        assert!(matches!(
            verification_err,
            InviteVerificationError::VerificationProofInvalid(ref msg)
                if msg.contains("cache_only_degraded")
        ));
    }
}

// Inline reference: spec doc anchors for reviewers.
//   `arkret-spec/spec/v1/artifacts/schemas/invite.schema.json`
// $defs.third_party_invite   `arkret-spec/spec/v1/zh/identity/
// 3pid-invite-engine.md` (round-4 SP3.4)   `arkret-spec/spec/v1/zh/sync/
// third-party-invites.md` §3-§4 (binding /     subject proof chain — invite
// verifier)
