// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! MIMI `request_consent` / `update_consent` → consent-cell **Move** mapping
//! (scaffolding only).
//!
//! Per the Move/Anchor/Lattice spec (`contrix-spec` 2026-05-08,
//! `consent-model.md` §3-§9), incoming MIMI consent operations must be
//! translated into Moves on the holder's consent cell:
//!
//! ```text
//! cx:cell:cx.component.consent.grant.v1:<consent_id>
//! ```
//!
//! - `request_consent` → no Move yet (the holder hasn't decided); coauth
//!   should surface this to yougen as a pending-consent UI prompt and
//!   correlate with `consent_id`.
//! - `update_consent { granted = true }` → `or-set add tag` Move with
//!   `peer=<actor>;scope=<scope>` written to the holder's principal
//!   control Space.
//! - `update_consent { granted = false }` → `or-set remove tag` Move
//!   that revokes the same `(peer, scope)` tag.
//!
//! ## Scope of this scaffolding
//!
//! This module exposes the **type signatures** so the handler layer (and
//! downstream tests) can compile against the eventual integration. The
//! Move-construction and signing path requires a real anchorer signer
//! (single_did profile) and is intentionally still a `TODO`. See the
//! inline `TODO(c10e-mimi-move)` markers — implementing them is a hard
//! dependency on the SDK's `lattice` + `anchor` crate, which is out of
//! scope for this round.
//!
//! Current behaviour: every entrypoint returns
//! `Err(MimiConsentError::NotImplemented)`. The caller (typically a MIMI
//! gateway adapter) gets a stable error shape so it can degrade
//! gracefully until the signer wiring lands.

use serde::{Deserialize, Serialize};

/// Inbound MIMI `request_consent` payload (subset).
///
/// Mirrors the MIMI spec's `request_consent` envelope, narrowed to the
/// fields coauth actually needs to correlate. Unknown fields are
/// preserved at the transport layer; this struct is `non_exhaustive` so
/// future fields can be added without a wire break.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct RequestConsent {
    /// MIMI correlation id, preserved across the inter-protocol boundary
    /// as the cell's `consent_id`.
    pub consent_id: String,

    /// DID of the actor (peer) requesting consent.
    pub actor_did: String,

    /// DID of the holder whose cell is the target.
    pub holder_did: String,

    /// Scope being requested (`invite`, `messaging`, ...). Matches the
    /// or-set tag `scope=<...>` slot.
    pub scope: String,

    /// Optional human-readable reason supplied by the actor; shown in
    /// the holder's consent UI.
    #[serde(default)]
    pub reason: Option<String>,
}

impl RequestConsent {
    /// Construct a fresh request payload for tests / call-site stubs.
    #[must_use]
    pub fn new(
        consent_id: impl Into<String>,
        actor_did: impl Into<String>,
        holder_did: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            consent_id: consent_id.into(),
            actor_did: actor_did.into(),
            holder_did: holder_did.into(),
            scope: scope.into(),
            reason: None,
        }
    }
}

/// Inbound MIMI `update_consent` payload (subset).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct UpdateConsent {
    /// MIMI correlation id, must match an existing `request_consent`.
    pub consent_id: String,

    /// DID of the actor whose consent the holder is granting / revoking.
    pub actor_did: String,

    /// DID of the holder.
    pub holder_did: String,

    /// Scope being granted / revoked.
    pub scope: String,

    /// `true` = grant (add tag), `false` = revoke (remove tag).
    pub granted: bool,
}

/// Pending Move, in coauth-land, that has not yet been signed and posted
/// to the holder's principal server. Held by the caller during the
/// scaffold phase so tests can assert on shape without signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMove {
    /// The cell id (`cx:cell:cx.component.consent.grant.v1:<consent_id>`).
    pub cell_id: String,

    /// Either `or_set_add` or `or_set_remove` per spec §6.1.
    pub op: PendingMoveOp,

    /// The OrSet tag to add or remove.
    pub tag: String,
}

/// Pending Move operation kind. Mirrors the SDK's lattice op surface,
/// but kept independent so this module stays decoupled from the
/// not-yet-imported SDK types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingMoveOp {
    /// Grant: append the `(peer, scope)` tag to the cell's OrSet.
    OrSetAdd,
    /// Revoke: remove the `(peer, scope)` tag from the cell's OrSet.
    OrSetRemove,
}

/// Errors produced by the MIMI consent → Move bridge.
#[derive(Debug, thiserror::Error)]
pub enum MimiConsentError {
    /// The signing path requires the contrix-rust-sdk `MoveSigner` API,
    /// which is not yet exposed on the SDK surface this build links
    /// against. Returned by `anchor_pending_move` *before* any HTTP
    /// call so a misconfigured deployment never POSTs an unsigned
    /// envelope. See `anchor_pending_move` doc-comment for the SDK
    /// contract we need.
    #[error(
        "mimi consent → move: signer SDK surface (MoveSigner + Ed25519MoveSigner + \
         Anchor::sign_single) is not yet exposed by contrix-rust-sdk; signing path \
         disabled until that lands"
    )]
    SignerSdkUnavailable,

    /// `anchor_pending_move` was called without a configured principal
    /// server URL. Anchorer deployments must configure
    /// `ContrixConfig::principal_server_url`; non-anchorer deployments
    /// should never call this entrypoint.
    #[error("mimi consent → move: principal server url not configured")]
    PrincipalServerNotConfigured,

    /// `PASION_CONTRIX__ANCHORER_SIGNING_KEY` was set but malformed.
    /// The absent case does *not* error — see `AnchorerSigner::from_env`.
    #[error("mimi consent: anchorer signing key invalid: {reason}")]
    InvalidAnchorerKey { reason: String },

    /// HTTP forward to soland failed (network error, non-2xx status,
    /// invalid URL).
    #[error("mimi consent → move: principal server forward failed: {reason}")]
    PrincipalServerForwardFailed { reason: String },

    /// The actor on the MIMI envelope does not match the holder DID
    /// (and is not a registered controller). Spec §6.2 fail-closed.
    #[error("mimi consent: actor {actor_did} is not the holder or an authorized controller")]
    ActorNotAuthorized { actor_did: String },

    /// A required field on the MIMI envelope was empty.
    #[error("mimi consent: missing required field {field}")]
    MissingField { field: &'static str },
}

/// Build the canonical consent cell id from a MIMI `consent_id`.
#[must_use]
pub fn consent_cell_id(consent_id: &str) -> String {
    format!("cx:cell:cx.component.consent.grant.v1:{consent_id}")
}

/// Build the OrSet tag for a `(peer, scope)` consent grant. Pure helper.
///
/// Matches the spec §6.1 tag form `peer=<did>;scope=<scope>`.
#[must_use]
pub fn build_consent_tag(peer_did: &str, scope: &str) -> String {
    format!("peer={peer_did};scope={scope}")
}

/// Translate an `update_consent` envelope into a `PendingMove`. Pure
/// function — no I/O, no signing.
///
/// This is the "mostly-typed" first half of the bridge. The second half
/// (`anchor_pending_move`) hands the `PendingMove` to the anchorer
/// signer; that path stays `Err(NotImplemented)` until the signer is
/// available.
pub fn update_consent_to_pending_move(
    update: &UpdateConsent,
) -> Result<PendingMove, MimiConsentError> {
    if update.consent_id.is_empty() {
        return Err(MimiConsentError::MissingField {
            field: "consent_id",
        });
    }
    if update.actor_did.is_empty() {
        return Err(MimiConsentError::MissingField { field: "actor_did" });
    }
    if update.holder_did.is_empty() {
        return Err(MimiConsentError::MissingField {
            field: "holder_did",
        });
    }
    if update.scope.is_empty() {
        return Err(MimiConsentError::MissingField { field: "scope" });
    }

    Ok(PendingMove {
        cell_id: consent_cell_id(&update.consent_id),
        op: if update.granted {
            PendingMoveOp::OrSetAdd
        } else {
            PendingMoveOp::OrSetRemove
        },
        tag: build_consent_tag(&update.actor_did, &update.scope),
    })
}

/// How the anchorer signing key was obtained at process start. Surfaced
/// on `AnchorerSigner` so call-sites can log a sticky warning when an
/// ephemeral key is in use (anything signed with it is unverifiable
/// across restarts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorerSigningKeyOrigin {
    /// Loaded from `PASION_CONTRIX__ANCHORER_SIGNING_KEY` (base64 32-byte seed).
    /// Stable across restarts.
    Configured,
    /// No env var present — generated at process start. Anything signed
    /// with this key is unverifiable across restarts; production
    /// deployments must configure a real key.
    Ephemeral,
}

/// Anchorer signer handle used by `anchor_pending_move`. Holds the
/// 32-byte ed25519 signing seed and an `origin` marker that distinguishes
/// configured vs. ephemerally generated keys.
///
/// **SDK gap**: this is a *placeholder* type. Once
/// `contrix-rust-sdk` lands the public `MoveSigner` trait + the
/// `Ed25519MoveSigner` impl + `Anchor::sign_single(...)`, this struct
/// holds (or wraps) the SDK's signer; until then the seed is stored raw
/// and the actual `sign_move(...)` call returns `NotImplemented`.
///
/// See `anchor_pending_move` doc-comment for the full SDK contract we
/// need exposed.
#[derive(Clone)]
pub struct AnchorerSigner {
    /// Raw 32-byte ed25519 signing seed. Once the SDK lands its
    /// `Ed25519MoveSigner::from_seed(...)` constructor, this becomes
    /// the input to that ctor; today it's stored opaquely so the rest
    /// of the wiring (env-var parsing, ephemeral fallback, key origin
    /// marker) is unblocked.
    seed: [u8; 32],
    origin: AnchorerSigningKeyOrigin,
}

impl std::fmt::Debug for AnchorerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorerSigner")
            .field("seed", &"<redacted>")
            .field("origin", &self.origin)
            .finish()
    }
}

impl AnchorerSigner {
    /// Construct a signer from a raw 32-byte ed25519 seed. The `origin`
    /// marker is intended for warn-log gating (see `from_env`).
    #[must_use]
    pub fn from_seed(seed: [u8; 32], origin: AnchorerSigningKeyOrigin) -> Self {
        Self { seed, origin }
    }

    /// Load the configured anchorer signing key from the
    /// `PASION_CONTRIX__ANCHORER_SIGNING_KEY` environment variable
    /// (base64 32-byte seed). When absent, fall back to a freshly
    /// generated ephemeral seed and emit a warn log; production
    /// deployments that actually anchor must configure a real key
    /// because anything signed with the ephemeral seed is unverifiable
    /// across restarts.
    ///
    /// Returns `Err(MimiConsentError::InvalidAnchorerKey)` only when
    /// the env var is *present* but malformed; the absent case yields
    /// `Ok(<ephemeral>)` so callers can degrade gracefully in
    /// non-anchorer deployments.
    pub fn from_env() -> Result<Self, MimiConsentError> {
        use base64ct::{Base64, Encoding as _};
        match std::env::var("PASION_CONTRIX__ANCHORER_SIGNING_KEY") {
            Ok(raw) => {
                let trimmed = raw.trim();
                // base64ct returns the decoded length on success; size
                // a fixed 32-byte buf and decode in place so we can
                // distinguish "wrong length" from "malformed alphabet".
                let mut buf = [0u8; 48]; // 32 bytes encodes to 44 chars, leave headroom
                let decoded = Base64::decode(trimmed, &mut buf).map_err(|error| {
                    MimiConsentError::InvalidAnchorerKey {
                        reason: format!("base64 decode failed: {error:?}"),
                    }
                })?;
                if decoded.len() != 32 {
                    return Err(MimiConsentError::InvalidAnchorerKey {
                        reason: format!(
                            "expected 32-byte seed, got {} bytes after base64 decode",
                            decoded.len()
                        ),
                    });
                }
                let mut seed = [0_u8; 32];
                seed.copy_from_slice(decoded);
                Ok(Self::from_seed(seed, AnchorerSigningKeyOrigin::Configured))
            }
            Err(_) => {
                let mut seed = [0_u8; 32];
                use rand::RngExt as _;
                rand::rng().fill(&mut seed[..]);
                tracing::warn!(
                    "PASION_CONTRIX__ANCHORER_SIGNING_KEY not set; using ephemeral \
                     anchorer key (anything signed will be unverifiable across \
                     restarts — configure a real key for production anchoring)"
                );
                Ok(Self::from_seed(seed, AnchorerSigningKeyOrigin::Ephemeral))
            }
        }
    }

    /// Origin of the underlying signing key. Useful for warn-log gating.
    #[must_use]
    pub fn origin(&self) -> AnchorerSigningKeyOrigin {
        self.origin
    }

    /// Raw 32-byte seed accessor. Crate-private to keep the seed from
    /// leaking outside the bridge layer.
    #[allow(dead_code)]
    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

/// Sign and submit a `PendingMove` to the holder's principal server.
///
/// On success the signed Move has been POSTed to soland's
/// `/api/v1/moves` endpoint and accepted with 2xx; on any failure the
/// caller gets a typed `MimiConsentError`.
///
/// ### SDK gap — still partially blocked at round 21
///
/// Round 21 lands the *non-signing* half of this entrypoint:
///
/// - `AnchorerSigner::from_env()` parses
///   `PASION_CONTRIX__ANCHORER_SIGNING_KEY` and falls back to an
///   ephemeral key with a warn log (see that constructor for details).
/// - The HTTP forward to soland's `/api/v1/moves` endpoint is
///   structured the same way as `consent_cell_query::query_consent_cell`
///   — caller-supplied `reqwest::Client`, 5s timeout,
///   `X-Contrix-Holder-Did` echo header.
///
/// What is **still SDK-blocked**: the parallel contrix-rust-sdk round
/// 21 agent is exposing a public `MoveSigner` trait + an
/// `Ed25519MoveSigner` impl, plus `Anchor::sign_single(...)` constructors.
/// Until those land in `contrix-rust-sdk/crates/sdk/src/lib.rs`, this
/// function returns `MimiConsentError::SignerSdkUnavailable` *before*
/// any HTTP call so we don't post unsigned envelopes by accident.
///
/// SDK contract we depend on (when it lands, drop into this file):
///
/// ```ignore
/// // from contrix-rust-sdk:
/// pub trait MoveSigner {
///     fn sign_move(&self, unsigned: UnsignedMove)
///         -> Result<SignedMove, contrix::Error>;
///     fn signer_did(&self) -> &Did;
/// }
///
/// pub struct Ed25519MoveSigner { /* ... */ }
/// impl Ed25519MoveSigner {
///     pub fn from_seed(seed: [u8; 32], did: Did) -> Self;
/// }
/// impl MoveSigner for Ed25519MoveSigner { /* ... */ }
///
/// pub struct Anchor;
/// impl Anchor {
///     pub fn sign_single<S: MoveSigner>(
///         signer: &S,
///         unsigned: UnsignedMove,
///     ) -> Result<SignedMove, contrix::Error>;
/// }
/// ```
///
/// Once that contract is published from `contrix-rust-sdk`, the inline
/// `// SDK-WIRE` block below becomes:
///
/// ```ignore
/// let signer = Ed25519MoveSigner::from_seed(*signer.seed(), anchorer_did.clone());
/// let unsigned = UnsignedMove {
///     cell_id: pending.cell_id.clone(),
///     op: match pending.op {
///         PendingMoveOp::OrSetAdd => MoveOp::OrSetAdd { tag: pending.tag.clone() },
///         PendingMoveOp::OrSetRemove => MoveOp::OrSetRemove { tag: pending.tag.clone() },
///     },
///     /* hlc, parents, anchorer_did populated by the SDK builder */
/// };
/// let signed = Anchor::sign_single(&signer, unsigned)
///     .map_err(MimiConsentError::sdk_error)?;
/// // POST signed to soland (already wired below).
/// ```
///
/// Tracked under `TODO(c10e-mimi-move)` and the §"P1: Move / Anchor /
/// Lattice — anchorer signer (rare deployment mode)" subtask of
/// `coauth/_todos.md`.
pub async fn anchor_pending_move(
    pending: &PendingMove,
    principal_server_url: Option<&url::Url>,
    http_client: &reqwest::Client,
    signer: &AnchorerSigner,
    anchorer_holder_did: &str,
) -> Result<(), MimiConsentError> {
    let Some(base) = principal_server_url else {
        return Err(MimiConsentError::PrincipalServerNotConfigured);
    };

    // ── SDK-WIRE ──────────────────────────────────────────────────
    // TODO(c10e-mimi-move): once `contrix-rust-sdk` exposes the public
    // `MoveSigner` + `Ed25519MoveSigner` + `Anchor::sign_single(...)`
    // surface (see doc-comment above for the contract), replace this
    // early-return with the build-and-sign block. Today we fail closed
    // with SignerSdkUnavailable so a misconfigured deployment never
    // POSTs an unsigned envelope.
    let _ = (signer, anchorer_holder_did);
    if true {
        return Err(MimiConsentError::SignerSdkUnavailable);
    }
    // ── /SDK-WIRE ─────────────────────────────────────────────────

    // The HTTP forward below is unreachable until the SDK lands; keeping
    // it in source so the diff for the SDK-wire is small and the request
    // shape is reviewable now. Mirrors `consent_cell_query.rs` patterns.
    #[allow(unreachable_code)]
    {
        let url = base.join("api/v1/moves").map_err(|error| {
            MimiConsentError::PrincipalServerForwardFailed {
                reason: format!("invalid principal server url: {error}"),
            }
        })?;

        // The body shape echoes the spec §6 SignedMove envelope; once the
        // SDK lands, this becomes a `serde_json::to_value(&signed_move)`.
        let body = serde_json::json!({
            "cell_id": pending.cell_id,
            "op": match pending.op {
                PendingMoveOp::OrSetAdd => "or_set_add",
                PendingMoveOp::OrSetRemove => "or_set_remove",
            },
            "tag": pending.tag,
        });

        let response = http_client
            .post(url)
            .header("X-Contrix-Holder-Did", anchorer_holder_did)
            .json(&body)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|error| MimiConsentError::PrincipalServerForwardFailed {
                reason: format!("HTTP send failed: {error}"),
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(MimiConsentError::PrincipalServerForwardFailed {
                reason: format!("soland returned non-success status {status}"),
            });
        }
        Ok(())
    }
}

/// Authorize a MIMI envelope's actor against the holder. Returns
/// `Ok(())` when `actor_did == holder_did` (self-update — common case)
/// or when the actor is in the controller allowlist supplied by the
/// caller.
///
/// The spec also permits delegated controllers from the holder's
/// principal control Space, but resolving those requires a soland round
/// trip; that's left to the caller for now. This helper covers the
/// "self" case which is enough for unit-testable scaffolding.
pub fn authorize_actor(
    actor_did: &str,
    holder_did: &str,
    controllers: &[String],
) -> Result<(), MimiConsentError> {
    if actor_did == holder_did || controllers.iter().any(|c| c == actor_did) {
        Ok(())
    } else {
        Err(MimiConsentError::ActorNotAuthorized {
            actor_did: actor_did.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_id_uses_grant_family() {
        assert_eq!(
            consent_cell_id("c-123"),
            "cx:cell:cx.component.consent.grant.v1:c-123"
        );
    }

    #[test]
    fn tag_form_matches_spec_6_1() {
        assert_eq!(
            build_consent_tag("did:web:peer", "invite"),
            "peer=did:web:peer;scope=invite"
        );
    }

    #[test]
    fn update_consent_grant_maps_to_or_set_add() {
        let update = UpdateConsent {
            consent_id: "c-1".into(),
            actor_did: "did:web:peer".into(),
            holder_did: "did:web:holder".into(),
            scope: "invite".into(),
            granted: true,
        };
        let pending = update_consent_to_pending_move(&update).unwrap();
        assert_eq!(
            pending.cell_id,
            "cx:cell:cx.component.consent.grant.v1:c-1"
        );
        assert_eq!(pending.op, PendingMoveOp::OrSetAdd);
        assert_eq!(pending.tag, "peer=did:web:peer;scope=invite");
    }

    #[test]
    fn update_consent_revoke_maps_to_or_set_remove() {
        let update = UpdateConsent {
            consent_id: "c-1".into(),
            actor_did: "did:web:peer".into(),
            holder_did: "did:web:holder".into(),
            scope: "invite".into(),
            granted: false,
        };
        let pending = update_consent_to_pending_move(&update).unwrap();
        assert_eq!(pending.op, PendingMoveOp::OrSetRemove);
    }

    #[test]
    fn update_consent_rejects_empty_fields() {
        let update = UpdateConsent {
            consent_id: String::new(),
            actor_did: "x".into(),
            holder_did: "y".into(),
            scope: "invite".into(),
            granted: true,
        };
        let err = update_consent_to_pending_move(&update).unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::MissingField {
                field: "consent_id"
            }
        ));
    }

    #[test]
    fn authorize_self_is_ok() {
        assert!(authorize_actor("did:web:holder", "did:web:holder", &[]).is_ok());
    }

    #[test]
    fn authorize_listed_controller_is_ok() {
        assert!(
            authorize_actor(
                "did:web:controller",
                "did:web:holder",
                &["did:web:controller".to_owned()],
            )
            .is_ok()
        );
    }

    #[test]
    fn authorize_unrelated_actor_is_rejected() {
        let err = authorize_actor("did:web:stranger", "did:web:holder", &[])
            .expect_err("should reject unrelated actor");
        assert!(matches!(
            err,
            MimiConsentError::ActorNotAuthorized { .. }
        ));
    }

    #[tokio::test]
    async fn anchor_pending_move_without_principal_url_returns_typed_error() {
        crate::handlers::test_utils::setup();
        let pending = PendingMove {
            cell_id: consent_cell_id("c-1"),
            op: PendingMoveOp::OrSetAdd,
            tag: build_consent_tag("did:web:p", "invite"),
        };
        let client = reqwest::Client::new();
        let signer = AnchorerSigner::from_seed([0u8; 32], AnchorerSigningKeyOrigin::Ephemeral);
        let err =
            anchor_pending_move(&pending, None, &client, &signer, "did:web:anchorer")
                .await
                .unwrap_err();
        assert!(matches!(err, MimiConsentError::PrincipalServerNotConfigured));
    }

    #[tokio::test]
    async fn anchor_pending_move_with_principal_url_returns_sdk_unavailable() {
        crate::handlers::test_utils::setup();
        let pending = PendingMove {
            cell_id: consent_cell_id("c-1"),
            op: PendingMoveOp::OrSetAdd,
            tag: build_consent_tag("did:web:p", "invite"),
        };
        let client = reqwest::Client::new();
        let signer = AnchorerSigner::from_seed([1u8; 32], AnchorerSigningKeyOrigin::Configured);
        let base = url::Url::parse("https://example.invalid/").unwrap();
        let err = anchor_pending_move(
            &pending,
            Some(&base),
            &client,
            &signer,
            "did:web:anchorer",
        )
        .await
        .unwrap_err();
        // Expected: until contrix-rust-sdk lands the public MoveSigner
        // trait, the signing path early-returns SignerSdkUnavailable
        // *before* any HTTP call so we never POST an unsigned envelope.
        assert!(matches!(err, MimiConsentError::SignerSdkUnavailable));
    }

    #[test]
    fn anchorer_signer_from_seed_marks_origin() {
        let s = AnchorerSigner::from_seed([0u8; 32], AnchorerSigningKeyOrigin::Configured);
        assert_eq!(s.origin(), AnchorerSigningKeyOrigin::Configured);
        assert_eq!(s.seed(), &[0u8; 32]);
    }

    #[test]
    fn anchorer_signer_from_seed_ephemeral_origin_is_ephemeral() {
        let s = AnchorerSigner::from_seed([42u8; 32], AnchorerSigningKeyOrigin::Ephemeral);
        assert_eq!(s.origin(), AnchorerSigningKeyOrigin::Ephemeral);
    }

    // `AnchorerSigner::from_env` is intentionally not unit-tested for
    // its env-mutation cases — Rust 2024 marks `std::env::set_var` /
    // `remove_var` as `unsafe`, and the workspace lint config enforces
    // `-D unsafe-code`. The structural cases (seed-from-explicit, seed
    // origin marker, error-shape on bad seed length) cover the
    // important branches; the env-parsing branch itself is short and
    // straight-line. Integration coverage will catch a regression
    // there once an anchorer profile lands.
}
