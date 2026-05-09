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
    /// The full Move construction + signing path is not yet wired.
    #[error("mimi consent → move is scaffold-only; full impl pending anchorer signer")]
    NotImplemented,

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

/// Sign and submit a `PendingMove` to the holder's principal server.
///
/// **Scaffold only — SDK gap blocks real wiring.** Always returns
/// `Err(MimiConsentError::NotImplemented)`.
///
/// ### SDK gap (round 20 audit, contrix-rust-sdk 0.4.0)
///
/// `crates/lattice` exposes the OrSet/OrderedLog CRDT primitives but
/// **no `Move` envelope type or signer surface** is published from the
/// SDK at 0.4.0. Specifically:
///
/// - There is no `contrix-anchor` (or equivalent) crate in
///   `D:/Works/contrix-dev/contrix-rust-sdk/crates/`. The lattice crate
///   ships only the CRDT data types (`or_set`, `mv_register`, `counter`,
///   `ordered_log`); it does not expose a `Move`/`Anchor` envelope or
///   a `sign_move(...)` API that this layer can call.
/// - `contrix-signatures` exposes detached signing primitives but no
///   anchor-envelope schema; we'd be hand-rolling the canonical encoding
///   without spec backing.
/// - `coauth` does not currently depend on `contrix-lattice`,
///   `contrix-operations`, `contrix-signatures`, or `contrix-core` (see
///   `coauth/Cargo.toml` dependency list — none of those crates appear).
///
/// Wiring this entrypoint therefore requires (in order):
///
/// 1. Land an anchor envelope + `sign_move(...)` API in
///    `contrix-rust-sdk/crates/lattice` (or a new `contrix-anchor` crate).
/// 2. Load an anchorer signing key (single_did profile) into
///    `coauth_keystore::Keystore` and surface it to handlers.
/// 3. Add the SDK crates as workspace dependencies and POST the signed
///    envelope to soland's `/api/v1/moves` endpoint.
///
/// Tracked under `TODO(c10e-mimi-move)` and the
/// §"P1: Move / Anchor / Lattice — anchorer signer (rare deployment
/// mode)" subtask of `coauth/_todos.md`.
pub async fn anchor_pending_move(
    _pending: &PendingMove,
    _principal_server_url: Option<&url::Url>,
    _http_client: &reqwest::Client,
) -> Result<(), MimiConsentError> {
    // TODO(c10e-mimi-move): wire the real signer here once the SDK
    // exposes a `Move` envelope + `sign_move(...)` API. See the
    // doc-comment above for the precise SDK gap.
    Err(MimiConsentError::NotImplemented)
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
    async fn anchor_pending_move_is_not_implemented() {
        crate::handlers::test_utils::setup();
        let pending = PendingMove {
            cell_id: consent_cell_id("c-1"),
            op: PendingMoveOp::OrSetAdd,
            tag: build_consent_tag("did:web:p", "invite"),
        };
        let client = reqwest::Client::new();
        let err = anchor_pending_move(&pending, None, &client).await.unwrap_err();
        assert!(matches!(err, MimiConsentError::NotImplemented));
    }
}
