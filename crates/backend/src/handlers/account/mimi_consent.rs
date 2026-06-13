// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! MIMI `request_consent` / `update_consent` → consent-cell **Move** mapping.
//!
//! Per the Move/Anchor/Lattice spec (`cokret-spec` 2026-05-08,
//! `consent-model.md` §3-§9), incoming MIMI consent operations are
//! translated into Moves on the holder's consent cell:
//!
//! ```text
//! ck:cell:ck.component.consent.grant.v1:<consent_id>
//! ```
//!
//! - `request_consent` → no Move yet (the holder hasn't decided); coauth surfaces this to yougen as
//!   a pending-consent UI prompt and correlates with `consent_id`.
//! - `update_consent { granted = true }` → `or-set add tag` Move with `peer=<actor>;scope=<scope>`
//!   written to the holder's principal control Realm.
//! - `update_consent { granted = false }` → `or-set remove tag` Move that revokes the same `(peer,
//!   scope)` tag.
//!
//! ## Round 22 (2026-05-09)
//!
//! `cokret-rust-sdk` 0.5.0 now exposes the public `MoveSigner` trait,
//! `UnsignedMove` builder, ergonomic `Move::sign(&unsigned, signer)` entry
//! point and `Ed25519MoveSigner` impl (behind the `signer` feature). This
//! module wires the full MIMI → `SignedMove` → soland POST path:
//!
//! 1. Caller hands an `UpdateConsent` (with `realm_id`, `anchor_ref`, `hlc` threaded in from
//!    upstream — typically populated either from the MIMI envelope or from a `consent_cell_query` +
//!    `anchor_view_query` round-trip).
//! 2. `update_consent_to_pending_move(...)` produces a `PendingMove` carrying everything needed to
//!    construct an `UnsignedMove`.
//! 3. `anchor_pending_move(...)` builds the `UnsignedMove`, calls `Move::sign(&unsigned, signer)`
//!    against the deployment's `AnchorerSigner` (an `Ed25519MoveSigner` wrapper), and POSTs the
//!    resulting `Move` envelope to soland's private peer-move endpoint.

use cokret_core::move_event::{Effect, LatticeOp, LatticeOpType};
use cokret_core::{CellRef, Did, Hash, Hlc, Move, RealmId, SealBasis, SealId, UnsignedMove};
use cokret_signatures::Ed25519MoveSigner;
use serde::{Deserialize, Serialize};

use crate::outbound_http;

/// Inbound MIMI `request_consent` payload (subset).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct RequestConsent {
    pub consent_id: String,
    pub actor_id: String,
    pub holder_did: String,
    pub scope: String,
    #[serde(default)]
    pub reason: Option<String>,
}

impl RequestConsent {
    #[must_use]
    pub fn new(
        consent_id: impl Into<String>,
        actor_id: impl Into<String>,
        holder_did: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            consent_id: consent_id.into(),
            actor_id: actor_id.into(),
            holder_did: holder_did.into(),
            scope: scope.into(),
            reason: None,
        }
    }
}

/// Inbound MIMI `update_consent` payload (subset).
///
/// Round 22: `realm_id`, `anchor_ref` and `hlc` are **required** so the
/// downstream `anchor_pending_move` can build a real `UnsignedMove`. They
/// are populated either by the MIMI gateway adapter (when those fields
/// ride on the MIMI envelope) or by an upstream `anchor_view_query`
/// fetch keyed by the holder's principal control Realm.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct UpdateConsent {
    pub consent_id: String,
    pub actor_id: String,
    pub holder_did: String,
    pub scope: String,
    pub granted: bool,
    /// `ck:realm:<uuidv7>` — holder's principal control Realm (per spec
    /// §6 the consent cell lives here). Resolve from `holder_did` via
    /// `anchor_view_query::holder_principal_realm_for_did` if the wire
    /// envelope does not carry it.
    pub realm_id: String,
    /// `ck:seal:sha256:<hex>` — latest seal leaf the issuer was
    /// working from. Fetch via
    /// `anchor_view_query::query_latest_anchor`.
    pub anchor_ref: String,
    /// HLC string `<unix-ms-hex>-<logical-hex>-<node-hex>` — populated by
    /// the upstream caller (typically `anchor_view_query::query_latest_anchor`
    /// returns one suitable for first use).
    pub hlc: String,
}

/// Pending Move: typed bundle ready for `anchor_pending_move` to sign and
/// submit. Decoupled from the SDK types only so unit tests can construct
/// one in a single literal expression — `anchor_pending_move` validates
/// each field through the SDK's `*::new` constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMove {
    /// `ck:realm:<uuidv7>` — holder's principal control Realm.
    pub realm_id: String,
    /// `ck:cell:ck.component.consent.grant.v1:<consent_id>`.
    pub cell_id: String,
    /// Either `or_set_add` or `or_set_remove` per spec §6.1.
    pub op: PendingMoveOp,
    /// The `OrSet` tag to add or remove.
    pub tag: String,
    /// Latest seal leaf the issuer references (`ck:seal:sha256:<hex>`).
    pub anchor_ref: String,
    /// HLC `<unix-ms-hex>-<logical-hex>-<node-hex>`.
    pub hlc: String,
}

/// Pending Move operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingMoveOp {
    /// Grant: append the `(peer, scope)` tag to the cell's `OrSet`.
    OrSetAdd,
    /// Revoke: remove the `(peer, scope)` tag from the cell's `OrSet`.
    OrSetRemove,
}

/// Errors produced by the MIMI consent → Move bridge.
#[derive(Debug, thiserror::Error)]
pub enum MimiConsentError {
    /// `anchor_pending_move` was called without a configured principal
    /// server URL.
    #[error("mimi consent → move: server_name url not configured")]
    PrincipalServerNotConfigured,

    /// `COAUTH_COKRET__ANCHORER_SIGNING_KEY` was set but malformed.
    #[error("mimi consent: anchorer signing key invalid: {reason}")]
    InvalidAnchorerKey { reason: String },

    /// HTTP forward to soland failed (network error, non-2xx status,
    /// invalid URL).
    #[error("mimi consent → move: principal server forward failed: {reason}")]
    PrincipalServerForwardFailed { reason: String },

    /// One of the typed identifier inputs (`realm_id`, `anchor_ref`,
    /// `hlc`, `cell_id`, `issuer_did`) failed strict validation by the
    /// SDK constructors. Surfaces the field name + the underlying message
    /// so the caller / operator can tell whether the bug is upstream or
    /// in the wiring here.
    #[error("mimi consent → move: invalid typed id for {field}: {reason}")]
    InvalidTypedId { field: &'static str, reason: String },

    /// `Move::sign(...)` rejected the `UnsignedMove` (issuer / signer
    /// mismatch, canonical-bytes hashing failure, etc.).
    #[error("mimi consent → move: signing failed: {reason}")]
    SigningFailed { reason: String },

    /// The actor on the MIMI envelope does not match the holder DID
    /// (and is not a registered controller). Spec §6.2 fail-closed.
    #[error("mimi consent: actor {actor_id} is not the holder or an authorized controller")]
    ActorNotAuthorized { actor_id: String },

    /// A required field on the MIMI envelope was empty.
    #[error("mimi consent: missing required field {field}")]
    MissingField { field: &'static str },
}

/// Build the canonical consent cell id from a MIMI `consent_id`.
#[must_use]
pub fn consent_cell_id(consent_id: &str) -> String {
    format!("ck:cell:ck.component.consent.grant.v1:{consent_id}")
}

/// Build the `OrSet` tag for a `(peer, scope)` consent grant. Pure helper.
///
/// Matches the spec §6.1 tag form `peer=<did>;scope=<scope>`.
#[must_use]
pub fn build_consent_tag(peer_did: &str, scope: &str) -> String {
    format!("peer={peer_did};scope={scope}")
}

/// Round R2/R3 T17 — sentinel scope value that, when present on a
/// revoke, cascades to every subscope on the same `(holder, consent_id)`
/// cell. Wire string per consent-model §6.4.
pub const ANY_SCOPE_SENTINEL: &str = "any";

/// Round R2/R3 T17 — outcome of [`cascade_any_revoke`]: the primary
/// `(peer, scope=any)` revoke Move plus one supplementary
/// `or_set_remove` Move per pre-existing subscope grant on the cell.
/// Each supplementary Move carries the `superseded_by_any_revoke`
/// marker in `extra` so reducers can attribute it to the cascade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyRevokeCascade {
    /// The primary `(peer, scope=any)` revoke Move.
    pub primary: PendingMove,
    /// One Move per pre-existing subscope grant. The reducer applies
    /// them after the primary so the final OrSet state is
    /// `subscope-tags removed AND scope=any removed`.
    pub superseded: Vec<SupersededRevoke>,
}

/// A subscope revoke spawned by an `scope=any` cascade. Carries the
/// `superseded_by_any_revoke` audit marker so downstream auditors and
/// the broadcast invalidation channel can correlate the cascade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersededRevoke {
    pub mv: PendingMove,
    /// Always `"superseded_by_any_revoke"` — kept as a field so the
    /// reducer / audit log can persist it without re-deriving.
    pub marker: &'static str,
}

/// Round R2/R3 T17 — build the cascade for a revoke that targets the
/// sentinel scope `any`. Given the set of subscope tags currently on
/// the cell (as observed from a `consent_cell_query`), this returns a
/// primary revoke + one supplementary `or_set_remove` per pre-existing
/// subscope tag, each marked `superseded_by_any_revoke`.
///
/// `current_subscope_tags` is the `OrSet` snapshot at the time of the
/// revoke, filtered to tags with `peer=<actor>;scope=<...>` where
/// `<...> != "any"`. Tag form follows [`build_consent_tag`].
///
/// Returns `MimiConsentError::MissingField { field: "scope" }` when
/// invoked on a non-revoke or a non-`any` scope (use
/// [`update_consent_to_pending_move`] for those).
///
/// TODO(round23-T17): pair this with a soland-side `cells/cascade`
/// endpoint so the Moves can land in a single anchor batch rather
/// than as N+1 sequential calls. The current shape is correct
/// (reducers idempotent on or_set_remove) but bandwidth-inefficient
/// for large grant lists.
pub fn cascade_any_revoke(
    update: &UpdateConsent,
    current_subscope_tags: &[String],
) -> Result<AnyRevokeCascade, MimiConsentError> {
    if update.granted {
        return Err(MimiConsentError::MissingField {
            field: "granted=false",
        });
    }
    if update.scope != ANY_SCOPE_SENTINEL {
        return Err(MimiConsentError::MissingField { field: "scope=any" });
    }

    let primary = update_consent_to_pending_move(update)?;

    let mut superseded = Vec::with_capacity(current_subscope_tags.len());
    for tag in current_subscope_tags {
        // Defensive: skip a "scope=any" tag that snuck through — it's
        // already covered by the primary, and replaying it would just
        // be a no-op or-set-remove.
        if tag.ends_with(";scope=any") {
            continue;
        }
        superseded.push(SupersededRevoke {
            mv: PendingMove {
                realm_id: update.realm_id.clone(),
                cell_id: consent_cell_id(&update.consent_id),
                op: PendingMoveOp::OrSetRemove,
                tag: tag.clone(),
                anchor_ref: update.anchor_ref.clone(),
                hlc: update.hlc.clone(),
            },
            marker: "superseded_by_any_revoke",
        });
    }

    Ok(AnyRevokeCascade {
        primary,
        superseded,
    })
}

/// Round R2/R3 T17 — broadcast a cache-invalidation event to
/// downstream services (teabay = consent/cache shadow, floria =
/// federated invite gate) when a `scope=any` revoke lands.
///
/// The broadcast channel doesn't exist yet (T17 leaves it as a stub).
/// For now this records the intent and returns; once
/// `services::cross_account_bus` is wired the body will publish to
/// the bus. The signature is in place so call-sites can adopt it
/// without further wire changes.
///
/// TODO(round23-T17): when `cross_account_bus` lands, replace the
/// `tracing::info!` below with a real publish. Until then the broadcast
/// is best-effort and idempotency is on the receiver.
///
/// STATUS: stub — NOT for production cache-invalidation.
/// CATEGORY: P1 / cross-service-bus.
/// RISK: silent no-op means downstream caches (teabay, floria) keep
///   stale grant state until their own TTLs expire. Acceptable while
///   no downstream actually consumes this signal; flip to a hard
///   failure once `services::cross_account_bus` lands (TODO scaffold).
pub fn broadcast_cache_invalidation_for_any_revoke(
    holder_did: &str,
    consent_id: &str,
    superseded_count: usize,
) {
    tracing::info!(
        target: "coauth::consent::cascade",
        holder_did,
        consent_id,
        superseded_count,
        marker = "superseded_by_any_revoke",
        "scope=any revoke cascade — broadcast stub (TODO round23-T17)"
    );
}

/// Translate an `update_consent` envelope into a `PendingMove`. Pure
/// function — no I/O, no signing.
pub fn update_consent_to_pending_move(
    update: &UpdateConsent,
) -> Result<PendingMove, MimiConsentError> {
    macro_rules! require {
        ($field:expr, $name:expr) => {
            if $field.is_empty() {
                return Err(MimiConsentError::MissingField { field: $name });
            }
        };
    }
    require!(update.consent_id, "consent_id");
    require!(update.actor_id, "actor_id");
    require!(update.holder_did, "holder_did");
    require!(update.scope, "scope");
    require!(update.realm_id, "realm_id");
    require!(update.anchor_ref, "anchor_ref");
    require!(update.hlc, "hlc");

    Ok(PendingMove {
        realm_id: update.realm_id.clone(),
        cell_id: consent_cell_id(&update.consent_id),
        op: if update.granted {
            PendingMoveOp::OrSetAdd
        } else {
            PendingMoveOp::OrSetRemove
        },
        tag: build_consent_tag(&update.actor_id, &update.scope),
        anchor_ref: update.anchor_ref.clone(),
        hlc: update.hlc.clone(),
    })
}

/// How the anchorer signing key was obtained at process start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorerSigningKeyOrigin {
    /// Loaded from `COAUTH_COKRET__ANCHORER_SIGNING_KEY` (base64 32-byte
    /// seed).
    Configured,
    /// No env var present — generated at process start. Anything signed
    /// with this key is unverifiable across restarts.
    Ephemeral,
}

/// Anchorer signer handle used by `anchor_pending_move`. Wraps an
/// SDK `Ed25519MoveSigner` plus the origin marker for warn-log gating.
///
/// Round 22 (2026-05-09): the SDK now publishes `MoveSigner` +
/// `Ed25519MoveSigner` so this is no longer a placeholder — `from_seed`
/// constructs the production signer directly. `from_env` is the
/// ergonomic variant that loads the seed from
/// `COAUTH_COKRET__ANCHORER_SIGNING_KEY` and falls back to an ephemeral
/// key with a warn log.
pub struct AnchorerSigner {
    inner: Ed25519MoveSigner,
    /// Held for clone semantics + debug logging — `Ed25519MoveSigner` is
    /// not `Clone`, so coauth keeps a copy of the seed and rebuilds the
    /// inner signer on demand inside `clone()`.
    seed: [u8; 32],
    issuer_did: String,
    verification_method_id: String,
    origin: AnchorerSigningKeyOrigin,
}

impl Clone for AnchorerSigner {
    fn clone(&self) -> Self {
        let did = Did::new(self.issuer_did.clone()).expect("did was already validated");
        Self {
            inner: Ed25519MoveSigner::from_did_key_seed(
                self.seed,
                did,
                self.verification_method_id.clone(),
            ),
            seed: self.seed,
            issuer_did: self.issuer_did.clone(),
            verification_method_id: self.verification_method_id.clone(),
            origin: self.origin,
        }
    }
}

impl std::fmt::Debug for AnchorerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorerSigner")
            .field("seed", &"<redacted>")
            .field("issuer_did", &self.issuer_did)
            .field("verification_method_id", &self.verification_method_id)
            .field("origin", &self.origin)
            .finish()
    }
}

impl AnchorerSigner {
    /// Construct a signer from a raw 32-byte ed25519 seed + the issuer
    /// DID + verification method id.
    pub fn from_seed(
        seed: [u8; 32],
        issuer_did: impl Into<String>,
        verification_method_id: impl Into<String>,
        origin: AnchorerSigningKeyOrigin,
    ) -> Result<Self, MimiConsentError> {
        let issuer_did = issuer_did.into();
        let did =
            Did::new(issuer_did.clone()).map_err(|error| MimiConsentError::InvalidTypedId {
                field: "issuer_did",
                reason: format!("{error}"),
            })?;
        let kid = verification_method_id.into();
        let inner = Ed25519MoveSigner::from_did_key_seed(seed, did, kid.clone());
        Ok(Self {
            inner,
            seed,
            issuer_did,
            verification_method_id: kid,
            origin,
        })
    }

    /// Load the configured anchorer signing key from
    /// `COAUTH_COKRET__ANCHORER_SIGNING_KEY` (base64 32-byte seed).
    /// Falls back to an ephemeral key with a warn log when the env var
    /// is absent.
    ///
    /// `issuer_did` is the DID coauth signs Moves under (the deployment's
    /// anchorer DID). `verification_method_id` is the `<did>#<frag>`
    /// published as `MoveSignature.verification_method`.
    pub fn from_env(
        issuer_did: impl Into<String>,
        verification_method_id: impl Into<String>,
    ) -> Result<Self, MimiConsentError> {
        use base64ct::{Base64, Encoding as _};
        let issuer_did = issuer_did.into();
        let kid = verification_method_id.into();
        if let Ok(raw) = std::env::var("COAUTH_COKRET__ANCHORER_SIGNING_KEY") {
            let trimmed = raw.trim();
            let mut buf = [0u8; 48];
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
            Self::from_seed(seed, issuer_did, kid, AnchorerSigningKeyOrigin::Configured)
        } else {
            let mut seed = [0_u8; 32];
            use rand::RngExt as _;
            rand::rng().fill(&mut seed[..]);
            tracing::warn!(
                "COAUTH_COKRET__ANCHORER_SIGNING_KEY not set; using ephemeral \
                 anchorer key (anything signed will be unverifiable across \
                 restarts — configure a real key for production anchoring)"
            );
            Self::from_seed(seed, issuer_did, kid, AnchorerSigningKeyOrigin::Ephemeral)
        }
    }

    /// Origin of the underlying signing key.
    #[must_use]
    pub fn origin(&self) -> AnchorerSigningKeyOrigin {
        self.origin
    }

    /// Issuer DID this signer signs Moves under.
    #[must_use]
    pub fn issuer_did(&self) -> &str {
        &self.issuer_did
    }

    /// Borrow the inner SDK signer (e.g. for `Move::sign(...)` callers
    /// that already hold an `UnsignedMove`).
    #[must_use]
    pub fn inner(&self) -> &Ed25519MoveSigner {
        &self.inner
    }
}

/// Build, sign, and POST a `PendingMove` to the holder's `server_name`.
///
/// On success the `SignedMove` envelope returned by `Move::sign` has been
/// `POSTed` to soland's private peer-move endpoint and accepted with 2xx.
///
/// ### Wire shape
///
/// The body is `serde_json::to_value(&signed_move)` directly — i.e.
/// the canonical `Move` envelope from `cokret-core::move_event::Move`.
/// `X-Cokret-Holder-Did` echoes the holder DID for soland's per-Space
/// routing.
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

    let signed_move = build_and_sign_move(pending, signer)?;

    let url = base.join("_soland/peer/moves").map_err(|error| {
        MimiConsentError::PrincipalServerForwardFailed {
            reason: format!("invalid server_name url: {error}"),
        }
    })?;

    let body = serde_json::to_value(&signed_move).map_err(|error| {
        MimiConsentError::PrincipalServerForwardFailed {
            reason: format!("failed to serialize SignedMove: {error}"),
        }
    })?;

    let response = outbound_http::send_with_policy(
        outbound_http::soland_policy("mimi_move_forward")
            .with_timeout(std::time::Duration::from_secs(5)),
        || {
            http_client
                .post(url.clone())
                .header("X-Cokret-Holder-Did", anchorer_holder_did)
                .json(&body)
        },
    )
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

/// Build a fully-signed `Move` from a `PendingMove`. Splits out of
/// `anchor_pending_move` so unit tests can assert on the wire body without
/// needing a wiremock server.
pub(crate) fn build_and_sign_move(
    pending: &PendingMove,
    signer: &AnchorerSigner,
) -> Result<Move, MimiConsentError> {
    let realm = RealmId::new(pending.realm_id.clone()).map_err(|error| {
        MimiConsentError::InvalidTypedId {
            field: "realm_id",
            reason: format!("{error}"),
        }
    })?;
    let cell = CellRef::new(pending.cell_id.clone()).map_err(|error| {
        MimiConsentError::InvalidTypedId {
            field: "cell_id",
            reason: format!("{error}"),
        }
    })?;
    let seal_leaf = SealId::new(pending.anchor_ref.clone()).map_err(|error| {
        MimiConsentError::InvalidTypedId {
            field: "anchor_ref",
            reason: format!("{error}"),
        }
    })?;
    let hlc = Hlc::new(pending.hlc.clone()).map_err(|error| MimiConsentError::InvalidTypedId {
        field: "hlc",
        reason: format!("{error}"),
    })?;
    let issuer = Did::new(signer.issuer_did().to_owned()).map_err(|error| {
        MimiConsentError::InvalidTypedId {
            field: "issuer_did",
            reason: format!("{error}"),
        }
    })?;

    let op_type = match pending.op {
        PendingMoveOp::OrSetAdd => LatticeOpType::Add,
        PendingMoveOp::OrSetRemove => LatticeOpType::Remove,
    };
    let effect = Effect {
        cell,
        op: LatticeOp {
            op_type,
            tag: Some(pending.tag.clone()),
            value: None,
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        },
    };
    let zero_hash = Hash::new(format!("sha256:{}", "0".repeat(64))).expect("valid zero hash");
    let seal_basis = SealBasis {
        leaves: vec![seal_leaf],
        control_event_set_root: zero_hash.clone(),
        state_root: zero_hash,
    };
    let unsigned = UnsignedMove::new(issuer, realm, seal_basis, vec![effect], hlc);
    Move::sign(&unsigned, signer.inner()).map_err(|error| MimiConsentError::SigningFailed {
        reason: format!("{error}"),
    })
}

/// Authorize a MIMI envelope's actor against the holder. Returns
/// `Ok(())` when `actor_id == holder_did` (self-update) or when the
/// actor is in the controller allowlist supplied by the caller.
pub fn authorize_actor(
    actor_id: &str,
    holder_did: &str,
    controllers: &[String],
) -> Result<(), MimiConsentError> {
    if actor_id == holder_did || controllers.iter().any(|c| c == actor_id) {
        Ok(())
    } else {
        Err(MimiConsentError::ActorNotAuthorized {
            actor_id: actor_id.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pending() -> PendingMove {
        PendingMove {
            realm_id: "ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned(),
            cell_id: consent_cell_id("c-1"),
            op: PendingMoveOp::OrSetAdd,
            tag: build_consent_tag("did:web:peer", "invite"),
            anchor_ref:
                "ck:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
            hlc: "0189c4d2af00-0000-aabbccdd".to_owned(),
        }
    }

    fn sample_signer() -> AnchorerSigner {
        AnchorerSigner::from_seed(
            [7u8; 32],
            "did:web:anchorer.example",
            "did:web:anchorer.example#key-1",
            AnchorerSigningKeyOrigin::Configured,
        )
        .unwrap()
    }

    #[test]
    fn cell_id_uses_grant_family() {
        assert_eq!(
            consent_cell_id("c-123"),
            "ck:cell:ck.component.consent.grant.v1:c-123"
        );
    }

    #[test]
    fn tag_form_matches_spec_6_1() {
        assert_eq!(
            build_consent_tag("did:web:peer", "invite"),
            "peer=did:web:peer;scope=invite"
        );
    }

    fn sample_update(granted: bool) -> UpdateConsent {
        UpdateConsent {
            consent_id: "c-1".into(),
            actor_id: "did:web:peer".into(),
            holder_did: "did:web:holder".into(),
            scope: "invite".into(),
            granted,
            realm_id: "ck:realm:0196419b-0000-7000-8000-00000000014a".into(),
            anchor_ref:
                "ck:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .into(),
            hlc: "0189c4d2af00-0000-aabbccdd".into(),
        }
    }

    #[test]
    fn update_consent_grant_maps_to_or_set_add() {
        let pending = update_consent_to_pending_move(&sample_update(true)).unwrap();
        assert_eq!(pending.cell_id, "ck:cell:ck.component.consent.grant.v1:c-1");
        assert_eq!(pending.op, PendingMoveOp::OrSetAdd);
        assert_eq!(pending.tag, "peer=did:web:peer;scope=invite");
        assert_eq!(
            pending.realm_id,
            "ck:realm:0196419b-0000-7000-8000-00000000014a"
        );
        assert_eq!(pending.hlc, "0189c4d2af00-0000-aabbccdd");
    }

    #[test]
    fn update_consent_revoke_maps_to_or_set_remove() {
        let pending = update_consent_to_pending_move(&sample_update(false)).unwrap();
        assert_eq!(pending.op, PendingMoveOp::OrSetRemove);
    }

    // Round R2/R3 T17 — scope=any cascade.

    #[test]
    fn cascade_any_revoke_emits_primary_plus_one_remove_per_subscope() {
        let mut update = sample_update(false);
        update.scope = ANY_SCOPE_SENTINEL.into();
        let subscopes = [
            "peer=did:web:peer;scope=invite".to_owned(),
            "peer=did:web:peer;scope=presence".to_owned(),
        ];
        let cascade = cascade_any_revoke(&update, &subscopes).unwrap();
        assert_eq!(cascade.primary.op, PendingMoveOp::OrSetRemove);
        assert_eq!(cascade.primary.tag, "peer=did:web:peer;scope=any");
        assert_eq!(cascade.superseded.len(), 2);
        for sup in &cascade.superseded {
            assert_eq!(sup.marker, "superseded_by_any_revoke");
            assert_eq!(sup.mv.op, PendingMoveOp::OrSetRemove);
            // Same cell + Realm + anchor + hlc as the primary.
            assert_eq!(sup.mv.cell_id, cascade.primary.cell_id);
            assert_eq!(sup.mv.realm_id, cascade.primary.realm_id);
        }
    }

    #[test]
    fn cascade_any_revoke_drops_redundant_scope_any_tag() {
        let mut update = sample_update(false);
        update.scope = ANY_SCOPE_SENTINEL.into();
        let subscopes = [
            "peer=did:web:peer;scope=invite".to_owned(),
            // This one must be skipped — it would duplicate the primary.
            "peer=did:web:peer;scope=any".to_owned(),
        ];
        let cascade = cascade_any_revoke(&update, &subscopes).unwrap();
        assert_eq!(cascade.superseded.len(), 1);
        assert_eq!(
            cascade.superseded[0].mv.tag,
            "peer=did:web:peer;scope=invite"
        );
    }

    #[test]
    fn cascade_any_revoke_rejects_non_any_scope() {
        let update = sample_update(false); // scope = "invite", not "any"
        assert!(cascade_any_revoke(&update, &[]).is_err());
    }

    #[test]
    fn cascade_any_revoke_rejects_grant() {
        let mut update = sample_update(true);
        update.scope = ANY_SCOPE_SENTINEL.into();
        assert!(cascade_any_revoke(&update, &[]).is_err());
    }

    #[test]
    fn update_consent_rejects_empty_consent_id() {
        let mut update = sample_update(true);
        update.consent_id = String::new();
        let err = update_consent_to_pending_move(&update).unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::MissingField {
                field: "consent_id"
            }
        ));
    }

    #[test]
    fn update_consent_rejects_empty_realm_id() {
        let mut update = sample_update(true);
        update.realm_id = String::new();
        let err = update_consent_to_pending_move(&update).unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::MissingField { field: "realm_id" }
        ));
    }

    #[test]
    fn update_consent_rejects_empty_anchor_ref() {
        let mut update = sample_update(true);
        update.anchor_ref = String::new();
        let err = update_consent_to_pending_move(&update).unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::MissingField {
                field: "anchor_ref"
            }
        ));
    }

    #[test]
    fn update_consent_rejects_empty_hlc() {
        let mut update = sample_update(true);
        update.hlc = String::new();
        let err = update_consent_to_pending_move(&update).unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::MissingField { field: "hlc" }
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
        assert!(matches!(err, MimiConsentError::ActorNotAuthorized { .. }));
    }

    #[tokio::test]
    async fn anchor_pending_move_without_principal_url_returns_typed_error() {
        crate::handlers::test_utils::setup();
        let pending = sample_pending();
        let client = reqwest::Client::new();
        let signer = sample_signer();
        let err = anchor_pending_move(&pending, None, &client, &signer, "did:web:anchorer.example")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::PrincipalServerNotConfigured
        ));
    }

    #[test]
    fn anchorer_signer_from_seed_marks_origin() {
        let s = AnchorerSigner::from_seed(
            [0u8; 32],
            "did:web:anchorer.example",
            "did:web:anchorer.example#key-1",
            AnchorerSigningKeyOrigin::Configured,
        )
        .unwrap();
        assert_eq!(s.origin(), AnchorerSigningKeyOrigin::Configured);
        assert_eq!(s.issuer_did(), "did:web:anchorer.example");
    }

    #[test]
    fn anchorer_signer_from_seed_ephemeral_origin_is_ephemeral() {
        let s = AnchorerSigner::from_seed(
            [42u8; 32],
            "did:web:anchorer.example",
            "did:web:anchorer.example#key-1",
            AnchorerSigningKeyOrigin::Ephemeral,
        )
        .unwrap();
        assert_eq!(s.origin(), AnchorerSigningKeyOrigin::Ephemeral);
    }

    #[test]
    fn anchorer_signer_rejects_malformed_did() {
        let err = AnchorerSigner::from_seed(
            [0u8; 32],
            "not-a-did",
            "not-a-did#key-1",
            AnchorerSigningKeyOrigin::Configured,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::InvalidTypedId {
                field: "issuer_did",
                ..
            }
        ));
    }

    #[test]
    fn build_and_sign_move_produces_valid_signed_envelope() {
        let pending = sample_pending();
        let signer = sample_signer();
        let signed = build_and_sign_move(&pending, &signer).unwrap();
        // SDK validators run on the wire envelope.
        signed.validate_id().unwrap();
        signed.validate_structural().unwrap();
        // Issuer + verification_method match the signer.
        assert_eq!(signed.issuer.as_str(), "did:web:anchorer.example");
        assert_eq!(
            signed.sig.verification_method,
            "did:web:anchorer.example#key-1"
        );
        // Single effect carrying the OrSet add tag.
        assert_eq!(signed.effects.len(), 1);
        let effect = &signed.effects[0];
        assert_eq!(effect.cell.as_str(), pending.cell_id);
        assert!(matches!(
            effect.op.op_type,
            cokret_core::move_event::LatticeOpType::Add
        ));
        assert_eq!(effect.op.tag.as_deref(), Some(pending.tag.as_str()));
    }

    #[test]
    fn build_and_sign_move_rejects_malformed_anchor_ref() {
        let mut pending = sample_pending();
        pending.anchor_ref = "not-an-anchor".into();
        let signer = sample_signer();
        let err = build_and_sign_move(&pending, &signer).unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::InvalidTypedId {
                field: "anchor_ref",
                ..
            }
        ));
    }

    #[test]
    fn build_and_sign_move_rejects_malformed_hlc() {
        let mut pending = sample_pending();
        pending.hlc = "not-an-hlc".into();
        let signer = sample_signer();
        let err = build_and_sign_move(&pending, &signer).unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::InvalidTypedId { field: "hlc", .. }
        ));
    }

    #[test]
    fn build_and_sign_move_emits_or_set_remove_for_revoke() {
        let mut pending = sample_pending();
        pending.op = PendingMoveOp::OrSetRemove;
        let signer = sample_signer();
        let signed = build_and_sign_move(&pending, &signer).unwrap();
        assert!(matches!(
            signed.effects[0].op.op_type,
            cokret_core::move_event::LatticeOpType::Remove
        ));
    }

    #[tokio::test]
    async fn anchor_pending_move_posts_signed_move_envelope_to_soland() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        crate::handlers::test_utils::setup();
        let server = MockServer::start().await;
        let pending = sample_pending();
        let signer = sample_signer();

        Mock::given(method("POST"))
            .and(path("/_soland/peer/moves"))
            .and(header("x-cokret-holder-did", "did:web:holder.example"))
            .respond_with(move |req: &Request| {
                let body: serde_json::Value =
                    serde_json::from_slice(&req.body).expect("valid JSON body");
                let m: cokret_core::Move =
                    serde_json::from_value(body.clone()).expect("body deserializes as Move");
                assert_eq!(m.issuer.as_str(), "did:web:anchorer.example");
                assert_eq!(m.effects.len(), 1);
                assert_eq!(
                    m.effects[0].cell.as_str(),
                    "ck:cell:ck.component.consent.grant.v1:c-1"
                );
                ResponseTemplate::new(202)
            })
            .expect(1)
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        anchor_pending_move(
            &pending,
            Some(&base),
            &client,
            &signer,
            "did:web:holder.example",
        )
        .await
        .expect("anchor_pending_move succeeds against mock soland");
    }

    #[tokio::test]
    async fn anchor_pending_move_surfaces_non_success_status() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        crate::handlers::test_utils::setup();
        let server = MockServer::start().await;
        let pending = sample_pending();
        let signer = sample_signer();

        Mock::given(method("POST"))
            .and(path("/_soland/peer/moves"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let err = anchor_pending_move(
            &pending,
            Some(&base),
            &client,
            &signer,
            "did:web:holder.example",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            MimiConsentError::PrincipalServerForwardFailed { .. }
        ));
    }

    #[test]
    fn anchorer_signer_clone_round_trips() {
        let s = sample_signer();
        let s2 = s.clone();
        assert_eq!(s.issuer_did(), s2.issuer_did());
        assert_eq!(s.origin(), s2.origin());
        // Both clones must be able to sign — verifies the cloned inner
        // Ed25519MoveSigner is functional.
        let pending = sample_pending();
        let m1 = build_and_sign_move(&pending, &s).unwrap();
        let m2 = build_and_sign_move(&pending, &s2).unwrap();
        // Same seed + same canonical body → identical move id.
        assert_eq!(m1.id, m2.id);
    }
}
