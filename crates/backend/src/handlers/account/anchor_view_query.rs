// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-service helper that fetches the holder's principal control Space
//! Anchor DAG snapshot from soland so coauth can populate `anchor_ref` +
//! `hlc` on a freshly-built `UnsignedMove`.
//!
//! Per the Move/Anchor/Lattice spec (`contrix-spec` 2026-05-08, §3 + §6),
//! every issued Move must reference an Anchor that the issuer was working
//! from. coauth's anchorer flow therefore needs:
//!
//! - the *latest leaf* `anchor_id` (cx:anchor:sha256:<hex>) — used for
//!   `UnsignedMove.anchor_ref`,
//! - a fresh `hlc` (`<unix-ms>-<logical>-<node>`) — used for
//!   `UnsignedMove.hlc`,
//!
//! both keyed by the holder's principal control `space_id`.
//!
//! ## Soland endpoint contract
//!
//! `GET /api/admin/v1/spaces/{space_id}/anchor-dag` returns the
//! `AnchorDagSnapshot` shape from `sodmin::types::anchor`:
//!
//! ```json
//! {
//!   "space_id": "cx:space:...",
//!   "leaves": [{ "anchor_id": "cx:anchor:sha256:...", "created_at": ..., "is_compaction": false }, ...],
//!   "frontier": ["cx:move:sha256:...", ...],
//!   "state_root": "sha256:...",
//!   "last_compaction_at": "..."
//! }
//! ```
//!
//! "Latest leaf" is selected by `created_at` descending; if the field is
//! absent on every leaf we fall back to the first array entry (matches
//! soland's natural emission order — newest-first).

use std::time::Duration;

use serde::Deserialize;
use tracing::{debug, warn};
use url::Url;

/// Result of consulting a space's anchor-dag snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestAnchorView {
    /// `cx:anchor:sha256:<hex>` of the latest leaf anchor.
    pub leaf_anchor_id: String,
    /// HLC string suitable for `UnsignedMove.hlc`. coauth generates a
    /// fresh HLC locally because soland's snapshot does not surface a
    /// "next-tick" hint; the leaf's anchor_id is the only durable input.
    pub hlc: String,
}

/// Errors produced by `query_latest_anchor`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnchorViewError {
    /// The principal server URL is not configured on this coauth deployment.
    #[error("anchor-view: principal server url not configured")]
    PrincipalServerNotConfigured,
    /// HTTP send failed (DNS, TLS, refused, etc.).
    #[error("anchor-view: principal server unreachable: {reason}")]
    PrincipalServerUnreachable { reason: String },
    /// soland returned a non-2xx status that's not covered by an explicit branch.
    #[error("anchor-view: principal server returned status {status}")]
    PrincipalServerStatus { status: u16 },
    /// Response body could not be deserialized into the expected shape.
    #[error("anchor-view: principal server response invalid: {reason}")]
    PrincipalServerResponseInvalid { reason: String },
    /// Snapshot loaded but contained zero leaves. A freshly-bootstrapped
    /// space should always have at least the genesis anchor.
    #[error("anchor-view: principal server returned empty leaves")]
    EmptyLeaves,
    /// Built URL was malformed (defensive — base URL passed validation
    /// upstream so this is mostly a logic-error guard).
    #[error("anchor-view: invalid principal server url: {reason}")]
    InvalidUrl { reason: String },
}

#[derive(Debug, Deserialize)]
struct AnchorDagSnapshotWire {
    #[serde(default)]
    leaves: Vec<AnchorLeafWire>,
}

#[derive(Debug, Deserialize)]
struct AnchorLeafWire {
    #[serde(default)]
    anchor_id: String,
    #[serde(default)]
    created_at: Option<String>,
}

/// Fetch the latest leaf anchor + a fresh HLC for the given Space. Mirrors
/// the `consent_cell_query::query_consent_cell` shape (caller-supplied
/// `reqwest::Client`, 5 s timeout, no `X-Contrix-Holder-Did` echo because
/// the resource is space-scoped not holder-scoped).
pub async fn query_latest_anchor(
    principal_server_url: Option<&Url>,
    space_id: &str,
    http_client: &reqwest::Client,
) -> Result<LatestAnchorView, AnchorViewError> {
    let Some(base) = principal_server_url else {
        return Err(AnchorViewError::PrincipalServerNotConfigured);
    };

    let path = format!(
        "api/admin/v1/spaces/{}/anchor-dag",
        urlencoding::encode_path(space_id)
    );
    let url = base.join(&path).map_err(|error| AnchorViewError::InvalidUrl {
        reason: format!("{error}"),
    })?;

    let response = http_client
        .get(url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|error| {
            warn!(?error, "anchor-view: HTTP error");
            AnchorViewError::PrincipalServerUnreachable {
                reason: format!("{error}"),
            }
        })?;

    let status = response.status();
    if !status.is_success() {
        warn!(?status, "anchor-view: non-success status");
        return Err(AnchorViewError::PrincipalServerStatus {
            status: status.as_u16(),
        });
    }

    let parsed: AnchorDagSnapshotWire = response.json().await.map_err(|error| {
        warn!(?error, "anchor-view: failed to parse response");
        AnchorViewError::PrincipalServerResponseInvalid {
            reason: format!("{error}"),
        }
    })?;

    let leaf = pick_latest_leaf(&parsed.leaves).ok_or(AnchorViewError::EmptyLeaves)?;
    debug!(
        space_id = %space_id,
        leaf_anchor_id = %leaf.anchor_id,
        "anchor-view: latest leaf selected",
    );

    Ok(LatestAnchorView {
        leaf_anchor_id: leaf.anchor_id.clone(),
        hlc: fresh_hlc(),
    })
}

/// "Latest" = greatest `created_at` (RFC 3339 string compare is monotonic
/// for canonical UTC timestamps). Falls back to the first leaf when no
/// entry has a `created_at` field — soland emits leaves newest-first by
/// natural ordering, so that's still a sensible default.
fn pick_latest_leaf(leaves: &[AnchorLeafWire]) -> Option<&AnchorLeafWire> {
    if leaves.is_empty() {
        return None;
    }
    let mut best: Option<&AnchorLeafWire> = None;
    for leaf in leaves {
        if leaf.anchor_id.is_empty() {
            continue;
        }
        match (&best, &leaf.created_at) {
            (None, _) => best = Some(leaf),
            (Some(b), Some(leaf_ts)) => {
                if let Some(best_ts) = &b.created_at {
                    if leaf_ts > best_ts {
                        best = Some(leaf);
                    }
                } else {
                    best = Some(leaf);
                }
            }
            (Some(_), None) => {}
        }
    }
    // If no `created_at` field anywhere, fall back to the first non-empty leaf.
    best.or_else(|| leaves.iter().find(|l| !l.anchor_id.is_empty()))
}

/// Generate a fresh HLC `<unix-ms-hex>-<logical-hex>-<node-hex>` that
/// passes `contrix_core::Hlc::new` validation:
/// - `unix-ms` must be 12 lowercase hex chars,
/// - `logical` must be 8 lowercase hex chars,
/// - `node` must be 8 lowercase hex chars,
/// - total length 30 with `-` at indices 12 and 21.
///
/// The logical counter is fixed at `0` (anchorer flow is single-issuer and
/// not expected to emit two Moves within the same millisecond); the node id
/// is derived from a fresh random 32-bit value so two parallel anchorers
/// can't collide.
fn fresh_hlc() -> String {
    use rand::RngExt as _;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let unix_ms = (now_ms.max(0) as u64) & 0x0000_FFFF_FFFF_FFFF;
    let mut node_bytes = [0u8; 4];
    rand::rng().fill(&mut node_bytes[..]);
    let node = u32::from_be_bytes(node_bytes);
    format!("{unix_ms:012x}-00000000-{node:08x}")
}

/// Resolve the holder's principal control Space from their DID.
///
/// **Convention** (until soland exposes a canonical
/// `account/{did}/principal-space` endpoint): map a DID to a deterministic
/// `cx:space:` UUIDv7 by `sha256(did)` → take the first 16 bytes, then
/// rewrite the version + variant nibbles so the result is a valid RFC 9562
/// UUIDv7. This keeps the convention reproducible across coauth /
/// soland / sodmin without any cross-service round-trip.
///
/// If/when soland publishes a real lookup endpoint, swap this for an
/// HTTP call and keep the deterministic mapping as the offline fallback.
pub fn holder_principal_space_for_did(holder_did: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"cx:space:principal-control:v1:");
    hasher.update(holder_did.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Force UUIDv7 version (top nibble of byte 6 = 0x7) and RFC-9562
    // variant (top two bits of byte 8 = 0b10).
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let h = |b: u8| -> String { format!("{b:02x}") };
    let group = |slice: &[u8]| -> String { slice.iter().copied().map(h).collect::<String>() };
    format!(
        "cx:space:{}-{}-{}-{}-{}",
        group(&bytes[0..4]),
        group(&bytes[4..6]),
        group(&bytes[6..8]),
        group(&bytes[8..10]),
        group(&bytes[10..16]),
    )
}

// `urlencoding` is not in the dep graph; mirror the tiny helper used by
// `consent_cell_query::urlencoding` so we don't pull in a new crate just
// for path-segment escaping.
mod urlencoding {
    pub fn encode_path(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            let safe = matches!(
                b,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
                    | b'.' | b'-' | b'_' | b'~' | b':' | b'*'
            );
            if safe {
                out.push(b as char);
            } else {
                use std::fmt::Write as _;
                let _ = write!(out, "%{:02X}", b);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_utils::setup;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    #[tokio::test]
    async fn anchor_view_returns_typed_error_when_url_missing() {
        setup();
        let client = reqwest::Client::new();
        let err = query_latest_anchor(None, "cx:space:abc", &client)
            .await
            .unwrap_err();
        assert_eq!(err, AnchorViewError::PrincipalServerNotConfigured);
    }

    #[tokio::test]
    async fn anchor_view_picks_latest_leaf_by_created_at() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/api/admin/v1/spaces/.*/anchor-dag"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "space_id": "cx:space:test",
                "leaves": [
                    {
                        "anchor_id": "cx:anchor:sha256:1111111111111111111111111111111111111111111111111111111111111111",
                        "created_at": "2026-05-09T10:00:00Z",
                    },
                    {
                        "anchor_id": "cx:anchor:sha256:2222222222222222222222222222222222222222222222222222222222222222",
                        "created_at": "2026-05-09T11:00:00Z",
                    }
                ],
                "frontier": [],
                "state_root": null,
            })))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let view = query_latest_anchor(Some(&base), "cx:space:test", &client)
            .await
            .unwrap();
        assert_eq!(
            view.leaf_anchor_id,
            "cx:anchor:sha256:2222222222222222222222222222222222222222222222222222222222222222"
        );
        // HLC shape: 12-hex + - + 8-hex + - + 8-hex.
        assert_eq!(view.hlc.len(), 30);
        assert_eq!(view.hlc.as_bytes()[12], b'-');
        assert_eq!(view.hlc.as_bytes()[21], b'-');
    }

    #[tokio::test]
    async fn anchor_view_falls_back_to_first_leaf_when_no_created_at() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/api/admin/v1/spaces/.*/anchor-dag"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "space_id": "cx:space:test",
                "leaves": [
                    { "anchor_id": "cx:anchor:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                    { "anchor_id": "cx:anchor:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
                ],
                "frontier": [],
            })))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let view = query_latest_anchor(Some(&base), "cx:space:test", &client)
            .await
            .unwrap();
        // First non-empty leaf wins when no `created_at` is present.
        assert_eq!(
            view.leaf_anchor_id,
            "cx:anchor:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[tokio::test]
    async fn anchor_view_errors_when_leaves_empty() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/api/admin/v1/spaces/.*/anchor-dag"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "space_id": "cx:space:test",
                "leaves": [],
                "frontier": [],
            })))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let err = query_latest_anchor(Some(&base), "cx:space:test", &client)
            .await
            .unwrap_err();
        assert_eq!(err, AnchorViewError::EmptyLeaves);
    }

    #[tokio::test]
    async fn anchor_view_errors_on_5xx() {
        setup();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        Mock::given(method("GET"))
            .and(path_regex(r"^/api/admin/v1/spaces/.*/anchor-dag"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let err = query_latest_anchor(Some(&base), "cx:space:test", &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AnchorViewError::PrincipalServerStatus { status: 503 }
        ));
    }

    #[test]
    fn fresh_hlc_passes_contrix_core_validation() {
        let s = fresh_hlc();
        // Round-trip through `contrix_core::Hlc` so we know the format
        // matches what `UnsignedMove.hlc` will accept.
        let parsed = contrix_core::Hlc::new(s.clone()).unwrap();
        assert_eq!(parsed.as_str(), s);
    }

    #[test]
    fn holder_principal_space_for_did_is_deterministic_and_strict_uuid7() {
        let a = holder_principal_space_for_did("did:web:alice.example");
        let b = holder_principal_space_for_did("did:web:alice.example");
        assert_eq!(a, b, "mapping must be deterministic for stable replay");
        let c = holder_principal_space_for_did("did:web:bob.example");
        assert_ne!(a, c, "different DIDs must map to different spaces");
        // SDK validates `cx:space:` IDs as strict UUIDv7 — let it round-trip
        // so we know the convention is accepted by the wire layer.
        contrix_core::SpaceId::new(a).unwrap();
        contrix_core::SpaceId::new(c).unwrap();
    }
}
