// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 — frontier source for `cx.policy.check`.
//!
//! The spec ([`policy-server.md` §4]) requires every signed decision to
//! carry three frontier digests:
//!
//! - `auth_state_digest` — accepted authorization-state root used during
//!   evaluation;
//! - `policy_frontier_digest` — policy-source frontier digest;
//! - `membership_frontier_digest` — membership / role frontier digest.
//!
//! These come from soland's `/api/v1/events/frontier?peer_role=
//! federation_peer` response, which returns
//! [`contrix_core::EventsFrontierFederationPeerResponse`] including a
//! single `frontier_root`. The federation-peer variant is the only one
//! that exposes the root commitment; account-client and
//! anonymous-health variants intentionally omit it.
//!
//! ## Pluggable
//!
//! We define a [`FrontierSource`] trait so handler code never sees the
//! HTTP wiring. Implementations:
//!
//! - [`SolandFrontierSource`] — production. Holds the soland base URL + shared
//!   `reqwest::Client`; performs the GET and maps the result.
//! - [`StaticFrontierSource`] — tests. Returns a fixed frontier so the unit
//!   tests in `policy_check.rs` can assert byte-equal transcripts without
//!   standing up an HTTP mock.
//!
//! The trait is `async_trait`-free deliberately — the futures are
//! `BoxFuture` so the trait stays object-safe for `dyn FrontierSource`.

use std::{fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use contrix_core::{Hash, RealmId};
use thiserror::Error;
use url::Url;

use crate::outbound_http;

#[derive(Debug, Error)]
pub enum FrontierError {
    #[error("frontier fetch failed: {0}")]
    Http(String),
    #[error("frontier response missing required field {0}")]
    MissingField(&'static str),
    #[error("frontier response payload is not the expected federation-peer shape")]
    InvalidShape,
    #[error("frontier fetch deadline exceeded")]
    Timeout,
}

/// The three frontier hashes that bind a policy decision to the
/// authorization / policy / membership state at decision time.
///
/// All fields are required by the spec; an evaluator MUST NOT fabricate
/// them. The "unknown frontier" sentinel below is reserved for the
/// failure path where soland is unreachable AND the fail mode is
/// fail-closed (we still emit the response so the caller can verify the
/// signature, but the decision is `deny`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frontier {
    pub auth_state_digest: Hash,
    pub policy_frontier_digest: Hash,
    pub membership_frontier_digest: Hash,
    /// Optional `policy_version` echo. When absent the evaluator
    /// substitutes `"v1"`.
    pub policy_version: Option<String>,
}

impl Frontier {
    /// "Unknown frontier" sentinel — `sha256("")` repeated for all
    /// three hashes. Downstream verifiers recognise this as the
    /// fail-closed marker.
    #[must_use]
    pub fn empty() -> Self {
        // Construct once and clone; the canonical form is the same for
        // every invocation.
        let empty = Hash::new(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
        )
        .expect("sentinel hash is structurally valid");
        Self {
            auth_state_digest: empty.clone(),
            policy_frontier_digest: empty.clone(),
            membership_frontier_digest: empty,
            policy_version: None,
        }
    }
}

/// Source the per-realm authorization / policy / membership frontier
/// digests from. Object-safe so handlers can carry a
/// `Arc<dyn FrontierSource>` in app state.
pub trait FrontierSource: Send + Sync {
    /// Fetch the frontier for the realm being evaluated. Returns
    /// [`FrontierError::Timeout`] if the underlying source does not
    /// respond within its configured deadline; the caller decides
    /// whether to fail-closed (deny) or fall back to a sentinel.
    fn fetch<'a>(
        &'a self,
        realm_id: &'a RealmId,
    ) -> Pin<Box<dyn Future<Output = Result<Frontier, FrontierError>> + Send + 'a>>;
}

impl fmt::Debug for dyn FrontierSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dyn FrontierSource")
    }
}

/// Production frontier source — calls soland's federation-peer frontier
/// endpoint and lifts `frontier_root` into
/// [`Frontier::policy_frontier_digest`].
///
/// Today soland only exposes a single `frontier_root` covering all
/// federation-visible events; the spec splits the digest into three
/// (auth / policy / membership) but soland has not yet wired separate
/// roots. We therefore use `frontier_root` for all three slots and
/// leave a clearly-marked TODO so the next round of soland work can
/// switch to dedicated roots without touching the policy-check handler.
pub struct SolandFrontierSource {
    base_url: Option<Url>,
    http_client: reqwest::Client,
    request_timeout: Duration,
}

impl SolandFrontierSource {
    /// `base_url` is `contrix_config.principal_server_url`; when `None`
    /// (single-host dev deployments) every fetch returns
    /// [`Frontier::empty`] so the policy-check pipeline still produces
    /// a signed response.
    #[must_use]
    pub fn new(base_url: Option<Url>, http_client: reqwest::Client) -> Self {
        Self {
            base_url,
            http_client,
            // Hard ceiling: leave headroom under the 2 s evaluator
            // deadline so the evaluator can time out before the
            // frontier fetch does. Tuneable later from config.
            request_timeout: Duration::from_millis(1_500),
        }
    }
}

impl FrontierSource for SolandFrontierSource {
    fn fetch<'a>(
        &'a self,
        realm_id: &'a RealmId,
    ) -> Pin<Box<dyn Future<Output = Result<Frontier, FrontierError>> + Send + 'a>> {
        Box::pin(async move {
            let Some(base) = self.base_url.as_ref() else {
                // No principal server configured. Spec-compliant
                // fallback: emit the sentinel so the response is still
                // signable but verifiers recognise the missing root.
                return Ok(Frontier::empty());
            };

            // TODO(G3.S0): when soland exposes dedicated
            // `auth_state_root`, `policy_frontier_root`,
            // `membership_frontier_root` fields on
            // `EventsFrontierFederationPeerResponse`, plumb each into
            // the matching slot below instead of duplicating
            // `frontier_root`. See `soland/src/routing/events/event_log.rs`
            // around `events_frontier` for the response builder.
            let mut url = base
                .join("api/v1/events/frontier")
                .map_err(|e| FrontierError::Http(format!("invalid frontier URL: {e}")))?;

            // soland scopes by query params: peer_role=federation_peer
            // plus the realm id so receivers only see the visible
            // events for the realm being evaluated. We build the query
            // string manually because the `query` builder method on
            // `reqwest::RequestBuilder` requires the `serde_urlencoded`
            // dep which isn't enabled in coauth-backend's reqwest
            // feature set.
            {
                let mut pairs = url.query_pairs_mut();
                pairs.append_pair("peer_role", "federation_peer");
                pairs.append_pair("realm_id", realm_id.as_str());
            }

            let response = outbound_http::send_with_policy(
                outbound_http::policy_frontier_policy().with_timeout(self.request_timeout),
                || self.http_client.get(url.clone()),
            )
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    FrontierError::Timeout
                } else {
                    FrontierError::Http(e.to_string())
                }
            })?;

            if !response.status().is_success() {
                return Err(FrontierError::Http(format!(
                    "soland frontier returned HTTP {}",
                    response.status()
                )));
            }

            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| FrontierError::Http(format!("frontier body parse: {e}")))?;

            // soland's response envelope places the typed federation
            // peer response under `events_frontier`; the inner shape
            // is `EventsFrontierFederationPeerResponse`. We probe
            // defensively so a soland that hasn't migrated yet (or a
            // mock that returns the legacy envelope) still produces a
            // signed sentinel rather than a 500.
            let frontier_root = body
                .get("events_frontier")
                .and_then(|v| v.get("frontier_root"))
                .and_then(|v| v.as_str())
                .ok_or(FrontierError::MissingField("frontier_root"))?;

            let h = Hash::new(frontier_root.to_owned()).map_err(|_| FrontierError::InvalidShape)?;
            Ok(Frontier {
                auth_state_digest: h.clone(),
                policy_frontier_digest: h.clone(),
                membership_frontier_digest: h,
                policy_version: Some("v1".to_owned()),
            })
        })
    }
}

/// Test-only frontier source returning a fixed value. Exposed at crate
/// level so the integration tests in `handlers::policy_check::tests`
/// can stand it up without touching `reqwest`.
pub struct StaticFrontierSource {
    pub frontier: Frontier,
}

impl StaticFrontierSource {
    #[must_use]
    pub fn new(frontier: Frontier) -> Self {
        Self { frontier }
    }
}

impl FrontierSource for StaticFrontierSource {
    fn fetch<'a>(
        &'a self,
        _realm_id: &'a RealmId,
    ) -> Pin<Box<dyn Future<Output = Result<Frontier, FrontierError>> + Send + 'a>> {
        let frontier = self.frontier.clone();
        Box::pin(async move { Ok(frontier) })
    }
}

/// Type alias for the shared, depot-injected handle. Handlers extract a
/// clone via `DepotExt::policy_frontier_source` (see `app_state.rs`).
pub type PolicyFrontierSourceHandle = Arc<dyn FrontierSource>;

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use super::*;

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn realm() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    #[tokio::test]
    async fn static_source_returns_configured_frontier() {
        let frontier = Frontier::empty();
        let source = StaticFrontierSource::new(frontier.clone());
        let got = source.fetch(&realm()).await.unwrap();
        assert_eq!(got, frontier);
    }

    #[tokio::test]
    async fn soland_source_with_no_base_url_returns_sentinel() {
        install_crypto_provider();
        let source = SolandFrontierSource::new(None, reqwest::Client::new());
        let got = source.fetch(&realm()).await.unwrap();
        assert_eq!(got, Frontier::empty());
    }

    #[test]
    fn empty_sentinel_hashes_are_canonical_sha256_empty() {
        let empty = Frontier::empty();
        assert_eq!(
            empty.auth_state_digest.as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(empty.auth_state_digest, empty.policy_frontier_digest);
        assert_eq!(
            empty.policy_frontier_digest,
            empty.membership_frontier_digest
        );
    }
}
