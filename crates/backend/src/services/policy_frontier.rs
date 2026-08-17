// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 — frontier source for `ak.self.policy.read.check`.
//!
//! The spec ([`policy-server.md` §4]) requires every signed decision to
//! carry three frontier digests:
//!
//! - `auth_state_digest` — accepted authorization-state root used during evaluation;
//! - `policy_frontier_digest` — policy-source frontier digest;
//! - `membership_frontier_digest` — membership / role frontier digest.
//!
//! These come from soland's `/_arkret/self/events/frontier?peer_role=
//! federation_peer` response, which returns
//! [`arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState`] including a
//! single `frontier_root`. The federation-peer variant is the only one
//! that exposes the root commitment; account-client and
//! anonymous-health variants intentionally omit it.
//!
//! ## Pluggable
//!
//! We define a [`FrontierSource`] trait so handler code never sees the
//! HTTP wiring. Implementations:
//!
//! - [`SolandFrontierSource`] — production. Holds the soland base URL + shared `reqwest::Client`;
//!   performs the registered QUERY operation and maps the result.
//! - [`StaticFrontierSource`] — tests. Returns a fixed frontier so the unit tests in
//!   `policy_check.rs` can assert byte-equal transcripts without standing up an HTTP mock.
//!
//! The trait is `async_trait`-free deliberately — the futures are
//! `BoxFuture` so the trait stays object-safe for `dyn FrontierSource`.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arkret_identifiers::{Hash, RealmId};
use arkret_models_collaboration::event_query::PeerEventsFrontierRequestBody;
use arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding;
use arkret_wire::FreshnessState;
use chrono::{DateTime, Utc};
use thiserror::Error;
use url::Url;

use crate::services::peer_protocol_client::PeerProtocolClient;

const FRESHNESS_REQUIRED_MS: i64 = 180_000;
const CLOCK_SKEW_TOLERANCE_MS: i64 = 60_000;

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
    pub freshness_state: FreshnessState,
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
            freshness_state: FreshnessState::Unknown,
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
    signing: Option<(
        coauth_keystore::Keystore,
        arkret_identifiers::DidFullId,
        KeyPackagesClaimServiceBinding,
        arkret_identifiers::TrustDomainId,
        arkret_identifiers::TrustDomainId,
    )>,
}

impl SolandFrontierSource {
    /// `base_url` is the primary configured Principal Server endpoint; when `None`
    /// (single-host dev deployments) every fetch returns
    /// [`Frontier::empty`] so the policy-check pipeline still produces
    /// a signed response.
    #[must_use]
    pub fn new(
        base_url: Option<Url>,
        http_client: reqwest::Client,
        signing: Option<(
            coauth_keystore::Keystore,
            arkret_identifiers::DidFullId,
            KeyPackagesClaimServiceBinding,
            arkret_identifiers::TrustDomainId,
            arkret_identifiers::TrustDomainId,
        )>,
    ) -> Self {
        Self {
            base_url,
            http_client,
            // Hard ceiling: leave headroom under the 2 s evaluator
            // deadline so the evaluator can time out before the
            // frontier fetch does. Tuneable later from config.
            request_timeout: Duration::from_millis(1_500),
            signing,
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
            // `EventsFrontierFederationPeerState`, plumb each into
            // the matching slot below instead of duplicating
            // `frontier_root`. See `soland/src/routing/events/event_log.rs`
            // around `events_frontier` for the response builder.
            // Spec-canonical federation-peer frontier path is the
            // version-less `/_arkret/peer/events/frontier`. We join with
            // a leading slash so the absolute path replaces any existing
            // path on `principal_server_url` rather than being resolved
            // relative to it (URL relative-resolution would otherwise
            // truncate the last base segment).
            let (keystore, source_full_id, identity, source_trust_domain, destination_trust_domain) =
                self.signing.as_ref().ok_or_else(|| {
                    FrontierError::Http("peer frontier signing identity is unavailable".to_owned())
                })?;
            let client = PeerProtocolClient::new(
                Some(base),
                &self.http_client,
                keystore,
                source_full_id.clone(),
                identity.clone(),
                source_trust_domain.clone(),
                destination_trust_domain.clone(),
            )
            .map_err(|error| FrontierError::Http(error.to_string()))?;
            let request = PeerEventsFrontierRequestBody {
                realm_id: realm_id.clone(),
            };
            let frontier =
                tokio::time::timeout(self.request_timeout, client.read_events_frontier(&request))
                    .await
                    .map_err(|_| FrontierError::Timeout)?
                    .map_err(|error| FrontierError::Http(error.to_string()))?;

            let h = frontier.frontier_root.clone();
            let freshness_state = frontier_freshness_state(&frontier.observed_at, Utc::now());
            Ok(Frontier {
                auth_state_digest: h.clone(),
                policy_frontier_digest: h.clone(),
                membership_frontier_digest: h,
                freshness_state,
                policy_version: Some("v1".to_owned()),
            })
        })
    }
}

fn frontier_freshness_state(observed_at: &str, now: DateTime<Utc>) -> FreshnessState {
    let Ok(observed_at) =
        DateTime::parse_from_rfc3339(observed_at).map(|ts| ts.with_timezone(&Utc))
    else {
        return FreshnessState::Unknown;
    };
    let age_ms = now.signed_duration_since(observed_at).num_milliseconds();
    if age_ms < -CLOCK_SKEW_TOLERANCE_MS {
        return FreshnessState::Unknown;
    }
    if age_ms <= FRESHNESS_REQUIRED_MS {
        FreshnessState::Fresh
    } else {
        FreshnessState::Stale
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
        RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap()
    }

    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-20T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
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
        let source = SolandFrontierSource::new(None, reqwest::Client::new(), None);
        let got = source.fetch(&realm()).await.unwrap();
        assert_eq!(got, Frontier::empty());
        assert_eq!(got.freshness_state, FreshnessState::Unknown);
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

    #[test]
    fn observed_frontier_within_required_window_is_fresh() {
        assert_eq!(
            frontier_freshness_state("2026-06-19T23:58:30.000Z", fixed_now()),
            FreshnessState::Fresh
        );
    }

    #[test]
    fn observed_frontier_outside_required_window_is_stale() {
        assert_eq!(
            frontier_freshness_state("2026-06-19T23:55:00.000Z", fixed_now()),
            FreshnessState::Stale
        );
    }

    #[test]
    fn missing_or_future_frontier_observation_is_unknown() {
        // An unparseable / absent timestamp yields Unknown.
        assert_eq!(
            frontier_freshness_state("", fixed_now()),
            FreshnessState::Unknown
        );
        assert_eq!(
            frontier_freshness_state("2026-06-20T00:02:00.000Z", fixed_now()),
            FreshnessState::Unknown
        );
    }
}
