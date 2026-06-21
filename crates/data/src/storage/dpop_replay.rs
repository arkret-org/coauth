//! Durable DPoP proof replay repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::repository_impl;

/// Parameters used to record a DPoP proof `jti` replay key.
#[derive(Debug, Clone)]
pub struct NewDpopJtiReplay {
    /// SHA-256 digest of the caller-supplied `jti`.
    pub jti_digest: String,
    /// Time the verifier accepted the proof.
    pub seen_at: DateTime<Utc>,
    /// Replay-window expiry. The row can be pruned after this instant.
    pub expires_at: DateTime<Utc>,
}

/// Repository for durable DPoP proof `jti` replay detection.
#[async_trait]
pub trait DpopReplayRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Atomically consume a DPoP `jti`. Returns `true` when the insert won
    /// the single-use race and `false` when the digest already exists inside
    /// the replay window.
    async fn consume_jti(&mut self, params: NewDpopJtiReplay) -> Result<bool, Self::Error>;
}

repository_impl!(DpopReplayRepository:
    async fn consume_jti(
        &mut self,
        params: NewDpopJtiReplay,
    ) -> Result<bool, Self::Error>;
);
