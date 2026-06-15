//! Strand execution engine.
//!
//! Provides a framework for executing multi-step user interaction strands
//! (registration, recovery, authentication, etc.) as composable stage
//! sequences, inspired by authentik's strand architecture.

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::Utc;
use coauth_data::strand::StrandSession;
use tokio::sync::RwLock;
use ulid::Ulid;

pub mod defaults;
pub mod definition;
mod executor;
pub mod stages;

pub use self::defaults::{
    default_authentication_strand, default_authorization_strand, default_enrollment_strand,
    default_password_change_strand, default_recovery_strand, default_registration_strand,
};
pub use self::executor::{CaptchaVerifyContext, StrandExecutor, StrandPlan, StrandPlannerError};

// ---------------------------------------------------------------------------
// Shared in-memory session store
// ---------------------------------------------------------------------------

/// In-memory store for active strand sessions.
///
/// Maps `session_id -> (StrandPlan, StrandSession)`.  This is intentionally
/// simple — a proper database-backed store will replace this once
/// `StrandSession` gets a repository implementation.
///
/// This is shared between `rest/strand.rs` (the strand API endpoints) and
/// account-flow handlers (registration, recovery, password change).
static STRAND_SESSION_STORE: LazyLock<RwLock<HashMap<Ulid, (StrandPlan, StrandSession)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Hard upper bound on the number of concurrent in-memory strand sessions.
///
/// `start_strand` is reachable unauthenticated, so without a cap an attacker
/// could grow this map without bound (a slow-DoS on process memory). When the
/// cap is reached we evict expired sessions first, then the oldest sessions.
const MAX_STRAND_SESSIONS: usize = 50_000;

/// Get a write lock on the strand session store.
pub(crate) async fn strand_session_store_write()
-> tokio::sync::RwLockWriteGuard<'static, HashMap<Ulid, (StrandPlan, StrandSession)>> {
    STRAND_SESSION_STORE.write().await
}

/// Drop expired sessions from `store`, then — if still at or above the
/// capacity cap — evict the oldest sessions by `expires_at` until back under
/// the cap. Call this under the write lock before inserting a new session.
pub(crate) fn evict_strand_sessions(store: &mut HashMap<Ulid, (StrandPlan, StrandSession)>) {
    let now = Utc::now();
    store.retain(|_, (_, session)| session.expires_at > now);

    if store.len() >= MAX_STRAND_SESSIONS {
        let mut expiries: Vec<_> = store.values().map(|(_, s)| s.expires_at).collect();
        expiries.sort_unstable();
        // Evict the oldest ~10% slab to amortise the O(n) scan across many
        // inserts rather than scanning on every call once full.
        let target = store.len() / 10 + 1;
        let cutoff = expiries[target.min(expiries.len() - 1)];
        store.retain(|_, (_, session)| session.expires_at > cutoff);
    }
}
