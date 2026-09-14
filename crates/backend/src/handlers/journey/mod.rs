//! Journey execution engine.
//!
//! Provides a framework for executing multi-step user interaction journeys
//! (registration, recovery, authentication, etc.) as composable stage
//! sequences, inspired by authentik's journey architecture.

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::Utc;
use coauth_data::journey::JourneySession;
use tokio::sync::RwLock;
use ulid::Ulid;

pub mod defaults;
mod executor;

pub use self::defaults::{
    default_authentication_journey, default_authorization_journey, default_enrollment_journey,
    default_password_change_journey, default_recovery_journey, default_registration_journey,
};
pub use self::executor::{CaptchaVerifyContext, JourneyExecutor, JourneyPlan, JourneyPlannerError};

// ---------------------------------------------------------------------------
// Shared in-memory session store
// ---------------------------------------------------------------------------

/// In-memory store for active journey sessions.
///
/// Maps `session_id -> (JourneyPlan, JourneySession)`.  This is intentionally
/// simple — a proper database-backed store will replace this once
/// `JourneySession` gets a repository implementation.
///
/// This is shared between [`crate::handlers::account::journey`] and account-flow
/// handlers (registration, recovery, password change).
static JOURNEY_SESSION_STORE: LazyLock<RwLock<HashMap<Ulid, (JourneyPlan, JourneySession)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Hard upper bound on the number of concurrent in-memory journey sessions.
///
/// `start_journey` is reachable unauthenticated, so without a cap an attacker
/// could grow this map without bound (a slow-DoS on process memory). When the
/// cap is reached we evict expired sessions first, then the oldest sessions.
const MAX_JOURNEY_SESSIONS: usize = 50_000;

/// Get a write lock on the journey session store.
pub(crate) async fn journey_session_store_write()
-> tokio::sync::RwLockWriteGuard<'static, HashMap<Ulid, (JourneyPlan, JourneySession)>> {
    JOURNEY_SESSION_STORE.write().await
}

/// Drop expired sessions from `store`, then — if still at or above the
/// capacity cap — evict the oldest sessions by `expires_at` until back under
/// the cap. Call this under the write lock before inserting a new session.
pub(crate) fn evict_journey_sessions(store: &mut HashMap<Ulid, (JourneyPlan, JourneySession)>) {
    let now = Utc::now();
    store.retain(|_, (_, session)| session.expires_at > now);

    if store.len() >= MAX_JOURNEY_SESSIONS {
        let mut expiries: Vec<_> = store.values().map(|(_, s)| s.expires_at).collect();
        expiries.sort_unstable();
        // Evict the oldest ~10% slab to amortise the O(n) scan across many
        // inserts rather than scanning on every call once full.
        let target = store.len() / 10 + 1;
        let cutoff = expiries[target.min(expiries.len() - 1)];
        store.retain(|_, (_, session)| session.expires_at > cutoff);
    }
}
