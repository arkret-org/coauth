//! Flow execution engine.
//!
//! Provides a framework for executing multi-step user interaction flows
//! (registration, recovery, authentication, etc.) as composable stage
//! sequences, inspired by authentik's flow architecture.

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::Utc;
use coauth_data::flow::FlowSession;
use tokio::sync::RwLock;
use ulid::Ulid;

pub mod defaults;
pub mod definition;
mod executor;
pub mod stages;

pub use self::defaults::{
    default_authentication_flow, default_authorization_flow, default_enrollment_flow,
    default_password_change_flow, default_recovery_flow, default_registration_flow,
};
pub use self::executor::{CaptchaVerifyContext, FlowExecutor, FlowPlan, FlowPlannerError};

// ---------------------------------------------------------------------------
// Shared in-memory session store
// ---------------------------------------------------------------------------

/// In-memory store for active flow sessions.
///
/// Maps `session_id -> (FlowPlan, FlowSession)`.  This is intentionally
/// simple — a proper database-backed store will replace this once
/// `FlowSession` gets a repository implementation.
///
/// This is shared between `rest/flow.rs` (the flow API endpoints) and the
/// legacy handler integration (registration, recovery, password change).
static FLOW_SESSION_STORE: LazyLock<RwLock<HashMap<Ulid, (FlowPlan, FlowSession)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Hard upper bound on the number of concurrent in-memory flow sessions.
///
/// `start_flow` is reachable unauthenticated, so without a cap an attacker
/// could grow this map without bound (a slow-DoS on process memory). When the
/// cap is reached we evict expired sessions first, then the oldest sessions.
const MAX_FLOW_SESSIONS: usize = 50_000;

/// Get a write lock on the flow session store.
pub(crate) async fn flow_session_store_write()
-> tokio::sync::RwLockWriteGuard<'static, HashMap<Ulid, (FlowPlan, FlowSession)>> {
    FLOW_SESSION_STORE.write().await
}

/// Drop expired sessions from `store`, then — if still at or above the
/// capacity cap — evict the oldest sessions by `expires_at` until back under
/// the cap. Call this under the write lock before inserting a new session.
pub(crate) fn evict_flow_sessions(store: &mut HashMap<Ulid, (FlowPlan, FlowSession)>) {
    let now = Utc::now();
    store.retain(|_, (_, session)| session.expires_at > now);

    if store.len() >= MAX_FLOW_SESSIONS {
        let mut expiries: Vec<_> = store.values().map(|(_, s)| s.expires_at).collect();
        expiries.sort_unstable();
        // Evict the oldest ~10% slab to amortise the O(n) scan across many
        // inserts rather than scanning on every call once full.
        let target = store.len() / 10 + 1;
        let cutoff = expiries[target.min(expiries.len() - 1)];
        store.retain(|_, (_, session)| session.expires_at > cutoff);
    }
}
