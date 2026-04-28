//! Flow execution engine.
//!
//! Provides a framework for executing multi-step user interaction flows
//! (registration, recovery, authentication, etc.) as composable stage
//! sequences, inspired by authentik's flow architecture.

use std::{collections::HashMap, sync::LazyLock};

use coauth_data::flow::FlowSession;
use tokio::sync::RwLock;
use ulid::Ulid;

pub mod defaults;
pub mod definition;
mod executor;
pub mod stages;

pub use self::{
    defaults::{
        default_authentication_flow, default_authorization_flow, default_enrollment_flow,
        default_password_change_flow, default_recovery_flow, default_registration_flow,
    },
    executor::{CaptchaVerifyContext, FlowExecutor, FlowPlan, FlowPlannerError},
};

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

/// Get a read lock on the flow session store.
pub(crate) async fn flow_session_store_read()
-> tokio::sync::RwLockReadGuard<'static, HashMap<Ulid, (FlowPlan, FlowSession)>> {
    FLOW_SESSION_STORE.read().await
}

/// Get a write lock on the flow session store.
pub(crate) async fn flow_session_store_write()
-> tokio::sync::RwLockWriteGuard<'static, HashMap<Ulid, (FlowPlan, FlowSession)>> {
    FLOW_SESSION_STORE.write().await
}
