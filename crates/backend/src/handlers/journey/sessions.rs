//! Process-local ownership for the currently exposed Journey REST surface.
//! Product authentication and durable side effects belong to owning services.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use chrono::{DateTime, Utc};
use coauth_data::journey::JourneySession;
use tokio::sync::{Mutex, RwLock, RwLockReadGuard};
use ulid::Ulid;

use super::JourneyPlan;

pub(crate) static SESSIONS: LazyLock<JourneySessions> =
    LazyLock::new(|| JourneySessions::new(50_000));

pub(crate) struct JourneyState {
    pub plan: JourneyPlan,
    pub session: JourneySession,
}

#[derive(Clone)]
struct Entry {
    expires_at: DateTime<Utc>,
    state: Arc<Mutex<JourneyState>>,
}

pub(crate) struct SessionLease {
    id: Ulid,
    pub state: Arc<Mutex<JourneyState>>,
}

pub(crate) struct JourneySessions {
    entries: RwLock<HashMap<Ulid, Entry>>,
    capacity: usize,
}

impl JourneySessions {
    fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            entries: RwLock::new(HashMap::new()),
            capacity,
        }
    }

    pub async fn insert(&self, plan: JourneyPlan, session: JourneySession) {
        let mut entries = self.entries.write().await;
        let now = Utc::now();
        entries.retain(|_, entry| entry.expires_at > now);
        if entries.len() >= self.capacity {
            let mut expiries = entries
                .values()
                .map(|entry| entry.expires_at)
                .collect::<Vec<_>>();
            expiries.sort_unstable();
            // Preserve the existing oldest-ten-percent capacity eviction policy.
            let target = entries.len() / 10 + 1;
            let cutoff = expiries[target.min(expiries.len() - 1)];
            entries.retain(|_, entry| entry.expires_at > cutoff);
        }
        entries.insert(
            session.id,
            Entry {
                expires_at: session.expires_at,
                state: Arc::new(Mutex::new(JourneyState { plan, session })),
            },
        );
    }

    pub async fn get(&self, id: Ulid) -> Option<SessionLease> {
        let mut entries = self.entries.write().await;
        let entry = entries.get(&id)?;
        // Terminal sessions have the same bounded lifetime as active sessions.
        if entry.expires_at <= Utc::now() {
            entries.remove(&id);
            return None;
        }
        Some(SessionLease {
            id,
            state: Arc::clone(&entry.state),
        })
    }

    /// Hold this only during synchronous admission/commit, never external I/O.
    /// A stale handle cannot commit after expiration or capacity eviction.
    pub async fn admit(&self, lease: &SessionLease) -> Option<Admission<'_>> {
        let entries = self.entries.read().await;
        let entry = entries.get(&lease.id)?;
        if entry.expires_at <= Utc::now() || !Arc::ptr_eq(&entry.state, &lease.state) {
            return None;
        }
        Some(Admission { _entries: entries })
    }
}

pub(crate) struct Admission<'a> {
    _entries: RwLockReadGuard<'a, HashMap<Ulid, Entry>>,
}

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;
