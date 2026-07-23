use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

const MAX_ACTIVE_NONCES: usize = 16_384;

#[derive(Debug, Default, Clone)]
pub struct NonceStore {
    inner: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceReplayError;

impl NonceStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_record(
        &self,
        nonce: &str,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), NonceReplayError> {
        let mut guard = self.inner.lock().expect("nonce store mutex poisoned");
        guard.retain(|_, expiry| *expiry > now);
        if guard
            .get(nonce)
            .is_some_and(|existing_expiry| *existing_expiry > now)
        {
            return Err(NonceReplayError);
        }
        if guard.len() >= MAX_ACTIVE_NONCES {
            return Err(NonceReplayError);
        }
        guard.insert(nonce.to_owned(), expires_at);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_growth_beyond_active_nonce_limit() {
        let store = NonceStore::new();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(5);
        for index in 0..MAX_ACTIVE_NONCES {
            store
                .check_and_record(&format!("nonce-{index}"), expires_at, now)
                .unwrap();
        }
        assert_eq!(
            store.check_and_record("over-limit", expires_at, now),
            Err(NonceReplayError)
        );
    }
}
