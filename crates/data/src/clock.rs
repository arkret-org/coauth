//! Abstractions over wall-clock time.
//!
//! Production code uses [`SystemClock`] to obtain the real time, while tests
//! can substitute a [`MockClock`] whose value is fully deterministic and can
//! be moved forward on demand.

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use chrono::{DateTime, Utc};

/// A source of "current" timestamps.
///
/// Implementors must be safe to share across threads.
pub trait Clock: Send + Sync {
    /// Return the current instant as a UTC datetime.
    fn now(&self) -> DateTime<Utc>;
}

// Delegate through `Arc` so that cloned handles share the same clock.
impl<C: Clock + Send + ?Sized> Clock for Arc<C> {
    fn now(&self) -> DateTime<Utc> {
        (**self).now()
    }
}

// Delegate through `Box` so that trait-object holders can call `now()`.
impl<C: Clock + ?Sized> Clock for Box<C> {
    fn now(&self) -> DateTime<Utc> {
        (**self).now()
    }
}

/// Wall-clock implementation that returns the real system time.
#[derive(Clone, Default)]
pub struct SystemClock {
    _private: (),
}

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        #[allow(clippy::disallowed_methods)]
        Utc::now()
    }
}

/// A controllable clock for use in tests.
///
/// Internally stores a Unix timestamp as an atomic integer so it can be
/// shared across threads without a mutex.  The time starts at whatever
/// instant is supplied to [`MockClock::new`] and only changes when
/// [`MockClock::advance`] is called.
pub struct MockClock {
    epoch_secs: AtomicI64,
}

impl Default for MockClock {
    /// Creates a mock clock pinned to 2022-01-16 14:40:00 UTC.
    fn default() -> Self {
        let dt = chrono::TimeZone::with_ymd_and_hms(&Utc, 2022, 1, 16, 14, 40, 0).unwrap();
        Self::new(dt)
    }
}

impl MockClock {
    /// Build a mock clock starting at `start`.
    #[must_use]
    pub fn new(start: DateTime<Utc>) -> Self {
        Self {
            epoch_secs: AtomicI64::new(start.timestamp()),
        }
    }

    /// Push the clock forward by `delta`.
    ///
    /// Negative durations are technically accepted by the underlying atomic
    /// add, but callers should treat this as moving time forward only.
    pub fn advance(&self, delta: chrono::Duration) {
        self.epoch_secs
            .fetch_add(delta.num_seconds(), Ordering::Relaxed);
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        let ts = self.epoch_secs.load(Ordering::Relaxed);
        DateTime::from_timestamp(ts, 0).expect("stored timestamp is always valid")
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn mock_clock_is_frozen_by_default() {
        let clk = MockClock::default();

        let t1 = clk.now();
        // A short sleep must not move the mock clock.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = clk.now();

        assert_eq!(t1, t2, "mock clock should not advance on its own");
    }

    #[test]
    fn mock_clock_advances_by_requested_amount() {
        let clk = MockClock::default();
        let before = clk.now();

        let step = Duration::seconds(10);
        clk.advance(step);

        let after = clk.now();
        assert_eq!(after, before + step);
    }

    #[test]
    fn system_clock_progresses() {
        let clk = SystemClock::default();

        let t1 = clk.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = clk.now();

        assert!(t2 > t1, "real clock must move forward");
    }
}
