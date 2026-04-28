use salvo::prelude::*;
use sentry::types::Uuid;

/// A wrapper to include a Sentry event ID in the response headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SentryEventID(Uuid);

impl SentryEventID {
    /// Create a new Sentry event ID header for the last event on the hub.
    pub fn for_last_event() -> Option<Self> {
        sentry::last_event_id().map(Self)
    }

    /// Write the Sentry event ID to the response headers
    pub fn write_to_response(&self, res: &mut Response) {
        if let Ok(value) = http::HeaderValue::from_str(&self.0.to_string()) {
            res.headers_mut().insert("X-Sentry-Event-ID", value);
        }
    }
}

impl std::fmt::Display for SentryEventID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for SentryEventID {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

/// Record an error. It will emit a tracing event with the error level if
/// matches the pattern, warning otherwise. It also returns the Sentry event ID
/// if the error was recorded.
#[macro_export]
macro_rules! record_error {
    ($error:expr, !) => {{
        tracing::warn!(message = &$error as &dyn std::error::Error);
        Option::<$crate::salvo_utils::sentry::SentryEventID>::None
    }};

    ($error:expr) => {{
        tracing::error!(message = &$error as &dyn std::error::Error);

        // With the `sentry-tracing` integration, Sentry should have
        // captured an error, so let's extract the last event ID from the
        // current hub
        $crate::salvo_utils::sentry::SentryEventID::for_last_event()
    }};

    ($error:expr, $pattern:pat) => {
        if let $pattern = $error {
            record_error!($error)
        } else {
            record_error!($error, !)
        }
    };
}
