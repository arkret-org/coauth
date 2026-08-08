//! Debug-only transport fault hooks used by live durability tests.
//!
//! These hooks run strictly after a repository transaction has committed and
//! before the canonical HTTP response is rendered. They never alter durable
//! state or synthesize protocol outcomes; Cotest kills the real process while
//! it is paused and verifies recovery from PostgreSQL after restart.

/// Pause a selected committed request before its canonical response is sent.
///
/// The hook is inert unless all of the following hold:
///
/// - this is a debug build;
/// - `COAUTH_ENABLE_TEST_ENDPOINTS` is enabled;
/// - `COAUTH_TEST_CHAOS_BREAKPOINT` exactly equals `kind`;
/// - `COAUTH_TEST_CHAOS_REQUEST_IDENTITY`, when set, exactly equals `request_identity`;
/// - `COAUTH_TEST_CHAOS_DELAY_MS` is a positive integer.
pub(crate) async fn maybe_delay_post_commit(kind: &str, request_identity: &str) {
    #[cfg(debug_assertions)]
    {
        if !super::test_endpoints_enabled() {
            return;
        }
        let Ok(selected) = coauth_config::runtime_var("COAUTH_TEST_CHAOS_BREAKPOINT") else {
            return;
        };
        if selected.trim() != kind {
            return;
        }
        if let Ok(selected_identity) =
            coauth_config::runtime_var("COAUTH_TEST_CHAOS_REQUEST_IDENTITY")
            && selected_identity.trim() != request_identity
        {
            return;
        }
        let delay_ms = coauth_config::runtime_var("COAUTH_TEST_CHAOS_DELAY_MS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or_default();
        if delay_ms == 0 {
            return;
        }
        tracing::warn!(
            breakpoint = kind,
            request_identity,
            delay_ms,
            "coauth test chaos paused after durable commit and before response"
        );
        if let Ok(path) = coauth_config::runtime_var("COAUTH_TEST_CHAOS_REACHED_FILE") {
            let marker = format!("breakpoint={kind}\nrequest_identity={request_identity}\n");
            if let Err(error) = std::fs::write(path, marker) {
                tracing::warn!(%error, "failed to write coauth test chaos reached marker");
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (kind, request_identity);
    }
}
