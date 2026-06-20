//! Database-backed [`PrincipalServerAdmin`] for coauth's account/profile facade.
//!
//! Replaces the in-memory `coauth_principal::MockPrincipalServerAdmin`, whose
//! non-persistent state lost all accounts on every coauth restart and made the
//! OIDC token-exchange device upsert fail with "No account found" (a
//! `session-grants` 500 when logging back into a pre-existing account).
//!
//! coauth's own persistent `users` table is the authoritative account store —
//! registration, profile updates and lifecycle changes write it directly (see
//! `services::user_profile` / `services::user_admin`). This adapter therefore:
//!
//! * resolves reads (`query_user`, `is_handle_available`) straight from `users`, so the value is
//!   always the real, persisted profile; and
//! * treats the account/device *mutation* hooks as no-ops — they exist to mirror state into a
//!   downstream principal projection, but here there is no separate projection to keep (the device
//!   set has no reader: the admin device list aggregates session grants, and soland is the
//!   authoritative device store).
//!
//! The result removes the mock-vs-real divergence entirely: a single source of
//! truth (`users`), persistent across restarts, no shadow state to drift.

use std::collections::HashSet;

use async_trait::async_trait;
use coauth_data::{BoxRepositoryFactory, RepositoryAccess};
use coauth_principal::{
    PrincipalAccountProfile, PrincipalCapabilityFanoutRequest, PrincipalProvisionRequest,
    PrincipalServerAdmin,
};

/// `PrincipalServerAdmin` backed by coauth's own Postgres (`users`).
pub struct DbPrincipalServerAdmin {
    server_name: String,
    repository_factory: BoxRepositoryFactory,
}

impl DbPrincipalServerAdmin {
    /// Create a facade rooted at `server_name`, reading accounts through
    /// `repository_factory`.
    #[must_use]
    pub fn new(server_name: impl Into<String>, repository_factory: BoxRepositoryFactory) -> Self {
        Self {
            server_name: server_name.into(),
            repository_factory,
        }
    }
}

#[async_trait]
impl PrincipalServerAdmin for DbPrincipalServerAdmin {
    fn principal_authority(&self) -> &str {
        self.server_name.as_str()
    }

    async fn verify_token(&self, _token: &str) -> Result<bool, anyhow::Error> {
        // coauth IS the principal authority — there is no separate downstream
        // principal service whose bearer this would validate. The
        // server-to-server bearer at the call sites (oauth introspection /
        // revoke) is checked there against the configured static principal
        // bearer (`principal_server_static_oauth_bearer_matches`), so this
        // never honours a token of its own.
        Ok(false)
    }

    async fn query_user(&self, handle: &str) -> Result<PrincipalAccountProfile, anyhow::Error> {
        let mut repo = self
            .repository_factory
            .create()
            .await
            .map_err(|error| anyhow::anyhow!("acquire repository: {error}"))?;
        let user = repo
            .user()
            .find_by_handle(handle)
            .await
            .map_err(|error| anyhow::anyhow!("user lookup: {error}"))?;
        repo.cancel().await.ok();
        let user = user.ok_or_else(|| anyhow::anyhow!("No account found for {handle}"))?;
        Ok(PrincipalAccountProfile {
            displayname: user.display_name.clone(),
            avatar_url: user.avatar_url.clone(),
            deactivated: user.deactivated_at.is_some(),
        })
    }

    async fn is_handle_available(&self, handle: &str) -> Result<bool, anyhow::Error> {
        let mut repo = self
            .repository_factory
            .create()
            .await
            .map_err(|error| anyhow::anyhow!("acquire repository: {error}"))?;
        let exists = repo
            .user()
            .exists(handle)
            .await
            .map_err(|error| anyhow::anyhow!("user exists: {error}"))?;
        repo.cancel().await.ok();
        Ok(!exists)
    }

    // ── Mutation hooks: intentional no-ops ────────────────────────────────
    // coauth maintains the authoritative `users` row directly for each of
    // these (registration creates it; `user_profile`/`user_admin` patch the
    // profile + activation; account deletion runs through the user repo /
    // DeactivateUserJob). There is no separate persistent projection to update,
    // and the device set has no reader, so mirroring here would only
    // reintroduce drift.

    async fn provision_user(
        &self,
        _request: &PrincipalProvisionRequest,
    ) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn upsert_device(
        &self,
        _handle: &str,
        _device_id: &str,
        _initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn update_device_display_name(
        &self,
        _handle: &str,
        _device_id: &str,
        _display_name: &str,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn delete_device(&self, _handle: &str, _device_id: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn sync_devices(
        &self,
        _handle: &str,
        _devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn submit_collaboration_capability_fanout(
        &self,
        request: &PrincipalCapabilityFanoutRequest,
    ) -> Result<(), anyhow::Error> {
        tracing::info!(
            operation = request.operation().as_str(),
            idempotency_key = request.idempotency_key(),
            capability_grant_id = request.capability_grant_id(),
            event_id = request.event_id(),
            raw_payload_digest = request.raw_payload_digest(),
            "accepted collaboration capability fanout in local principal facade"
        );
        Ok(())
    }

    async fn delete_user(&self, _handle: &str, _erase: bool) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn reactivate_user(&self, _handle: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn set_displayname(
        &self,
        _handle: &str,
        _displayname: &str,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn unset_displayname(&self, _handle: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
