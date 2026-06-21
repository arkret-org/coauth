//! Database-backed [`ConnectorAdmin`] for coauth's account/profile facade.
//!
//! Replaces the former in-memory connector mock, whose
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

use anyhow::Context as _;
use async_trait::async_trait;
use coauth_config::{CokretConfig, PrincipalServerConfig};
use coauth_data::{BoxRepositoryFactory, RepositoryAccess};
use coauth_principal::{
    ConnectorAccountProfile, ConnectorAdmin, ConnectorProvisionRequest,
    PrincipalCapabilityFanoutOperation, PrincipalCapabilityFanoutRequest,
};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

/// `ConnectorAdmin` backed by coauth's own Postgres (`users`).
pub struct DbConnectorAdmin {
    server_name: String,
    repository_factory: BoxRepositoryFactory,
    cokret_config: CokretConfig,
    http_client: reqwest::Client,
}

impl DbConnectorAdmin {
    /// Create a facade rooted at `server_name`, reading accounts through
    /// `repository_factory`.
    #[must_use]
    pub fn new(
        server_name: impl Into<String>,
        repository_factory: BoxRepositoryFactory,
        cokret_config: CokretConfig,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            repository_factory,
            cokret_config,
            http_client,
        }
    }
}

#[derive(Clone, Debug)]
struct CapabilityFanoutTarget {
    name: String,
    endpoint: Url,
    bearer: String,
}

#[derive(Debug, Deserialize)]
struct CapabilityFanoutResponse {
    accepted: Vec<String>,
    duplicate: Vec<String>,
    event_id: String,
    capability_grant_id: String,
    authz_state: CapabilityFanoutAuthzState,
}

#[derive(Debug, Deserialize)]
struct CapabilityFanoutAuthzState {
    projected: bool,
    effective: bool,
    revoked: bool,
    #[allow(dead_code)]
    grant_present: bool,
}

pub(crate) async fn submit_collaboration_capability_fanout_to_principal_servers(
    http_client: &reqwest::Client,
    cokret_config: &CokretConfig,
    request: &PrincipalCapabilityFanoutRequest,
) -> Result<(), anyhow::Error> {
    let targets = capability_fanout_targets(cokret_config, request.payload())?;
    if targets.is_empty() {
        tracing::warn!(
            event_id = request.event_id(),
            capability_grant_id = request.capability_grant_id(),
            "collaboration capability fanout has no principal_servers targets"
        );
        return Ok(());
    }

    for target in targets {
        submit_collaboration_capability_fanout_to_target(http_client, &target, request).await?;
    }
    Ok(())
}

async fn submit_collaboration_capability_fanout_to_target(
    http_client: &reqwest::Client,
    target: &CapabilityFanoutTarget,
    request: &PrincipalCapabilityFanoutRequest,
) -> Result<(), anyhow::Error> {
    let url = capability_fanout_url(&target.endpoint);
    let response = http_client
        .post(url.clone())
        .bearer_auth(&target.bearer)
        .header("idempotency-key", request.idempotency_key())
        .header(
            "x-cokret-capability-fanout-digest",
            request.raw_payload_digest(),
        )
        .header("x-cokret-capability-event-id", request.event_id())
        .header(
            "x-cokret-capability-grant-id",
            request.capability_grant_id(),
        )
        .json(request.payload())
        .send()
        .await
        .with_context(|| format!("send capability fanout to {}", target.name))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("read capability fanout response from {}", target.name))?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        anyhow::bail!(
            "principal server {} rejected capability fanout {} with status {}: {}",
            target.name,
            request.event_id(),
            status,
            truncate_response_body(&body)
        );
    }
    let response: CapabilityFanoutResponse = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode capability fanout response from {}", target.name))?;
    validate_capability_fanout_response(request, &response)
        .with_context(|| format!("validate capability fanout response from {}", target.name))?;
    tracing::info!(
        principal_server = target.name,
        endpoint = %url,
        operation = request.operation().as_str(),
        event_id = request.event_id(),
        capability_grant_id = request.capability_grant_id(),
        "delivered collaboration capability fanout to principal server"
    );
    Ok(())
}

fn capability_fanout_targets(
    cokret_config: &CokretConfig,
    payload: &Value,
) -> Result<Vec<CapabilityFanoutTarget>, anyhow::Error> {
    let Some(entries) = payload.get("principal_servers").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut targets = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry
            .as_object()
            .context("principal_servers[] entries must be objects")?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .context("principal_servers[].name is required")?;
        let endpoint_raw = object
            .get("endpoint")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .context("principal_servers[].endpoint is required")?;
        let endpoint = Url::parse(endpoint_raw)
            .with_context(|| format!("principal server {name} endpoint is invalid"))?;
        let configured = configured_principal_server(cokret_config, name, &endpoint)
            .with_context(|| format!("principal server {name} is not configured"))?;
        let bearer = configured
            .embedded_webvh_registration_bearer
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .with_context(|| {
                format!("principal server {name} missing embedded_webvh_registration_bearer")
            })?
            .to_owned();
        targets.push(CapabilityFanoutTarget {
            name: name.to_owned(),
            endpoint,
            bearer,
        });
    }
    Ok(targets)
}

fn configured_principal_server<'a>(
    cokret_config: &'a CokretConfig,
    name: &str,
    endpoint: &Url,
) -> Option<&'a PrincipalServerConfig> {
    cokret_config
        .principal_servers
        .iter()
        .find(|server| server.name == name && endpoint_matches(&server.endpoint, endpoint))
        .or_else(|| {
            cokret_config
                .principal_servers
                .iter()
                .find(|server| server.name == name)
        })
        .or_else(|| {
            cokret_config
                .principal_servers
                .iter()
                .find(|server| endpoint_matches(&server.endpoint, endpoint))
        })
}

fn endpoint_matches(left: &Url, right: &Url) -> bool {
    normalized_endpoint(left) == normalized_endpoint(right)
}

fn normalized_endpoint(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_owned()
}

fn capability_fanout_url(endpoint: &Url) -> Url {
    let mut url = endpoint.clone();
    url.set_path("/_soland/root/authz/capability-fanout");
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn validate_capability_fanout_response(
    request: &PrincipalCapabilityFanoutRequest,
    response: &CapabilityFanoutResponse,
) -> Result<(), anyhow::Error> {
    anyhow::ensure!(
        response.event_id == request.event_id(),
        "response event_id mismatch"
    );
    anyhow::ensure!(
        response.capability_grant_id == request.capability_grant_id(),
        "response capability_grant_id mismatch"
    );
    let returned_event = response
        .accepted
        .iter()
        .chain(response.duplicate.iter())
        .any(|event_id| event_id == request.event_id());
    anyhow::ensure!(returned_event, "response did not acknowledge event_id");
    anyhow::ensure!(response.authz_state.projected, "authz state not projected");
    match request.operation() {
        PrincipalCapabilityFanoutOperation::Grant => {
            anyhow::ensure!(
                response.authz_state.effective && !response.authz_state.revoked,
                "grant fanout did not become effective"
            );
        }
        PrincipalCapabilityFanoutOperation::Revoke => {
            anyhow::ensure!(
                response.authz_state.revoked && !response.authz_state.effective,
                "revoke fanout did not revoke grant"
            );
        }
    }
    Ok(())
}

fn truncate_response_body(body: &str) -> String {
    const MAX: usize = 1024;
    if body.chars().count() <= MAX {
        body.to_owned()
    } else {
        format!("{}...", body.chars().take(MAX).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use coauth_config::PrincipalServerConfig;
    use serde_json::json;

    use super::*;

    const EVENT: &str = "ck:event:01970000-0000-7000-8000-000000000001";
    const GRANT: &str = "ck:grant:01970000-0000-7000-8000-000000000002";

    fn cokret_config() -> CokretConfig {
        CokretConfig {
            principal_servers: vec![PrincipalServerConfig {
                name: "soland-dev".to_owned(),
                audience: "soland".to_owned(),
                endpoint: Url::parse("http://127.0.0.1:3322").unwrap(),
                did: Some("did:web:soland.example".to_owned()),
                session_grant_introspection_bearer: None,
                embedded_webvh_registration_bearer: Some("secret".to_owned()),
            }],
            ..CokretConfig::default()
        }
    }

    fn payload() -> Value {
        json!({
            "principal_servers": [{
                "name": "soland-dev",
                "audience": "soland",
                "endpoint": "http://127.0.0.1:3322/",
                "did": "did:web:soland.example"
            }]
        })
    }

    fn request() -> PrincipalCapabilityFanoutRequest {
        PrincipalCapabilityFanoutRequest::new(
            PrincipalCapabilityFanoutOperation::Grant,
            "capability-fanout:test".to_owned(),
            GRANT.to_owned(),
            EVENT.to_owned(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            payload(),
        )
    }

    #[test]
    fn fanout_targets_resolve_payload_principal_servers_to_configured_bearer() {
        let targets = capability_fanout_targets(&cokret_config(), &payload()).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "soland-dev");
        assert_eq!(
            capability_fanout_url(&targets[0].endpoint).as_str(),
            "http://127.0.0.1:3322/_soland/root/authz/capability-fanout"
        );
        assert_eq!(targets[0].bearer, "secret");
    }

    #[test]
    fn grant_response_must_confirm_effective_authz_state() {
        let response = CapabilityFanoutResponse {
            accepted: vec![EVENT.to_owned()],
            duplicate: Vec::new(),
            event_id: EVENT.to_owned(),
            capability_grant_id: GRANT.to_owned(),
            authz_state: CapabilityFanoutAuthzState {
                projected: true,
                effective: false,
                revoked: false,
                grant_present: true,
            },
        };

        assert!(validate_capability_fanout_response(&request(), &response).is_err());
    }
}

#[async_trait]
impl ConnectorAdmin for DbConnectorAdmin {
    fn principal_authority(&self) -> &str {
        self.server_name.as_str()
    }

    async fn verify_token(&self, _token: &str) -> Result<bool, anyhow::Error> {
        // coauth IS the principal authority — there is no separate downstream
        // principal service whose bearer this would validate. Session-grant
        // introspection uses its own static Principal Server bearer check, so
        // this never honours a token of its own.
        Ok(false)
    }

    async fn query_user(&self, handle: &str) -> Result<ConnectorAccountProfile, anyhow::Error> {
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
        Ok(ConnectorAccountProfile {
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
        _request: &ConnectorProvisionRequest,
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
        submit_collaboration_capability_fanout_to_principal_servers(
            &self.http_client,
            &self.cokret_config,
            request,
        )
        .await?;
        tracing::info!(
            operation = request.operation().as_str(),
            idempotency_key = request.idempotency_key(),
            capability_grant_id = request.capability_grant_id(),
            event_id = request.event_id(),
            raw_payload_digest = request.raw_payload_digest(),
            "submitted collaboration capability fanout through local principal facade"
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
