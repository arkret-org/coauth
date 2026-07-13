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
use coauth_config::{ArkretConfig, PrincipalServerConfig};
use coauth_data::{BoxRepositoryFactory, RepositoryAccess};
use coauth_principal::{
    ConnectorAccountProfile, ConnectorAdmin, ConnectorProvisionRequest,
    PrincipalAgentKeyPairCommitRequest, PrincipalCapabilityFanoutRequest,
};
use soland_core::capability_fanout::{CapabilityFanoutBody, CapabilityFanoutResponse};
use url::Url;

/// `ConnectorAdmin` backed by coauth's own Postgres (`users`).
pub struct DbConnectorAdmin {
    server_name: String,
    repository_factory: BoxRepositoryFactory,
    arkret_config: ArkretConfig,
    http_client: reqwest::Client,
}

impl DbConnectorAdmin {
    /// Create a facade rooted at `server_name`, reading accounts through
    /// `repository_factory`.
    #[must_use]
    pub fn new(
        server_name: impl Into<String>,
        repository_factory: BoxRepositoryFactory,
        arkret_config: ArkretConfig,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            repository_factory,
            arkret_config,
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

pub(crate) async fn submit_collaboration_capability_fanout_to_principal_servers(
    http_client: &reqwest::Client,
    arkret_config: &ArkretConfig,
    request: &PrincipalCapabilityFanoutRequest,
) -> Result<(), anyhow::Error> {
    let targets = capability_fanout_targets(arkret_config, request.body())?;
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

pub(crate) async fn commit_agent_key_pair_to_principal_server(
    http_client: &reqwest::Client,
    arkret_config: &ArkretConfig,
    request: &PrincipalAgentKeyPairCommitRequest,
) -> Result<(), anyhow::Error> {
    let server = arkret_config
        .principal_servers
        .iter()
        .find(|server| server.name == request.principal_server_name())
        .ok_or_else(|| anyhow::anyhow!("authoritative Principal Server is no longer configured"))?;
    let bearer = server
        .session_grant_introspection_bearer
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("authoritative Principal Server has no S2S bearer"))?;
    submit_agent_key_pair_to_target(http_client, server, bearer, request).await
}

async fn submit_agent_key_pair_to_target(
    http_client: &reqwest::Client,
    target: &PrincipalServerConfig,
    bearer: &str,
    request: &PrincipalAgentKeyPairCommitRequest,
) -> Result<(), anyhow::Error> {
    let url = agent_key_pair_url(&target.endpoint);
    let response = http_client
        .post(url.clone())
        .bearer_auth(bearer)
        .header("idempotency-key", request.idempotency_key())
        .json(request.body())
        .send()
        .await
        .with_context(|| format!("send Agent key-pair commit to {}", target.name))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("read Agent key-pair response from {}", target.name))?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        anyhow::bail!(
            "Principal Server {} rejected Agent key-pair commit {} with status {}: {}",
            target.name,
            request.authorized_event_id(),
            status,
            truncate_response_body(&body)
        );
    }
    let response: arkret_core::AgentKeyPairOutcome = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode Agent key-pair response from {}", target.name))?;
    validate_agent_key_pair_response(request, &response)
        .with_context(|| format!("validate Agent key-pair response from {}", target.name))?;
    tracing::info!(
        principal_server = target.name,
        endpoint = %url,
        authorized_event_id = request.authorized_event_id(),
        "committed Agent key pair at authoritative Principal Server"
    );
    Ok(())
}

// RULING: this fanout is a
// deployment-internal server-to-server contract, NOT a protocol responsibility.
// The soland-private `POST /_soland/root/authz/capability-fanout` edge is the
// correct, compliant surface — there is nothing to migrate to and nothing to
// "fix".
//
// coauth issues the collaboration capability fanout in its Auth-Server role: it
// holds no principal session and signs as the issuing *service* DID, not a
// logged-in principal device. The protocol path `POST /_arkret/self/events`
// (submitting a `ak.capability.grant` Event) is gated to `user_session` /
// `device_proof` / a principal-authorised delegated service signature
// (service-http-binding.md §2.1 row `self/events` + §189; api-conventions.md
// requires `ak.session.grant` + DPoP). A bare service with no principal context
// is, by spec, not an eligible caller of that protocol surface. Separately, the
// DataEvent submit outcome is eventually-consistent (operations-sync.md §3:
// a DataEvent enters the accepted set without waiting on a Seal), so the generic
// events outcome cannot express the synchronous "grant became effective" ack
// that `validate_capability_fanout_response` below requires.
//
// Both facts point to the same ruling: this belongs on soland's own
// negative-space root per service-http-binding.md §2.1.3(b) (product /
// deployment-private capability MUST NOT occupy a `/_arkret/*` protocol
// segment). soland exposes it as `org.arkret.soland.root.authz.capability_fanout
// .submit`, bearer-gated by the shared `embedded_webvh_registration_bearer`,
// returning an explicit `authz_state` projection ack. The coauth↔soland S2S
// trust boundary is registered in `docs/{zh,en}/setup/principal-server.md`.
// No spec change; no new protocol operation.
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
            "x-arkret-capability-fanout-digest",
            request.raw_payload_digest(),
        )
        .header("x-arkret-capability-event-id", request.event_id())
        .header(
            "x-arkret-capability-grant-id",
            request.capability_grant_id(),
        )
        .json(request.body())
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
        operation = request.operation(),
        event_id = request.event_id(),
        capability_grant_id = request.capability_grant_id(),
        "delivered collaboration capability fanout to principal server"
    );
    Ok(())
}

fn capability_fanout_targets(
    arkret_config: &ArkretConfig,
    body: &CapabilityFanoutBody,
) -> Result<Vec<CapabilityFanoutTarget>, anyhow::Error> {
    principal_server_targets(arkret_config, &body.principal_servers)
}

fn principal_server_targets(
    arkret_config: &ArkretConfig,
    entries: &[serde_json::Value],
) -> Result<Vec<CapabilityFanoutTarget>, anyhow::Error> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let mut targets = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry
            .as_object()
            .context("principal_servers[] entries must be objects")?;
        let name = object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .context("principal_servers[].name is required")?;
        let endpoint_raw = object
            .get("endpoint")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .context("principal_servers[].endpoint is required")?;
        let endpoint = Url::parse(endpoint_raw)
            .with_context(|| format!("principal server {name} endpoint is invalid"))?;
        let configured = configured_principal_server(arkret_config, name, &endpoint)
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
    arkret_config: &'a ArkretConfig,
    name: &str,
    endpoint: &Url,
) -> Option<&'a PrincipalServerConfig> {
    arkret_config
        .principal_servers
        .iter()
        .find(|server| server.name == name && endpoint_matches(&server.endpoint, endpoint))
        .or_else(|| {
            arkret_config
                .principal_servers
                .iter()
                .find(|server| server.name == name)
        })
        .or_else(|| {
            arkret_config
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

fn agent_key_pair_url(endpoint: &Url) -> Url {
    let mut url = endpoint.clone();
    url.set_path("/_arkret/gate/account/agent-key-pair");
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn validate_agent_key_pair_response(
    request: &PrincipalAgentKeyPairCommitRequest,
    response: &arkret_core::AgentKeyPairOutcome,
) -> Result<(), anyhow::Error> {
    anyhow::ensure!(
        response.ok,
        "Agent key-pair commit response is not successful"
    );
    anyhow::ensure!(
        response.authorized_event_ref.as_str() == request.authorized_event_id(),
        "response authorized_event_ref mismatch"
    );
    Ok(())
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
        "grant" => {
            anyhow::ensure!(
                response.authz_state.effective && !response.authz_state.revoked,
                "grant fanout did not become effective"
            );
        }
        "revoke" => {
            anyhow::ensure!(
                response.authz_state.revoked && !response.authz_state.effective,
                "revoke fanout did not revoke grant"
            );
        }
        operation => anyhow::bail!("unknown fanout operation {operation}"),
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
    use soland_core::capability_fanout::CapabilityFanoutAuthzState;

    use super::*;

    const EVENT: &str = "ak:event:01970000-0000-7000-8000-000000000001";
    const GRANT: &str = "ak:grant:01970000-0000-7000-8000-000000000002";

    fn arkret_config() -> ArkretConfig {
        ArkretConfig {
            principal_servers: vec![PrincipalServerConfig {
                name: "soland-dev".to_owned(),
                audience: "soland".to_owned(),
                endpoint: Url::parse("http://127.0.0.1:3322").unwrap(),
                did: Some("did:web:soland.example".to_owned()),
                session_grant_introspection_bearer: None,
                embedded_webvh_registration_bearer: Some("secret".to_owned()),
            }],
            ..ArkretConfig::default()
        }
    }

    fn body() -> CapabilityFanoutBody {
        CapabilityFanoutBody {
            kind: "ak.coauth.collaboration_capability.fanout.v1".to_owned(),
            operation: "grant".to_owned(),
            issuer_service_id: "did:web:coauth.example".to_owned(),
            event_kind: "ak.capability.grant".to_owned(),
            event_id: EVENT.to_owned(),
            capability_grant_id: GRANT.to_owned(),
            payload: json!({}),
            principal_servers: vec![json!({
                "name": "soland-dev",
                "audience": "soland",
                "endpoint": "http://127.0.0.1:3322/",
                "did": "did:web:soland.example"
            })],
        }
    }

    fn request() -> PrincipalCapabilityFanoutRequest {
        PrincipalCapabilityFanoutRequest::new(
            "capability-fanout:test".to_owned(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            body(),
        )
    }

    #[test]
    fn fanout_targets_resolve_payload_principal_servers_to_configured_bearer() {
        let targets = capability_fanout_targets(&arkret_config(), &body()).unwrap();

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
            operation: "grant".to_owned(),
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
            &self.arkret_config,
            request,
        )
        .await?;
        tracing::info!(
            operation = request.operation(),
            idempotency_key = request.idempotency_key(),
            capability_grant_id = request.capability_grant_id(),
            event_id = request.event_id(),
            raw_payload_digest = request.raw_payload_digest(),
            "submitted collaboration capability fanout through local principal facade"
        );
        Ok(())
    }

    async fn commit_agent_key_pair(
        &self,
        request: &PrincipalAgentKeyPairCommitRequest,
    ) -> Result<(), anyhow::Error> {
        commit_agent_key_pair_to_principal_server(&self.http_client, &self.arkret_config, request)
            .await
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
