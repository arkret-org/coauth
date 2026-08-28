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
    ConnectorAccountProfile, ConnectorAdmin, ConnectorProvider, ConnectorProvisionRequest,
    PrincipalAccountStatusPublicationRequest, PrincipalAgentKeyPairCommitRequest,
    PrincipalErasureReceiptRequest,
};
use url::Url;

/// `ConnectorAdmin` backed by coauth's own Postgres (`users`).
pub struct DbConnectorAdmin {
    principal_authority: String,
    repository_factory: BoxRepositoryFactory,
    arkret_config: ArkretConfig,
    http_client: reqwest::Client,
    peer_signing: Option<PeerSigningContext>,
}

#[derive(Clone)]
struct PeerSigningContext {
    keystore: coauth_keystore::Keystore,
    source_trust_domain: arkret_identifiers::TrustDomainId,
    url_builder: coauth_data::UrlBuilder,
}

impl DbConnectorAdmin {
    /// Create a facade rooted at `principal_authority`, reading accounts
    /// through `repository_factory`.
    #[must_use]
    pub fn new(
        principal_authority: impl Into<String>,
        repository_factory: BoxRepositoryFactory,
        arkret_config: ArkretConfig,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            principal_authority: principal_authority.into(),
            repository_factory,
            arkret_config,
            http_client,
            peer_signing: None,
        }
    }

    /// Attach the runtime service identity used for RFC 9421 peer requests.
    #[must_use]
    pub fn with_peer_signing(
        mut self,
        keystore: coauth_keystore::Keystore,
        source_trust_domain: arkret_identifiers::TrustDomainId,
        url_builder: coauth_data::UrlBuilder,
    ) -> Self {
        self.peer_signing = Some(PeerSigningContext {
            keystore,
            source_trust_domain,
            url_builder,
        });
        self
    }
}

fn default_principal_server(
    arkret_config: &ArkretConfig,
) -> Result<&PrincipalServerConfig, anyhow::Error> {
    match arkret_config.principal_servers.as_slice() {
        [server] => Ok(server),
        [] => anyhow::bail!("no Principal Server is configured for account-status publication"),
        _ => anyhow::bail!(
            "account-status publication destination is ambiguous; configure exactly one Principal Server"
        ),
    }
}

/// Snapshot both halves of the runtime service identity from one lifecycle
/// state. The Provider supervisor can move the shared handle from
/// `WaitingProvider` to `Ready` after this facade is constructed, so peer
/// signing must never freeze an empty (or stale) identity at process startup.
fn runtime_peer_identity(
    arkret_config: &ArkretConfig,
) -> Result<(arkret_identifiers::DidCoreId, arkret_identifiers::Did), anyhow::Error> {
    let state = arkret_config.runtime_service_identity.state();
    let identity = state.identity().ok_or_else(|| {
        anyhow::anyhow!(
            "account-status peer signing identity is unavailable while the runtime service identity is {state:?}"
        )
    })?;
    Ok((identity.service_id.clone(), identity.did.clone()))
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
    let body_bytes = arkret_canonical::canonical_json_bytes(request.body())
        .context("canonicalize Agent key-pair commit")?;
    let response = http_client
        .post(url.clone())
        .bearer_auth(bearer)
        .header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
        )
        .header("idempotency-key", request.idempotency_key())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body_bytes)
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
    let response: arkret_models_collaboration::agent_operations::AgentKeyPairOutcome =
        serde_json::from_slice(&bytes)
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

fn agent_key_pair_url(endpoint: &Url) -> Url {
    let mut url = endpoint.clone();
    url.set_path("/_arkret/gate/account/agent-key-pair");
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn validate_agent_key_pair_response(
    request: &PrincipalAgentKeyPairCommitRequest,
    response: &arkret_models_collaboration::agent_operations::AgentKeyPairOutcome,
) -> Result<(), anyhow::Error> {
    anyhow::ensure!(
        response.authorize_event_ref.as_str() == request.authorized_event_id(),
        "response authorize_event_ref mismatch"
    );
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

#[async_trait]
impl ConnectorAdmin for DbConnectorAdmin {
    fn principal_authority(&self) -> &str {
        self.principal_authority.as_str()
    }

    fn account_status_destination(
        &self,
    ) -> Result<(String, arkret_identifiers::DidCoreId), anyhow::Error> {
        let target = default_principal_server(&self.arkret_config)?;
        let audience = crate::services::principal_server_trust::effective_audience_shared(target)
            .context("configured Principal Server identity is unavailable or stale")?;
        Ok((target.name.clone(), audience))
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

    async fn submit_account_status_publication(
        &self,
        request: &PrincipalAccountStatusPublicationRequest,
    ) -> Result<
        arkret_models_collaboration::account_lifecycle::AccountStatusPublicationOutcome,
        anyhow::Error,
    > {
        let target = self
            .arkret_config
            .principal_servers
            .iter()
            .find(|server| server.name == request.destination_name())
            .context("account-status destination Principal Server is no longer configured")?;
        let signing = self
            .peer_signing
            .as_ref()
            .context("account-status peer signing configuration is unavailable")?;
        let (source_id, source_did) = runtime_peer_identity(&self.arkret_config)?;
        let destination_id =
            crate::services::principal_server_trust::effective_audience_shared(target)
                .context("account-status destination service identity is unavailable or stale")?;
        let identity = arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding {
            source_id,
            destination_id,
        };
        let client = crate::services::peer_protocol_client::PeerProtocolClient::new(
            Some(&target.endpoint),
            &self.http_client,
            &signing.keystore,
            source_did,
            identity,
            signing.source_trust_domain.clone(),
            signing.source_trust_domain.clone(),
        )?;
        let outcome = client
            .post_account_status_publication(request.body(), request.idempotency_key())
            .await?;
        let record = request.body().publication.record();
        anyhow::ensure!(
            outcome.account_status_record_id == record.account_status_record_id,
            "response record_id mismatch"
        );
        anyhow::ensure!(
            outcome.account_id == record.account_id,
            "response account_id mismatch"
        );
        anyhow::ensure!(
            outcome.status_seq == record.status_seq,
            "response status_seq mismatch"
        );
        Ok(outcome)
    }

    async fn erasure_receipt(
        &self,
        request: &PrincipalErasureReceiptRequest,
    ) -> Result<
        Option<arkret_models_collaboration::governance::erasure::ErasureReceiptPackage>,
        anyhow::Error,
    > {
        use arkret_models_collaboration::governance::erasure::{
            ErasureStorageBoundary, ErasureSubjectKind, account_erasure_receipt_id,
        };

        use crate::services::peer_protocol_client::PeerProtocolClientError;

        let target = self
            .arkret_config
            .principal_servers
            .iter()
            .find(|server| server.name == request.destination_name())
            .context("erasure-receipt destination Principal Server is no longer configured")?;
        let signing = self
            .peer_signing
            .as_ref()
            .context("erasure-receipt peer signing configuration is unavailable")?;
        let (source_service_id, source_did) = runtime_peer_identity(&self.arkret_config)?;
        let destination_service_id =
            crate::services::principal_server_trust::effective_audience_shared(target)
                .context("erasure-receipt destination service identity is unavailable or stale")?;
        let identity = arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding {
            source_service_id,
            destination_service_id,
        };
        let client = crate::services::peer_protocol_client::PeerProtocolClient::new(
            Some(&target.endpoint),
            &self.http_client,
            &signing.keystore,
            source_did,
            identity,
            signing.source_trust_domain.clone(),
            signing.source_trust_domain.clone(),
        )?;
        let receipt_id = account_erasure_receipt_id(
            request.triggering_status_record_id(),
            ErasureStorageBoundary::AccountPrivateStore,
        );
        let resource = match client.get_erasure_receipt(&receipt_id).await {
            Ok(resource) => resource,
            Err(PeerProtocolClientError::Status(404)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let package = resource.package;
        package.validate_bindings()?;
        anyhow::ensure!(
            package.receipt.receipt_id == receipt_id,
            "receipt id mismatch"
        );
        anyhow::ensure!(
            package.receipt.trigger
                == arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger::AccountStatusRecord {
                    account_status_record_id: request.triggering_status_record_id().clone(),
                },
            "receipt triggering status record mismatch"
        );
        anyhow::ensure!(
            package.receipt.subject.kind == ErasureSubjectKind::Principal
                && package.receipt.subject.subject_ref == request.principal_id().as_str(),
            "receipt principal subject mismatch"
        );
        anyhow::ensure!(
            package.receipt.scope.storage_boundary == ErasureStorageBoundary::AccountPrivateStore,
            "receipt storage boundary mismatch"
        );
        anyhow::ensure!(
            package.receipt.scope.service_scope.as_deref()
                == Some("account_status.erasure_execution"),
            "receipt service scope mismatch"
        );
        anyhow::ensure!(
            package
                .receipt
                .scope
                .target_refs
                .iter()
                .any(|target| target == request.principal_id().as_str()),
            "receipt target refs do not cover the principal"
        );
        anyhow::ensure!(
            !request.account_id().trim().is_empty(),
            "account id is empty"
        );
        let mut repo = self.repository_factory.create().await?;
        let resolver =
            crate::services::did_resolver::default_did_resolver_service(&self.arkret_config);
        let binding_store = crate::services::did_binding::shared_verified_did_binding_store();
        crate::services::erasure_receipt::verify_erasure_receipt_package(
            &self.http_client,
            &signing.url_builder,
            &self.arkret_config,
            &signing.keystore,
            &mut repo,
            resolver.as_ref(),
            binding_store.as_ref(),
            &package,
            chrono::Utc::now(),
        )
        .await?;
        Ok(Some(package))
    }

    async fn commit_agent_key_pair(
        &self,
        request: &PrincipalAgentKeyPairCommitRequest,
    ) -> Result<(), anyhow::Error> {
        commit_agent_key_pair_to_principal_server(&self.http_client, &self.arkret_config, request)
            .await
    }

    async fn delete_user(&self, _handle: &str, erase: bool) -> Result<(), anyhow::Error> {
        anyhow::bail!(unsupported_principal_delete_reason(erase))
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

impl ConnectorProvider for DbConnectorAdmin {
    #[allow(
        clippy::unnecessary_literal_bound,
        reason = "the public provider trait permits names borrowed from provider state"
    )]
    fn provider_name(&self) -> &str {
        "principal"
    }
}

fn unsupported_principal_delete_reason(erase: bool) -> &'static str {
    if erase {
        "hard erasure cannot be requested: the peer protocol has no typed erasure command carrier"
    } else {
        "principal account deactivation must be driven by the signed account-status publication"
    }
}

#[cfg(test)]
mod tests {
    use super::{
        default_principal_server, runtime_peer_identity, unsupported_principal_delete_reason,
    };

    fn principal_server(name: &str) -> coauth_config::PrincipalServerConfig {
        coauth_config::PrincipalServerConfig {
            name: name.to_owned(),
            endpoint: "https://principal.example/".parse().unwrap(),
            service_id: Some(
                arkret_identifiers::DidCoreId::new("ak:did_core:webvh:QmPrincipal".to_owned())
                    .unwrap(),
            ),
            session_grant_introspection_bearer: None,
            embedded_webvh_registration_bearer: None,
        }
    }

    #[test]
    fn account_status_destination_uses_the_only_configured_principal_server() {
        let config = coauth_config::ArkretConfig {
            principal_servers: vec![principal_server("soland-dev")],
            ..coauth_config::ArkretConfig::default()
        };

        let server = default_principal_server(&config).expect("single destination");

        assert_eq!(server.name, "soland-dev");
    }

    #[test]
    fn account_status_destination_fails_closed_when_not_unique() {
        let empty = coauth_config::ArkretConfig::default();
        assert!(
            default_principal_server(&empty)
                .unwrap_err()
                .to_string()
                .contains("no Principal Server")
        );

        let ambiguous = coauth_config::ArkretConfig {
            principal_servers: vec![principal_server("a"), principal_server("b")],
            ..coauth_config::ArkretConfig::default()
        };
        assert!(
            default_principal_server(&ambiguous)
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
    }

    #[test]
    fn runtime_peer_identity_is_unavailable_before_provider_readiness() {
        let config = coauth_config::ArkretConfig::default();

        let error = runtime_peer_identity(&config).expect_err("default identity is faulted");

        assert!(error.to_string().contains("identity is unavailable"));
    }

    #[test]
    fn runtime_peer_identity_observes_identity_installed_after_construction() {
        let config = coauth_config::ArkretConfig::default();
        let shared = config.runtime_service_identity.clone();
        let ready = coauth_config::RuntimeServiceIdentity::fixture(
            "did:webvh:QmService:auth.example:webvh:service",
        )
        .state();

        shared.store(ready);
        let (service_id, did) = runtime_peer_identity(&config).expect("identity became ready");

        assert_eq!(service_id.as_str(), "ak:did_core:webvh:QmService");
        assert_eq!(
            did.as_str(),
            "did:webvh:QmService:auth.example:webvh:service"
        );
    }

    #[test]
    fn unsupported_principal_delete_never_reports_false_success() {
        assert!(unsupported_principal_delete_reason(false).contains("account-status publication"));
        assert!(unsupported_principal_delete_reason(true).contains("no typed erasure command"));
    }
}
