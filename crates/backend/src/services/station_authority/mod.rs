//! Same-Station issuer capability backed by the actual Account Authority ledger.
//! These functions define no HTTP operation, protocol DTO, or shadow session store.

#[cfg(test)]
mod binding_tests;
pub(crate) mod controller_gate;
pub(crate) mod device_pairing;
pub(crate) mod introspection;
mod pinned_repository;
pub(crate) mod session_termination;

use coauth_config::ArkretConfig;
use coauth_data::RepositoryFactory;
use coauth_keyring::{Encrypter, Keyring};
use salvo::Depot;

use crate::handlers::arkret::ArkretRouteError;
use crate::handlers::common::DepotExt;

pub(crate) struct Context<'a> {
    pub repository_factory: &'a (dyn RepositoryFactory + Send + Sync),
    pub config: ArkretConfig,
    pub keyring: Keyring,
    pub encrypter: Encrypter,
    pub http_client: reqwest::Client,
    pub account_authority_origin: String,
}

impl<'a> Context<'a> {
    pub(crate) fn from_depot(depot: &'a Depot) -> Result<Self, ArkretRouteError> {
        Ok(Self {
            repository_factory: depot.repo_factory()?.as_ref(),
            config: depot.arkret_config()?,
            keyring: depot.keyring()?,
            encrypter: depot.encrypter()?,
            http_client: depot.http_client()?,
            account_authority_origin: depot
                .url_builder()?
                .http_base()
                .origin()
                .ascii_serialization(),
        })
    }
}

/// Actual issuer repository owner for one explicitly bound native Station.
/// Construction does not provision keys, copy ledger rows or mint a new issuer.
pub struct IssuerLedgerAuthority {
    repository_factory: coauth_data::BoxRepositoryFactory,
    config: ArkretConfig,
    keyring: Keyring,
    encrypter: Encrypter,
    http_client: reqwest::Client,
    station_id: arkret_wire::DidCoreId,
    cache_namespace: String,
    account_authority_origin: String,
}

impl IssuerLedgerAuthority {
    /// Open the exact delegated issuer deployment without migration or key provisioning.
    pub async fn connect_from_file(
        path: &std::path::Path,
        identity: &arkret_identity::service_identity::DidCoreIdentityState,
        resolution: &arkret_models_identity::AuthenticatedServiceResolution,
        principal_base: &url::Url,
        account_authority_base: &url::Url,
    ) -> anyhow::Result<std::sync::Arc<Self>> {
        use coauth_config::ConfigurationSection;
        use figment::providers::Format;
        use serde_saphyr::figment::Yaml;
        let figment = figment::Figment::from(Yaml::file(path));
        anyhow::ensure!(
            figment.contains("database.uri")
                || (figment.contains("database.database")
                    && (figment.contains("database.host") || figment.contains("database.socket"))),
            "local issuer database must be explicit in its delegated configuration"
        );
        let mut config =
            coauth_config::AppConfig::extract(&figment).map_err(anyhow::Error::from_boxed)?;
        config
            .arkret
            .resolve_internal_authority_shared_secrets()
            .await?;
        anyhow::ensure!(
            config.http.public_base_url.as_str().trim_end_matches('/')
                == account_authority_base.as_str().trim_end_matches('/'),
            "local issuer configuration belongs to a different Account Authority endpoint"
        );
        let database_url = crate::util::database_url_from_config(&config.database)?;
        anyhow::ensure!(
            !coauth_storage_postgres::has_pending_migrations(&database_url).await?,
            "local issuer database migrations must be completed by the Account Authority"
        );
        let pool = crate::util::diesel_pool_from_config(&config.database).await?;
        let serving = identity
            .identity()
            .ok_or_else(|| anyhow::anyhow!("native Station identity unavailable"))?;
        identity.validate()?;
        anyhow::ensure!(
            resolution.service_id == serving.service_id
                && resolution.normalized_did_document.id == serving.did
                && resolution.method_history_evidence.boundary().to_version_id
                    == serving.version_id,
            "native Station state and original method proof disagree"
        );
        let factory: coauth_data::BoxRepositoryFactory =
            Box::new(coauth_storage_postgres::PgRepositoryFactory::new(pool));
        let binding = super::station_trust::native_delegation::bind_native_station_identity(
            factory.as_ref(),
            &config.arkret,
            &serving.service_id,
            resolution,
        )
        .await?;
        let secrets = config.secrets.runtime(false).await?;
        let client = crate::reqwest_client_for_server(
            &config.arkret,
            &config.http.public_base_url,
            config.http.issuer.as_ref(),
        );
        let authority = Self::from_parts(
            Box::new(pinned_repository::PinnedIssuerRepositoryFactory::new(
                factory, binding,
            )),
            config.arkret,
            secrets.keyring(),
            secrets.encrypter(),
            client,
            serving.service_id.clone(),
            serving.did.clone(),
            principal_base,
            account_authority_base,
        )?;
        Ok(std::sync::Arc::new(authority))
    }

    fn from_parts(
        repository_factory: coauth_data::BoxRepositoryFactory,
        config: ArkretConfig,
        keyring: Keyring,
        encrypter: Encrypter,
        http_client: reqwest::Client,
        station_id: arkret_wire::DidCoreId,
        station_did: arkret_wire::Did,
        principal_base: &url::Url,
        account_authority_base: &url::Url,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            arkret_identifiers::project_did_to_core_id(&station_did)? == station_id,
            "native Station identity coordinates disagree"
        );
        let configured = config
            .owning_station()
            .ok_or_else(|| anyhow::anyhow!("owning Station is not configured"))?;
        anyhow::ensure!(
            configured.endpoint.as_str().trim_end_matches('/')
                == principal_base.as_str().trim_end_matches('/'),
            "issuer deployment belongs to a different Station endpoint"
        );
        let prior = config
            .runtime_owning_station_identity
            .get()
            .ok_or_else(|| {
                anyhow::anyhow!("issuer deployment has no verified Station delegation")
            })?;
        anyhow::ensure!(
            prior.station_id == station_id && prior.did == station_did,
            "issuer deployment belongs to a different Station identity"
        );
        Ok(Self {
            repository_factory,
            config,
            keyring,
            encrypter,
            http_client,
            station_id,
            cache_namespace: ulid::Ulid::generate().to_string(),
            account_authority_origin: account_authority_base.origin().ascii_serialization(),
        })
    }

    fn context(&self) -> Context<'_> {
        Context {
            repository_factory: self.repository_factory.as_ref(),
            config: self.config.clone(),
            keyring: self.keyring.clone(),
            encrypter: self.encrypter.clone(),
            http_client: self.http_client.clone(),
            account_authority_origin: self.account_authority_origin.clone(),
        }
    }
}

impl coland_contracts::account_authority::LocalAccountAuthority for IssuerLedgerAuthority {
    fn station_id(&self) -> &arkret_wire::DidCoreId {
        &self.station_id
    }
    fn cache_namespace(&self) -> &str {
        &self.cache_namespace
    }

    fn validate_session_grant(
        &self,
        input: arkret_models_collaboration::session_grants::SessionGrantValidationInput,
    ) -> coland_contracts::account_authority::AccountAuthorityCall<
        '_,
        arkret_models_collaboration::session_grants::SessionGrantValidationResponseBody,
    > {
        Box::pin(async move {
            let allowed = vec![self.station_id.to_string()];
            let result =
                introspection::validate_session_grant(&self.context(), input, Some(&allowed))
                    .await
                    .map_err(|_| {
                        coland_contracts::account_authority::AccountAuthorityUnavailable
                    })?;
            if result.grant.as_ref().is_some_and(|grant| {
                grant.issuer_id != self.station_id || grant.audience_id != self.station_id
            }) {
                return Err(coland_contracts::account_authority::AccountAuthorityUnavailable);
            }
            Ok(result)
        })
    }

    fn terminate_authentication_session(
        &self,
        input: arkret_models_collaboration::session_grants::AuthenticationSessionTerminationInput,
    ) -> coland_contracts::account_authority::AccountAuthorityCall<
        '_,
        arkret_models_collaboration::session_grants::AuthenticationSessionTerminationResponseBody,
    > {
        Box::pin(async move {
            if input.grant_jwt.trim().is_empty() || coauth_jose::jwt::Jwt::<arkret_models_identity::SignedSessionGrantClaims>::try_from(input.grant_jwt.as_str()).is_err() {
                return Err(coland_contracts::account_authority::AccountAuthorityUnavailable);
            }
            session_termination::terminate_auth_side_session_by_grant_jwt(
                &self.context(),
                self.station_id.as_str(),
                &input.grant_jwt,
            )
            .await
            .map_err(|_| coland_contracts::account_authority::AccountAuthorityUnavailable)
        })
    }

    fn issue_controller_gate(
        &self, input: arkret_models_identity::agent_signer_evidence::ControllerAccountGateIssuanceInput,
    ) -> coland_contracts::account_authority::AccountAuthorityCall<'_, arkret_models_identity::agent_signer_evidence::ControllerAccountGateAttestationIssueResponseBody>{
        Box::pin(async move {
            let original = controller_gate::issue_controller_gate(
                &self.context(),
                &input,
                self.station_id.as_str(),
            )
            .await
            .map_err(|_| coland_contracts::account_authority::AccountAuthorityUnavailable)?;
            serde_json::from_slice(&original)
                .map_err(|_| coland_contracts::account_authority::AccountAuthorityUnavailable)
        })
    }
    fn stage_device_pairing(
        &self,
        request: arkret_models_collaboration::device_pairing::DevicePairingStageRequestBody,
        idempotency_key: String,
    ) -> coland_contracts::account_authority::AccountAuthorityCall<
        '_,
        arkret_models_collaboration::device_pairing::DevicePairingStageResponseBody,
        coland_contracts::account_authority::AccountAuthorityPairingError,
    > {
        Box::pin(async move {
            let original = device_pairing::stage(request, idempotency_key, &self.context())
                .await
                .map_err(pairing_error)?;
            serde_json::from_slice(&original).map_err(|_| {
                coland_contracts::account_authority::AccountAuthorityPairingError::Unavailable
            })
        })
    }
    fn resolve_device_pairing(
        &self,
        request: arkret_models_collaboration::device_pairing::DevicePairingResolveRequestBody,
    ) -> coland_contracts::account_authority::AccountAuthorityCall<
        '_,
        arkret_models_collaboration::device_pairing::DevicePairingBootstrap,
        coland_contracts::account_authority::AccountAuthorityPairingError,
    > {
        Box::pin(async move {
            let original = device_pairing::resolve(&self.context(), request)
                .await
                .map_err(pairing_error)?;
            serde_json::from_slice(&original).map_err(|_| {
                coland_contracts::account_authority::AccountAuthorityPairingError::Unavailable
            })
        })
    }
    fn device_pairing_status(
        &self,
        request: arkret_models_collaboration::device_pairing::DevicePairingStatusRequestBody,
    ) -> coland_contracts::account_authority::AccountAuthorityCall<
        '_,
        arkret_models_collaboration::device_pairing::DevicePairingStatusResponseBody,
        coland_contracts::account_authority::AccountAuthorityPairingError,
    > {
        Box::pin(async move {
            let original = device_pairing::status(&self.context(), request)
                .await
                .map_err(pairing_error)?;
            serde_json::from_slice(&original).map_err(|_| {
                coland_contracts::account_authority::AccountAuthorityPairingError::Unavailable
            })
        })
    }
}

fn pairing_error(
    error: ArkretRouteError,
) -> coland_contracts::account_authority::AccountAuthorityPairingError {
    use coland_contracts::account_authority::AccountAuthorityPairingError as Error;
    match error {
        ArkretRouteError::NotFound => Error::NotFound,
        ArkretRouteError::Coded { status, code, .. }
            if status == salvo::http::StatusCode::CONFLICT
                && code == arkret_wire::ErrorCode::DUPLICATE_CONFLICT =>
        {
            Error::DuplicateConflict
        }
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use coland_contracts::account_authority::LocalAccountAuthority as _;

    use super::*;
    use crate::handlers::test_utils::{TestState, setup};

    #[tokio::test]
    async fn issuer_capability_binds_the_actual_station_and_isolates_each_instance_cache() {
        setup();
        let pool = coauth_storage_postgres::test_utils::setup_test_pool()
            .await
            .expect("actual PostgreSQL is required");
        let mut state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        state.configure_status_issuer_webvh();
        let identity = state
            .arkret_config
            .runtime_owning_station_identity
            .get()
            .unwrap();
        let endpoint = state
            .arkret_config
            .owning_station()
            .unwrap()
            .endpoint
            .clone();
        let create = |station_id, station_did, endpoint: &url::Url| {
            IssuerLedgerAuthority::from_parts(
                Box::new(state.repository_factory.clone()),
                state.arkret_config.clone(),
                state.keyring.clone(),
                state.encrypter.clone(),
                state.http_client.clone(),
                station_id,
                station_did,
                endpoint,
                &state.url_builder.http_base(),
            )
        };
        let first = create(identity.station_id.clone(), identity.did.clone(), &endpoint).unwrap();
        let second = create(identity.station_id.clone(), identity.did.clone(), &endpoint).unwrap();
        assert_eq!(first.station_id(), &identity.station_id);
        assert_ne!(first.cache_namespace(), second.cache_namespace());
        use arkret_models_collaboration::device_pairing::{
            DevicePairingStageRequestBody, DevicePairingState, DevicePairingStatusRequestBody,
        };
        let candidate_key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[0x71; 32]);
        let input: DevicePairingStageRequestBody = serde_json::from_value(serde_json::json!({
            "new_device_public_key": {"kty":"OKP", "kid":"ak:device:01999999-0000-7000-8000-00000000feed", "algorithm":"Ed25519", "key":arkret_canonical::base64url_encode(candidate_key.verifying_key().to_bytes())},
            "client_nonce":arkret_canonical::base64url_encode([0x72; 32]),
        })).unwrap();
        let staged = first
            .stage_device_pairing(input.clone(), "component-stage:one".to_owned())
            .await
            .unwrap();
        let replay = first
            .stage_device_pairing(input.clone(), "component-stage:one".to_owned())
            .await
            .unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&staged).unwrap(),
            arkret_canonical::canonical_json_bytes(&replay).unwrap()
        );
        assert_eq!(
            staged.gate_audience_uri,
            state.url_builder.http_base().origin().ascii_serialization()
        );
        let independent = first
            .stage_device_pairing(input.clone(), "component-stage:two".to_owned())
            .await
            .unwrap();
        assert_ne!(
            staged.device_pairing_request_id,
            independent.device_pairing_request_id
        );
        let mut changed = input;
        changed.display_name =
            Some(arkret_wire::NonEmptyString::new("another component intent".to_owned()).unwrap());
        assert_eq!(
            first
                .stage_device_pairing(changed, "component-stage:one".to_owned())
                .await
                .unwrap_err(),
            coland_contracts::account_authority::AccountAuthorityPairingError::DuplicateConflict
        );
        let status = first
            .device_pairing_status(DevicePairingStatusRequestBody {
                device_pairing_request_id: staged.device_pairing_request_id.clone(),
                pairing_code: staged.pairing_code.clone(),
            })
            .await
            .unwrap();
        assert_eq!(status.state, DevicePairingState::Staged);
        assert!(status.device_id.is_none() && status.authorized_event_ref.is_none());
        assert!(
            create(
                "ak:did_core:web:another.example".parse().unwrap(),
                identity.did.clone(),
                &endpoint
            )
            .is_err()
        );
        assert!(
            create(
                identity.station_id.clone(),
                identity.did.clone(),
                &"https://another.example/".parse().unwrap()
            )
            .is_err()
        );
    }
}
