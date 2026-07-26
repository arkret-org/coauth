//! Provider-backed runtime service identity for the class-A Coauth service.

use std::time::Duration;

use arkret_http_client::{Auth, Client, ClientBuilder};
use arkret_identity::service_identity::{
    LocalServiceIdentity, ServiceIdentityDiagnostic, ServiceIdentityKeyRef,
    ServiceIdentityProviderRef, ServiceIdentityState, StoredServiceIdentity,
};
use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey,
    ServiceRegistrationOutcome,
};
use arkret_signatures::webvh::{
    PreparedInception, ServiceRegistrationInceptionInput,
    prepare_service_registration_inception_with_did_key_seed,
};
use arkret_wire::ServiceKind;
use chrono::Utc;
use coauth_config::{ArkretConfig, RuntimeServiceIdentity};
use coauth_keystore::Keystore;
use coauth_storage_postgres::PgRepositoryFactory;
use diesel::OptionalExtension;
use diesel::prelude::*;
use diesel::sql_types::Jsonb;
use diesel_async::RunQueryDsl;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

const RETRY_DELAY_SECONDS: i64 = 5;

#[derive(Clone)]
struct ProviderCandidate {
    reference: ServiceIdentityProviderRef,
    bearer: String,
}

#[derive(QueryableByName)]
struct IdentityRow {
    #[diesel(sql_type = Jsonb)]
    identity: Value,
}

enum StoredIdentityLoad {
    Missing,
    Loaded(Box<StoredServiceIdentity>),
    Invalid(String),
}

impl StoredIdentityLoad {
    fn into_runtime_result(
        self,
    ) -> Result<Option<StoredServiceIdentity>, Box<ServiceIdentityState>> {
        match self {
            Self::Missing => Ok(None),
            Self::Loaded(stored) => Ok(Some(*stored)),
            Self::Invalid(error) => Err(Box::new(ServiceIdentityState::Faulted {
                diagnostic: ServiceIdentityDiagnostic::RestoreFailed,
                next_action: format!(
                    "restore a verified service_identity database record; the stored record cannot be decoded: {error}"
                ),
            })),
        }
    }
}

/// Resolve the initial state and start the bounded Provider retry supervisor
/// when the external service is temporarily unavailable.
pub async fn initialize_and_spawn(
    repository_factory: PgRepositoryFactory,
    arkret_config: &ArkretConfig,
    public_base: &Url,
    key_store: &Keystore,
    http: reqwest::Client,
) -> anyhow::Result<()> {
    let handle = arkret_config.runtime_service_identity.clone();
    let provider = match select_provider(arkret_config) {
        Ok(provider) => provider,
        Err(state) => {
            handle.store(*state);
            return Ok(());
        }
    };
    let registration_key = ServiceRegistrationKey::new(
        ServiceKind::AuthServer,
        CanonicalServiceUrl::canonicalize(public_base.as_str())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let signing_seed = match key_store.service_identity_seed() {
        Ok(seed) => seed,
        Err(error) => {
            handle.store(ServiceIdentityState::Faulted {
                diagnostic: ServiceIdentityDiagnostic::KeyMismatch,
                next_action: format!(
                    "restore the Ed25519 key backend entry with kid `{}`: {error}",
                    coauth_keystore::SERVICE_IDENTITY_KEY_ID
                ),
            });
            return Ok(());
        }
    };

    let state = resolve_once(
        &repository_factory,
        &provider,
        &registration_key,
        &signing_seed,
        &http,
    )
    .await?;
    let retry = matches!(
        state,
        ServiceIdentityState::WaitingProvider { .. } | ServiceIdentityState::DegradedStored { .. }
    );
    handle.store(state);

    if retry {
        tokio::spawn(run_supervisor(
            repository_factory,
            provider,
            registration_key,
            signing_seed,
            http,
            handle,
        ));
    }
    Ok(())
}

async fn run_supervisor(
    repository_factory: PgRepositoryFactory,
    provider: ProviderCandidate,
    registration_key: ServiceRegistrationKey,
    signing_seed: [u8; 32],
    http: reqwest::Client,
    handle: RuntimeServiceIdentity,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(RETRY_DELAY_SECONDS as u64));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        match resolve_once(
            &repository_factory,
            &provider,
            &registration_key,
            &signing_seed,
            &http,
        )
        .await
        {
            Ok(state) => {
                let retry = matches!(
                    state,
                    ServiceIdentityState::WaitingProvider { .. }
                        | ServiceIdentityState::DegradedStored { .. }
                );
                handle.store(state);
                if !retry {
                    break;
                }
            }
            Err(error) => tracing::error!(%error, "service identity supervisor database failure"),
        }
    }
}

fn select_provider(config: &ArkretConfig) -> Result<ProviderCandidate, Box<ServiceIdentityState>> {
    let mut candidates = config
        .principal_servers
        .iter()
        .filter_map(|server| {
            server
                .embedded_webvh_registration_bearer
                .as_ref()
                .map(|bearer| (server.name.clone(), server.endpoint.clone(), bearer.clone()))
        })
        .collect::<Vec<_>>();
    candidates.extend(config.identity_services.iter().map(|service| {
        (
            service.name.clone(),
            service.endpoint.clone(),
            service.registration_bearer.clone(),
        )
    }));
    if let Some(selected) = config.identity_provider.as_deref() {
        candidates.retain(|(name, ..)| name == selected);
    }
    match candidates.as_slice() {
        [] => Err(Box::new(ServiceIdentityState::Faulted {
            diagnostic: ServiceIdentityDiagnostic::ProviderNotConfigured,
            next_action: "configure registration credentials on one trusted principal_servers[] or identity_services[] entry"
                .to_owned(),
        })),
        [(name, provider_endpoint, bearer)] => {
            let endpoint = CanonicalServiceUrl::canonicalize(provider_endpoint.as_str()).map_err(
                |error| Box::new(ServiceIdentityState::Faulted {
                    diagnostic: ServiceIdentityDiagnostic::ProviderNotConfigured,
                    next_action: format!("fix Provider endpoint {provider_endpoint}: {error}"),
                }),
            )?;
            Ok(ProviderCandidate {
                reference: ServiceIdentityProviderRef {
                    name: name.clone(),
                    endpoint,
                },
                bearer: bearer.clone(),
            })
        }
        _ => Err(Box::new(ServiceIdentityState::Faulted {
            diagnostic: ServiceIdentityDiagnostic::ProviderAmbiguous,
            next_action: format!(
                "set `arkret.identity_provider` to one of: {}",
                candidates
                    .iter()
                    .map(|(name, _, _)| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })),
    }
}

async fn resolve_once(
    repository_factory: &PgRepositoryFactory,
    provider: &ProviderCandidate,
    registration_key: &ServiceRegistrationKey,
    signing_seed: &[u8; 32],
    http: &reqwest::Client,
) -> anyhow::Result<ServiceIdentityState> {
    let stored = match load_stored(repository_factory).await?.into_runtime_result() {
        Ok(stored) => stored,
        Err(state) => return Ok(*state),
    };
    let prepared = match prepare_inception(provider, registration_key, signing_seed) {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(ServiceIdentityState::Faulted {
                diagnostic: ServiceIdentityDiagnostic::KeyMismatch,
                next_action: format!("repair the configured service-identity key backend: {error}"),
            });
        }
    };
    if let Some(stored) = &stored {
        if let Err(error) = stored.validate() {
            return Ok(ServiceIdentityState::Faulted {
                diagnostic: ServiceIdentityDiagnostic::RestoreFailed,
                next_action: format!(
                    "restore a verified service_identity database record; the stored record is invalid: {error}"
                ),
            });
        }
        if let Err(error) = validate_local_key_binding(stored, signing_seed, &prepared) {
            return Ok(ServiceIdentityState::Faulted {
                diagnostic: ServiceIdentityDiagnostic::KeyMismatch,
                next_action: format!(
                    "restore the key backend that controls the persisted service identity: {error}"
                ),
            });
        }
        if stored.identity.registration_key != *registration_key {
            return Ok(ServiceIdentityState::RegistrationKeyDrift {
                identity: stored.identity.clone(),
                stored_key: stored.identity.registration_key.clone(),
                computed_key: registration_key.clone(),
            });
        }
    }

    let client = match provider_client(provider, http.clone()) {
        Ok(client) => client,
        Err(error) => {
            return Ok(ServiceIdentityState::Faulted {
                diagnostic: ServiceIdentityDiagnostic::ProviderNotConfigured,
                next_action: format!("fix the configured Provider endpoint: {error}"),
            });
        }
    };
    match client.service_registration_get(registration_key).await {
        Ok(outcome) => {
            accept_provider_outcome(
                repository_factory,
                provider,
                registration_key,
                signing_seed,
                &prepared,
                stored.as_ref(),
                outcome,
            )
            .await
        }
        Err(arkret_http_client::Error::Api { status: 404, .. }) if stored.is_none() => {
            let request = match ServiceRegistrationEnsureRequestBody::new(
                registration_key.clone(),
                match prepared.service_registration_operation() {
                    Ok(operation) => operation,
                    Err(error) => {
                        return Ok(ServiceIdentityState::Faulted {
                            diagnostic: ServiceIdentityDiagnostic::KeyMismatch,
                            next_action: format!(
                                "repair the configured service-identity key backend: {error}"
                            ),
                        });
                    }
                },
                None,
            ) {
                Ok(request) => request,
                Err(error) => {
                    return Ok(ServiceIdentityState::Faulted {
                        diagnostic: ServiceIdentityDiagnostic::RestoreFailed,
                        next_action: format!(
                            "repair the service-registration inception input: {error}"
                        ),
                    });
                }
            };
            match client.service_registration_ensure(&request).await {
                Ok(outcome) => {
                    accept_provider_outcome(
                        repository_factory,
                        provider,
                        registration_key,
                        signing_seed,
                        &prepared,
                        None,
                        outcome,
                    )
                    .await
                }
                Err(error) if provider_unavailable(&error) => {
                    Ok(waiting_provider(registration_key))
                }
                Err(ensure_error) => {
                    match client.service_registration_get(registration_key).await {
                        // Another process may have won the first-provisioning race
                        // with the same local key but a different versionTime.
                        Ok(outcome) => {
                            accept_provider_outcome(
                                repository_factory,
                                provider,
                                registration_key,
                                signing_seed,
                                &prepared,
                                None,
                                outcome,
                            )
                            .await
                        }
                        Err(error) if provider_unavailable(&error) => {
                            Ok(waiting_provider(registration_key))
                        }
                        Err(lookup_error) => Ok(ServiceIdentityState::Faulted {
                            diagnostic: ServiceIdentityDiagnostic::RestoreFailed,
                            next_action: format!(
                                "Provider rejected service registration ({ensure_error}) and the follow-up mapping lookup failed ({lookup_error}); verify the endpoint, transport credential, and retained key backend"
                            ),
                        }),
                    }
                }
            }
        }
        Err(error) if provider_unavailable(&error) => {
            if let Some(stored) = stored {
                Ok(ServiceIdentityState::DegradedStored {
                    identity: stored.identity,
                    retry_at: retry_at(),
                    last_error: error.to_string(),
                })
            } else {
                Ok(waiting_provider(registration_key))
            }
        }
        Err(error) => Ok(ServiceIdentityState::Faulted {
            diagnostic: ServiceIdentityDiagnostic::RestoreFailed,
            next_action: format!(
                "Provider mapping lookup failed: {error}; verify the endpoint, transport credential, and retained key backend"
            ),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_provider_outcome(
    repository_factory: &PgRepositoryFactory,
    provider: &ProviderCandidate,
    registration_key: &ServiceRegistrationKey,
    signing_seed: &[u8; 32],
    prepared: &PreparedInception,
    prior: Option<&StoredServiceIdentity>,
    outcome: ServiceRegistrationOutcome,
) -> anyhow::Result<ServiceIdentityState> {
    if let Some(prior) = prior
        && prior.identity.service_id != outcome.service_id
    {
        return Ok(ServiceIdentityState::Conflict {
            stored_service_id: prior.identity.service_id.clone(),
            provider_service_id: outcome.service_id,
        });
    }
    let stored = match stored_from_outcome(
        provider,
        registration_key,
        signing_seed,
        prepared,
        outcome,
    ) {
        Ok(stored) => stored,
        Err(error) => {
            let diagnostic = if error.to_string().contains("service_identity_key_mismatch") {
                ServiceIdentityDiagnostic::KeyMismatch
            } else {
                ServiceIdentityDiagnostic::RestoreFailed
            };
            return Ok(ServiceIdentityState::Faulted {
                diagnostic,
                next_action: format!(
                    "reject the Provider result and restore the expected mapping/key backend: {error}"
                ),
            });
        }
    };
    save_stored(repository_factory, &stored).await?;
    Ok(ServiceIdentityState::Ready {
        identity: stored.identity,
    })
}

fn provider_client(provider: &ProviderCandidate, http: reqwest::Client) -> anyhow::Result<Client> {
    ClientBuilder::new(provider.reference.endpoint.as_url())
        .http_client(http)
        .auth(Auth::Bearer(provider.bearer.clone()))
        .allow_insecure_localhost()
        .build()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn prepare_inception(
    provider: &ProviderCandidate,
    registration_key: &ServiceRegistrationKey,
    signing_seed: &[u8; 32],
) -> anyhow::Result<PreparedInception> {
    let mut hasher = Sha256::new();
    hasher.update(b"arkret.coauth.service-identity.webvh-update.v1\0");
    hasher.update(signing_seed);
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha20Rng::from_seed(seed);
    prepare_service_registration_inception_with_did_key_seed(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &provider.reference.endpoint.as_url(),
            registration_key,
            also_known_as: &[],
            version_time: Utc::now(),
            did_key_fragment: Some("service-key"),
        },
        signing_seed,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn stored_from_outcome(
    provider: &ProviderCandidate,
    registration_key: &ServiceRegistrationKey,
    signing_seed: &[u8; 32],
    prepared: &PreparedInception,
    outcome: ServiceRegistrationOutcome,
) -> anyhow::Result<StoredServiceIdentity> {
    outcome
        .validate_for(registration_key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let expected_assertion = assertion_public_key(signing_seed);
    let signing_key_ref =
        ServiceIdentityKeyRef::new(format!("coauth:secrets:ed25519:{expected_assertion}"))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let control_key_ref = ServiceIdentityKeyRef::new(format!(
        "coauth:secrets:derived-webvh-update:{}",
        prepared.update_public_key_multibase
    ))
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let stored = StoredServiceIdentity {
        identity: LocalServiceIdentity {
            service_id: outcome.service_id,
            registration_key: registration_key.clone(),
            provider: Some(provider.reference.clone()),
            signing_key_refs: vec![signing_key_ref.clone()],
            active_signing_key_ref: signing_key_ref,
            control_key_ref,
            version_id: outcome.version_id,
            last_verified_at: Utc::now(),
        },
        did_document: outcome.did_document,
        registration_receipt: outcome.registration_receipt,
        stored_at: Utc::now(),
    };
    stored
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    validate_local_key_binding(&stored, signing_seed, prepared)?;
    Ok(stored)
}

fn assertion_public_key(signing_seed: &[u8; 32]) -> String {
    arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
        &ed25519_dalek::SigningKey::from_bytes(signing_seed)
            .verifying_key()
            .to_bytes(),
    )
}

fn validate_local_key_binding(
    stored: &StoredServiceIdentity,
    signing_seed: &[u8; 32],
    prepared: &PreparedInception,
) -> anyhow::Result<()> {
    let expected_assertion = assertion_public_key(signing_seed);
    let Some(assertion_method) = stored
        .did_document
        .verification_method
        .iter()
        .find(|method| method.public_key_multibase == expected_assertion)
    else {
        anyhow::bail!(
            "service_identity_key_mismatch: DID document does not publish the configured Ed25519 service key"
        );
    };
    if !stored
        .did_document
        .assertion_method
        .iter()
        .any(|method| method == &assertion_method.id)
    {
        anyhow::bail!(
            "service_identity_key_mismatch: configured Ed25519 service key is not an assertionMethod"
        );
    }

    let expected_signing_ref =
        ServiceIdentityKeyRef::new(format!("coauth:secrets:ed25519:{expected_assertion}"))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if stored.identity.active_signing_key_ref != expected_signing_ref
        || !stored
            .identity
            .signing_key_refs
            .iter()
            .any(|key_ref| key_ref == &expected_signing_ref)
    {
        anyhow::bail!(
            "service_identity_key_mismatch: persisted active signing key reference does not match the configured key"
        );
    }

    let expected_control_ref = ServiceIdentityKeyRef::new(format!(
        "coauth:secrets:derived-webvh-update:{}",
        prepared.update_public_key_multibase
    ))
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if stored.identity.control_key_ref != expected_control_ref {
        anyhow::bail!(
            "service_identity_key_mismatch: persisted control key reference does not match the configured key"
        );
    }

    let control_digest = prepared
        .service_registration_operation()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .control_key_digest()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if stored.registration_receipt.control_key_digest != control_digest {
        anyhow::bail!(
            "service_identity_key_mismatch: registration receipt is controlled by different WebVH key material"
        );
    }
    Ok(())
}

async fn load_stored(
    repository_factory: &PgRepositoryFactory,
) -> anyhow::Result<StoredIdentityLoad> {
    let mut connection = repository_factory.pool().get().await?;
    let row = diesel::sql_query("SELECT identity FROM service_identity WHERE id = 1")
        .get_result::<IdentityRow>(&mut *connection)
        .await
        .optional()?;
    Ok(match row {
        None => StoredIdentityLoad::Missing,
        Some(row) => match serde_json::from_value(row.identity) {
            Ok(stored) => StoredIdentityLoad::Loaded(Box::new(stored)),
            Err(error) => StoredIdentityLoad::Invalid(error.to_string()),
        },
    })
}

async fn save_stored(
    repository_factory: &PgRepositoryFactory,
    identity: &StoredServiceIdentity,
) -> anyhow::Result<()> {
    let mut connection = repository_factory.pool().get().await?;
    diesel::sql_query(
        "INSERT INTO service_identity (id, identity, updated_at) VALUES (1, $1, now()) \
         ON CONFLICT (id) DO UPDATE SET identity = EXCLUDED.identity, updated_at = now()",
    )
    .bind::<Jsonb, _>(serde_json::to_value(identity)?)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

fn waiting_provider(registration_key: &ServiceRegistrationKey) -> ServiceIdentityState {
    ServiceIdentityState::WaitingProvider {
        registration_key: registration_key.clone(),
        retry_at: retry_at(),
    }
}

fn retry_at() -> chrono::DateTime<Utc> {
    Utc::now() + chrono::Duration::seconds(RETRY_DELAY_SECONDS)
}

fn provider_unavailable(error: &arkret_http_client::Error) -> bool {
    matches!(
        error,
        arkret_http_client::Error::Http(_)
            | arkret_http_client::Error::Api {
                status: 429 | 502 | 503 | 504,
                ..
            }
    )
}

#[cfg(test)]
mod tests {
    use coauth_config::{IdentityServiceConfig, PrincipalServerConfig};

    use super::*;

    fn standalone(name: &str, endpoint: &str) -> IdentityServiceConfig {
        IdentityServiceConfig {
            name: name.to_owned(),
            endpoint: endpoint.parse().unwrap(),
            registration_bearer: format!("{name}-bearer"),
        }
    }

    fn principal(name: &str, endpoint: &str) -> PrincipalServerConfig {
        PrincipalServerConfig {
            name: name.to_owned(),
            endpoint: endpoint.parse().unwrap(),
            session_grant_introspection_bearer: None,
            embedded_webvh_registration_bearer: Some(format!("{name}-bearer")),
        }
    }

    #[test]
    fn standalone_provider_is_selected_without_product_branching() {
        let config = ArkretConfig {
            identity_services: vec![standalone("identity-a", "https://identity.example/")],
            ..ArkretConfig::default()
        };
        let selected = select_provider(&config).unwrap();
        assert_eq!(selected.reference.name, "identity-a");
        assert_eq!(
            selected.reference.endpoint.as_str(),
            "https://identity.example/"
        );
    }

    #[test]
    fn multiple_provider_roles_require_explicit_name() {
        let config = ArkretConfig {
            principal_servers: vec![principal("principal-a", "https://principal.example/")],
            identity_services: vec![standalone("identity-a", "https://identity.example/")],
            ..ArkretConfig::default()
        };
        assert!(select_provider(&config).is_err_and(|state| matches!(
            *state,
            ServiceIdentityState::Faulted {
                diagnostic: ServiceIdentityDiagnostic::ProviderAmbiguous,
                ..
            }
        )));
    }

    #[test]
    fn explicit_provider_name_disambiguates_equal_roles() {
        let config = ArkretConfig {
            principal_servers: vec![principal("principal-a", "https://principal.example/")],
            identity_services: vec![standalone("identity-a", "https://identity.example/")],
            identity_provider: Some("identity-a".to_owned()),
            ..ArkretConfig::default()
        };
        let selected = select_provider(&config).unwrap();
        assert_eq!(selected.reference.name, "identity-a");
    }

    #[test]
    fn malformed_persisted_identity_is_a_faulted_runtime_state() {
        let load = match serde_json::from_value::<StoredServiceIdentity>(Value::Null) {
            Ok(stored) => StoredIdentityLoad::Loaded(Box::new(stored)),
            Err(error) => StoredIdentityLoad::Invalid(error.to_string()),
        };

        let state = load
            .into_runtime_result()
            .expect_err("malformed persisted identity must fail closed");

        assert!(matches!(
            *state,
            ServiceIdentityState::Faulted {
                diagnostic: ServiceIdentityDiagnostic::RestoreFailed,
                ..
            }
        ));
    }
}
