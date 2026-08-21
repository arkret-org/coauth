//! Provider-backed runtime service identity for the class-A Coauth service.

use std::time::Duration;

use arkret_http_client::{Auth, Client, ClientBuilder};
use arkret_identity::DidWebvhResolver;
use arkret_identity::service_identity::{
    DidCoreIdentityBundle, DidCoreIdentityDiagnostic, DidCoreIdentityKeyRef,
    DidCoreIdentityProviderRef, DidCoreIdentityState, LocalDidCoreIdentity, StoredDidCoreIdentity,
};
use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey,
    ServiceRegistrationOutcome, ServiceWebvhInceptionOperation,
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
use uuid::Uuid;

use crate::outbound_http;

const RETRY_DELAY_SECONDS: i64 = 5;
pub(crate) const SERVICE_IDENTITY_VERIFICATION_METHOD_FRAGMENT: &str = "service-key";

#[derive(Clone)]
struct ProviderCandidate {
    reference: DidCoreIdentityProviderRef,
    bearer: String,
}

#[derive(QueryableByName)]
struct IdentityRow {
    #[diesel(sql_type = Jsonb)]
    identity: Value,
}

#[derive(Clone, Debug)]
struct StoredIdentityRecord {
    identity: StoredDidCoreIdentity,
    inception_operation: ServiceWebvhInceptionOperation,
}

enum StoredIdentityLoad {
    Missing,
    Loaded(Box<StoredIdentityRecord>),
    Invalid(String),
}

#[derive(Debug, thiserror::Error)]
enum LocalKeyBindingError {
    #[error("DID document does not publish the configured Ed25519 service key")]
    AssertionKeyMissing,
    #[error("configured Ed25519 service key is not an assertionMethod")]
    AssertionMethodMissing,
    #[error("persisted active signing key reference does not match the configured key")]
    SigningKeyReferenceMismatch,
    #[error("persisted control key reference does not match the configured key")]
    ControlKeyReferenceMismatch,
    #[error("registration receipt is controlled by different WebVH key material")]
    RegistrationControlKeyMismatch,
    #[error("invalid local service-identity key reference: {0}")]
    InvalidKeyReference(String),
    #[error("cannot derive the local WebVH control-key digest: {0}")]
    ControlKeyDigest(String),
}

/// Failure of [`restore_inception_operation`].
#[derive(Debug, thiserror::Error)]
enum InceptionRestoreError {
    #[error("the provider-hosted did:webvh history is unreachable: {0}")]
    Unreachable(String),
    #[error("the provider-hosted did:webvh history is not evidence for this registration: {0}")]
    InvalidEvidence(String),
    #[error(
        "the registered did:webvh inception is controlled by key material this deployment does not hold"
    )]
    ControlKeyMismatch,
}

impl LocalKeyBindingError {
    const fn is_key_mismatch(&self) -> bool {
        matches!(
            self,
            Self::AssertionKeyMissing
                | Self::AssertionMethodMissing
                | Self::SigningKeyReferenceMismatch
                | Self::ControlKeyReferenceMismatch
                | Self::RegistrationControlKeyMismatch
        )
    }
}

fn local_key_binding_diagnostic(error: &anyhow::Error) -> DidCoreIdentityDiagnostic {
    if error
        .downcast_ref::<LocalKeyBindingError>()
        .is_some_and(LocalKeyBindingError::is_key_mismatch)
    {
        DidCoreIdentityDiagnostic::KeyMismatch
    } else {
        DidCoreIdentityDiagnostic::RestoreFailed
    }
}

impl StoredIdentityLoad {
    fn into_runtime_result(
        self,
    ) -> Result<Option<StoredIdentityRecord>, Box<DidCoreIdentityState>> {
        match self {
            Self::Missing => Ok(None),
            Self::Loaded(stored) => Ok(Some(*stored)),
            Self::Invalid(error) => Err(Box::new(DidCoreIdentityState::Faulted {
                diagnostic: DidCoreIdentityDiagnostic::RestoreFailed,
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
            handle.store(DidCoreIdentityState::Faulted {
                diagnostic: DidCoreIdentityDiagnostic::KeyMismatch,
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
        DidCoreIdentityState::WaitingProvider { .. } | DidCoreIdentityState::DegradedStored { .. }
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
                    DidCoreIdentityState::WaitingProvider { .. }
                        | DidCoreIdentityState::DegradedStored { .. }
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

fn select_provider(config: &ArkretConfig) -> Result<ProviderCandidate, Box<DidCoreIdentityState>> {
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
        [] => Err(Box::new(DidCoreIdentityState::Faulted {
            diagnostic: DidCoreIdentityDiagnostic::ProviderNotConfigured,
            next_action: "configure registration credentials on one trusted principal_servers[] or identity_services[] entry"
                .to_owned(),
        })),
        [(name, provider_endpoint, bearer)] => {
            let endpoint = CanonicalServiceUrl::canonicalize(provider_endpoint.as_str()).map_err(
                |error| Box::new(DidCoreIdentityState::Faulted {
                    diagnostic: DidCoreIdentityDiagnostic::ProviderNotConfigured,
                    next_action: format!("fix Provider endpoint {provider_endpoint}: {error}"),
                }),
            )?;
            Ok(ProviderCandidate {
                reference: DidCoreIdentityProviderRef {
                    name: name.clone(),
                    endpoint,
                },
                bearer: bearer.clone(),
            })
        }
        _ => Err(Box::new(DidCoreIdentityState::Faulted {
            diagnostic: DidCoreIdentityDiagnostic::ProviderAmbiguous,
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
) -> anyhow::Result<DidCoreIdentityState> {
    let stored = match load_stored(repository_factory).await?.into_runtime_result() {
        Ok(stored) => stored,
        Err(state) => return Ok(*state),
    };
    let prepared = match prepare_inception(provider, registration_key, signing_seed) {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(DidCoreIdentityState::Faulted {
                diagnostic: DidCoreIdentityDiagnostic::KeyMismatch,
                next_action: format!("repair the configured service-identity key backend: {error}"),
            });
        }
    };
    if let Some(stored) = &stored {
        if let Err(error) = stored.identity.validate() {
            return Ok(DidCoreIdentityState::Faulted {
                diagnostic: DidCoreIdentityDiagnostic::RestoreFailed,
                next_action: format!(
                    "restore a verified service_identity database record; the stored record is invalid: {error}"
                ),
            });
        }
        if let Err(error) = validate_local_key_binding(&stored.identity, signing_seed, &prepared) {
            return Ok(DidCoreIdentityState::Faulted {
                diagnostic: DidCoreIdentityDiagnostic::KeyMismatch,
                next_action: format!(
                    "restore the key backend that controls the persisted service identity: {error}"
                ),
            });
        }
        if stored.identity.identity.registration_key != *registration_key {
            return Ok(DidCoreIdentityState::RegistrationKeyDrift {
                identity: stored.identity.identity.clone(),
                stored_key: stored.identity.identity.registration_key.clone(),
                computed_key: registration_key.clone(),
            });
        }
    }

    let client = match provider_client(provider, http.clone()) {
        Ok(client) => client,
        Err(error) => {
            return Ok(DidCoreIdentityState::Faulted {
                diagnostic: DidCoreIdentityDiagnostic::ProviderNotConfigured,
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
                http,
            )
            .await
        }
        Err(arkret_http_client::Error::Api { status: 404, .. }) => {
            let request = match service_registration_request(
                registration_key,
                &prepared,
                stored.as_ref(),
            ) {
                Ok(request) => request,
                Err(error) => {
                    return Ok(DidCoreIdentityState::Faulted {
                        diagnostic: DidCoreIdentityDiagnostic::RestoreFailed,
                        next_action: format!(
                            "restore the service identity bundle needed to replay the original registration: {error}"
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
                        stored.as_ref(),
                        outcome,
                        http,
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
                                stored.as_ref(),
                                outcome,
                                http,
                            )
                            .await
                        }
                        Err(error) if provider_unavailable(&error) => {
                            Ok(waiting_provider(registration_key))
                        }
                        Err(lookup_error) => Ok(DidCoreIdentityState::Faulted {
                            diagnostic: DidCoreIdentityDiagnostic::RestoreFailed,
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
                Ok(DidCoreIdentityState::DegradedStored {
                    identity: stored.identity.identity,
                    retry_at: retry_at(),
                    last_error: error.to_string(),
                })
            } else {
                Ok(waiting_provider(registration_key))
            }
        }
        Err(error) => Ok(DidCoreIdentityState::Faulted {
            diagnostic: DidCoreIdentityDiagnostic::RestoreFailed,
            next_action: format!(
                "Provider mapping lookup failed: {error}; verify the endpoint, transport credential, and retained key backend"
            ),
        }),
    }
}

fn service_registration_request(
    registration_key: &ServiceRegistrationKey,
    prepared: &PreparedInception,
    stored: Option<&StoredIdentityRecord>,
) -> anyhow::Result<ServiceRegistrationEnsureRequestBody> {
    let (operation, previous_receipt) = match stored {
        Some(stored) => (
            stored.inception_operation.clone(),
            Some(stored.identity.registration_receipt.clone()),
        ),
        None => (
            prepared
                .service_registration_operation()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            None,
        ),
    };
    ServiceRegistrationEnsureRequestBody::new(
        registration_key.clone(),
        operation,
        ensure_attempt_correlation_id(),
        previous_receipt,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Bounded opaque correlation string for a single ensure attempt. It only
/// relates audit records for that attempt: registration identity is the
/// canonical `(service_kind, public_base)` key, and the sole idempotency
/// authority is the operation registry's `idempotency_mechanism=object_id`,
/// so this value MUST NOT be derived from the registration key.
fn ensure_attempt_correlation_id() -> String {
    format!("coauth-service-registration-ensure-{}", Uuid::now_v7())
}

#[allow(clippy::too_many_arguments)]
async fn accept_provider_outcome(
    repository_factory: &PgRepositoryFactory,
    provider: &ProviderCandidate,
    registration_key: &ServiceRegistrationKey,
    signing_seed: &[u8; 32],
    prepared: &PreparedInception,
    prior: Option<&StoredIdentityRecord>,
    outcome: ServiceRegistrationOutcome,
    http: &reqwest::Client,
) -> anyhow::Result<DidCoreIdentityState> {
    if let Some(prior) = prior
        && prior.identity.identity.service_id != outcome.service_id
    {
        return Ok(DidCoreIdentityState::Conflict {
            stored_service_id: prior.identity.identity.service_id.clone(),
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
            let diagnostic = local_key_binding_diagnostic(&error);
            return Ok(DidCoreIdentityState::Faulted {
                diagnostic,
                next_action: format!(
                    "reject the Provider result and restore the expected mapping/key backend: {error}"
                ),
            });
        }
    };
    let local_operation = prior
        .map(|prior| prior.inception_operation.clone())
        .or_else(|| {
            prepared
                .service_registration_operation()
                .ok()
                .filter(|operation| operation.state.id == stored.identity.full_id)
        });
    let inception_operation = match local_operation {
        Some(operation) => operation,
        None => {
            match restore_inception_operation(http, registration_key, prepared, &stored).await {
                Ok(operation) => operation,
                Err(InceptionRestoreError::Unreachable(error)) => {
                    tracing::warn!(
                        %error,
                        "provider-hosted did:webvh history unreachable while restoring the registered service identity"
                    );
                    return Ok(waiting_provider(registration_key));
                }
                Err(error @ InceptionRestoreError::ControlKeyMismatch) => {
                    return Ok(DidCoreIdentityState::Faulted {
                        diagnostic: DidCoreIdentityDiagnostic::KeyMismatch,
                        next_action: format!(
                            "restore the key backend that controls the registered service DID: {error}"
                        ),
                    });
                }
                Err(error) => {
                    return Ok(DidCoreIdentityState::Faulted {
                        diagnostic: DidCoreIdentityDiagnostic::RestoreFailed,
                        next_action: format!(
                            "restore a verified service_identity database record or repair the Provider-hosted did:webvh history: {error}"
                        ),
                    });
                }
            }
        }
    };
    save_stored(repository_factory, &stored, inception_operation).await?;
    Ok(DidCoreIdentityState::Ready {
        identity: stored.identity,
    })
}

/// Recover the byte-exact signed inception operation of an existing Provider
/// registration from its method-native `did:webvh` history.
///
/// `identity/identity-did.md` §3.7 I-3 requires a class-A service to look its
/// registration key up on the Provider and, when the mapping exists and the
/// local control/signing key binding checks out, back-fill the original DID.
/// Losing local persistence (a restore onto a fresh database) leaves the
/// runtime holding its key backend but no `webvh_history`, and the inception
/// bytes cannot be re-derived locally: the SCID commits to the original
/// `versionTime`, which the registration outcome does not carry. Re-signing a
/// fresh inception would therefore mint a *different* DID, which is exactly
/// what the Provider's `service_identity_conflict` correctly refuses.
///
/// The history is self-certifying — SCID derivation plus entry proofs signed
/// by `updateKeys` — so nothing here trusts transport or the Provider's word:
///
/// 1. the verified head must still be the registration coordinates the Provider just returned, so a
///    DID whose history has moved on is never silently adopted;
/// 2. the first entry must be a well-formed inception for this registration key and DID;
/// 3. its canonical digest must equal the `log_head_digest` the Provider signed into the receipt;
/// 4. its `updateKeys[0]` must be the control key this process derives from its own key backend.
///
/// Step 4 is the control proof. Only a process holding the local
/// service-identity seed satisfies it, so a registration rooted in foreign key
/// material fails closed instead of being adopted.
async fn restore_inception_operation(
    http: &reqwest::Client,
    registration_key: &ServiceRegistrationKey,
    prepared: &PreparedInception,
    stored: &StoredDidCoreIdentity,
) -> Result<ServiceWebvhInceptionOperation, InceptionRestoreError> {
    let full_id = &stored.identity.full_id;
    let log_url = DidWebvhResolver::log_url(full_id)
        .map_err(|error| InceptionRestoreError::InvalidEvidence(error.to_string()))?;
    let log_url = Url::parse(&log_url)
        .map_err(|error| InceptionRestoreError::InvalidEvidence(error.to_string()))?;
    let log_bytes = outbound_http::fetch_bounded(
        http,
        outbound_http::soland_policy("service_identity_webvh_log"),
        log_url,
        outbound_http::WEBVH_LOG_MAX_BYTES,
    )
    .await
    .map_err(|error| match error {
        outbound_http::BoundedFetchError::Unreachable(message)
        | outbound_http::BoundedFetchError::EgressDenied(message) => {
            InceptionRestoreError::Unreachable(message)
        }
        outbound_http::BoundedFetchError::TooLarge(message) => {
            InceptionRestoreError::InvalidEvidence(message)
        }
    })?;
    adopt_inception_from_log(registration_key, prepared, stored, &log_bytes)
}

/// Pure evidence half of [`restore_inception_operation`]: everything except
/// the network fetch, so the fail-closed rules are directly testable.
fn adopt_inception_from_log(
    registration_key: &ServiceRegistrationKey,
    prepared: &PreparedInception,
    stored: &StoredDidCoreIdentity,
    log_bytes: &[u8],
) -> Result<ServiceWebvhInceptionOperation, InceptionRestoreError> {
    let full_id = &stored.identity.full_id;
    let verified = arkret_identity::verify_did_webvh_v1_chain_bytes(full_id, log_bytes)
        .map_err(|error| InceptionRestoreError::InvalidEvidence(error.to_string()))?;
    if verified.head_version_id != stored.identity.version_id {
        return Err(InceptionRestoreError::InvalidEvidence(format!(
            "verified did:webvh head {} is not the registered version {}",
            verified.head_version_id, stored.identity.version_id
        )));
    }
    let genesis = verified.raw_entries.as_slice().first().ok_or_else(|| {
        InceptionRestoreError::InvalidEvidence(
            "verified did:webvh history has no inception entry".to_owned(),
        )
    })?;
    let operation: ServiceWebvhInceptionOperation = serde_json::from_value(genesis.clone())
        .map_err(|error| InceptionRestoreError::InvalidEvidence(error.to_string()))?;
    operation
        .validate_for(registration_key)
        .map_err(|error| InceptionRestoreError::InvalidEvidence(error.to_string()))?;
    if operation.state.id != *full_id {
        return Err(InceptionRestoreError::InvalidEvidence(format!(
            "did:webvh inception subject {} is not the registered service DID {full_id}",
            operation.state.id
        )));
    }
    let log_head_digest = operation
        .log_head_digest()
        .map_err(|error| InceptionRestoreError::InvalidEvidence(error.to_string()))?;
    if log_head_digest != stored.registration_receipt.log_head_digest {
        return Err(InceptionRestoreError::InvalidEvidence(
            "did:webvh inception digest does not match the signed registration receipt".to_owned(),
        ));
    }
    let expected_control_key_digest = prepared
        .service_registration_operation()
        .map_err(|error| InceptionRestoreError::InvalidEvidence(error.to_string()))?
        .control_key_digest()
        .map_err(|error| InceptionRestoreError::InvalidEvidence(error.to_string()))?;
    let control_key_digest = operation
        .control_key_digest()
        .map_err(|error| InceptionRestoreError::InvalidEvidence(error.to_string()))?;
    if control_key_digest != expected_control_key_digest {
        return Err(InceptionRestoreError::ControlKeyMismatch);
    }
    Ok(operation)
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
            did_key_fragment: Some(SERVICE_IDENTITY_VERIFICATION_METHOD_FRAGMENT),
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
) -> anyhow::Result<StoredDidCoreIdentity> {
    outcome
        .validate_for(registration_key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let expected_assertion = assertion_public_key(signing_seed);
    let signing_key_ref =
        DidCoreIdentityKeyRef::new(format!("coauth:secrets:ed25519:{expected_assertion}"))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let control_key_ref = DidCoreIdentityKeyRef::new(format!(
        "coauth:secrets:derived-webvh-update:{}",
        prepared.update_public_key_multibase
    ))
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let stored = StoredDidCoreIdentity {
        identity: LocalDidCoreIdentity {
            service_id: outcome.service_id,
            full_id: outcome.full_id,
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
    stored: &StoredDidCoreIdentity,
    signing_seed: &[u8; 32],
    prepared: &PreparedInception,
) -> Result<(), LocalKeyBindingError> {
    let expected_assertion = assertion_public_key(signing_seed);
    let Some(assertion_method) = stored
        .did_document
        .verification_method
        .iter()
        .find(|method| method.public_key_multibase == expected_assertion)
    else {
        return Err(LocalKeyBindingError::AssertionKeyMissing);
    };
    if !stored
        .did_document
        .assertion_method
        .iter()
        .any(|method| method == &assertion_method.id)
    {
        return Err(LocalKeyBindingError::AssertionMethodMissing);
    }

    let expected_signing_ref =
        DidCoreIdentityKeyRef::new(format!("coauth:secrets:ed25519:{expected_assertion}"))
            .map_err(|error| LocalKeyBindingError::InvalidKeyReference(error.to_string()))?;
    if stored.identity.active_signing_key_ref != expected_signing_ref
        || !stored
            .identity
            .signing_key_refs
            .iter()
            .any(|key_ref| key_ref == &expected_signing_ref)
    {
        return Err(LocalKeyBindingError::SigningKeyReferenceMismatch);
    }

    let expected_control_ref = DidCoreIdentityKeyRef::new(format!(
        "coauth:secrets:derived-webvh-update:{}",
        prepared.update_public_key_multibase
    ))
    .map_err(|error| LocalKeyBindingError::InvalidKeyReference(error.to_string()))?;
    if stored.identity.control_key_ref != expected_control_ref {
        return Err(LocalKeyBindingError::ControlKeyReferenceMismatch);
    }

    let control_digest = prepared
        .service_registration_operation()
        .map_err(|error| LocalKeyBindingError::ControlKeyDigest(error.to_string()))?
        .control_key_digest()
        .map_err(|error| LocalKeyBindingError::ControlKeyDigest(error.to_string()))?;
    if stored.registration_receipt.control_key_digest != control_digest {
        return Err(LocalKeyBindingError::RegistrationControlKeyMismatch);
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
        Some(row) => decode_stored_identity(row.identity),
    })
}

fn decode_stored_identity(value: Value) -> StoredIdentityLoad {
    match serde_json::from_value::<DidCoreIdentityBundle>(value) {
        Ok(bundle) => match bundle.validate() {
            Ok(()) => StoredIdentityLoad::Loaded(Box::new(StoredIdentityRecord {
                inception_operation: bundle.webvh_history[0].clone(),
                identity: bundle.identity,
            })),
            Err(error) => StoredIdentityLoad::Invalid(error.to_string()),
        },
        Err(error) => StoredIdentityLoad::Invalid(error.to_string()),
    }
}

async fn save_stored(
    repository_factory: &PgRepositoryFactory,
    identity: &StoredDidCoreIdentity,
    inception_operation: ServiceWebvhInceptionOperation,
) -> anyhow::Result<()> {
    let persisted = DidCoreIdentityBundle {
        schema: DidCoreIdentityBundle::SCHEMA.to_owned(),
        identity: identity.clone(),
        webvh_history: vec![inception_operation],
        receipt_chain: vec![identity.registration_receipt.clone()],
        exported_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
    };
    persisted
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut connection = repository_factory.pool().get().await?;
    diesel::sql_query(
        "INSERT INTO service_identity (id, identity, updated_at) VALUES (1, $1, now()) \
         ON CONFLICT (id) DO UPDATE SET identity = EXCLUDED.identity, updated_at = now()",
    )
    .bind::<Jsonb, _>(serde_json::to_value(persisted)?)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

fn waiting_provider(registration_key: &ServiceRegistrationKey) -> DidCoreIdentityState {
    DidCoreIdentityState::WaitingProvider {
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
            service_id: None,
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
            DidCoreIdentityState::Faulted {
                diagnostic: DidCoreIdentityDiagnostic::ProviderAmbiguous,
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
        let load = decode_stored_identity(Value::Null);

        let state = load
            .into_runtime_result()
            .expect_err("malformed persisted identity must fail closed");

        assert!(matches!(
            *state,
            DidCoreIdentityState::Faulted {
                diagnostic: DidCoreIdentityDiagnostic::RestoreFailed,
                ..
            }
        ));
    }

    #[test]
    fn receipt_signing_method_is_the_configured_service_assertion_key() {
        let config = ArkretConfig {
            identity_services: vec![standalone("identity-a", "https://identity.example/")],
            ..ArkretConfig::default()
        };
        let provider = select_provider(&config).unwrap();
        let registration_key = ServiceRegistrationKey::new(
            ServiceKind::AuthServer,
            CanonicalServiceUrl::canonicalize("https://account.example/").unwrap(),
        )
        .unwrap();
        let signing_seed = [7_u8; 32];
        let prepared = prepare_inception(&provider, &registration_key, &signing_seed).unwrap();
        let operation = prepared.service_registration_operation().unwrap();
        let expected_method = format!(
            "{}#{}",
            prepared.did, SERVICE_IDENTITY_VERIFICATION_METHOD_FRAGMENT
        );

        assert_eq!(prepared.did_key_id, expected_method);
        assert!(
            operation
                .state
                .assertion_method
                .iter()
                .any(|method| method == &expected_method)
        );
        let expected_public_key = assertion_public_key(&signing_seed);
        assert_eq!(
            operation.state.signing_key_multibase(),
            Some(expected_public_key.as_str())
        );
    }

    fn registration_key_for_tests() -> ServiceRegistrationKey {
        ServiceRegistrationKey::new(
            ServiceKind::AuthServer,
            CanonicalServiceUrl::canonicalize("https://account.example/").unwrap(),
        )
        .unwrap()
    }

    fn provider_for_tests() -> ProviderCandidate {
        let config = ArkretConfig {
            identity_services: vec![standalone("identity-a", "https://identity.example/")],
            ..ArkretConfig::default()
        };
        select_provider(&config).unwrap()
    }

    fn did_jsonl(prepared: &PreparedInception) -> Vec<u8> {
        format!(
            "{}
",
            serde_json::to_string(&prepared.log_entry).unwrap()
        )
        .into_bytes()
    }

    /// A persisted record shaped exactly like the one `stored_from_outcome`
    /// builds from a Provider registration outcome for `operation`.
    fn stored_for_tests(
        registration_key: &ServiceRegistrationKey,
        operation: &ServiceWebvhInceptionOperation,
        log_head_digest: String,
    ) -> StoredDidCoreIdentity {
        let full_id = operation.state.id.clone();
        let service_id = arkret_wire::project_full_id_to_core_id(&full_id).unwrap();
        let key_ref = DidCoreIdentityKeyRef::new("coauth:secrets:ed25519:test".to_owned()).unwrap();
        let receipt = arkret_models_identity::service_identity::ServiceRegistrationReceipt {
            registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
                "ak:service_registration_receipt:{}",
                "0".repeat(64)
            ))
            .unwrap(),
            registration_key: registration_key.clone(),
            service_id: service_id.clone(),
            full_id: full_id.clone(),
            version_id: operation.version_id.clone(),
            log_head_digest,
            control_key_digest: operation.control_key_digest().unwrap(),
            issued_at: Utc::now(),
            provider_service_id: service_id.clone(),
            proof: arkret_wire::PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new(format!("{full_id}#service-key"))
                    .unwrap(),
                payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at: Utc::now(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "test".to_owned(),
            },
        };
        StoredDidCoreIdentity {
            identity: LocalDidCoreIdentity {
                service_id,
                full_id,
                registration_key: registration_key.clone(),
                provider: None,
                signing_key_refs: vec![key_ref.clone()],
                active_signing_key_ref: key_ref.clone(),
                control_key_ref: key_ref,
                version_id: operation.version_id.clone(),
                last_verified_at: Utc::now(),
            },
            did_document: operation.state.clone(),
            registration_receipt: receipt,
            stored_at: Utc::now(),
        }
    }

    /// Losing the local `service_identity` row must not cost the deployment
    /// its DID: the inception bytes come back verbatim from the Provider's
    /// published history, not from a fresh signature over a new `versionTime`.
    #[test]
    fn registered_inception_is_restored_verbatim_from_the_published_history() {
        let provider = provider_for_tests();
        let registration_key = registration_key_for_tests();
        let signing_seed = [7_u8; 32];
        let prepared = prepare_inception(&provider, &registration_key, &signing_seed).unwrap();
        let operation = prepared.service_registration_operation().unwrap();
        let stored = stored_for_tests(
            &registration_key,
            &operation,
            operation.log_head_digest().unwrap(),
        );

        let restored =
            adopt_inception_from_log(&registration_key, &prepared, &stored, &did_jsonl(&prepared))
                .expect("the published history must restore the registered inception");

        assert_eq!(restored, operation);
    }

    /// The control proof, not the Provider's word, decides adoption: a
    /// registration for the same key rooted in someone else's update key is
    /// never adopted, however well formed its history is.
    #[test]
    fn history_rooted_in_foreign_control_key_material_is_never_adopted() {
        let provider = provider_for_tests();
        let registration_key = registration_key_for_tests();
        let local = prepare_inception(&provider, &registration_key, &[7_u8; 32]).unwrap();
        let foreign = prepare_inception(&provider, &registration_key, &[9_u8; 32]).unwrap();
        let foreign_operation = foreign.service_registration_operation().unwrap();
        let stored = stored_for_tests(
            &registration_key,
            &foreign_operation,
            foreign_operation.log_head_digest().unwrap(),
        );

        let error =
            adopt_inception_from_log(&registration_key, &local, &stored, &did_jsonl(&foreign))
                .expect_err("a foreign control root must fail closed");

        assert!(matches!(error, InceptionRestoreError::ControlKeyMismatch));
    }

    /// The published history is only adopted when the Provider's signed
    /// receipt commits to exactly those inception bytes.
    #[test]
    fn history_the_registration_receipt_does_not_cover_is_rejected() {
        let provider = provider_for_tests();
        let registration_key = registration_key_for_tests();
        let signing_seed = [7_u8; 32];
        let prepared = prepare_inception(&provider, &registration_key, &signing_seed).unwrap();
        let operation = prepared.service_registration_operation().unwrap();
        let stored = stored_for_tests(
            &registration_key,
            &operation,
            format!("sha256:{}", "1".repeat(64)),
        );

        let error =
            adopt_inception_from_log(&registration_key, &prepared, &stored, &did_jsonl(&prepared))
                .expect_err("an inception the receipt does not cover must fail closed");

        assert!(matches!(error, InceptionRestoreError::InvalidEvidence(_)));
    }

    #[test]
    fn local_key_binding_diagnostic_uses_error_type_not_display_text() {
        let typed = anyhow::Error::new(LocalKeyBindingError::AssertionKeyMissing);
        assert_eq!(
            local_key_binding_diagnostic(&typed),
            DidCoreIdentityDiagnostic::KeyMismatch
        );

        let prose =
            anyhow::anyhow!("service_identity_key_mismatch appears in untrusted diagnostic prose");
        assert_eq!(
            local_key_binding_diagnostic(&prose),
            DidCoreIdentityDiagnostic::RestoreFailed
        );
    }
}
