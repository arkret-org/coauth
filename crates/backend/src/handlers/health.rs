// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context as _;
use arkret_core::ServiceIdentityState;
use coauth_config::ArkretConfig;
use coauth_keystore::Keystore;
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use salvo::prelude::*;
use tracing::{Instrument, info_span};

use crate::salvo_utils::InternalError;

/// Process liveness must not depend on PostgreSQL or signing-key readiness.
#[handler]
pub async fn livez() -> &'static str {
    "ok"
}

#[handler]
pub async fn get(depot: &Depot) -> Result<Json<serde_json::Value>, InternalError> {
    check_postgres(depot).await?;
    Ok(Json(health_payload(depot)))
}

#[handler]
pub async fn readyz(
    depot: &Depot,
    res: &mut Response,
) -> Result<Json<serde_json::Value>, InternalError> {
    check_postgres(depot).await?;
    check_jwks(depot)?;
    if !runtime_identity(depot)?.is_ready() {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(health_payload(depot)))
}

fn runtime_identity(depot: &Depot) -> Result<ServiceIdentityState, InternalError> {
    depot
        .get::<ArkretConfig>("arkret_config")
        .map(|config| config.runtime_service_identity.state())
        .map_err(|_| {
            InternalError::from_anyhow(anyhow::anyhow!("arkret_config not found in depot"))
        })
}

fn health_payload(depot: &Depot) -> serde_json::Value {
    let state = runtime_identity(depot).unwrap_or(ServiceIdentityState::Faulted {
        diagnostic: arkret_core::ServiceIdentityDiagnostic::ProviderNotConfigured,
        next_action: "initialize runtime service identity".to_owned(),
    });
    let configured_provider_endpoint = depot
        .get::<ArkretConfig>("arkret_config")
        .ok()
        .and_then(configured_provider_endpoint);
    let (state_name, service_id, provider_endpoint, last_verified_at, retry_at, next_action) =
        match &state {
            ServiceIdentityState::Ready { identity } => (
                "ready",
                Some(identity.service_id.to_string()),
                identity
                    .provider
                    .as_ref()
                    .map(|provider| provider.endpoint.to_string()),
                Some(identity.last_verified_at),
                None,
                None,
            ),
            ServiceIdentityState::DegradedStored {
                identity, retry_at, ..
            } => (
                "degraded_stored",
                Some(identity.service_id.to_string()),
                identity
                    .provider
                    .as_ref()
                    .map(|provider| provider.endpoint.to_string()),
                Some(identity.last_verified_at),
                Some(*retry_at),
                None,
            ),
            ServiceIdentityState::WaitingProvider { retry_at, .. } => (
                "waiting_provider",
                None,
                configured_provider_endpoint,
                None,
                Some(*retry_at),
                None,
            ),
            ServiceIdentityState::RegistrationKeyDrift { identity, .. } => (
                "registration_key_drift",
                Some(identity.service_id.to_string()),
                identity
                    .provider
                    .as_ref()
                    .map(|provider| provider.endpoint.to_string()),
                Some(identity.last_verified_at),
                None,
                Some(
                    "run `coauth service-identity migrate-base` after verifying the new issuer/public base"
                        .to_owned(),
                ),
            ),
            ServiceIdentityState::Conflict {
                stored_service_id, ..
            } => (
                "conflict",
                Some(stored_service_id.to_string()),
                None,
                None,
                None,
                Some("run `coauth service-identity doctor`".to_owned()),
            ),
            ServiceIdentityState::Faulted { next_action, .. } => (
                "faulted",
                None,
                None,
                None,
                None,
                Some(next_action.clone()),
            ),
        };
    serde_json::json!({
        "ok": state.is_ready(),
        "service": "coauth",
        "service_identity_state": state_name,
        "service_id": service_id,
        "provider_endpoint": provider_endpoint,
        "last_verified_at": last_verified_at,
        "retry_at": retry_at,
        "next_action": next_action,
    })
}

fn configured_provider_endpoint(config: &ArkretConfig) -> Option<String> {
    let mut candidates = config
        .principal_servers
        .iter()
        .filter(|server| server.embedded_webvh_registration_bearer.is_some())
        .map(|server| (server.name.as_str(), &server.endpoint))
        .chain(
            config
                .identity_services
                .iter()
                .map(|service| (service.name.as_str(), &service.endpoint)),
        )
        .filter(|(name, _)| {
            config
                .identity_provider
                .as_deref()
                .is_none_or(|selected| selected == *name)
        });
    let (_, endpoint) = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    Some(endpoint.to_string())
}

async fn check_postgres(depot: &Depot) -> Result<(), InternalError> {
    let pool = depot
        .get::<DieselPool<AsyncPgConnection>>("pg_pool")
        .map_err(|_| InternalError::from_anyhow(anyhow::anyhow!("pg_pool not found in depot")))?;

    let mut conn = pool.get().await?;

    diesel::sql_query("SELECT 1")
        .execute(&mut *conn)
        .instrument(info_span!("DB health"))
        .await?;

    Ok(())
}

fn check_jwks(depot: &Depot) -> Result<(), InternalError> {
    let key_store = depot
        .get::<Keystore>("keystore")
        .map_err(|_| InternalError::from_anyhow(anyhow::anyhow!("keystore not found in depot")))?;

    let public_jwks = key_store.public_jwks();
    if public_jwks.is_empty() {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "keystore does not expose any public JWKS keys"
        )));
    }
    serde_json::to_value(&public_jwks)
        .context("public JWKS could not be serialized")
        .map_err(InternalError::from_anyhow)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use coauth_keystore::{JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};

    use super::*;

    #[test]
    fn jwks_check_accepts_materialized_public_keys() {
        let rsa = PrivateKey::load_pem(include_str!("../../../keystore/tests/keys/rsa.pkcs1.pem"))
            .expect("test RSA key should load");
        let key_store = Keystore::new(JsonWebKeySet::new(vec![
            JsonWebKey::new(rsa).with_kid("readyz-rsa"),
        ]));
        let mut depot = Depot::new();
        depot.insert("keystore", key_store);

        assert!(check_jwks(&depot).is_ok());
    }

    #[test]
    fn jwks_check_rejects_empty_keystore() {
        let mut depot = Depot::new();
        depot.insert("keystore", Keystore::default());

        assert!(check_jwks(&depot).is_err());
    }
}
