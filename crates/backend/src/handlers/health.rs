// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context as _;
use coauth_config::ArkretConfig;
use coauth_keyring::Keyring;
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use http::HeaderValue;
use salvo::prelude::*;
use tracing::{Instrument, info_span};

use crate::salvo_utils::InternalError;
use crate::services::station_trust;

/// Process liveness must not depend on PostgreSQL or signing-key readiness.
#[handler]
pub async fn livez() -> &'static str {
    "ok"
}

#[handler]
pub async fn get(depot: &Depot) -> Result<Json<serde_json::Value>, InternalError> {
    check_postgres(depot).await?;
    Ok(Json(health_payload(depot, true)))
}

#[handler]
pub async fn readyz(
    depot: &Depot,
    res: &mut Response,
) -> Result<Json<serde_json::Value>, InternalError> {
    check_postgres(depot).await?;
    check_jwks(depot)?;
    let station_trust_ready = station_trust_ready(depot);
    if !station_trust_ready {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
        res.headers_mut()
            .insert("retry-after", HeaderValue::from_static("5"));
    }
    Ok(Json(health_payload(depot, station_trust_ready)))
}

fn health_payload(depot: &Depot, ok: bool) -> serde_json::Value {
    let owning_station = depot
        .get::<ArkretConfig>("arkret_config")
        .ok()
        .and_then(|config| config.owning_station())
        .map(|station| station.name.clone());
    serde_json::json!({
        "ok": ok,
        "service": "coauth",
        "component_role": "station_account_authority",
        "owning_station": owning_station,
        "station_trust": if station_trust_ready(depot) { "ready" } else { "waiting" },
    })
}

fn station_trust_ready(depot: &Depot) -> bool {
    depot
        .get::<ArkretConfig>("arkret_config")
        .is_ok_and(station_trust::is_ready)
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
    let keyring = depot
        .get::<Keyring>("keyring")
        .map_err(|_| InternalError::from_anyhow(anyhow::anyhow!("keyring not found in depot")))?;

    let public_jwks = keyring.public_jwks();
    if public_jwks.is_empty() {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "keyring does not expose any public JWKS keys"
        )));
    }
    serde_json::to_value(&public_jwks)
        .context("public JWKS could not be serialized")
        .map_err(InternalError::from_anyhow)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use coauth_keyring::{JsonWebKey, JsonWebKeySet, Keyring, PrivateKey};

    use super::*;

    #[test]
    fn jwks_check_accepts_materialized_public_keys() {
        let rsa = PrivateKey::load_pem(include_str!("../../../keyring/tests/keys/rsa.pkcs1.pem"))
            .expect("test RSA key should load");
        let keyring = Keyring::new(JsonWebKeySet::new(vec![
            JsonWebKey::new(rsa).with_kid("readyz-rsa"),
        ]));
        let mut depot = Depot::new();
        depot.insert("keyring", keyring);

        assert!(check_jwks(&depot).is_ok());
    }

    #[test]
    fn jwks_check_rejects_empty_keyring() {
        let mut depot = Depot::new();
        depot.insert("keyring", Keyring::default());

        assert!(check_jwks(&depot).is_err());
    }
}
