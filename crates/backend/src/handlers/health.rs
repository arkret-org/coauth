// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context as _;
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
pub async fn get(depot: &Depot) -> Result<String, InternalError> {
    check_postgres(depot).await?;
    Ok("ok".to_owned())
}

#[handler]
pub async fn readyz(depot: &Depot) -> Result<String, InternalError> {
    check_postgres(depot).await?;
    check_jwks(depot)?;
    Ok("ok".to_owned())
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
