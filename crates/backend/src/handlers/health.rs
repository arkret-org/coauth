// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use diesel_async::{
    AsyncPgConnection, RunQueryDsl, pooled_connection::deadpool::Pool as DieselPool,
};
use salvo::prelude::*;
use tracing::{Instrument, info_span};

use crate::salvo_utils::InternalError;

#[handler]
pub async fn get(depot: &Depot) -> Result<String, InternalError> {
    let pool = depot
        .get::<DieselPool<AsyncPgConnection>>("pg_pool")
        .map_err(|_| InternalError::from_anyhow(anyhow::anyhow!("pg_pool not found in depot")))?;

    let mut conn = pool.get().await?;

    diesel::sql_query("SELECT 1")
        .execute(&mut *conn)
        .instrument(info_span!("DB health"))
        .await?;

    Ok("ok".to_string())
}

#[cfg(test)]
mod tests {
    // Tests would need to be updated for Salvo's test utilities
}
