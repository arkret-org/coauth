// Copyright 2025 Taidge Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Test utilities for creating temporary test databases.

use diesel_async::{
    AsyncPgConnection,
    pooled_connection::{AsyncDieselConnectionManager, deadpool::Pool},
};

/// Create a diesel connection pool suitable for tests.
///
/// This connects to the database specified by `DATABASE_URL` env var
/// (set by the test harness or CI) and returns a pool.
/// Migrations should already be applied to the test database.
pub async fn setup_test_pool() -> Pool<AsyncPgConnection> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database_url);
    Pool::builder(manager)
        .max_size(5)
        .build()
        .expect("could not build test pool")
}
