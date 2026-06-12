// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Test utilities for creating temporary test databases.

use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;

/// Create a diesel connection pool suitable for tests.
///
/// Returns `Some(pool)` when the `DATABASE_URL` env var is set (typical CI
/// or a developer with a local Postgres available), or `None` when it is
/// not set. Tests requiring a live Postgres should early-return on `None`,
/// e.g.:
///
/// ```ignore
/// let Some(pool) = setup_test_pool().await else { return; };
/// ```
///
/// This makes the test suite's "happy path" — `cargo test --workspace`
/// without any environment — actually pass, while still fully exercising
/// the Postgres path under CI. Migrations are expected to already have
/// been applied to the test database.
#[must_use = "tests should early-return when this returns None"]
pub async fn setup_test_pool() -> Option<Pool<AsyncPgConnection>> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database_url);
    let pool = Pool::builder(manager)
        .max_size(5)
        .build()
        .expect("could not build test pool");
    Some(pool)
}
