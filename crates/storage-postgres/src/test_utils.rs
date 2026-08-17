// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Test utilities for creating temporary test databases.

use std::ops::Deref;

use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _};

/// Session-scoped Postgres advisory-lock key that serializes every test
/// holding a [`TestDatabase`]. Postgres releases a session-level advisory lock
/// when the owning session closes, so the guard needs no async drop.
const TEST_DATABASE_ADVISORY_LOCK_KEY: i64 = 0x0063_6f61_7574_68db;

/// Exclusive handle on the shared test database.
///
/// Holding one guarantees two things for the duration of a test:
///
/// * no other test in any process may hold one at the same time, and
/// * every application table starts empty.
///
/// Both are required because the repository tests assert on global state
/// (`count(all) == 0`) and seed deterministic identifiers from fixed RNG
/// seeds, so two tests sharing a populated database collide on `users_pkey`
/// and on handle uniqueness instead of exercising their assertions.
pub struct TestDatabase {
    pool: Pool<AsyncPgConnection>,
    /// Owns the advisory lock. Dropping it closes the session and releases
    /// the lock for the next test.
    _lock: AsyncPgConnection,
}

impl Deref for TestDatabase {
    type Target = Pool<AsyncPgConnection>;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

/// Take exclusive ownership of the test database and return a connection pool
/// for it.
///
/// Returns `Some(database)` when the `DATABASE_URL` env var is set (typical CI
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
///
/// # Panics
///
/// Panics when `DATABASE_URL` is set but the database cannot be reached or
/// reset; a test database that cannot be isolated must fail loudly rather
/// than run against leftover rows.
#[must_use = "tests should early-return when this returns None"]
pub async fn setup_test_pool() -> Option<TestDatabase> {
    let database_url = std::env::var("DATABASE_URL").ok()?;

    let mut lock = AsyncPgConnection::establish(&database_url)
        .await
        .expect("could not connect to the test database");
    diesel::sql_query(format!(
        "SELECT pg_advisory_lock({TEST_DATABASE_ADVISORY_LOCK_KEY})"
    ))
    .execute(&mut lock)
    .await
    .expect("could not acquire the test database advisory lock");
    reset_database(&mut lock).await;

    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database_url);
    let pool = Pool::builder(manager)
        .max_size(5)
        .build()
        .expect("could not build test pool");
    Some(TestDatabase { pool, _lock: lock })
}

#[derive(diesel::QueryableByName)]
struct QualifiedTableName {
    #[diesel(sql_type = diesel::sql_types::Text)]
    qualified_name: String,
}

/// Empty every application table. The diesel migration ledger is preserved so
/// the already-applied schema stays valid.
async fn reset_database(connection: &mut AsyncPgConnection) {
    let tables = diesel::sql_query(
        "SELECT format('%I.%I', schemaname, tablename) AS qualified_name \
         FROM pg_tables \
         WHERE schemaname = 'public' AND tablename <> '__diesel_schema_migrations'",
    )
    .get_results::<QualifiedTableName>(connection)
    .await
    .expect("could not enumerate the test database tables");
    if tables.is_empty() {
        return;
    }
    let names = tables
        .iter()
        .map(|table| table.qualified_name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    diesel::sql_query(format!("TRUNCATE TABLE {names} RESTART IDENTITY CASCADE"))
        .execute(connection)
        .await
        .expect("could not reset the test database");
}
