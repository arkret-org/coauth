//! An implementation of the storage traits for a PostgreSQL database
//!
//! This backend uses [`diesel`] with [`diesel_async`] for all database access.

#![deny(clippy::future_not_send, missing_docs)]
#![allow(clippy::module_name_repetitions, clippy::blocks_in_conditions)]

use ::tracing::{info, warn};
use diesel::sql_types::BigInt;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

diesel::define_sql_function! {
    /// SQL `lower()` function for case-insensitive text comparisons.
    fn lower(x: diesel::sql_types::Text) -> diesel::sql_types::Text;
}

/// Apply a [`Pagination`] cursor window and its direction-dependent ordering
/// to a boxed diesel query keyed on a ULID-valued `id` column.
///
/// Every paginated repository does the same three things, in the same order:
/// clamp to the `after`/`before` cursor window, order by the key column in the
/// direction being walked, and over-fetch one row so
/// [`Pagination::process`] can tell whether another page exists. Writing that
/// out per repository is what produced eleven byte-identical copies of the
/// same `match pagination.direction` block.
///
/// The over-fetch of `count + 1` is load-bearing and belongs here rather than
/// at the call site: [`Pagination::process`] pops the extra row and reports it
/// as `has_next_page`/`has_previous_page`, so a caller that forgot the `+ 1`
/// would silently lose the last row of every page.
///
/// [`Pagination`]: coauth_data::pagination::Pagination
/// [`Pagination::process`]: coauth_data::pagination::Pagination::process
macro_rules! paginate_by_id {
    ($query:expr, $pagination:expr, $id_column:expr $(,)?) => {{
        let mut query = $query;
        if let Some(after) = $pagination.after {
            query = query.filter($id_column.gt(::uuid::Uuid::from(after)));
        }
        if let Some(before) = $pagination.before {
            query = query.filter($id_column.lt(::uuid::Uuid::from(before)));
        }

        match $pagination.direction {
            ::coauth_data::pagination::PaginationDirection::Forward => {
                query = query
                    .order($id_column.asc())
                    .limit(($pagination.count + 1) as i64);
            }
            ::coauth_data::pagination::PaginationDirection::Backward => {
                query = query
                    .order($id_column.desc())
                    .limit(($pagination.count + 1) as i64);
            }
        }

        query
    }};
}

pub(crate) use paginate_by_id;

/// PostgreSQL account aggregate repositories.
pub mod account;
pub mod account_handoff;
/// PostgreSQL Account Authority issuer ledger.
pub mod account_status;
/// PostgreSQL accountability grant repositories.
pub mod accountability;
/// Shared helpers for PostgreSQL advisory locks.
pub mod advisory_lock;
/// PostgreSQL agent key authorization + agent-key-proof replay repositories.
pub mod agent_key;
/// PostgreSQL app session repositories.
pub mod app_session;
/// PostgreSQL audit log repositories.
pub mod audit;
/// PostgreSQL Circle capability grant repository.
pub mod circle_capability;
/// PostgreSQL collaboration capability grant repository.
pub mod collaboration_capability;
/// PostgreSQL accepted-DID-binding repository (DID-P2-A).
pub mod did_binding;
/// PostgreSQL DPoP proof replay repository.
pub mod dpop_replay;
/// PostgreSQL self-service erasure intent repository
/// (account-lifecycle.md §8.1).
pub mod erasure_request;
/// PostgreSQL append-only handle audit log repository (T3.2).
pub mod handle_audit;
/// PostgreSQL notification persistence repositories.
pub mod notification;
/// PostgreSQL OAuth repositories.
pub mod oauth;
/// PostgreSQL organization principal control + delegation repository.
pub mod organization_control;
/// PostgreSQL personal access repositories.
pub mod personal;
/// PostgreSQL queue repositories.
pub mod queue;
/// PostgreSQL recovery-completion grant issuance repository.
pub mod recovery_authority;
/// Diesel schema definitions generated from the database
pub mod schema;
mod session_grant_codec;
/// PostgreSQL upstream OAuth repositories.
pub mod upstream_oauth;
/// PostgreSQL user repositories.
pub mod user;

mod errors;
/// PostgreSQL notification template version repository.
pub mod notification_template;
pub mod policy_data;
pub(crate) mod repository;
/// PostgreSQL Station trust enrollment repository.
pub mod station_trust;
pub(crate) mod telemetry;
/// Test utilities for creating temporary test databases.
///
/// This module is always compiled (not `#[cfg(test)]`) so that other crates
/// can use `coauth_storage_postgres::test_utils::setup_test_pool()` in their own
/// test code.
pub mod test_utils;

pub use self::errors::DatabaseError;
pub(crate) use self::errors::DatabaseInconsistencyError;
pub use self::notification_template::PgNotificationTemplateRepository;
pub use self::repository::{PgRepository, PgRepositoryFactory};

/// Embedded Diesel migrations.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Run the migrations on the given connection pool.
///
/// The `database_url` is needed to establish a separate synchronous connection
/// for running diesel migrations (which require a synchronous
/// `MigrationHarness`).
///
/// This function acquires a PostgreSQL advisory lock to ensure that only one
/// migrator is running at a time.
///
/// # Errors
///
/// Returns an error if the migration fails.
#[::tracing::instrument(name = "db.migrate", skip_all, err)]
pub async fn migrate(
    pool: &Pool<AsyncPgConnection>,
    database_url: &str,
) -> Result<(), anyhow::Error> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("could not get connection from pool: {e}"))?;

    // Get the current database name for the advisory lock
    let db_name: String = diesel::sql_query("SELECT current_database()::text AS name")
        .get_result::<DbName>(&mut *conn)
        .await
        .map_err(|e| anyhow::anyhow!("could not get current database name: {e}"))?
        .name;

    let lock_id = generate_lock_id(&db_name);

    // Try to acquire the advisory lock, retrying with backoff
    let mut backoff = std::time::Duration::from_millis(250);
    loop {
        let result: self::advisory_lock::AdvisoryLockResult =
            diesel::sql_query("SELECT pg_try_advisory_lock($1) AS acquired")
                .bind::<BigInt, _>(lock_id)
                .get_result(&mut *conn)
                .await
                .map_err(|e| anyhow::anyhow!("could not acquire advisory lock: {e}"))?;

        if result.acquired {
            break;
        }

        warn!(
            "Another process is already running migrations on the database, waiting {duration}s and trying again…",
            duration = backoff.as_secs_f32()
        );
        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff * 2, std::time::Duration::from_secs(5));
    }

    // Run pending migrations using diesel_migrations.
    // MigrationHarness requires a synchronous connection, so we establish
    // a separate blocking connection via AsyncConnectionWrapper.
    let url = database_url.to_owned();
    let migration_result = tokio::task::spawn_blocking(move || {
        use diesel::Connection;
        let mut wrapper = diesel_async::async_connection_wrapper::AsyncConnectionWrapper::<
            AsyncPgConnection,
        >::establish(&url)
        .map_err(|e| anyhow::anyhow!("could not establish migration connection: {e}"))?;
        let applied = wrapper
            .run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("could not run migrations: {e}"))?;
        // Convert MigrationVersion (which borrows wrapper) to owned strings
        let versions: Vec<String> = applied
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        Ok::<_, anyhow::Error>(versions)
    })
    .await
    .map_err(|e| anyhow::anyhow!("migration task panicked: {e}"))??;

    for version in &migration_result {
        info!("Applied migration: {version}");
    }

    // Release the advisory lock
    let _ = diesel::sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<BigInt, _>(lock_id)
        .execute(&mut *conn)
        .await;

    Ok(())
}

/// Check if there are pending migrations.
///
/// # Errors
///
/// Returns an error if there is a problem checking the migration state.
pub async fn has_pending_migrations(database_url: &str) -> Result<bool, anyhow::Error> {
    let url = database_url.to_owned();
    tokio::task::spawn_blocking(move || {
        use diesel::Connection;
        let mut wrapper = diesel_async::async_connection_wrapper::AsyncConnectionWrapper::<
            AsyncPgConnection,
        >::establish(&url)
        .map_err(|e| anyhow::anyhow!("could not establish connection: {e}"))?;
        let pending = wrapper
            .pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("could not check pending migrations: {e}"))?;
        Ok::<_, anyhow::Error>(!pending.is_empty())
    })
    .await
    .map_err(|e| anyhow::anyhow!("migration check task panicked: {e}"))?
}

/// Generate a stable advisory lock ID from the database name.
fn generate_lock_id(database_name: &str) -> i64 {
    const CRC_IEEE: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    0x3d32_ad9e * i64::from(CRC_IEEE.checksum(database_name.as_bytes()))
}

/// Helper struct for database name query
#[derive(diesel::QueryableByName)]
struct DbName {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}
