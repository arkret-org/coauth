//! Deadlines for pooled sessions, including checkout hooks and SQL lock waits.

use std::time::Duration;

use diesel_async::pooled_connection::deadpool::{Object, Pool};
use diesel_async::{AsyncPgConnection, SimpleAsyncConnection};

use crate::DatabaseError;

/// Apply server-side bounds to business sessions, not migration connections.
pub async fn configure_connection(conn: &mut AsyncPgConnection) -> diesel::QueryResult<()> {
    conn.batch_execute("SET statement_timeout = '30s'; SET lock_timeout = '5s'; SET idle_in_transaction_session_timeout = '60s';").await
}

/// Obtain a connection within one budget, including creation and pool hooks.
///
/// # Errors
/// Returns a pool error on checkout failure or deadline expiry.
pub async fn get_connection(
    pool: &Pool<AsyncPgConnection>,
) -> Result<Object<AsyncPgConnection>, DatabaseError> {
    tokio::time::timeout(
        pool.timeouts().wait.unwrap_or(Duration::from_secs(5)),
        pool.get(),
    )
    .await
    .map_err(|source| DatabaseError::Pool {
        source: Box::new(source),
    })?
    .map_err(|source| DatabaseError::Pool {
        source: Box::new(source),
    })
}

#[cfg(test)]
mod tests {
    use coauth_data::RepositoryFactory;
    use diesel_async::pooled_connection::AsyncDieselConnectionManager;
    use diesel_async::pooled_connection::deadpool::Hook;

    use super::*;

    #[tokio::test]
    async fn checkout_includes_hooks_and_exhaustion() {
        let _database = crate::test_utils::setup_test_pool()
            .await
            .expect("test database required");
        let url = std::env::var("DATABASE_URL").unwrap();
        for stage in ["exhaustion", "pre_recycle", "post_create"] {
            let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&url);
            let mut builder = Pool::builder(manager)
                .max_size(1)
                .wait_timeout(Some(Duration::from_millis(100)))
                .runtime(deadpool::Runtime::Tokio1);
            let hook = || Hook::async_fn(|_, _| Box::pin(std::future::pending()));
            if stage == "pre_recycle" {
                builder = builder.pre_recycle(hook());
            }
            if stage == "post_create" {
                builder = builder.post_create(hook());
            }
            let pool = builder.build().unwrap();
            let held = if stage == "post_create" {
                None
            } else {
                Some(pool.get().await.unwrap())
            };
            let held = if stage == "pre_recycle" {
                drop(held);
                None
            } else {
                held
            };
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                crate::PgRepositoryFactory::new(pool).create(),
            )
            .await
            .expect("checkout must finish");
            assert!(result.is_err(), "{stage}");
            drop(held);
        }
    }
}
