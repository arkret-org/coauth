//! Deadlines for pooled sessions, including checkout hooks and SQL lock waits.

use std::time::Duration;

use diesel_async::pooled_connection::deadpool::{Object, Pool};
use diesel_async::{AsyncPgConnection, SimpleAsyncConnection};

use crate::DatabaseError;

/// A query source that either borrows an explicit transaction or leases per query.
pub enum PgConnection {
    /// Ordinary operations return their checkout before yielding a result.
    Queries(horme::Db<Pool<AsyncPgConnection>>),
    /// A caller-owned transaction retains its checkout until save or cancel.
    Transaction(Option<Box<Object<AsyncPgConnection>>>),
}

/// Build a query provider without acquiring a physical connection.
pub fn queries(pool: &Pool<AsyncPgConnection>) -> PgConnection {
    PgConnection::Queries(horme::Db::new(pool.clone()))
}

/// A lease borrowed from a transaction or owned for one query.
pub enum PgLease<'a> {
    /// An ordinary pooled checkout.
    Query(Box<Object<AsyncPgConnection>>),
    /// A connection already owned by the transaction.
    Transaction(&'a mut AsyncPgConnection),
}

impl std::ops::Deref for PgLease<'_> {
    type Target = AsyncPgConnection;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Query(conn) => conn,
            Self::Transaction(conn) => conn,
        }
    }
}

impl std::ops::DerefMut for PgLease<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Query(conn) => conn,
            Self::Transaction(conn) => conn,
        }
    }
}

impl horme::GetConnection for PgConnection {
    type Connection = AsyncPgConnection;
    type Lease<'a> = PgLease<'a>;

    async fn get_mut_conn(&mut self) -> horme::Result<Self::Lease<'_>> {
        match self {
            Self::Queries(db) => {
                let budget = db.pool().timeouts().wait.unwrap_or(Duration::from_secs(5));
                let lease = tokio::time::timeout(budget, db.get_mut_conn())
                    .await
                    .map_err(|error| horme::Error::Acquire(Box::new(error)))??;
                Ok(PgLease::Query(Box::new(lease)))
            }
            Self::Transaction(conn) => Ok(PgLease::Transaction(
                conn.as_mut().expect("open repository transaction"),
            )),
        }
    }
}

impl Drop for PgConnection {
    fn drop(&mut self) {
        if let Self::Transaction(conn) = self
            && let Some(conn) = conn.take()
        {
            drop(Object::take(*conn));
        }
    }
}

impl PgConnection {
    pub(crate) fn finish(&mut self) {
        if let Self::Transaction(conn) = self {
            drop(conn.take());
        }
    }
}

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
    async fn retained_query_repository_releases_single_connection() {
        let database = crate::test_utils::setup_test_pool()
            .await
            .expect("test database required");
        let _ = &database;
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(
            std::env::var("DATABASE_URL").unwrap(),
        );
        let pool = Pool::builder(manager)
            .max_size(1)
            .wait_timeout(Some(Duration::from_millis(100)))
            .runtime(deadpool::Runtime::Tokio1)
            .build()
            .unwrap();
        let factory = crate::PgRepositoryFactory::new(pool.clone());
        let mut first = factory.read().await.unwrap();
        let mut second = factory.read().await.unwrap();
        assert_eq!(pool.status().size, 0);
        assert!(!first.user().exists("horme-missing-user").await.unwrap());
        assert_eq!(pool.status().available, 1);
        assert!(!second.user().exists("horme-missing-user").await.unwrap());
        let transaction = factory.create().await.unwrap();
        assert!(second.user().exists("horme-missing-user").await.is_err());
        transaction.cancel().await.unwrap();
        assert!(!second.user().exists("horme-missing-user").await.unwrap());
    }

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
