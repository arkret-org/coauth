//! A module containing the PostgreSQL implementation of the policy data
//! storage.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::policy_data::PolicyDataRepository;
use coauth_data::{Clock, PolicyData, PolicyDataDocument, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use serde_json::Value;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::policy_data;

/// An implementation of [`PolicyDataRepository`] for a PostgreSQL connection.
pub struct PgPolicyDataRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgPolicyDataRepository<'c> {
    /// Create a new [`PgPolicyDataRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading policy data from the database
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = policy_data)]
struct PolicyDataRow {
    id: Uuid,
    data: Value,
    created_at: DateTime<Utc>,
}

impl From<PolicyDataRow> for PolicyData {
    fn from(value: PolicyDataRow) -> Self {
        PolicyData {
            id: value.id.into(),
            created_at: value.created_at,
            data: PolicyDataDocument::from_json(value.data),
        }
    }
}

/// Insertable row for creating new policy data
#[derive(Insertable)]
#[diesel(table_name = policy_data)]
struct NewPolicyData {
    id: Uuid,
    data: Value,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl PolicyDataRepository for PgPolicyDataRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.policy_data.get", skip_all, err)]
    async fn get(&mut self) -> Result<Option<PolicyData>, Self::Error> {
        let row = policy_data::table
            .select(PolicyDataRow::as_select())
            .order(policy_data::id.desc())
            .first::<PolicyDataRow>(self.conn)
            .await
            .optional()?;

        Ok(row.map(PolicyData::from))
    }

    #[tracing::instrument(name = "db.policy_data.set", skip_all, err)]
    async fn set(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        data: PolicyDataDocument,
    ) -> Result<PolicyData, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);

        let new_row = NewPolicyData {
            id: Uuid::from(id),
            created_at,
            data: data.as_json().clone(),
        };

        diesel::insert_into(policy_data::table)
            .values(&new_row)
            .execute(self.conn)
            .await?;

        Ok(PolicyData {
            id,
            created_at,
            data,
        })
    }

    #[tracing::instrument(name = "db.policy_data.prune", skip_all, err)]
    async fn prune(&mut self, keep: usize) -> Result<usize, Self::Error> {
        let offset = i64::try_from(keep).map_err(DatabaseError::to_invalid_operation)?;

        // Get the IDs of entries to delete (all except the `keep` most recent)
        let ids_to_delete: Vec<Uuid> = policy_data::table
            .select(policy_data::id)
            .order(policy_data::id.desc())
            .offset(offset)
            .load(self.conn)
            .await?;

        if ids_to_delete.is_empty() {
            return Ok(0);
        }

        let rows_affected =
            diesel::delete(policy_data::table.filter(policy_data::id.eq_any(&ids_to_delete)))
                .execute(self.conn)
                .await?;

        Ok(rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use coauth_data::clock::MockClock;
    use coauth_data::policy_data::PolicyDataRepository;
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
    use diesel_async::RunQueryDsl;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use serde_json::json;

    use crate::PgRepositoryFactory;

    #[tokio::test]
    async fn test_policy_data() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        // Get an empty state at first
        let data = repo.policy_data().get().await.unwrap();
        assert_eq!(data, None);

        // Set some data
        let value1 = json!({"hello": "world"});
        let policy_data1 = repo
            .policy_data()
            .set(&mut rng, &clock, value1.clone().into())
            .await
            .unwrap();
        assert_eq!(policy_data1.data.as_json(), &value1);

        let data_fetched1 = repo.policy_data().get().await.unwrap().unwrap();
        assert_eq!(policy_data1, data_fetched1);

        // Set some new data
        clock.advance(chrono::Duration::seconds(1));
        let value2 = json!({"foo": "bar"});
        let policy_data2 = repo
            .policy_data()
            .set(&mut rng, &clock, value2.clone().into())
            .await
            .unwrap();
        assert_eq!(policy_data2.data.as_json(), &value2);

        // Check the new data is fetched
        let data_fetched2 = repo.policy_data().get().await.unwrap().unwrap();
        assert_eq!(data_fetched2, policy_data2);

        // Prune until the first entry
        let affected = repo.policy_data().prune(1).await.unwrap();
        let data_fetched3 = repo.policy_data().get().await.unwrap().unwrap();
        assert_eq!(data_fetched3, policy_data2);
        assert_eq!(affected, 1);

        // Do a raw query to check the other rows were pruned
        #[derive(diesel::QueryableByName)]
        struct CountResult {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            count: i64,
        }

        let mut conn = pool.get().await.unwrap();
        let count = diesel::sql_query("SELECT COUNT(*) FROM policy_data")
            .get_result::<CountResult>(&mut *conn)
            .await
            .unwrap()
            .count;
        assert_eq!(count, 1);
    }
}
