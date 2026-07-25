//! PostgreSQL implementation of the Circle capability grant repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::circle_capability::{
    CapabilityActionId, CircleCapabilityGrant, CircleCapabilityGrantRepository,
    NewCircleCapabilityGrant, is_circle_capability_action,
};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::circle_capability_grants;
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`CircleCapabilityGrantRepository`].
pub struct PgCircleCapabilityGrantRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgCircleCapabilityGrantRepository<'c> {
    /// Construct from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = circle_capability_grants)]
struct CircleCapabilityGrantRow {
    id: Uuid,
    subject: String,
    realm_id: String,
    action: String,
    allowed_circle_ids: Vec<String>,
    granted_by: String,
    granted_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<CircleCapabilityGrantRow> for CircleCapabilityGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: CircleCapabilityGrantRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let action = CapabilityActionId::from_wire(&value.action)
            .filter(|action| is_circle_capability_action(*action))
            .ok_or_else(|| {
                DatabaseInconsistencyError::on("circle_capability_grants")
                    .column("action")
                    .row(id)
                    .source(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unknown or non-Circle capability action: {}", value.action),
                    ))
            })?;

        Ok(Self {
            id: id.to_string(),
            subject: value.subject,
            realm_id: value.realm_id,
            action,
            allowed_circle_ids: value.allowed_circle_ids,
            granted_by: value.granted_by,
            granted_at: value.granted_at,
            revoked_at: value.revoked_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = circle_capability_grants)]
struct InsertableCircleCapabilityGrant {
    id: Uuid,
    subject: String,
    realm_id: String,
    action: String,
    allowed_circle_ids: Vec<String>,
    granted_by: String,
    granted_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl CircleCapabilityGrantRepository for PgCircleCapabilityGrantRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.circle_capability_grant.add", skip_all, err)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewCircleCapabilityGrant,
    ) -> Result<CircleCapabilityGrant, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);
        let row = InsertableCircleCapabilityGrant {
            id: Uuid::from(id),
            subject: params.subject,
            realm_id: params.realm_id,
            action: params.action.to_string(),
            allowed_circle_ids: params.allowed_circle_ids,
            granted_by: params.granted_by,
            granted_at: now,
            created_at: now,
            updated_at: now,
        };

        diesel::insert_into(circle_capability_grants::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(CircleCapabilityGrant {
            id: id.to_string(),
            subject: row.subject,
            realm_id: row.realm_id,
            action: params.action,
            allowed_circle_ids: row.allowed_circle_ids,
            granted_by: row.granted_by,
            granted_at: row.granted_at,
            revoked_at: None,
        })
    }

    #[tracing::instrument(name = "db.circle_capability_grant.list_active", skip_all, err)]
    async fn list_active(&mut self) -> Result<Vec<CircleCapabilityGrant>, Self::Error> {
        circle_capability_grants::table
            .filter(circle_capability_grants::revoked_at.is_null())
            .order((
                circle_capability_grants::realm_id.asc(),
                circle_capability_grants::subject.asc(),
                circle_capability_grants::granted_at.asc(),
            ))
            .select(CircleCapabilityGrantRow::as_select())
            .load::<CircleCapabilityGrantRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.circle_capability_grant.revoke_by_id", skip_all, err)]
    async fn revoke_by_id(
        &mut self,
        clock: &dyn Clock,
        grant_id: &str,
    ) -> Result<Option<CircleCapabilityGrant>, Self::Error> {
        let Ok(id) = grant_id.parse::<Ulid>() else {
            return Ok(None);
        };
        let row_id = Uuid::from(id);
        let now = clock.now();

        let updated = diesel::update(
            circle_capability_grants::table
                .filter(circle_capability_grants::id.eq(row_id))
                .filter(circle_capability_grants::revoked_at.is_null()),
        )
        .set((
            circle_capability_grants::revoked_at.eq(Some(now)),
            circle_capability_grants::updated_at.eq(now),
        ))
        .returning(CircleCapabilityGrantRow::as_returning())
        .get_result::<CircleCapabilityGrantRow>(self.conn)
        .await
        .optional()?;

        updated
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use coauth_data::circle_capability::CapabilityActionId;
    use coauth_data::clock::MockClock;
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::PgRepositoryFactory;

    fn sample(label: &str) -> NewCircleCapabilityGrant {
        NewCircleCapabilityGrant {
            subject: format!("did:web:{label}.example"),
            realm_id: format!("ak:realm:{label}"),
            action: CapabilityActionId::CircleManage,
            allowed_circle_ids: vec![format!("ak:circle:{label}")],
            granted_by: "did:web:admin.example".to_owned(),
        }
    }

    #[tokio::test]
    async fn grant_persists_across_repository_instances_and_can_revoke() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = PgRepositoryFactory::new(pool);
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(51);
        let label = uuid::Uuid::now_v7().to_string();

        let mut repo = factory.create().await.unwrap();
        let grant = repo
            .circle_capability_grant()
            .add(&mut rng, &clock, sample(&label))
            .await
            .unwrap();
        repo.save().await.unwrap();

        let mut repo = factory.create().await.unwrap();
        let active = repo.circle_capability_grant().list_active().await.unwrap();
        assert!(active.iter().any(|row| row.id == grant.id));
        let revoked = repo
            .circle_capability_grant()
            .revoke_by_id(&clock, &grant.id)
            .await
            .unwrap()
            .expect("active grant can be revoked");
        assert!(revoked.revoked_at.is_some());
        repo.save().await.unwrap();
    }
}
