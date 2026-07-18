//! PostgreSQL implementation of the collaboration capability grant repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::collaboration_capability::{
    CollaborationCapabilityAction, CollaborationCapabilityGrant,
    CollaborationCapabilityGrantRepository, CollaborationCapabilityRevokeFanout,
    NewCollaborationCapabilityGrant,
};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::collaboration_capability_grants;
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`CollaborationCapabilityGrantRepository`].
pub struct PgCollaborationCapabilityGrantRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgCollaborationCapabilityGrantRepository<'c> {
    /// Construct from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = collaboration_capability_grants)]
struct CollaborationCapabilityGrantRow {
    id: Uuid,
    capability_grant_id: String,
    grant_event_id: String,
    revoke_event_id: Option<String>,
    subject: String,
    realm_id: String,
    action: String,
    expires_at: Option<DateTime<Utc>>,
    approval_evidence_ref: Option<String>,
    granted_by: String,
    granted_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    grant_raw_payload_digest: String,
    grant_fanout_idempotency_key: String,
}

impl TryFrom<CollaborationCapabilityGrantRow> for CollaborationCapabilityGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: CollaborationCapabilityGrantRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let action = value
            .action
            .parse::<CollaborationCapabilityAction>()
            .map_err(|e| {
                DatabaseInconsistencyError::on("collaboration_capability_grants")
                    .column("action")
                    .row(id)
                    .source(e)
            })?;

        Ok(Self {
            id: id.to_string(),
            capability_grant_id: value.capability_grant_id,
            grant_event_id: value.grant_event_id,
            revoke_event_id: value.revoke_event_id,
            subject: value.subject,
            realm_id: value.realm_id,
            action,
            expires_at: value.expires_at,
            approval_evidence_ref: value.approval_evidence_ref,
            granted_by: value.granted_by,
            granted_at: value.granted_at,
            revoked_at: value.revoked_at,
            grant_raw_payload_digest: value.grant_raw_payload_digest,
            grant_fanout_idempotency_key: value.grant_fanout_idempotency_key,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = collaboration_capability_grants)]
struct InsertableCollaborationCapabilityGrant {
    id: Uuid,
    capability_grant_id: String,
    grant_event_id: String,
    subject: String,
    realm_id: String,
    action: String,
    expires_at: Option<DateTime<Utc>>,
    approval_evidence_ref: Option<String>,
    granted_by: String,
    granted_at: DateTime<Utc>,
    grant_raw_payload_digest: String,
    grant_fanout_idempotency_key: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl CollaborationCapabilityGrantRepository for PgCollaborationCapabilityGrantRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.collaboration_capability_grant.add", skip_all, err)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewCollaborationCapabilityGrant,
    ) -> Result<CollaborationCapabilityGrant, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);
        let row = InsertableCollaborationCapabilityGrant {
            id: Uuid::from(id),
            capability_grant_id: params.capability_grant_id,
            grant_event_id: params.grant_event_id,
            subject: params.subject,
            realm_id: params.realm_id,
            action: params.action.to_string(),
            expires_at: params.expires_at,
            approval_evidence_ref: params.approval_evidence_ref,
            granted_by: params.granted_by,
            granted_at: now,
            grant_raw_payload_digest: params.grant_raw_payload_digest,
            grant_fanout_idempotency_key: params.grant_fanout_idempotency_key,
            created_at: now,
            updated_at: now,
        };

        diesel::insert_into(collaboration_capability_grants::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(CollaborationCapabilityGrant {
            id: id.to_string(),
            capability_grant_id: row.capability_grant_id,
            grant_event_id: row.grant_event_id,
            revoke_event_id: None,
            subject: row.subject,
            realm_id: row.realm_id,
            action: params.action,
            expires_at: row.expires_at,
            approval_evidence_ref: row.approval_evidence_ref,
            granted_by: row.granted_by,
            granted_at: row.granted_at,
            revoked_at: None,
            grant_raw_payload_digest: row.grant_raw_payload_digest,
            grant_fanout_idempotency_key: row.grant_fanout_idempotency_key,
        })
    }

    #[tracing::instrument(name = "db.collaboration_capability_grant.list_active", skip_all, err)]
    async fn list_active(&mut self) -> Result<Vec<CollaborationCapabilityGrant>, Self::Error> {
        collaboration_capability_grants::table
            .filter(collaboration_capability_grants::revoked_at.is_null())
            .order((
                collaboration_capability_grants::realm_id.asc(),
                collaboration_capability_grants::subject.asc(),
                collaboration_capability_grants::granted_at.asc(),
            ))
            .select(CollaborationCapabilityGrantRow::as_select())
            .load::<CollaborationCapabilityGrantRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.collaboration_capability_grant.list_active_for_subject_action",
        skip_all,
        err
    )]
    async fn list_active_for_subject_action(
        &mut self,
        subject: &str,
        realm_id: &str,
        action: CollaborationCapabilityAction,
    ) -> Result<Vec<CollaborationCapabilityGrant>, Self::Error> {
        collaboration_capability_grants::table
            .filter(collaboration_capability_grants::revoked_at.is_null())
            .filter(collaboration_capability_grants::subject.eq(subject))
            .filter(collaboration_capability_grants::realm_id.eq(realm_id))
            .filter(collaboration_capability_grants::action.eq(action.to_string()))
            .order(collaboration_capability_grants::granted_at.asc())
            .select(CollaborationCapabilityGrantRow::as_select())
            .load::<CollaborationCapabilityGrantRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.collaboration_capability_grant.revoke_by_id", skip_all, err)]
    async fn revoke_by_id(
        &mut self,
        clock: &dyn Clock,
        grant_id: &str,
        fanout: CollaborationCapabilityRevokeFanout,
    ) -> Result<Option<CollaborationCapabilityGrant>, Self::Error> {
        let Ok(id) = grant_id.parse::<Ulid>() else {
            return Ok(None);
        };
        let row_id = Uuid::from(id);
        let now = clock.now();

        let updated = diesel::update(
            collaboration_capability_grants::table
                .filter(collaboration_capability_grants::id.eq(row_id))
                .filter(collaboration_capability_grants::revoked_at.is_null()),
        )
        .set((
            collaboration_capability_grants::revoke_event_id.eq(Some(fanout.revoke_event_id)),
            collaboration_capability_grants::revoked_at.eq(Some(now)),
            collaboration_capability_grants::updated_at.eq(now),
        ))
        .returning(CollaborationCapabilityGrantRow::as_returning())
        .get_result::<CollaborationCapabilityGrantRow>(self.conn)
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
    use coauth_data::clock::MockClock;
    use coauth_data::collaboration_capability::CollaborationCapabilityAction;
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::PgRepositoryFactory;

    fn sample(label: &str) -> NewCollaborationCapabilityGrant {
        NewCollaborationCapabilityGrant {
            capability_grant_id: format!("ak:grant:{label}"),
            grant_event_id: format!("ak:event:{label}"),
            subject: format!("did:web:{label}.example"),
            realm_id: format!("ak:realm:{label}"),
            action: CollaborationCapabilityAction::PinAdd,
            expires_at: None,
            approval_evidence_ref: None,
            granted_by: "did:web:admin.example".to_owned(),
            grant_raw_payload_digest: format!("sha256:{}", "a".repeat(64)),
            grant_fanout_idempotency_key: format!("coauth:collaboration_capability_grant:{label}"),
        }
    }

    #[tokio::test]
    async fn grant_persists_across_repository_instances_and_can_revoke() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = PgRepositoryFactory::new(pool);
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(52);
        let label = uuid::Uuid::now_v7().to_string();

        let mut repo = factory.create().await.unwrap();
        let grant = repo
            .collaboration_capability_grant()
            .add(&mut rng, &clock, sample(&label))
            .await
            .unwrap();
        repo.save().await.unwrap();

        let mut repo = factory.create().await.unwrap();
        let active = repo
            .collaboration_capability_grant()
            .list_active_for_subject_action(&grant.subject, &grant.realm_id, grant.action)
            .await
            .unwrap();
        assert!(active.iter().any(|row| row.id == grant.id));
        let revoked = repo
            .collaboration_capability_grant()
            .revoke_by_id(
                &clock,
                &grant.id,
                CollaborationCapabilityRevokeFanout {
                    revoke_event_id: format!("ak:event:{label}-revoke"),
                },
            )
            .await
            .unwrap()
            .expect("active grant can be revoked");
        assert!(revoked.revoked_at.is_some());
        repo.save().await.unwrap();
    }
}
