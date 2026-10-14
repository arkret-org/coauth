//! Read-only PostgreSQL access to local collaboration capability review records.

use arkret_identifiers::DidCoreId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::collaboration_capability::{
    CapabilityActionId, CollaborationCapabilityGrant, CollaborationCapabilityGrantRepository,
    is_collaboration_capability_action,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
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
    granted_by: DidCoreId,
    granted_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    grant_raw_payload_digest: String,
    grant_fanout_idempotency_key: String,
}

impl TryFrom<CollaborationCapabilityGrantRow> for CollaborationCapabilityGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: CollaborationCapabilityGrantRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let action = CapabilityActionId::from_wire(&value.action)
            .filter(|action| is_collaboration_capability_action(*action))
            .ok_or_else(|| {
                DatabaseInconsistencyError::on("collaboration_capability_grants")
                    .column("action")
                    .row(id)
                    .source(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "unknown or non-collaboration capability action: {}",
                            value.action
                        ),
                    ))
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

#[async_trait]
impl CollaborationCapabilityGrantRepository for PgCollaborationCapabilityGrantRepository<'_> {
    type Error = DatabaseError;

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
}

#[cfg(test)]
mod tests {
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
    use diesel::sql_types::{Bool, Text};

    use super::*;
    use crate::PgRepositoryFactory;

    async fn seed_record(
        conn: &mut diesel_async::AsyncPgConnection,
        label: &str,
        action: &str,
        revoked: bool,
    ) -> Uuid {
        let id = Uuid::now_v7();
        diesel::sql_query(
            "INSERT INTO collaboration_capability_grants
             (id, capability_grant_id, grant_event_id, subject, realm_id, action,
              granted_by, granted_at, revoked_at, grant_raw_payload_digest,
              grant_fanout_idempotency_key, created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'review-realm', $5,
                     'ak:did_core:web:admin.example', '2026-10-14T00:00:00Z',
                     CASE WHEN $6 THEN '2026-10-14T00:00:00Z'::timestamptz END,
                     $7, $8, '2026-10-14T00:00:00Z', '2026-10-14T00:00:00Z')",
        )
        .bind::<diesel::sql_types::Uuid, _>(id)
        .bind::<Text, _>(format!("review-grant:{label}"))
        .bind::<Text, _>(format!("review-event:{label}"))
        .bind::<Text, _>(label)
        .bind::<Text, _>(action)
        .bind::<Bool, _>(revoked)
        .bind::<Text, _>(format!("sha256:{}", "a".repeat(64)))
        .bind::<Text, _>(format!("review-fixture:{label}"))
        .execute(conn)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn review_list_survives_repository_recreation_and_excludes_revoked_records() {
        let database = crate::test_utils::setup_test_pool().await.unwrap();
        let factory = PgRepositoryFactory::new(database.clone());
        let mut conn = database.get().await.unwrap();
        let second = seed_record(
            &mut conn,
            "b",
            CapabilityActionId::PinRemove.as_str(),
            false,
        )
        .await;
        let first = seed_record(&mut conn, "a", CapabilityActionId::PinAdd.as_str(), false).await;
        seed_record(
            &mut conn,
            "revoked",
            CapabilityActionId::PinAdd.as_str(),
            true,
        )
        .await;
        drop(conn);

        for _ in 0..2 {
            let mut repo = factory.create().await.unwrap();
            let rows = repo
                .collaboration_capability_grant()
                .list_active()
                .await
                .unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0].id, Ulid::from(first).to_string());
            assert_eq!(rows[1].id, Ulid::from(second).to_string());
            assert_eq!(rows[0].action, CapabilityActionId::PinAdd);
            assert_eq!(rows[1].action, CapabilityActionId::PinRemove);
            assert_eq!(rows[0].granted_by.as_str(), "ak:did_core:web:admin.example");
            assert_eq!(rows[0].grant_event_id, "review-event:a");
            assert_eq!(
                rows[0].grant_raw_payload_digest,
                format!("sha256:{}", "a".repeat(64))
            );
            assert!(rows.iter().all(|row| row.revoked_at.is_none()));
            repo.cancel().await.unwrap();
        }
    }

    #[tokio::test]
    async fn review_list_rejects_unknown_and_non_collaboration_actions() {
        let database = crate::test_utils::setup_test_pool().await.unwrap();
        let factory = PgRepositoryFactory::new(database.clone());
        for action in [
            "invalid-action",
            CapabilityActionId::CircleManage.as_str(),
        ] {
            let mut conn = database.get().await.unwrap();
            diesel::delete(collaboration_capability_grants::table)
                .execute(&mut conn)
                .await
                .unwrap();
            seed_record(&mut conn, "invalid", action, false).await;
            drop(conn);
            let mut repo = factory.create().await.unwrap();
            assert!(
                repo.collaboration_capability_grant()
                    .list_active()
                    .await
                    .is_err()
            );
            repo.cancel().await.unwrap();
        }
    }
}
