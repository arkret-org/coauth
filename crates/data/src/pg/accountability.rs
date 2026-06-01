//! PostgreSQL implementation of the accountability grant repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    Clock,
    accountability::{
        AccountabilityGrant, AccountabilityGrantRepository, AccountabilitySubjectKind,
        AccountabilitySubjectRevocation, NewAccountabilityGrant,
    },
    new_id,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    schema::{accountability_grants, accountability_subject_revocations},
};

/// PostgreSQL implementation of [`AccountabilityGrantRepository`].
pub struct PgAccountabilityGrantRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgAccountabilityGrantRepository<'c> {
    /// Construct from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use coauth_data::{
        AccountabilityGrantFanoutState, AccountabilitySubjectKind, RepositoryAccess as _,
        RepositoryFactory as _, clock::MockClock,
    };
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::PgRepositoryFactory;

    fn unique_label(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        format!("{name}-{nanos}")
    }

    fn digest(label: &str) -> String {
        format!("sha256:{label}")
    }

    fn grant_id() -> String {
        format!(
            "cx:accountability_grant:{}",
            uuid::Uuid::from(ulid::Ulid::new())
        )
    }

    fn agent_did(label: &str) -> String {
        format!("did:web:{label}-agent.example")
    }

    fn sample_new(label: &str, agent: &str, controller: &str) -> NewAccountabilityGrant {
        NewAccountabilityGrant {
            accountability_grant_id: grant_id(),
            agent_principal_id: agent.to_owned(),
            controller_did: controller.to_owned(),
            capabilities: vec!["cx.agent.provision".to_owned()],
            capabilities_digest: digest(label),
            reason: Some("test grant".to_owned()),
            issued_at: chrono::Utc::now(),
            raw_payload_digest: digest(&format!("payload-{label}")),
            soland_fanout_state: AccountabilityGrantFanoutState::Queued,
            soland_fanout_idempotency_key: format!("idem-{label}"),
            soland_fanout_payload: serde_json::json!({
                "kind": "cx.coauth.accountability_grant.fanout.v1",
                "label": label,
            }),
            soland_fanout_attempt: 0,
            soland_fanout_next_retry_at: Some(chrono::Utc::now()),
            soland_fanout_dead_letter_reason: None,
        }
    }

    #[tokio::test]
    async fn duplicate_active_grant_is_rejected() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(42);
        let label = unique_label("duplicate");
        let agent = agent_did(&label);
        let controller = format!("did:web:{label}.example");

        repo.accountability_grant()
            .add(&mut rng, &clock, sample_new(&label, &agent, &controller))
            .await
            .unwrap();

        let mut duplicate = sample_new(&label, &agent, &controller);
        duplicate.accountability_grant_id = grant_id();
        duplicate.soland_fanout_idempotency_key = format!("idem-{label}-2");
        let err = repo
            .accountability_grant()
            .add(&mut rng, &clock, duplicate)
            .await;
        assert!(err.is_err(), "active fingerprint must be unique");

        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn fanout_failure_can_enter_retryable_queue() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(43);
        let label = unique_label("fanout");
        let agent = agent_did(&label);
        let controller = format!("did:web:{label}.example");
        let grant = repo
            .accountability_grant()
            .add(&mut rng, &clock, sample_new(&label, &agent, &controller))
            .await
            .unwrap();

        assert_eq!(
            grant.soland_fanout_state,
            AccountabilityGrantFanoutState::Queued
        );
        assert_eq!(grant.soland_fanout_attempt, 0);
        assert!(grant.soland_fanout_next_retry_at.is_some());

        let queue = unique_label("soland-accountability-grant-fanout");
        repo.queue_job()
            .schedule(
                &mut rng,
                &clock,
                &queue,
                grant.soland_fanout_payload.clone(),
                serde_json::json!({
                    "idempotency_key": grant.soland_fanout_idempotency_key,
                    "attempt": grant.soland_fanout_attempt,
                    "next_retry_at": grant.soland_fanout_next_retry_at,
                }),
            )
            .await
            .unwrap();
        let worker = repo
            .queue_worker()
            .register(&mut rng, &clock)
            .await
            .unwrap();
        let reserved = repo
            .queue_job()
            .reserve(&clock, &worker, &[queue.as_str()], 1)
            .await
            .unwrap();
        assert_eq!(reserved.len(), 1);
        assert_eq!(reserved[0].attempt, 0);

        repo.save().await.unwrap();
    }

    #[tokio::test]
    async fn grant_persists_across_repository_instances_and_can_revoke() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = PgRepositoryFactory::new(pool);
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(45);
        let label = unique_label("durable");
        let agent = agent_did(&label);
        let controller = format!("did:web:{label}.example");

        let mut repo = factory.create().await.unwrap();
        let grant = repo
            .accountability_grant()
            .add(&mut rng, &clock, sample_new(&label, &agent, &controller))
            .await
            .unwrap();
        repo.save().await.unwrap();

        let mut repo = factory.create().await.unwrap();
        let loaded = repo
            .accountability_grant()
            .lookup_by_grant_id(&grant.accountability_grant_id)
            .await
            .unwrap()
            .expect("grant survives a new repository transaction");
        assert_eq!(
            loaded.accountability_grant_id,
            grant.accountability_grant_id
        );
        let revoked = repo
            .accountability_grant()
            .revoke_by_grant_id(&clock, &loaded.accountability_grant_id, "manual_revoke")
            .await
            .unwrap()
            .expect("manual revoke returns the durable grant");
        assert!(revoked.revoked_at.is_some());
        repo.save().await.unwrap();
    }

    #[tokio::test]
    async fn revocation_index_hits_controller_agent_and_manual_paths() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(44);
        let label = unique_label("revocation");
        let controller = format!("did:web:{label}.example");
        let other_controller = format!("did:web:{label}-other.example");
        let agent_one = format!("did:web:{label}-agent-one.example");
        let agent_two = format!("did:web:{label}-agent-two.example");

        let grant_one = repo
            .accountability_grant()
            .add(
                &mut rng,
                &clock,
                sample_new(&format!("{label}-one"), &agent_one, &controller),
            )
            .await
            .unwrap();
        repo.accountability_grant()
            .add(
                &mut rng,
                &clock,
                sample_new(&format!("{label}-two"), &agent_two, &controller),
            )
            .await
            .unwrap();
        repo.accountability_grant()
            .add(
                &mut rng,
                &clock,
                sample_new(&format!("{label}-three"), &agent_two, &other_controller),
            )
            .await
            .unwrap();

        let revoked = repo
            .accountability_grant()
            .revoke_for_subject(
                &clock,
                AccountabilitySubjectKind::ControllerDid,
                &controller,
                "controller_paused",
            )
            .await
            .unwrap();
        assert_eq!(revoked, 2);
        assert!(
            repo.accountability_grant()
                .list_active_for_subject(AccountabilitySubjectKind::ControllerDid, &controller)
                .await
                .unwrap()
                .is_empty()
        );

        let manually_revoked = repo
            .accountability_grant()
            .revoke_by_grant_id(
                &clock,
                &grant_one.accountability_grant_id,
                "manual_revoke_after_controller",
            )
            .await
            .unwrap()
            .expect("grant still loads after revoke");
        assert!(manually_revoked.revoked_at.is_some());

        repo.accountability_grant()
            .mark_subject_revoked(
                &mut rng,
                &clock,
                AccountabilitySubjectKind::AgentPrincipalId,
                &agent_two,
                "agent_deactivated",
            )
            .await
            .unwrap();
        assert!(
            repo.accountability_grant()
                .subject_revoked(AccountabilitySubjectKind::AgentPrincipalId, &agent_two)
                .await
                .unwrap()
        );
        let revoked = repo
            .accountability_grant()
            .revoke_for_subject(
                &clock,
                AccountabilitySubjectKind::AgentPrincipalId,
                &agent_two,
                "agent_deactivated",
            )
            .await
            .unwrap();
        assert_eq!(revoked, 1);

        repo.save().await.unwrap();
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = accountability_grants)]
struct AccountabilityGrantRow {
    id: Uuid,
    accountability_grant_id: String,
    agent_principal_id: String,
    controller_did: String,
    capabilities: Vec<String>,
    capabilities_digest: String,
    reason: Option<String>,
    issued_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_reason: Option<String>,
    raw_payload_digest: String,
    soland_fanout_state: String,
    soland_fanout_idempotency_key: String,
    soland_fanout_payload: serde_json::Value,
    soland_fanout_attempt: i32,
    soland_fanout_next_retry_at: Option<DateTime<Utc>>,
    soland_fanout_dead_letter_reason: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<AccountabilityGrantRow> for AccountabilityGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: AccountabilityGrantRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let soland_fanout_state = value.soland_fanout_state.parse().map_err(|e| {
            DatabaseInconsistencyError::on("accountability_grants")
                .column("soland_fanout_state")
                .row(id)
                .source(e)
        })?;

        Ok(Self {
            id,
            accountability_grant_id: value.accountability_grant_id,
            agent_principal_id: value.agent_principal_id,
            controller_did: value.controller_did,
            capabilities: value.capabilities,
            capabilities_digest: value.capabilities_digest,
            reason: value.reason,
            issued_at: value.issued_at,
            revoked_at: value.revoked_at,
            revoked_reason: value.revoked_reason,
            raw_payload_digest: value.raw_payload_digest,
            soland_fanout_state,
            soland_fanout_idempotency_key: value.soland_fanout_idempotency_key,
            soland_fanout_payload: value.soland_fanout_payload,
            soland_fanout_attempt: value.soland_fanout_attempt,
            soland_fanout_next_retry_at: value.soland_fanout_next_retry_at,
            soland_fanout_dead_letter_reason: value.soland_fanout_dead_letter_reason,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = accountability_grants)]
struct InsertableAccountabilityGrant {
    id: Uuid,
    accountability_grant_id: String,
    agent_principal_id: String,
    controller_did: String,
    capabilities: Vec<String>,
    capabilities_digest: String,
    reason: Option<String>,
    issued_at: DateTime<Utc>,
    raw_payload_digest: String,
    soland_fanout_state: String,
    soland_fanout_idempotency_key: String,
    soland_fanout_payload: serde_json::Value,
    soland_fanout_attempt: i32,
    soland_fanout_next_retry_at: Option<DateTime<Utc>>,
    soland_fanout_dead_letter_reason: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = accountability_subject_revocations)]
struct SubjectRevocationRow {
    id: Uuid,
    subject_kind: String,
    subject_id: String,
    reason: String,
    revoked_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<SubjectRevocationRow> for AccountabilitySubjectRevocation {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: SubjectRevocationRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let subject_kind = value.subject_kind.parse().map_err(|e| {
            DatabaseInconsistencyError::on("accountability_subject_revocations")
                .column("subject_kind")
                .row(id)
                .source(e)
        })?;

        Ok(Self {
            id,
            subject_kind,
            subject_id: value.subject_id,
            reason: value.reason,
            revoked_at: value.revoked_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = accountability_subject_revocations)]
struct InsertableSubjectRevocation {
    id: Uuid,
    subject_kind: String,
    subject_id: String,
    reason: String,
    revoked_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl AccountabilityGrantRepository for PgAccountabilityGrantRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.accountability_grant.add",
        skip_all,
        fields(accountability_grant.id, accountability_grant.typed_id = params.accountability_grant_id),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAccountabilityGrant,
    ) -> Result<AccountabilityGrant, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);
        tracing::Span::current().record("accountability_grant.id", tracing::field::display(id));

        let row = InsertableAccountabilityGrant {
            id: Uuid::from(id),
            accountability_grant_id: params.accountability_grant_id,
            agent_principal_id: params.agent_principal_id,
            controller_did: params.controller_did,
            capabilities: params.capabilities,
            capabilities_digest: params.capabilities_digest,
            reason: params.reason,
            issued_at: params.issued_at,
            raw_payload_digest: params.raw_payload_digest,
            soland_fanout_state: params.soland_fanout_state.to_string(),
            soland_fanout_idempotency_key: params.soland_fanout_idempotency_key,
            soland_fanout_payload: params.soland_fanout_payload,
            soland_fanout_attempt: params.soland_fanout_attempt,
            soland_fanout_next_retry_at: params.soland_fanout_next_retry_at,
            soland_fanout_dead_letter_reason: params.soland_fanout_dead_letter_reason,
            created_at: now,
            updated_at: now,
        };

        diesel::insert_into(accountability_grants::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(AccountabilityGrant {
            id,
            accountability_grant_id: row.accountability_grant_id,
            agent_principal_id: row.agent_principal_id,
            controller_did: row.controller_did,
            capabilities: row.capabilities,
            capabilities_digest: row.capabilities_digest,
            reason: row.reason,
            issued_at: row.issued_at,
            revoked_at: None,
            revoked_reason: None,
            raw_payload_digest: row.raw_payload_digest,
            soland_fanout_state: params.soland_fanout_state,
            soland_fanout_idempotency_key: row.soland_fanout_idempotency_key,
            soland_fanout_payload: row.soland_fanout_payload,
            soland_fanout_attempt: row.soland_fanout_attempt,
            soland_fanout_next_retry_at: row.soland_fanout_next_retry_at,
            soland_fanout_dead_letter_reason: row.soland_fanout_dead_letter_reason,
            created_at: now,
            updated_at: now,
        })
    }

    #[tracing::instrument(name = "db.accountability_grant.lookup_by_grant_id", skip_all, err)]
    async fn lookup_by_grant_id(
        &mut self,
        accountability_grant_id: &str,
    ) -> Result<Option<AccountabilityGrant>, Self::Error> {
        accountability_grants::table
            .filter(accountability_grants::accountability_grant_id.eq(accountability_grant_id))
            .select(AccountabilityGrantRow::as_select())
            .first::<AccountabilityGrantRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.accountability_grant.find_active_by_fingerprint",
        skip_all,
        err
    )]
    async fn find_active_by_fingerprint(
        &mut self,
        agent_principal_id: &str,
        controller_did: &str,
        capabilities_digest: &str,
    ) -> Result<Option<AccountabilityGrant>, Self::Error> {
        accountability_grants::table
            .filter(accountability_grants::agent_principal_id.eq(agent_principal_id))
            .filter(accountability_grants::controller_did.eq(controller_did))
            .filter(accountability_grants::capabilities_digest.eq(capabilities_digest))
            .filter(accountability_grants::revoked_at.is_null())
            .select(AccountabilityGrantRow::as_select())
            .first::<AccountabilityGrantRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.accountability_grant.list_active_for_subject",
        skip_all,
        err
    )]
    async fn list_active_for_subject(
        &mut self,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &str,
    ) -> Result<Vec<AccountabilityGrant>, Self::Error> {
        let mut query = accountability_grants::table
            .filter(accountability_grants::revoked_at.is_null())
            .order(accountability_grants::issued_at.asc())
            .select(AccountabilityGrantRow::as_select())
            .into_boxed();

        query = match subject_kind {
            AccountabilitySubjectKind::ControllerDid => {
                query.filter(accountability_grants::controller_did.eq(subject_id))
            }
            AccountabilitySubjectKind::AgentPrincipalId => {
                query.filter(accountability_grants::agent_principal_id.eq(subject_id))
            }
        };

        query
            .load::<AccountabilityGrantRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.accountability_grant.revoke_by_grant_id", skip_all, err)]
    async fn revoke_by_grant_id(
        &mut self,
        clock: &dyn Clock,
        accountability_grant_id: &str,
        reason: &str,
    ) -> Result<Option<AccountabilityGrant>, Self::Error> {
        let now = clock.now();
        diesel::update(
            accountability_grants::table
                .filter(accountability_grants::accountability_grant_id.eq(accountability_grant_id))
                .filter(accountability_grants::revoked_at.is_null()),
        )
        .set((
            accountability_grants::revoked_at.eq(Some(now)),
            accountability_grants::revoked_reason.eq(Some(reason.to_owned())),
            accountability_grants::updated_at.eq(now),
        ))
        .execute(self.conn)
        .await?;

        self.lookup_by_grant_id(accountability_grant_id).await
    }

    #[tracing::instrument(name = "db.accountability_grant.revoke_for_subject", skip_all, err)]
    async fn revoke_for_subject(
        &mut self,
        clock: &dyn Clock,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &str,
        reason: &str,
    ) -> Result<usize, Self::Error> {
        let now = clock.now();
        let base = accountability_grants::table.filter(accountability_grants::revoked_at.is_null());

        let count = match subject_kind {
            AccountabilitySubjectKind::ControllerDid => {
                diesel::update(base.filter(accountability_grants::controller_did.eq(subject_id)))
                    .set((
                        accountability_grants::revoked_at.eq(Some(now)),
                        accountability_grants::revoked_reason.eq(Some(reason.to_owned())),
                        accountability_grants::updated_at.eq(now),
                    ))
                    .execute(self.conn)
                    .await?
            }
            AccountabilitySubjectKind::AgentPrincipalId => {
                diesel::update(
                    base.filter(accountability_grants::agent_principal_id.eq(subject_id)),
                )
                .set((
                    accountability_grants::revoked_at.eq(Some(now)),
                    accountability_grants::revoked_reason.eq(Some(reason.to_owned())),
                    accountability_grants::updated_at.eq(now),
                ))
                .execute(self.conn)
                .await?
            }
        };

        Ok(count)
    }

    #[tracing::instrument(name = "db.accountability_subject_revocation.mark", skip_all, err)]
    async fn mark_subject_revoked(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &str,
        reason: &str,
    ) -> Result<AccountabilitySubjectRevocation, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);
        let row = InsertableSubjectRevocation {
            id: Uuid::from(id),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_owned(),
            reason: reason.to_owned(),
            revoked_at: now,
            created_at: now,
            updated_at: now,
        };

        diesel::insert_into(accountability_subject_revocations::table)
            .values(&row)
            .on_conflict((
                accountability_subject_revocations::subject_kind,
                accountability_subject_revocations::subject_id,
            ))
            .do_update()
            .set((
                accountability_subject_revocations::reason.eq(row.reason.clone()),
                accountability_subject_revocations::revoked_at.eq(now),
                accountability_subject_revocations::updated_at.eq(now),
            ))
            .execute(self.conn)
            .await?;

        accountability_subject_revocations::table
            .filter(accountability_subject_revocations::subject_kind.eq(subject_kind.to_string()))
            .filter(accountability_subject_revocations::subject_id.eq(subject_id))
            .select(SubjectRevocationRow::as_select())
            .first::<SubjectRevocationRow>(self.conn)
            .await?
            .try_into()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.accountability_subject_revocation.exists", skip_all, err)]
    async fn subject_revoked(
        &mut self,
        subject_kind: AccountabilitySubjectKind,
        subject_id: &str,
    ) -> Result<bool, Self::Error> {
        let count: i64 = accountability_subject_revocations::table
            .filter(accountability_subject_revocations::subject_kind.eq(subject_kind.to_string()))
            .filter(accountability_subject_revocations::subject_id.eq(subject_id))
            .count()
            .get_result(self.conn)
            .await?;

        Ok(count > 0)
    }
}
