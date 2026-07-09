//! PostgreSQL implementation of the agent key authorization + agent-key-proof
//! replay repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::agent_key::{
    AgentKeyAuthorization, AgentKeyAuthorizationRepository, NewAgentKeyAuthorization,
    NewAgentSessionProofReplay,
};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{agent_key_authorizations, agent_session_proof_replay};
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`AgentKeyAuthorizationRepository`].
pub struct PgAgentKeyAuthorizationRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgAgentKeyAuthorizationRepository<'c> {
    /// Construct from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use coauth_data::clock::MockClock;
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
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

    fn proof_replay(label: &str, clock: &dyn Clock) -> NewAgentSessionProofReplay {
        let now = clock.now();
        NewAgentSessionProofReplay {
            agent_principal_id: format!("did:web:{label}-agent.example"),
            verification_method: format!("did:web:{label}-agent.example#runtime-key-1"),
            challenge: format!("challenge-{label}"),
            nonce: format!("nonce-{label}"),
            request_canonical_digest: format!("sha256:{}", "1".repeat(64)),
            audience: "https://arkret.example/_cokret".to_owned(),
            proof_expires_at: now + chrono::Duration::minutes(5),
            prune_after: now + chrono::Duration::minutes(10),
        }
    }

    #[tokio::test]
    async fn proof_challenge_consumption_rejects_replay() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(0xa91e);
        let replay = proof_replay(&unique_label("agent-proof-replay"), &clock);

        let first = repo
            .agent_key_authorization()
            .consume_proof_challenge(&mut rng, &clock, replay.clone())
            .await
            .unwrap();
        let second = repo
            .agent_key_authorization()
            .consume_proof_challenge(&mut rng, &clock, replay)
            .await
            .unwrap();

        assert!(first, "first challenge consumption must win");
        assert!(!second, "replayed challenge must fail closed");

        repo.cancel().await.unwrap();
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = agent_key_authorizations)]
struct AgentKeyAuthorizationRow {
    id: Uuid,
    authorized_event_id: String,
    agent_principal_id: String,
    key_id: String,
    verification_method: String,
    public_key: serde_json::Value,
    accountable_principal_id: String,
    agent_key_scope: String,
    audience: Vec<String>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    pairing_request_id: String,
    request_canonical_digest: String,
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

impl TryFrom<AgentKeyAuthorizationRow> for AgentKeyAuthorization {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: AgentKeyAuthorizationRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let soland_fanout_state = value.soland_fanout_state.parse().map_err(|e| {
            DatabaseInconsistencyError::on("agent_key_authorizations")
                .column("soland_fanout_state")
                .row(id)
                .source(e)
        })?;

        Ok(Self {
            id,
            authorized_event_id: value.authorized_event_id,
            agent_principal_id: value.agent_principal_id,
            key_id: value.key_id,
            verification_method: value.verification_method,
            public_key: value.public_key,
            accountable_principal_id: value.accountable_principal_id,
            agent_key_scope: value.agent_key_scope,
            audience: value.audience,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            pairing_request_id: value.pairing_request_id,
            request_canonical_digest: value.request_canonical_digest,
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
#[diesel(table_name = agent_key_authorizations)]
struct InsertableAgentKeyAuthorization {
    id: Uuid,
    authorized_event_id: String,
    agent_principal_id: String,
    key_id: String,
    verification_method: String,
    public_key: serde_json::Value,
    accountable_principal_id: String,
    agent_key_scope: String,
    audience: Vec<String>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    pairing_request_id: String,
    request_canonical_digest: String,
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

#[derive(Insertable)]
#[diesel(table_name = agent_session_proof_replay)]
struct InsertableProofReplay {
    id: Uuid,
    agent_principal_id: String,
    verification_method: String,
    challenge: String,
    nonce: String,
    request_canonical_digest: String,
    audience: String,
    consumed_at: DateTime<Utc>,
    proof_expires_at: DateTime<Utc>,
    prune_after: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl AgentKeyAuthorizationRepository for PgAgentKeyAuthorizationRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.agent_key_authorization.add",
        skip_all,
        fields(agent_key_authorization.id, agent_key_authorization.event_id = params.authorized_event_id),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAgentKeyAuthorization,
    ) -> Result<AgentKeyAuthorization, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);
        tracing::Span::current().record("agent_key_authorization.id", tracing::field::display(id));

        let row = InsertableAgentKeyAuthorization {
            id: Uuid::from(id),
            authorized_event_id: params.authorized_event_id,
            agent_principal_id: params.agent_principal_id,
            key_id: params.key_id,
            verification_method: params.verification_method,
            public_key: params.public_key,
            accountable_principal_id: params.accountable_principal_id,
            agent_key_scope: params.agent_key_scope,
            audience: params.audience,
            issued_at: params.issued_at,
            expires_at: params.expires_at,
            pairing_request_id: params.pairing_request_id,
            request_canonical_digest: params.request_canonical_digest,
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

        diesel::insert_into(agent_key_authorizations::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(AgentKeyAuthorization {
            id,
            authorized_event_id: row.authorized_event_id,
            agent_principal_id: row.agent_principal_id,
            key_id: row.key_id,
            verification_method: row.verification_method,
            public_key: row.public_key,
            accountable_principal_id: row.accountable_principal_id,
            agent_key_scope: row.agent_key_scope,
            audience: row.audience,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            pairing_request_id: row.pairing_request_id,
            request_canonical_digest: row.request_canonical_digest,
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

    #[tracing::instrument(name = "db.agent_key_authorization.lookup_by_event_id", skip_all, err)]
    async fn lookup_by_event_id(
        &mut self,
        authorized_event_id: &str,
    ) -> Result<Option<AgentKeyAuthorization>, Self::Error> {
        agent_key_authorizations::table
            .filter(agent_key_authorizations::authorized_event_id.eq(authorized_event_id))
            .select(AgentKeyAuthorizationRow::as_select())
            .first::<AgentKeyAuthorizationRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.agent_key_authorization.list_active_for_agent",
        skip_all,
        err
    )]
    async fn list_active_for_agent(
        &mut self,
        agent_principal_id: &str,
    ) -> Result<Vec<AgentKeyAuthorization>, Self::Error> {
        agent_key_authorizations::table
            .filter(agent_key_authorizations::agent_principal_id.eq(agent_principal_id))
            .filter(agent_key_authorizations::revoked_at.is_null())
            .order(agent_key_authorizations::issued_at.asc())
            .select(AgentKeyAuthorizationRow::as_select())
            .load::<AgentKeyAuthorizationRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.agent_key_authorization.revoke_for_agent", skip_all, err)]
    async fn revoke_for_agent(
        &mut self,
        clock: &dyn Clock,
        agent_principal_id: &str,
        reason: &str,
    ) -> Result<usize, Self::Error> {
        let now = clock.now();
        let count = diesel::update(
            agent_key_authorizations::table
                .filter(agent_key_authorizations::agent_principal_id.eq(agent_principal_id))
                .filter(agent_key_authorizations::revoked_at.is_null()),
        )
        .set((
            agent_key_authorizations::revoked_at.eq(Some(now)),
            agent_key_authorizations::revoked_reason.eq(Some(reason.to_owned())),
            agent_key_authorizations::updated_at.eq(now),
        ))
        .execute(self.conn)
        .await?;
        Ok(count)
    }

    #[tracing::instrument(
        name = "db.agent_key_authorization.consume_proof_challenge",
        skip_all,
        err
    )]
    async fn consume_proof_challenge(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAgentSessionProofReplay,
    ) -> Result<bool, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);
        let row = InsertableProofReplay {
            id: Uuid::from(id),
            agent_principal_id: params.agent_principal_id,
            verification_method: params.verification_method,
            challenge: params.challenge,
            nonce: params.nonce,
            request_canonical_digest: params.request_canonical_digest,
            audience: params.audience,
            consumed_at: now,
            proof_expires_at: params.proof_expires_at,
            prune_after: params.prune_after,
            created_at: now,
        };

        // Single-use: either a repeated challenge or repeated nonce makes the
        // insert a no-op. The first caller inserts one row and wins; a replay
        // inserts zero and loses.
        let inserted = diesel::insert_into(agent_session_proof_replay::table)
            .values(&row)
            .on_conflict_do_nothing()
            .execute(self.conn)
            .await?;

        Ok(inserted == 1)
    }

    #[tracing::instrument(
        name = "db.agent_key_authorization.prune_expired_replay",
        skip_all,
        err
    )]
    async fn prune_expired_replay(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error> {
        let now = clock.now();
        let count = diesel::delete(
            agent_session_proof_replay::table
                .filter(agent_session_proof_replay::prune_after.lt(now)),
        )
        .execute(self.conn)
        .await?;
        Ok(count)
    }
}
