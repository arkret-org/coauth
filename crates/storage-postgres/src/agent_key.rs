//! PostgreSQL implementation of the agent key authorization + agent-key-proof
//! replay repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::accountability::AccountabilityGrantFanoutState;
use coauth_data::agent_key::{
    AgentEventCollisionVariant, AgentKeyAuthorization, AgentKeyAuthorizationRepository,
    NewAgentKeyAuthorization, NewAgentSessionProofReplay,
};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{
    agent_key_authorization_collision_variants, agent_key_authorizations,
    agent_session_proof_replay,
};
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
    use coauth_data::{
        AccountabilityGrantFanoutState, RepositoryAccess as _, RepositoryFactory as _,
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

    fn proof_replay(label: &str, clock: &dyn Clock) -> NewAgentSessionProofReplay {
        let now = clock.now();
        NewAgentSessionProofReplay {
            agent_id: format!("did:web:{label}-agent.example"),
            verification_method: format!("did:web:{label}-agent.example#runtime-key-1"),
            challenge: format!("challenge-{label}"),
            nonce: format!("nonce-{label}"),
            request_canonical_digest: format!("sha256:{}", "1".repeat(64)),
            audience: "https://arkret.example/_arkret".to_owned(),
            proof_expires_at: now + chrono::Duration::minutes(5),
            prune_after: now + chrono::Duration::minutes(10),
        }
    }

    fn authorization(
        label: &str,
        event_suffix: &str,
        clock: &dyn Clock,
    ) -> NewAgentKeyAuthorization {
        let agent_id = format!("did:web:{label}-agent.example");
        NewAgentKeyAuthorization {
            authorized_event_id: format!("ak:event:{event_suffix}"),
            agent_id: agent_id.clone(),
            key_id: "runtime-key-1".to_owned(),
            verification_method: format!("{agent_id}#runtime-key-1"),
            public_key: serde_json::json!({ "kty": "OKP", "key": "fixture" }),
            accountable_principal_id: format!("did:web:{label}-controller.example"),
            agent_key_scope: r#"{"actions":["ak.self.events.stream.subscribe.v1"],"resources":[]}"#
                .to_owned(),
            audience: vec!["did:web:soland.test".to_owned()],
            issued_at: clock.now(),
            expires_at: None,
            pairing_request_id: format!("pair-{event_suffix}"),
            request_canonical_digest: format!("sha256:{}", "1".repeat(64)),
            raw_payload_digest: format!("sha256:{}", "2".repeat(64)),
            soland_fanout_state: AccountabilityGrantFanoutState::Queued,
            soland_fanout_idempotency_key: format!("ak:event:{event_suffix}"),
            soland_fanout_payload: serde_json::json!({}),
            soland_fanout_attempt: 0,
            soland_fanout_next_retry_at: Some(clock.now()),
            soland_fanout_dead_letter_reason: None,
        }
    }

    #[tokio::test]
    async fn proof_challenge_consumption_rejects_replay() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
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

    #[tokio::test]
    async fn same_key_id_can_record_successive_authorization_dots() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(0xa92e);
        let label = unique_label("agent-same-key-replacement");
        let first_event = "ak:event:AQsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsL";
        let replacement_event = "ak:event:AQwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";
        let newer_event = "ak:event:AQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0N";

        repo.agent_key_authorization()
            .add(
                &mut rng,
                &clock,
                authorization(
                    &label,
                    "AQsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsL",
                    &clock,
                ),
            )
            .await
            .unwrap();
        repo.agent_key_authorization()
            .add(
                &mut rng,
                &clock,
                authorization(
                    &label,
                    "AQwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
                    &clock,
                ),
            )
            .await
            .expect("replacement authorization is a new dot even when key_id is unchanged");
        repo.agent_key_authorization()
            .add(
                &mut rng,
                &clock,
                authorization(
                    &label,
                    "AQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0N",
                    &clock,
                ),
            )
            .await
            .unwrap();

        repo.agent_key_authorization()
            .mark_fanout_delivered_and_revoke(
                &clock,
                replacement_event,
                &[first_event.to_owned()],
                arkret_wire::ReasonCode::SUPERSEDED_BY_REPAIRING,
            )
            .await
            .unwrap();

        let active_event_ids = repo
            .agent_key_authorization()
            .list_active_for_agent(&format!("did:web:{label}-agent.example"))
            .await
            .unwrap()
            .into_iter()
            .map(|authorization| authorization.authorized_event_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            active_event_ids,
            [replacement_event.to_owned(), newer_event.to_owned()]
                .into_iter()
                .collect(),
            "a delayed older reconciliation must not revoke a newer authorization"
        );
        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn collision_quarantine_removes_authorization_from_active_use() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(0xa93e);
        let label = unique_label("agent-event-collision");
        let token = "AQ8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8P";
        let event_id = format!("ak:event:{token}");

        repo.agent_key_authorization()
            .add(&mut rng, &clock, authorization(&label, token, &clock))
            .await
            .unwrap();
        let variants = [
            AgentEventCollisionVariant {
                canonical_preimage: br#"{"actor_seq":1}"#.to_vec(),
                envelope: serde_json::json!({ "variant": 1 }),
            },
            AgentEventCollisionVariant {
                canonical_preimage: br#"{"actor_seq":2}"#.to_vec(),
                envelope: serde_json::json!({ "variant": 2 }),
            },
        ];
        assert!(
            repo.agent_key_authorization()
                .quarantine_event_collision(&mut rng, &clock, &event_id, &variants)
                .await
                .unwrap()
        );

        let quarantined = repo
            .agent_key_authorization()
            .lookup_by_event_id(&event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            quarantined.quarantine_reason.as_deref(),
            Some("event_hash_collision")
        );
        assert!(quarantined.quarantined_at.is_some());
        assert!(
            repo.agent_key_authorization()
                .list_active_for_agent(&format!("did:web:{label}-agent.example"))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !repo
                .agent_key_authorization()
                .mark_fanout_delivered_and_revoke(&clock, &event_id, &[], "unused")
                .await
                .unwrap()
        );
        repo.cancel().await.unwrap();
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = agent_key_authorizations)]
struct AgentKeyAuthorizationRow {
    id: Uuid,
    authorized_event_id: String,
    agent_id: String,
    key_id: String,
    verification_method: String,
    public_key: serde_json::Value,
    accountable_principal_id: String,
    agent_key_scope: String,
    audience: Vec<String>,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    pairing_request_id: String,
    request_canonical_digest: String,
    revoked_at: Option<DateTime<Utc>>,
    revoked_reason: Option<String>,
    quarantined_at: Option<DateTime<Utc>>,
    quarantine_reason: Option<String>,
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
            agent_id: value.agent_id,
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
            quarantined_at: value.quarantined_at,
            quarantine_reason: value.quarantine_reason,
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
    agent_id: String,
    key_id: String,
    verification_method: String,
    public_key: serde_json::Value,
    accountable_principal_id: String,
    agent_key_scope: String,
    audience: Vec<String>,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
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
    agent_id: String,
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

#[derive(Insertable)]
#[diesel(table_name = agent_key_authorization_collision_variants)]
struct InsertableAgentEventCollisionVariant {
    id: Uuid,
    authorized_event_id: String,
    canonical_preimage: Vec<u8>,
    envelope: serde_json::Value,
    observed_at: DateTime<Utc>,
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
            agent_id: params.agent_id,
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
            agent_id: row.agent_id,
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
            quarantined_at: None,
            quarantine_reason: None,
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
        agent_id: &str,
    ) -> Result<Vec<AgentKeyAuthorization>, Self::Error> {
        agent_key_authorizations::table
            .filter(agent_key_authorizations::agent_id.eq(agent_id))
            .filter(agent_key_authorizations::revoked_at.is_null())
            .filter(agent_key_authorizations::quarantined_at.is_null())
            .order(agent_key_authorizations::issued_at.asc())
            .select(AgentKeyAuthorizationRow::as_select())
            .load::<AgentKeyAuthorizationRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.agent_key_authorization.quarantine_event_collision",
        skip_all,
        err
    )]
    async fn quarantine_event_collision(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        authorized_event_id: &str,
        variants: &[AgentEventCollisionVariant],
    ) -> Result<bool, Self::Error> {
        if variants.len() < 2 {
            return Ok(false);
        }
        let now = clock.now();
        let updated = diesel::update(
            agent_key_authorizations::table
                .filter(agent_key_authorizations::authorized_event_id.eq(authorized_event_id)),
        )
        .set((
            agent_key_authorizations::quarantined_at.eq(Some(now)),
            agent_key_authorizations::quarantine_reason.eq(Some("event_hash_collision")),
            agent_key_authorizations::soland_fanout_state
                .eq(AccountabilityGrantFanoutState::DeadLettered.as_str()),
            agent_key_authorizations::soland_fanout_next_retry_at.eq(Option::<DateTime<Utc>>::None),
            agent_key_authorizations::soland_fanout_dead_letter_reason
                .eq(Some("event_hash_collision".to_owned())),
            agent_key_authorizations::updated_at.eq(now),
        ))
        .execute(self.conn)
        .await?;
        if updated != 1 {
            return Ok(false);
        }

        for variant in variants {
            let row = InsertableAgentEventCollisionVariant {
                id: Uuid::from(new_id(now, rng)),
                authorized_event_id: authorized_event_id.to_owned(),
                canonical_preimage: variant.canonical_preimage.clone(),
                envelope: variant.envelope.clone(),
                observed_at: now,
            };
            diesel::insert_into(agent_key_authorization_collision_variants::table)
                .values(row)
                .execute(self.conn)
                .await?;
        }
        Ok(true)
    }

    #[tracing::instrument(name = "db.agent_key_authorization.revoke_for_agent", skip_all, err)]
    async fn revoke_for_agent(
        &mut self,
        clock: &dyn Clock,
        agent_id: &str,
        reason: &str,
    ) -> Result<usize, Self::Error> {
        let now = clock.now();
        let count = diesel::update(
            agent_key_authorizations::table
                .filter(agent_key_authorizations::agent_id.eq(agent_id))
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
        name = "db.agent_key_authorization.mark_fanout_delivered_and_revoke",
        skip_all,
        err
    )]
    async fn mark_fanout_delivered_and_revoke(
        &mut self,
        clock: &dyn Clock,
        authorized_event_id: &str,
        superseded_event_ids: &[String],
        revoked_reason: &str,
    ) -> Result<bool, Self::Error> {
        let Some(current) = self.lookup_by_event_id(authorized_event_id).await? else {
            return Ok(false);
        };
        let now = clock.now();
        let delivered = diesel::update(
            agent_key_authorizations::table
                .filter(agent_key_authorizations::authorized_event_id.eq(authorized_event_id))
                .filter(agent_key_authorizations::quarantined_at.is_null()),
        )
        .set((
            agent_key_authorizations::soland_fanout_state
                .eq(AccountabilityGrantFanoutState::Delivered.as_str()),
            agent_key_authorizations::soland_fanout_next_retry_at.eq(Option::<DateTime<Utc>>::None),
            agent_key_authorizations::soland_fanout_dead_letter_reason.eq(Option::<String>::None),
            agent_key_authorizations::updated_at.eq(now),
        ))
        .execute(self.conn)
        .await?;
        if delivered != 1 {
            return Ok(false);
        }
        if !superseded_event_ids.is_empty() {
            diesel::update(
                agent_key_authorizations::table
                    .filter(agent_key_authorizations::agent_id.eq(&current.agent_id))
                    .filter(
                        agent_key_authorizations::authorized_event_id.eq_any(superseded_event_ids),
                    )
                    .filter(agent_key_authorizations::revoked_at.is_null()),
            )
            .set((
                agent_key_authorizations::revoked_at.eq(Some(now)),
                agent_key_authorizations::revoked_reason.eq(Some(revoked_reason.to_owned())),
                agent_key_authorizations::updated_at.eq(now),
            ))
            .execute(self.conn)
            .await?;
        }
        Ok(true)
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
            agent_id: params.agent_id,
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
