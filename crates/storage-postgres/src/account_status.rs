//! PostgreSQL Account Authority issuer ledger.

use arkret_models_collaboration::account_status::AccountStatusRecord;
use async_trait::async_trait;
use coauth_data::{AccountStatusAppendOutcome, AccountStatusLedgerRepository, LocalAccountId};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::DatabaseError;
use crate::schema::{account_status_ledger_heads, account_status_records};

/// PostgreSQL-backed Account Authority issuer ledger.
pub struct PgAccountStatusLedgerRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgAccountStatusLedgerRepository<'c> {
    /// Construct a ledger repository over the caller's active transaction.
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }

    fn decode(value: serde_json::Value) -> Result<AccountStatusRecord, DatabaseError> {
        let record: AccountStatusRecord = serde_json::from_value(value)?;
        record
            .validate_shape()
            .map_err(DatabaseError::to_invalid_operation)?;
        Ok(record)
    }

    async fn lock_head(
        &mut self,
        authority: &str,
        local_account_id: &str,
    ) -> Result<(), DatabaseError> {
        diesel::insert_into(account_status_ledger_heads::table)
            .values((
                account_status_ledger_heads::account_authority_id.eq(authority),
                account_status_ledger_heads::local_account_id.eq(local_account_id),
            ))
            .on_conflict_do_nothing()
            .execute(self.conn)
            .await?;
        account_status_ledger_heads::table
            .filter(account_status_ledger_heads::account_authority_id.eq(authority))
            .filter(account_status_ledger_heads::local_account_id.eq(local_account_id))
            .select(account_status_ledger_heads::local_account_id)
            .for_update()
            .first::<String>(self.conn)
            .await?;

        Ok(())
    }

    async fn current_locked(
        &mut self,
        authority: &str,
        local_account_id: &str,
    ) -> Result<Option<AccountStatusRecord>, DatabaseError> {
        let value = account_status_records::table
            .filter(account_status_records::account_authority_id.eq(authority))
            .filter(account_status_records::local_account_id.eq(local_account_id))
            .order(account_status_records::status_seq.desc())
            .select(account_status_records::record)
            .for_update()
            .first::<serde_json::Value>(self.conn)
            .await
            .optional()?;
        value.map(Self::decode).transpose()
    }
}

#[derive(Insertable)]
#[diesel(table_name = account_status_records)]
struct NewRecord {
    account_authority_id: String,
    local_account_id: String,
    status_seq: i64,
    record_id: String,
    record: serde_json::Value,
    issued_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
impl AccountStatusLedgerRepository for PgAccountStatusLedgerRepository<'_> {
    type Error = DatabaseError;

    async fn append(
        &mut self,
        local_account_id: &LocalAccountId,
        record: &AccountStatusRecord,
    ) -> Result<AccountStatusAppendOutcome, Self::Error> {
        record
            .validate_shape()
            .map_err(DatabaseError::to_invalid_operation)?;
        let existing = account_status_records::table
            .filter(account_status_records::record_id.eq(record.account_status_record_id.as_str()))
            .select(account_status_records::record)
            .first::<serde_json::Value>(self.conn)
            .await
            .optional()?;
        if let Some(existing) = existing {
            let existing = Self::decode(existing)?;
            return if existing.account_status_record_id == record.account_status_record_id {
                Ok(AccountStatusAppendOutcome::Duplicate)
            } else {
                Err(DatabaseError::invalid_operation())
            };
        }

        self.lock_head(
            record.account_authority_id.as_str(),
            local_account_id.as_str(),
        )
        .await?;

        let current = self
            .current_locked(
                record.account_authority_id.as_str(),
                local_account_id.as_str(),
            )
            .await?;
        if current
            .as_ref()
            .is_some_and(|head| head.account_status_record_id == record.account_status_record_id)
        {
            return Ok(AccountStatusAppendOutcome::Duplicate);
        }
        let is_next = match &current {
            None => record.status_seq == 1 && record.previous_account_status_record_id.is_none(),
            Some(head) => {
                record.status_seq == head.status_seq + 1
                    && record.previous_account_status_record_id.as_ref()
                        == Some(&head.account_status_record_id)
            }
        };
        if !is_next {
            return Ok(AccountStatusAppendOutcome::Conflict {
                current: current.map(Box::new),
            });
        }

        let status_seq = i64::try_from(record.status_seq)?;
        diesel::insert_into(account_status_records::table)
            .values(NewRecord {
                account_authority_id: record.account_authority_id.to_string(),
                local_account_id: local_account_id.to_string(),
                status_seq,
                record_id: record.account_status_record_id.to_string(),
                record: serde_json::to_value(record)?,
                issued_at: record.issued_at,
            })
            .execute(self.conn)
            .await?;
        diesel::update(
            account_status_ledger_heads::table
                .filter(
                    account_status_ledger_heads::account_authority_id
                        .eq(record.account_authority_id.as_str()),
                )
                .filter(
                    account_status_ledger_heads::local_account_id.eq(local_account_id.as_str()),
                ),
        )
        .set((
            account_status_ledger_heads::current_status_seq.eq(status_seq),
            account_status_ledger_heads::current_record_id
                .eq(record.account_status_record_id.as_str()),
        ))
        .execute(self.conn)
        .await?;
        Ok(AccountStatusAppendOutcome::Appended)
    }

    async fn append_with_issuer_source(
        &mut self,
        local_account_id: &LocalAccountId,
        record: &AccountStatusRecord,
        source: &serde_json::Value,
    ) -> Result<AccountStatusAppendOutcome, Self::Error> {
        if source.get("record_id").and_then(serde_json::Value::as_str)
            != Some(record.account_status_record_id.as_str())
        {
            return Err(DatabaseError::invalid_operation());
        }
        let result = self.append(local_account_id, record).await?;
        match &result {
            AccountStatusAppendOutcome::Appended => {
                let affected = diesel::update(
                    account_status_records::table
                        .filter(
                            account_status_records::account_authority_id
                                .eq(record.account_authority_id.as_str()),
                        )
                        .filter(
                            account_status_records::local_account_id.eq(local_account_id.as_str()),
                        )
                        .filter(
                            account_status_records::record_id
                                .eq(record.account_status_record_id.as_str()),
                        )
                        .filter(account_status_records::issuer_source.is_null()),
                )
                .set(account_status_records::issuer_source.eq(Some(source.clone())))
                .execute(self.conn)
                .await?;
                if affected != 1 {
                    return Err(DatabaseError::invalid_operation());
                }
            }
            AccountStatusAppendOutcome::Duplicate => {
                // Exact replay has to retain the ORIGINAL source, never mint a replacement.
                let held = self
                    .issuer_source(
                        record.account_authority_id.as_str(),
                        local_account_id.as_str(),
                        record.account_status_record_id.as_str(),
                    )
                    .await?;
                if held.as_ref() != Some(source) {
                    return Err(DatabaseError::invalid_operation());
                }
            }
            AccountStatusAppendOutcome::Conflict { .. } => {}
        }
        Ok(result)
    }

    async fn issuer_source(
        &mut self,
        authority: &str,
        local_account_id: &str,
        record_id: &str,
    ) -> Result<Option<serde_json::Value>, Self::Error> {
        let value = account_status_records::table
            .filter(account_status_records::account_authority_id.eq(authority))
            .filter(account_status_records::local_account_id.eq(local_account_id))
            .filter(account_status_records::record_id.eq(record_id))
            .select(account_status_records::issuer_source)
            .first::<Option<serde_json::Value>>(self.conn)
            .await
            .optional()?;
        Ok(value.flatten())
    }

    async fn current(
        &mut self,
        account_authority_id: &str,
        local_account_id: &str,
    ) -> Result<Option<AccountStatusRecord>, Self::Error> {
        self.current_locked(account_authority_id, local_account_id)
            .await
    }

    async fn current_for_gate(
        &mut self,
        account_authority_id: &str,
        local_account_id: &str,
    ) -> Result<Option<AccountStatusRecord>, Self::Error> {
        self.lock_head(account_authority_id, local_account_id)
            .await?;
        self.current_locked(account_authority_id, local_account_id)
            .await
    }

    async fn resolve(
        &mut self,
        account_authority_id: &str,
        local_account_id: &str,
        from_status_seq: u64,
        limit: u16,
    ) -> Result<Vec<AccountStatusRecord>, Self::Error> {
        let from = i64::try_from(from_status_seq)?;
        let values = account_status_records::table
            .filter(account_status_records::account_authority_id.eq(account_authority_id))
            .filter(account_status_records::local_account_id.eq(local_account_id))
            .filter(account_status_records::status_seq.ge(from))
            .order(account_status_records::status_seq.asc())
            .limit(i64::from(limit))
            .select(account_status_records::record)
            .load::<serde_json::Value>(self.conn)
            .await?;
        values.into_iter().map(Self::decode).collect()
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::account_lifecycle::{
        AccountStatusInitialPublication, AccountStatusPublication,
        AccountStatusPublicationRequestBody,
    };
    use arkret_models_collaboration::account_status::{
        AccountStatusRecord, UnsignedAccountStatusRecord,
    };
    use arkret_models_collaboration::objects::account_status::AccountStatus;
    use arkret_wire::{DidCoreId, DidUrl, Hash, SchemaId};
    use coauth_data::audit::{AdminOperation, AdminOperationFilter, NewAdminOperationLog};
    use coauth_data::queue::{AccountStatusPublicationJob, QueueJobRepositoryExt as _};
    use coauth_data::user::UserRepository as _;
    use coauth_data::{
        AccountStatusAppendOutcome, AccountStatusLedgerRepository as _, Clock as _,
        RepositoryAccess as _, RepositoryFactory as _,
    };
    use diesel::{ExpressionMethods as _, QueryDsl as _};
    use diesel_async::RunQueryDsl as _;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng as _;

    use crate::PgRepositoryFactory;
    use crate::schema::{queue_jobs, users};

    #[derive(Clone, Copy)]
    enum FailureAfter {
        Ledger,
        AccountRow,
        OutboxAndAudit,
    }

    fn genesis_record(now: chrono::DateTime<chrono::Utc>) -> AccountStatusRecord {
        let authority = DidCoreId::new("ak:did_core:webvh:zrollbackauthority").unwrap();
        let unsigned = UnsignedAccountStatusRecord {
            schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
            account_authority_id: authority,
            account_id: arkret_wire::AccountId {
                principal_id: DidCoreId::new("ak:did_core:webvh:zrollbackprincipal").unwrap(),
                station_id: DidCoreId::new("ak:did_core:webvh:zrollbackserver").unwrap(),
            },
            principal_control_realm_id: arkret_wire::RealmId::from_event_id(
                &arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x31; 32],
                ),
            ),
            binding_version: 1,
            status_seq: 1,
            previous_account_status_record_id: None,
            status: AccountStatus::Active,
            reason_code: None,
            reason: None,
            issued_at: now,
            effective_at: now,
            expires_at: None,
        };
        arkret_signatures::account_status::sign_account_status_record(
            unsigned,
            DidUrl::new("did:webvh:zrollbackauthority:auth.example#account-status-key").unwrap(),
            &crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[0x52; 32]),
        )
        .unwrap()
    }

    // Exercises the real PostgreSQL serialization point, including the empty
    // ledger case. A concurrent append must not invalidate a signed absence.
    #[tokio::test]
    async fn gate_stable_absence_blocks_first_append_until_transaction_finishes() {
        let pool = crate::test_utils::setup_test_pool()
            .await
            .expect("actual PostgreSQL required; no opt-out for gate regression");
        let factory = PgRepositoryFactory::new(pool.clone());
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let record = genesis_record(now);
        let local =
            coauth_data::LocalAccountId::new(format!("gate-empty-{}", uuid::Uuid::now_v7()))
                .unwrap();
        let mut gate = factory.create().await.unwrap();
        assert!(
            gate.account_status_ledger()
                .current_for_gate(record.account_authority_id.as_str(), local.as_str(),)
                .await
                .unwrap()
                .is_none()
        );
        let other_pool = pool.clone();
        let other_record = record.clone();
        let other_local = local.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut append = tokio::spawn(async move {
            let factory = PgRepositoryFactory::new(other_pool);
            let mut repo = factory.create().await.unwrap();
            started_tx.send(()).unwrap();
            let result = repo
                .account_status_ledger()
                .append(&other_local, &other_record)
                .await
                .unwrap();
            repo.save().await.unwrap();
            result
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut append)
                .await
                .is_err()
        );
        gate.save().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), append)
                .await
                .unwrap()
                .unwrap(),
            AccountStatusAppendOutcome::Appended
        ));
        let mut read = factory.create().await.unwrap();
        assert_eq!(
            read.account_status_ledger()
                .current_for_gate(record.account_authority_id.as_str(), local.as_str(),)
                .await
                .unwrap(),
            Some(record)
        );
        read.cancel().await.unwrap();
    }

    // Real durable reservation/commit replay after the ledger acquires a head.
    // This proves original canonical bytes remain available, not a re-mint.
    #[tokio::test]
    async fn gate_exact_signed_replay_survives_new_status_head_and_changed_intent_refuses() {
        use arkret_models_identity::agent_signer_evidence::{
            AgentDetachedJws, ControllerAccountEligibility, ControllerAccountGateAttestation,
            ControllerAccountGateBasis, ControllerAccountGateIssuanceResult,
            ControllerAccountStatus,
        };
        use coauth_data::account_handoff::{
            ControllerGateAttestationCommit, ControllerGateAttestationReserve,
            NewControllerGateAttestationIssuance,
        };
        let pool = crate::test_utils::setup_test_pool()
            .await
            .expect("actual PostgreSQL required; no opt-out for gate regression");
        let factory = PgRepositoryFactory::new(pool.clone());
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let record = genesis_record(now);
        let request_id = arkret_wire::RequestId::new_v7_at(now.timestamp_millis() as u64);
        let hash =
            |byte: u8| Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap();
        let intent = NewControllerGateAttestationIssuance {
            request_id: request_id.clone(),
            canonical_intent_digest: hash(1),
            principal_id: record.account_id.principal_id.clone(),
            agent_authority_id: record.account_authority_id.clone(),
            retained_until: now + chrono::Duration::days(7),
            now,
        };
        let basis = ControllerAccountGateBasis::AccountBindingDefault {
            binding_version: 1,
            binding_receipt_digest: hash(2),
        };
        let basis_digest = Hash::new(
            arkret_canonical::canonical_sha256(&serde_json::json!({
                "principal_id":intent.principal_id,"accepted_id":intent.agent_authority_id,
                "status":"active","basis":basis,
            }))
            .unwrap(),
        )
        .unwrap();
        let mut gate = ControllerAccountGateAttestation {
            schema: arkret_wire::NonEmptyString::new(
                SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1.to_owned(),
            )
            .unwrap(),
            principal_id: intent.principal_id.clone(),
            eligibility: ControllerAccountEligibility::Active,
            status: ControllerAccountStatus::Active,
            basis,
            basis_digest,
            authority_id: intent.agent_authority_id.clone(),
            verification_method: DidUrl::new(
                "did:webvh:zrollbackauthority:auth.example#account-authority",
            )
            .unwrap(),
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            proof: AgentDetachedJws {
                kind: arkret_wire::NonEmptyString::new("detached_jws".to_owned()).unwrap(),
                jws: arkret_wire::NonEmptyString::new("pending".to_owned()).unwrap(),
            },
        };
        let signer = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[0x52; 32]);
        arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
            &mut gate, &signer,
        )
        .unwrap();
        arkret_signatures::agent_evidence::verify_controller_account_gate_attestation(
            &gate,
            &intent.principal_id,
            &intent.agent_authority_id,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: signer.verifying_key().to_bytes().to_vec(),
            },
            now,
        )
        .unwrap();
        let expires = gate.expires_at;
        let bytes = arkret_canonical::canonical_json_bytes(&ControllerAccountGateIssuanceResult {
            request_id,
            controller_account_gate_attestation: gate,
        })
        .unwrap();
        let digest = Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap();
        let mut first = factory.create().await.unwrap();
        assert!(matches!(
            first
                .account_handoff()
                .reserve_controller_gate_attestation(intent.clone())
                .await
                .unwrap(),
            ControllerGateAttestationReserve::Reserved(_)
        ));
        assert!(matches!(
            first
                .account_handoff()
                .commit_controller_gate_attestation(
                    &intent.request_id,
                    &intent.canonical_intent_digest,
                    &bytes,
                    &digest,
                    expires,
                    now
                )
                .await
                .unwrap(),
            ControllerGateAttestationCommit::Committed(_)
        ));
        first.save().await.unwrap();
        let local =
            coauth_data::LocalAccountId::new(format!("gate-replay-{}", uuid::Uuid::now_v7()))
                .unwrap();
        let mut changed = factory.create().await.unwrap();
        assert!(matches!(
            changed
                .account_status_ledger()
                .append(&local, &record)
                .await
                .unwrap(),
            AccountStatusAppendOutcome::Appended
        ));
        changed.save().await.unwrap();
        let mut replay = factory.create().await.unwrap();
        let ControllerGateAttestationReserve::Replay(original) = replay
            .account_handoff()
            .reserve_controller_gate_attestation(intent.clone())
            .await
            .unwrap()
        else {
            panic!("exact accepted intent must replay");
        };
        assert_eq!(
            original.canonical_outcome.as_deref(),
            Some(bytes.as_slice())
        );
        assert!(
            replay
                .account_status_ledger()
                .current_for_gate(record.account_authority_id.as_str(), local.as_str())
                .await
                .unwrap()
                .is_some()
        );
        replay.cancel().await.unwrap();
        let mut wrong = factory.create().await.unwrap();
        let mut other = intent;
        other.canonical_intent_digest = hash(4);
        assert!(matches!(
            wrong
                .account_handoff()
                .reserve_controller_gate_attestation(other)
                .await
                .unwrap(),
            ControllerGateAttestationReserve::Conflict(_)
        ));
        wrong.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn account_status_transaction_rolls_back_at_every_post_write_failure_point() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = PgRepositoryFactory::new(pool.clone());
        let clock = coauth_data::clock::MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(0x625);
        let handle = format!(
            "account-status-rollback-{}",
            coauth_data::new_id(clock.now(), &mut rng)
        );

        let mut setup = factory.create().await.unwrap();
        let user = setup.user().add(&mut rng, &clock, handle).await.unwrap();
        setup.save().await.unwrap();

        let record = genesis_record(clock.now());
        let local_account_id = coauth_data::LocalAccountId::new(user.id.to_string()).unwrap();
        let body = AccountStatusPublicationRequestBody {
            publication: AccountStatusPublication::Initial(AccountStatusInitialPublication {
                record: record.clone(),
            }),
        };
        let body_digest = Hash::new(arkret_canonical::canonical_sha256(&body).unwrap()).unwrap();
        let idempotency_key = format!(
            "account-status-rollback:{}",
            record.account_status_record_id
        );

        for failure_after in [
            FailureAfter::Ledger,
            FailureAfter::AccountRow,
            FailureAfter::OutboxAndAudit,
        ] {
            let mut repo = factory.create().await.unwrap();
            assert!(matches!(
                repo.account_status_ledger()
                    .append(&local_account_id, &record,)
                    .await
                    .unwrap(),
                AccountStatusAppendOutcome::Appended
            ));

            if matches!(
                failure_after,
                FailureAfter::AccountRow | FailureAfter::OutboxAndAudit
            ) {
                let current = repo.user().lookup(user.id).await.unwrap().unwrap();
                repo.user().lock(&clock, current).await.unwrap();
            }

            if matches!(failure_after, FailureAfter::OutboxAndAudit) {
                repo.queue_job()
                    .schedule_job(
                        &mut rng,
                        &clock,
                        AccountStatusPublicationJob::new(
                            "station".to_owned(),
                            local_account_id.clone(),
                            idempotency_key.clone(),
                            body_digest.clone(),
                            body.clone(),
                        ),
                    )
                    .await
                    .unwrap();
                repo.audit()
                    .add_admin_operation(
                        &mut rng,
                        &clock,
                        NewAdminOperationLog::new(
                            user.id,
                            AdminOperation::UserUpdated,
                            "user",
                            serde_json::json!({"failure_injection": "after_outbox_and_audit"}),
                        )
                        .with_resource_id(user.id),
                    )
                    .await
                    .unwrap();
            }

            // Simulate the service returning an error before repo.save().
            repo.cancel().await.unwrap();

            let mut verify = factory.create().await.unwrap();
            assert!(
                verify
                    .account_status_ledger()
                    .current(
                        record.account_authority_id.as_str(),
                        local_account_id.as_str()
                    )
                    .await
                    .unwrap()
                    .is_none(),
                "issuer ledger must roll back"
            );
            assert_eq!(
                verify.user().lookup(user.id).await.unwrap().unwrap().status,
                AccountStatus::Active,
                "account row must roll back"
            );
            assert!(
                verify
                    .audit()
                    .list_admin_operations(
                        AdminOperationFilter::new()
                            .for_resource(user.id)
                            .with_limit(10)
                    )
                    .await
                    .unwrap()
                    .is_empty(),
                "audit write must roll back"
            );
            verify.cancel().await.unwrap();

            let mut conn = pool.get().await.unwrap();
            let payloads = queue_jobs::table
                .filter(queue_jobs::queue_name.eq("account-status-publication"))
                .select(queue_jobs::payload)
                .load::<serde_json::Value>(&mut conn)
                .await
                .unwrap();
            assert!(
                payloads.iter().all(|payload| {
                    payload
                        .get("idempotency_key")
                        .and_then(serde_json::Value::as_str)
                        != Some(idempotency_key.as_str())
                }),
                "publication outbox write must roll back"
            );
        }

        let mut conn = pool.get().await.unwrap();
        diesel::delete(users::table.filter(users::id.eq(uuid::Uuid::from(user.id))))
            .execute(&mut conn)
            .await
            .unwrap();
    }

    /// `account-lifecycle.md` §"at most one unfinished status update per destination": a
    /// destination may hold at most one unfinished publication per record. The
    /// partial unique index is the only thing enforcing it, and it enforces
    /// nothing unless its expressions actually resolve — a key that does not
    /// exist yields NULL, and NULLs are never unique-constrained.
    #[tokio::test]
    async fn one_destination_holds_at_most_one_pending_job_per_record() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = PgRepositoryFactory::new(pool.clone());
        let clock = coauth_data::clock::MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(0x626);
        let account_id = coauth_data::new_id(clock.now(), &mut rng);
        let record = genesis_record(clock.now());
        let local_account_id = coauth_data::LocalAccountId::new(account_id.to_string()).unwrap();
        let body = AccountStatusPublicationRequestBody {
            publication: AccountStatusPublication::Initial(AccountStatusInitialPublication {
                record: record.clone(),
            }),
        };
        let body_digest = Hash::new(arkret_canonical::canonical_sha256(&body).unwrap()).unwrap();
        let destination = format!("station-{account_id}");
        let mirror = format!("mirror-{account_id}");
        let record_id = record.account_status_record_id.to_string();

        let mut repo = factory.create().await.unwrap();
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                AccountStatusPublicationJob::new(
                    destination.clone(),
                    local_account_id.clone(),
                    format!("{record_id}:first"),
                    body_digest.clone(),
                    body.clone(),
                ),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        // The indexed expressions must resolve to real values; NULL keys would
        // make the unique index vacuous no matter how many jobs are inserted.
        let mut conn = pool.get().await.unwrap();
        let payloads = queue_jobs::table
            .filter(queue_jobs::queue_name.eq("account-status-publication"))
            .select(queue_jobs::payload)
            .load::<serde_json::Value>(&mut conn)
            .await
            .unwrap();
        let mut indexed: Vec<String> = Vec::new();
        for payload in &payloads {
            if payload["destination_name"] == serde_json::Value::String(destination.clone()) {
                indexed.push(payload["record_id"].as_str().unwrap_or_default().to_owned());
            }
        }
        assert_eq!(
            indexed,
            vec![record_id.clone()],
            "the queue payload must expose the record id the unique index reads"
        );

        // A second unfinished job for the same (destination, record) is refused
        // by the database, not merely by an in-process check.
        let mut duplicate = factory.create().await.unwrap();
        let outcome = duplicate
            .queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                AccountStatusPublicationJob::new(
                    destination.clone(),
                    local_account_id.clone(),
                    format!("{record_id}:second"),
                    body_digest.clone(),
                    body.clone(),
                ),
            )
            .await;
        assert!(
            outcome.is_err(),
            "a second pending publication for one destination + record must be rejected"
        );
        duplicate.cancel().await.unwrap();

        // A different destination for the same record stays legal.
        let mut other = factory.create().await.unwrap();
        other
            .queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                AccountStatusPublicationJob::new(
                    mirror.clone(),
                    local_account_id,
                    format!("{record_id}:mirror"),
                    body_digest.clone(),
                    body.clone(),
                ),
            )
            .await
            .unwrap();
        other.save().await.unwrap();

        let mut conn = pool.get().await.unwrap();
        let survivors = queue_jobs::table
            .filter(queue_jobs::queue_name.eq("account-status-publication"))
            .select(queue_jobs::payload)
            .load::<serde_json::Value>(&mut conn)
            .await
            .unwrap();
        let mut destinations: Vec<String> = Vec::new();
        for payload in &survivors {
            let name = payload["destination_name"].as_str().unwrap_or_default();
            if name == destination || name == mirror {
                destinations.push(name.to_owned());
            }
        }
        destinations.sort();
        let mut expected = vec![destination.clone(), mirror.clone()];
        expected.sort();
        assert_eq!(
            destinations, expected,
            "each destination keeps exactly one pending publication for the record"
        );

        diesel::delete(
            queue_jobs::table.filter(queue_jobs::queue_name.eq("account-status-publication")),
        )
        .execute(&mut conn)
        .await
        .unwrap();
    }
}
