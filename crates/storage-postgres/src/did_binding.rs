//! PostgreSQL implementation of the durable accepted-DID-binding repository
//! (`did-usage-and-verification.md` §5).
//!
//! # Hard expiry
//!
//! §5 distinguishes *stale* (past `refresh_after`; still readable) from
//! *hard-expired* (past `expires_at`; gone for readers). Only the second one is
//! visible at this layer, and it is enforced **in the query**: [`get`] filters
//! on `expires_at`, so an expired row can never be handed back even if it is
//! still physically present.
//!
//! Physical removal is lazy: every [`upsert`] first deletes rows that are
//! already hard-expired, exactly like `PgDpopReplayRepository::consume_jti`
//! prunes its replay window. That keeps the table bounded without a background
//! job, and [`prune_expired`] is available for an operator or a scheduled task
//! that wants to force the sweep. The two mechanisms are redundant on purpose:
//! correctness never depends on the sweep having run.
//!
//! [`get`]: VerifiedDidBindingRepository::get
//! [`upsert`]: VerifiedDidBindingRepository::upsert
//! [`prune_expired`]: VerifiedDidBindingRepository::prune_expired

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::did_binding::{
    VerifiedDidBindingInvalidation, VerifiedDidBindingKeyColumns, VerifiedDidBindingRepository,
    VerifiedDidBindingRow,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::DatabaseError;
use crate::schema::verified_did_bindings;

/// Sentinel for an absent optional key dimension.
///
/// A PostgreSQL primary key cannot contain `NULL`, and both optional
/// dimensions (`verification_method`, `version_id`) are part of the key.
/// Neither a DID URL nor a method version identifier can be the empty string,
/// so the empty string is a free, unambiguous encoding of "absent".
const ABSENT: &str = "";

fn column(value: Option<&String>) -> &str {
    value.map_or(ABSENT, String::as_str)
}

fn optional(value: String) -> Option<String> {
    (value != ABSENT).then_some(value)
}

/// PostgreSQL implementation of [`VerifiedDidBindingRepository`].
pub struct PgVerifiedDidBindingRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgVerifiedDidBindingRepository<'c> {
    /// Construct from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = verified_did_bindings)]
struct VerifiedDidBindingRecord {
    did: String,
    trust_domain: String,
    purpose: String,
    policy_digest: String,
    verification_method: String,
    version_id: String,
    history_head: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    accepted: serde_json::Value,
}

impl From<VerifiedDidBindingRecord> for VerifiedDidBindingRow {
    fn from(record: VerifiedDidBindingRecord) -> Self {
        Self {
            key: VerifiedDidBindingKeyColumns {
                did: record.did,
                trust_domain: record.trust_domain,
                purpose: record.purpose,
                policy_digest: record.policy_digest,
                verification_method: optional(record.verification_method),
                version_id: optional(record.version_id),
            },
            history_head: record.history_head,
            expires_at: record.expires_at,
            accepted: record.accepted,
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = verified_did_bindings)]
struct InsertableVerifiedDidBinding {
    did: String,
    trust_domain: String,
    purpose: String,
    policy_digest: String,
    verification_method: String,
    version_id: String,
    history_head: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    accepted: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl VerifiedDidBindingRepository for PgVerifiedDidBindingRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.verified_did_binding.get", skip_all, err)]
    async fn get(
        &mut self,
        key: &VerifiedDidBindingKeyColumns,
        now: DateTime<Utc>,
    ) -> Result<Option<VerifiedDidBindingRow>, Self::Error> {
        let record = verified_did_bindings::table
            .filter(verified_did_bindings::did.eq(&key.did))
            .filter(verified_did_bindings::trust_domain.eq(&key.trust_domain))
            .filter(verified_did_bindings::purpose.eq(&key.purpose))
            .filter(verified_did_bindings::policy_digest.eq(&key.policy_digest))
            .filter(
                verified_did_bindings::verification_method
                    .eq(column(key.verification_method.as_ref())),
            )
            .filter(verified_did_bindings::version_id.eq(column(key.version_id.as_ref())))
            // Hard expiry is enforced here, not by the caller: `expires_at`
            // in the past means the acceptance no longer exists for readers.
            .filter(
                verified_did_bindings::expires_at
                    .is_null()
                    .or(verified_did_bindings::expires_at.ge(now)),
            )
            .select(VerifiedDidBindingRecord::as_select())
            .first::<VerifiedDidBindingRecord>(self.conn)
            .await
            .optional()?;
        Ok(record.map(Into::into))
    }

    #[tracing::instrument(name = "db.verified_did_binding.upsert", skip_all, err)]
    async fn upsert(
        &mut self,
        row: VerifiedDidBindingRow,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        // Lazy prune, same pattern as the DPoP replay window: the table stays
        // bounded without a background job, and correctness does not depend on
        // this having run (reads filter on `expires_at` anyway).
        diesel::delete(
            verified_did_bindings::table.filter(verified_did_bindings::expires_at.lt(now)),
        )
        .execute(self.conn)
        .await?;

        let record = InsertableVerifiedDidBinding {
            did: row.key.did,
            trust_domain: row.key.trust_domain,
            purpose: row.key.purpose,
            policy_digest: row.key.policy_digest,
            verification_method: row
                .key
                .verification_method
                .unwrap_or_else(|| ABSENT.to_owned()),
            version_id: row.key.version_id.unwrap_or_else(|| ABSENT.to_owned()),
            history_head: row.history_head,
            expires_at: row.expires_at,
            accepted: row.accepted,
            created_at: now,
            updated_at: now,
        };

        diesel::insert_into(verified_did_bindings::table)
            .values(&record)
            .on_conflict((
                verified_did_bindings::did,
                verified_did_bindings::trust_domain,
                verified_did_bindings::purpose,
                verified_did_bindings::policy_digest,
                verified_did_bindings::verification_method,
                verified_did_bindings::version_id,
            ))
            .do_update()
            .set((
                verified_did_bindings::history_head.eq(record.history_head.clone()),
                verified_did_bindings::expires_at.eq(record.expires_at),
                verified_did_bindings::accepted.eq(record.accepted.clone()),
                verified_did_bindings::updated_at.eq(now),
            ))
            .execute(self.conn)
            .await?;
        Ok(())
    }

    #[tracing::instrument(name = "db.verified_did_binding.invalidate", skip_all, err)]
    async fn invalidate(
        &mut self,
        selector: &VerifiedDidBindingInvalidation,
    ) -> Result<usize, Self::Error> {
        // An unconstrained selector matches nothing. There is deliberately no
        // catch-all wipe: "rotate this key" must never be able to degenerate
        // into "distrust everything".
        if selector.is_empty() {
            return Ok(0);
        }

        let mut query = diesel::delete(verified_did_bindings::table).into_boxed();
        if let Some(did) = &selector.did {
            query = query.filter(verified_did_bindings::did.eq(did));
        }
        if let Some(verification_method) = &selector.verification_method {
            // The sentinel row (no pinned method) can never equal a real DID
            // URL, so it is correctly left alone.
            query =
                query.filter(verified_did_bindings::verification_method.eq(verification_method));
        }
        if let Some(history_head) = &selector.history_head {
            query = query.filter(verified_did_bindings::history_head.eq(history_head));
        }
        if let Some(trust_domain) = &selector.trust_domain {
            query = query.filter(verified_did_bindings::trust_domain.eq(trust_domain));
        }
        if let Some(purpose) = &selector.purpose {
            query = query.filter(verified_did_bindings::purpose.eq(purpose));
        }
        if let Some(policy_digest) = &selector.policy_digest {
            query = query.filter(verified_did_bindings::policy_digest.eq(policy_digest));
        }
        Ok(query.execute(self.conn).await?)
    }

    #[tracing::instrument(name = "db.verified_did_binding.prune_expired", skip_all, err)]
    async fn prune_expired(&mut self, now: DateTime<Utc>) -> Result<usize, Self::Error> {
        Ok(diesel::delete(
            verified_did_bindings::table.filter(verified_did_bindings::expires_at.lt(now)),
        )
        .execute(self.conn)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};

    use super::*;
    use crate::PgRepositoryFactory;

    fn key(label: &str) -> VerifiedDidBindingKeyColumns {
        VerifiedDidBindingKeyColumns {
            did: format!("did:web:{label}.example"),
            trust_domain: "ak:trust_domain:auth.example".to_owned(),
            purpose: "principal".to_owned(),
            policy_digest: format!("sha256:{}", "ab".repeat(32)),
            verification_method: None,
            version_id: None,
        }
    }

    fn row(label: &str, expires_at: Option<DateTime<Utc>>) -> VerifiedDidBindingRow {
        VerifiedDidBindingRow {
            key: key(label),
            history_head: Some(format!("sha256:{}", "cd".repeat(32))),
            expires_at,
            accepted: serde_json::json!({"label": label}),
        }
    }

    fn unique_label(prefix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is after unix epoch")
            .as_nanos();
        format!("{prefix}-{nanos}")
    }

    #[tokio::test]
    async fn round_trips_and_upserts_on_the_six_dimension_key() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let now = Utc::now();
        let label = unique_label("roundtrip");

        repo.verified_did_binding()
            .upsert(row(&label, Some(now + Duration::hours(24))), now)
            .await
            .unwrap();
        let stored = repo
            .verified_did_binding()
            .get(&key(&label), now)
            .await
            .unwrap()
            .expect("row is readable");
        assert_eq!(stored.key, key(&label));
        assert_eq!(stored.accepted, serde_json::json!({"label": label}));

        // Same key, new payload -> replace, not duplicate.
        let mut updated = row(&label, Some(now + Duration::hours(24)));
        updated.accepted = serde_json::json!({"label": label, "generation": 2});
        repo.verified_did_binding()
            .upsert(updated, now)
            .await
            .unwrap();
        let stored = repo
            .verified_did_binding()
            .get(&key(&label), now)
            .await
            .unwrap()
            .expect("row is still readable");
        assert_eq!(stored.accepted["generation"], serde_json::json!(2));

        repo.verified_did_binding()
            .invalidate(&VerifiedDidBindingInvalidation {
                did: Some(key(&label).did),
                ..VerifiedDidBindingInvalidation::default()
            })
            .await
            .unwrap();
        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn a_hard_expired_row_is_never_read_back() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let now = Utc::now();
        let label = unique_label("expired");

        repo.verified_did_binding()
            .upsert(row(&label, Some(now + Duration::minutes(5))), now)
            .await
            .unwrap();
        let later = now + Duration::minutes(6);
        assert!(
            repo.verified_did_binding()
                .get(&key(&label), later)
                .await
                .unwrap()
                .is_none(),
            "a hard-expired acceptance must not be readable"
        );
        assert!(
            repo.verified_did_binding()
                .prune_expired(later)
                .await
                .unwrap()
                >= 1
        );
        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn an_empty_selector_deletes_nothing() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = PgRepositoryFactory::new(pool).create().await.unwrap();
        let now = Utc::now();
        let label = unique_label("empty-selector");

        repo.verified_did_binding()
            .upsert(row(&label, Some(now + Duration::hours(24))), now)
            .await
            .unwrap();
        assert_eq!(
            repo.verified_did_binding()
                .invalidate(&VerifiedDidBindingInvalidation::default())
                .await
                .unwrap(),
            0,
            "an unconstrained selector must not be a table wipe"
        );
        assert!(
            repo.verified_did_binding()
                .get(&key(&label), now)
                .await
                .unwrap()
                .is_some()
        );

        // A constrained selector on another dimension still misses this row.
        assert_eq!(
            repo.verified_did_binding()
                .invalidate(&VerifiedDidBindingInvalidation {
                    did: Some(key(&label).did),
                    purpose: Some("admin_action".to_owned()),
                    ..VerifiedDidBindingInvalidation::default()
                })
                .await
                .unwrap(),
            0,
            "invalidating one purpose must not clear another"
        );

        assert_eq!(
            repo.verified_did_binding()
                .invalidate(&VerifiedDidBindingInvalidation {
                    did: Some(key(&label).did),
                    ..VerifiedDidBindingInvalidation::default()
                })
                .await
                .unwrap(),
            1
        );
        repo.cancel().await.unwrap();
    }
}
