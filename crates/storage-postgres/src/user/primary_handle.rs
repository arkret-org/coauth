//! PostgreSQL implementation of the primary-handle preference repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::user::UserPrimaryHandlePreferenceRepository;
use coauth_data::{
    Clock, NewUserPrimaryHandlePreference, UserPrimaryHandlePreference, VerifiedUserHandleClaim,
    new_id,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::{handle_audit_log, user_primary_handle_preferences};

/// PostgreSQL implementation of [`UserPrimaryHandlePreferenceRepository`].
pub struct PgUserPrimaryHandlePreferenceRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserPrimaryHandlePreferenceRepository<'c> {
    /// Create a new repository from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_primary_handle_preferences)]
struct UserPrimaryHandlePreferenceRow {
    id: Uuid,
    user_id: Uuid,
    handle: Option<String>,
    effective_at: DateTime<Utc>,
    replaced_at: Option<DateTime<Utc>>,
    source_claim_id: Option<Uuid>,
    actor_user_id: Option<Uuid>,
    source: String,
    created_at: DateTime<Utc>,
}

impl From<UserPrimaryHandlePreferenceRow> for UserPrimaryHandlePreference {
    fn from(value: UserPrimaryHandlePreferenceRow) -> Self {
        Self {
            id: value.id.into(),
            user_id: value.user_id.into(),
            handle: value.handle,
            effective_at: value.effective_at,
            replaced_at: value.replaced_at,
            source_claim_id: value.source_claim_id.map(Into::into),
            actor_user_id: value.actor_user_id.map(Into::into),
            source: value.source,
            created_at: value.created_at,
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = user_primary_handle_preferences)]
struct InsertableUserPrimaryHandlePreference {
    id: Uuid,
    user_id: Uuid,
    handle: Option<String>,
    effective_at: DateTime<Utc>,
    replaced_at: Option<DateTime<Utc>>,
    source_claim_id: Option<Uuid>,
    actor_user_id: Option<Uuid>,
    source: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = handle_audit_log)]
struct HandleClaimAuditRow {
    id: Uuid,
    user_id: Option<Uuid>,
    event_type: String,
    handle: Option<String>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl UserPrimaryHandlePreferenceRepository for PgUserPrimaryHandlePreferenceRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_primary_handle_preference.current",
        skip_all,
        fields(user.id = %user_id),
        err,
    )]
    async fn current(
        &mut self,
        user_id: Ulid,
    ) -> Result<Option<UserPrimaryHandlePreference>, Self::Error> {
        user_primary_handle_preferences::table
            .filter(user_primary_handle_preferences::user_id.eq(Uuid::from(user_id)))
            .filter(user_primary_handle_preferences::replaced_at.is_null())
            .order(user_primary_handle_preferences::effective_at.desc())
            .select(UserPrimaryHandlePreferenceRow::as_select())
            .first::<UserPrimaryHandlePreferenceRow>(self.conn)
            .await
            .optional()
            .map(|row| row.map(Into::into))
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.user_primary_handle_preference.at",
        skip_all,
        fields(user.id = %user_id, %as_of),
        err,
    )]
    async fn at(
        &mut self,
        user_id: Ulid,
        as_of: DateTime<Utc>,
    ) -> Result<Option<UserPrimaryHandlePreference>, Self::Error> {
        user_primary_handle_preferences::table
            .filter(user_primary_handle_preferences::user_id.eq(Uuid::from(user_id)))
            .filter(user_primary_handle_preferences::effective_at.le(as_of))
            .filter(
                user_primary_handle_preferences::replaced_at
                    .is_null()
                    .or(user_primary_handle_preferences::replaced_at.gt(as_of)),
            )
            .order(user_primary_handle_preferences::effective_at.desc())
            .select(UserPrimaryHandlePreferenceRow::as_select())
            .first::<UserPrimaryHandlePreferenceRow>(self.conn)
            .await
            .optional()
            .map(|row| row.map(Into::into))
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.user_primary_handle_preference.verified_handle_claim",
        skip_all,
        fields(user.id = %user_id, handle),
        err,
    )]
    async fn verified_handle_claim(
        &mut self,
        user_id: Ulid,
        handle: &str,
        as_of: DateTime<Utc>,
    ) -> Result<Option<VerifiedUserHandleClaim>, Self::Error> {
        let row = handle_audit_log::table
            .filter(handle_audit_log::handle.eq(Some(handle.to_owned())))
            .filter(handle_audit_log::created_at.le(as_of))
            .filter(handle_audit_log::event_type.eq_any([
                "claim_issued",
                "revoked",
                "claim_expired",
                "reassigned",
            ]))
            .order(handle_audit_log::created_at.desc())
            .select(HandleClaimAuditRow::as_select())
            .first::<HandleClaimAuditRow>(self.conn)
            .await
            .optional()?;

        let Some(row) = row else {
            return Ok(None);
        };
        if row.event_type != "claim_issued" || row.user_id != Some(Uuid::from(user_id)) {
            return Ok(None);
        }

        let Some(handle) = row.handle else {
            return Ok(None);
        };

        Ok(Some(VerifiedUserHandleClaim {
            id: row.id.into(),
            user_id,
            handle,
            issued_at: row.created_at,
        }))
    }

    #[tracing::instrument(
        name = "db.user_primary_handle_preference.set",
        skip_all,
        fields(user.id = %params.user_id),
        err,
    )]
    async fn set(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewUserPrimaryHandlePreference,
    ) -> Result<UserPrimaryHandlePreference, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);

        diesel::update(
            user_primary_handle_preferences::table
                .filter(user_primary_handle_preferences::user_id.eq(Uuid::from(params.user_id)))
                .filter(user_primary_handle_preferences::replaced_at.is_null()),
        )
        .set(user_primary_handle_preferences::replaced_at.eq(Some(now)))
        .execute(self.conn)
        .await?;

        let row = InsertableUserPrimaryHandlePreference {
            id: Uuid::from(id),
            user_id: Uuid::from(params.user_id),
            handle: params.handle,
            effective_at: now,
            replaced_at: None,
            source_claim_id: params.source_claim_id.map(Uuid::from),
            actor_user_id: params.actor_user_id.map(Uuid::from),
            source: params.source,
            created_at: now,
        };

        diesel::insert_into(user_primary_handle_preferences::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(UserPrimaryHandlePreference {
            id,
            user_id: params.user_id,
            handle: row.handle,
            effective_at: row.effective_at,
            replaced_at: row.replaced_at,
            source_claim_id: row.source_claim_id.map(Into::into),
            actor_user_id: row.actor_user_id.map(Into::into),
            source: row.source,
            created_at: row.created_at,
        })
    }
}
