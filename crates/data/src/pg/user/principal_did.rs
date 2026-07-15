use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::user::PrincipalDidRepository;
use coauth_data::{Clock, PrincipalDidBinding, User, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{principal_did_bindings, principal_did_owners};
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`PrincipalDidRepository`].
pub struct PgPrincipalDidRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgPrincipalDidRepository<'c> {
    /// Create a repository over an active connection.
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }

    async fn binding_query_for_user_and_audience(
        &mut self,
        user_id: Uuid,
        audience: &str,
    ) -> Result<Option<PrincipalDidBinding>, DatabaseError> {
        let row = principal_did_bindings::table
            .inner_join(principal_did_owners::table)
            .filter(principal_did_bindings::user_id.eq(user_id))
            .filter(principal_did_bindings::audience.eq(audience))
            .select(binding_selection())
            .first::<PrincipalDidJoinedRow>(self.conn)
            .await
            .optional()?;
        row.map(binding_from_row).transpose()
    }
}

type PrincipalDidJoinedRow = (
    Uuid,
    Uuid,
    String,
    String,
    String,
    String,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
);

fn binding_selection() -> (
    principal_did_bindings::id,
    principal_did_bindings::user_id,
    principal_did_bindings::audience,
    principal_did_owners::principal_id,
    principal_did_owners::key_log_head,
    principal_did_owners::enrollment_authority_did,
    principal_did_owners::enrollment_authority_ref,
    principal_did_bindings::created_at,
    principal_did_bindings::updated_at,
) {
    (
        principal_did_bindings::id,
        principal_did_bindings::user_id,
        principal_did_bindings::audience,
        principal_did_owners::principal_id,
        principal_did_owners::key_log_head,
        principal_did_owners::enrollment_authority_did,
        principal_did_owners::enrollment_authority_ref,
        principal_did_bindings::created_at,
        principal_did_bindings::updated_at,
    )
}

fn binding_from_row(row: PrincipalDidJoinedRow) -> Result<PrincipalDidBinding, DatabaseError> {
    let id = Ulid::from(row.0);
    let key_log_head = arkret_core::Hash::new(row.4).map_err(|error| {
        DatabaseInconsistencyError::on("principal_did_owners")
            .column("key_log_head")
            .row(id)
            .source(error)
    })?;
    let enrollment_authority_did = arkret_core::Did::new(row.5).map_err(|error| {
        DatabaseInconsistencyError::on("principal_did_owners")
            .column("enrollment_authority_did")
            .row(id)
            .source(error)
    })?;
    Ok(PrincipalDidBinding {
        id,
        user_id: Ulid::from(row.1),
        audience: row.2,
        principal_id: row.3,
        key_log_head,
        enrollment_authority_did,
        enrollment_authority_ref: row.6,
        created_at: row.7,
        updated_at: row.8,
    })
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = principal_did_owners)]
struct PrincipalDidOwnerLookup {
    id: Uuid,
    user_id: Uuid,
    key_log_head: String,
    enrollment_authority_did: String,
    enrollment_authority_ref: String,
}

#[derive(Insertable)]
#[diesel(table_name = principal_did_owners)]
struct NewPrincipalDidOwner {
    id: Uuid,
    user_id: Uuid,
    principal_id: String,
    key_log_head: String,
    enrollment_authority_did: String,
    enrollment_authority_ref: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = principal_did_bindings)]
struct NewPrincipalDidBinding {
    id: Uuid,
    principal_did_owner_id: Uuid,
    user_id: Uuid,
    audience: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl PrincipalDidRepository for PgPrincipalDidRepository<'_> {
    type Error = DatabaseError;

    async fn get_for_user_and_audience(
        &mut self,
        user: &User,
        audience: &str,
    ) -> Result<Option<PrincipalDidBinding>, Self::Error> {
        self.binding_query_for_user_and_audience(Uuid::from(user.id), audience)
            .await
    }

    async fn get_by_did(&mut self, did: &str) -> Result<Option<PrincipalDidBinding>, Self::Error> {
        let row = principal_did_bindings::table
            .inner_join(principal_did_owners::table)
            .filter(principal_did_owners::principal_id.eq(did))
            .order(principal_did_bindings::created_at.asc())
            .select(binding_selection())
            .first::<PrincipalDidJoinedRow>(self.conn)
            .await
            .optional()?;
        row.map(binding_from_row).transpose()
    }

    async fn get_by_did_and_audience(
        &mut self,
        did: &str,
        audience: &str,
    ) -> Result<Option<PrincipalDidBinding>, Self::Error> {
        let row = principal_did_bindings::table
            .inner_join(principal_did_owners::table)
            .filter(principal_did_owners::principal_id.eq(did))
            .filter(principal_did_bindings::audience.eq(audience))
            .select(binding_selection())
            .first::<PrincipalDidJoinedRow>(self.conn)
            .await
            .optional()?;
        row.map(binding_from_row).transpose()
    }

    async fn add_verified(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        audience: String,
        principal_id: String,
        key_log_head: arkret_core::Hash,
        enrollment_authority_did: arkret_core::Did,
        enrollment_authority_ref: String,
    ) -> Result<PrincipalDidBinding, Self::Error> {
        if audience.trim().is_empty()
            || principal_id.trim() != principal_id
            || arkret_core::Did::new(principal_id.clone()).is_err()
            || !enrollment_authority_ref
                .strip_prefix(&principal_id)
                .is_some_and(|fragment| fragment.starts_with('#') && fragment.len() > 1)
            || arkret_core::DidUrl::new(enrollment_authority_ref.clone()).is_err()
        {
            return Err(DatabaseError::invalid_operation());
        }

        if let Some(binding) = self
            .binding_query_for_user_and_audience(Uuid::from(user.id), &audience)
            .await?
            && binding.principal_id != principal_id
        {
            return Err(DatabaseError::invalid_operation());
        }

        let now = clock.now();
        let owner_id = new_id(now, rng);
        let owner_row = NewPrincipalDidOwner {
            id: Uuid::from(owner_id),
            user_id: Uuid::from(user.id),
            principal_id: principal_id.clone(),
            key_log_head: key_log_head.to_string(),
            enrollment_authority_did: enrollment_authority_did.as_str().to_owned(),
            enrollment_authority_ref: enrollment_authority_ref.clone(),
            created_at: now,
            updated_at: now,
        };
        diesel::insert_into(principal_did_owners::table)
            .values(owner_row)
            .on_conflict(principal_did_owners::principal_id)
            .do_nothing()
            .execute(self.conn)
            .await?;

        let owner = principal_did_owners::table
            .filter(principal_did_owners::principal_id.eq(&principal_id))
            .select(PrincipalDidOwnerLookup::as_select())
            .first::<PrincipalDidOwnerLookup>(self.conn)
            .await?;
        if owner.user_id != Uuid::from(user.id) {
            return Err(DatabaseError::invalid_operation());
        }

        if owner.enrollment_authority_did != enrollment_authority_did.as_str()
            || owner.enrollment_authority_ref != enrollment_authority_ref
        {
            return Err(DatabaseError::invalid_operation());
        }

        if owner.key_log_head != key_log_head.to_string() {
            diesel::update(
                principal_did_owners::table.filter(principal_did_owners::id.eq(owner.id)),
            )
            .set((
                principal_did_owners::key_log_head.eq(key_log_head.to_string()),
                principal_did_owners::updated_at.eq(now),
            ))
            .execute(self.conn)
            .await?;
        }

        let binding_row = NewPrincipalDidBinding {
            id: Uuid::from(new_id(now, rng)),
            principal_did_owner_id: owner.id,
            user_id: Uuid::from(user.id),
            audience: audience.clone(),
            created_at: now,
            updated_at: now,
        };
        diesel::insert_into(principal_did_bindings::table)
            .values(binding_row)
            .on_conflict_do_nothing()
            .execute(self.conn)
            .await?;

        let binding = self
            .binding_query_for_user_and_audience(Uuid::from(user.id), &audience)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if binding.principal_id != principal_id {
            return Err(DatabaseError::invalid_operation());
        }
        Ok(binding)
    }

    async fn remove_for_user_and_did(
        &mut self,
        user: &User,
        principal_id: &str,
    ) -> Result<(), Self::Error> {
        diesel::delete(
            principal_did_owners::table
                .filter(principal_did_owners::user_id.eq(Uuid::from(user.id)))
                .filter(principal_did_owners::principal_id.eq(principal_id)),
        )
        .execute(self.conn)
        .await?;
        Ok(())
    }
}
