use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::user::{PrincipalDidRepository, VerifiedPrincipalDidBindingInput};
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
    Option<String>,
    Option<String>,
    Option<serde_json::Value>,
    Option<String>,
    Option<i64>,
    Option<String>,
    DateTime<Utc>,
    DateTime<Utc>,
);

fn binding_selection() -> (
    principal_did_bindings::id,
    principal_did_bindings::user_id,
    principal_did_bindings::audience,
    principal_did_owners::principal_id,
    principal_did_owners::key_log_head,
    principal_did_bindings::verified_full_id,
    principal_did_bindings::verified_version_id,
    principal_did_bindings::binding_receipt,
    principal_did_bindings::accepted_service_id,
    principal_did_bindings::binding_version,
    principal_did_bindings::binding_frontier_digest,
    principal_did_bindings::created_at,
    principal_did_bindings::updated_at,
) {
    (
        principal_did_bindings::id,
        principal_did_bindings::user_id,
        principal_did_bindings::audience,
        principal_did_owners::principal_id,
        principal_did_owners::key_log_head,
        principal_did_bindings::verified_full_id,
        principal_did_bindings::verified_version_id,
        principal_did_bindings::binding_receipt,
        principal_did_bindings::accepted_service_id,
        principal_did_bindings::binding_version,
        principal_did_bindings::binding_frontier_digest,
        principal_did_bindings::created_at,
        principal_did_bindings::updated_at,
    )
}

fn binding_from_row(row: PrincipalDidJoinedRow) -> Result<PrincipalDidBinding, DatabaseError> {
    let id = Ulid::from(row.0);
    let key_log_head = arkret_identifiers::Hash::new(row.4).map_err(|error| {
        DatabaseInconsistencyError::on("principal_did_owners")
            .column("key_log_head")
            .row(id)
            .source(error)
    })?;
    Ok(PrincipalDidBinding {
        id,
        user_id: Ulid::from(row.1),
        audience: row.2,
        principal_id: row.3,
        key_log_head,
        verified_full_id: row
            .5
            .map(arkret_identifiers::FullId::new)
            .transpose()
            .map_err(|error| {
                DatabaseInconsistencyError::on("principal_did_bindings")
                    .column("verified_full_id")
                    .row(id)
                    .source(error)
            })?,
        verified_version_id: row.6,
        binding_receipt: row.7,
        accepted_service_id: row
            .8
            .map(arkret_identifiers::ServiceId::new)
            .transpose()
            .map_err(|error| {
                DatabaseInconsistencyError::on("principal_did_bindings")
                    .column("accepted_service_id")
                    .row(id)
                    .source(error)
            })?,
        binding_version: row
            .9
            .map(|value| u64::try_from(value))
            .transpose()
            .map_err(|error| {
                DatabaseInconsistencyError::on("principal_did_bindings")
                    .column("binding_version")
                    .row(id)
                    .source(error)
            })?,
        binding_frontier_digest: row
            .10
            .map(arkret_identifiers::Hash::new)
            .transpose()
            .map_err(|error| {
                DatabaseInconsistencyError::on("principal_did_bindings")
                    .column("binding_frontier_digest")
                    .row(id)
                    .source(error)
            })?,
        created_at: row.11,
        updated_at: row.12,
    })
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = principal_did_owners)]
struct PrincipalDidOwnerLookup {
    id: Uuid,
    user_id: Uuid,
    key_log_head: String,
}

#[derive(Insertable)]
#[diesel(table_name = principal_did_owners)]
struct NewPrincipalDidOwner {
    id: Uuid,
    user_id: Uuid,
    principal_id: String,
    key_log_head: String,
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
    verified_full_id: Option<String>,
    verified_version_id: Option<String>,
    binding_receipt: Option<serde_json::Value>,
    accepted_service_id: Option<String>,
    binding_version: Option<i64>,
    binding_frontier_digest: Option<String>,
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
        input: VerifiedPrincipalDidBindingInput,
    ) -> Result<PrincipalDidBinding, Self::Error> {
        let VerifiedPrincipalDidBindingInput {
            audience,
            principal_id,
            key_log_head,
            verified_full_id,
            verified_version_id,
            binding_receipt,
            accepted_service_id,
            binding_version,
            binding_frontier_digest,
        } = input;
        let resolution_snapshot_is_valid = match (
            verified_full_id.as_ref(),
            verified_version_id.as_deref(),
            binding_receipt.as_ref(),
        ) {
            (None, None, None) => true,
            (Some(full_id), Some(version_id), Some(receipt)) => {
                let projected = arkret_identifiers::project_full_id_to_core_id(full_id)
                    .map(arkret_identifiers::PrincipalId::from);
                projected.is_ok_and(|projected| projected.as_str() == principal_id)
                    && !version_id.trim().is_empty()
                    && receipt.is_object()
                    && receipt
                        .get("principal_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(principal_id.as_str())
                    && receipt.get("full_id").and_then(serde_json::Value::as_str)
                        == Some(full_id.as_str())
                    && receipt
                        .get("did_version_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(version_id)
                    && receipt
                        .get("head_event_digest")
                        .and_then(serde_json::Value::as_str)
                        == Some(key_log_head.as_str())
            }
            _ => false,
        };
        if audience.trim().is_empty()
            || principal_id.trim() != principal_id
            || arkret_identifiers::PrincipalId::new(principal_id.clone()).is_err()
            || !resolution_snapshot_is_valid
            || (accepted_service_id.is_some()
                || binding_version.is_some()
                || binding_frontier_digest.is_some())
                && !(accepted_service_id.is_some()
                    && binding_version.is_some_and(|version| version >= 1)
                    && binding_frontier_digest.is_some())
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
            verified_full_id: verified_full_id.as_ref().map(ToString::to_string),
            verified_version_id: verified_version_id.clone(),
            binding_receipt: binding_receipt.clone(),
            accepted_service_id: accepted_service_id.as_ref().map(ToString::to_string),
            binding_version: binding_version
                .map(|value| i64::try_from(value))
                .transpose()
                .map_err(|_| DatabaseError::invalid_operation())?,
            binding_frontier_digest: binding_frontier_digest.as_ref().map(ToString::to_string),
            created_at: now,
            updated_at: now,
        };
        if verified_full_id.is_some() {
            diesel::insert_into(principal_did_bindings::table)
                .values(binding_row)
                .on_conflict((
                    principal_did_bindings::principal_did_owner_id,
                    principal_did_bindings::audience,
                ))
                .do_update()
                .set((
                    principal_did_bindings::verified_full_id
                        .eq(verified_full_id.map(|value| value.to_string())),
                    principal_did_bindings::verified_version_id.eq(verified_version_id),
                    principal_did_bindings::binding_receipt.eq(binding_receipt),
                    principal_did_bindings::accepted_service_id
                        .eq(accepted_service_id.map(|value| value.to_string())),
                    principal_did_bindings::binding_version.eq(binding_version
                        .map(|value| i64::try_from(value))
                        .transpose()
                        .map_err(|_| DatabaseError::invalid_operation())?),
                    principal_did_bindings::binding_frontier_digest
                        .eq(binding_frontier_digest.map(|value| value.to_string())),
                    principal_did_bindings::updated_at.eq(now),
                ))
                .execute(self.conn)
                .await?;
        } else {
            // Legacy/admin callers can establish a binding but cannot erase a
            // protocol registration snapshot on an idempotent hit.
            diesel::insert_into(principal_did_bindings::table)
                .values(binding_row)
                .on_conflict_do_nothing()
                .execute(self.conn)
                .await?;
        }

        let binding = self
            .binding_query_for_user_and_audience(Uuid::from(user.id), &audience)
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
        if binding.principal_id != principal_id {
            return Err(DatabaseError::invalid_operation());
        }
        Ok(binding)
    }

    async fn remove_for_user_and_core(
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
