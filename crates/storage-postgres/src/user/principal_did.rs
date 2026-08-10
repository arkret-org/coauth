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
    String,
    String,
    serde_json::Value,
    String,
    i64,
    String,
    serde_json::Value,
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
    principal_did_bindings::authority_instance,
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
        principal_did_bindings::authority_instance,
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
    let authority_instance: arkret_wire::PrincipalAuthorityInstance =
        serde_json::from_value(row.11).map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("authority_instance")
                .row(id)
                .source(error)
        })?;
    authority_instance.validate().map_err(|error| {
        DatabaseInconsistencyError::on("principal_did_bindings")
            .column("authority_instance")
            .row(id)
            .source(error)
    })?;
    Ok(PrincipalDidBinding {
        id,
        user_id: Ulid::from(row.1),
        audience: row.2,
        principal_id: row.3,
        key_log_head,
        verified_full_id: arkret_identifiers::DidFullId::new(row.5).map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("verified_full_id")
                .row(id)
                .source(error)
        })?,
        verified_version_id: row.6,
        binding_receipt: row.7,
        accepted_service_id: arkret_identifiers::DidCoreId::new(row.8).map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("accepted_service_id")
                .row(id)
                .source(error)
        })?,
        binding_version: u64::try_from(row.9).map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("binding_version")
                .row(id)
                .source(error)
        })?,
        binding_frontier_digest: arkret_identifiers::Hash::new(row.10).map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("binding_frontier_digest")
                .row(id)
                .source(error)
        })?,
        authority_instance,
        created_at: row.12,
        updated_at: row.13,
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
    verified_full_id: String,
    verified_version_id: String,
    binding_receipt: serde_json::Value,
    accepted_service_id: String,
    binding_version: i64,
    binding_frontier_digest: String,
    authority_instance: serde_json::Value,
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
            authority_instance,
        } = input;
        authority_instance
            .validate()
            .map_err(|_| DatabaseError::invalid_operation())?;
        let projected = arkret_identifiers::project_full_id_to_core_id(&verified_full_id)
            .map(arkret_identifiers::DidCoreId::from);
        let resolution_snapshot_is_valid = projected
            .is_ok_and(|projected| projected.as_str() == principal_id)
            && !verified_version_id.trim().is_empty()
            && binding_receipt.is_object()
            && binding_receipt
                .get("principal_id")
                .and_then(serde_json::Value::as_str)
                == Some(principal_id.as_str())
            && binding_receipt
                .get("full_id")
                .and_then(serde_json::Value::as_str)
                == Some(verified_full_id.as_str())
            && binding_receipt
                .get("did_version_id")
                .and_then(serde_json::Value::as_str)
                == Some(verified_version_id.as_str())
            && binding_receipt
                .get("head_event_digest")
                .and_then(serde_json::Value::as_str)
                == Some(key_log_head.as_str());
        if arkret_identifiers::DidCoreId::new(audience.clone()).is_err()
            || principal_id.trim() != principal_id
            || arkret_identifiers::DidCoreId::new(principal_id.clone()).is_err()
            || !resolution_snapshot_is_valid
            || binding_version < 1
            || accepted_service_id.as_str() != audience
            || authority_instance.principal_id.as_str() != principal_id
            || authority_instance.principal_server_id != accepted_service_id
        {
            return Err(DatabaseError::invalid_operation());
        }

        if let Some(binding) = self
            .binding_query_for_user_and_audience(Uuid::from(user.id), &audience)
            .await?
            && (binding.principal_id != principal_id
                || binding.authority_instance != authority_instance)
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
            verified_full_id: verified_full_id.to_string(),
            verified_version_id: verified_version_id.clone(),
            binding_receipt: binding_receipt.clone(),
            accepted_service_id: accepted_service_id.to_string(),
            binding_version: i64::try_from(binding_version)
                .map_err(|_| DatabaseError::invalid_operation())?,
            binding_frontier_digest: binding_frontier_digest.to_string(),
            authority_instance: serde_json::to_value(&authority_instance)
                .map_err(|_| DatabaseError::invalid_operation())?,
            created_at: now,
            updated_at: now,
        };
        diesel::insert_into(principal_did_bindings::table)
            .values(binding_row)
            .on_conflict((
                principal_did_bindings::principal_did_owner_id,
                principal_did_bindings::audience,
            ))
            .do_update()
            .set((
                principal_did_bindings::verified_full_id.eq(verified_full_id.to_string()),
                principal_did_bindings::verified_version_id.eq(verified_version_id),
                principal_did_bindings::binding_receipt.eq(binding_receipt),
                principal_did_bindings::accepted_service_id.eq(accepted_service_id.to_string()),
                principal_did_bindings::binding_version.eq(i64::try_from(binding_version)
                    .map_err(|_| DatabaseError::invalid_operation())?),
                principal_did_bindings::binding_frontier_digest
                    .eq(binding_frontier_digest.to_string()),
                principal_did_bindings::authority_instance
                    .eq(serde_json::to_value(&authority_instance)
                        .map_err(|_| DatabaseError::invalid_operation())?),
                principal_did_bindings::updated_at.eq(now),
            ))
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
