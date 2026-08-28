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
            .select(PrincipalDidJoinedRow::as_select())
            .first::<PrincipalDidJoinedRow>(self.conn)
            .await
            .optional()?;
        row.map(binding_from_row).transpose()
    }
}

#[derive(Debug, Queryable, Selectable)]
struct PrincipalDidJoinedRow {
    #[diesel(select_expression = principal_did_bindings::id)]
    id: Uuid,
    #[diesel(select_expression = principal_did_bindings::user_id)]
    user_id: Uuid,
    #[diesel(select_expression = principal_did_bindings::audience)]
    audience: arkret_identifiers::DidCoreId,
    #[diesel(select_expression = principal_did_owners::principal_id)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(select_expression = principal_did_owners::key_log_head)]
    key_log_head: String,
    #[diesel(select_expression = principal_did_bindings::verified_did)]
    verified_did: String,
    #[diesel(select_expression = principal_did_bindings::verified_version_id)]
    verified_version_id: String,
    #[diesel(select_expression = principal_did_bindings::binding_receipt)]
    binding_receipt: serde_json::Value,
    #[diesel(select_expression = principal_did_bindings::accepted_service_id)]
    accepted_service_id: arkret_identifiers::DidCoreId,
    #[diesel(select_expression = principal_did_bindings::binding_version)]
    binding_version: i64,
    #[diesel(select_expression = principal_did_bindings::binding_frontier_digest)]
    binding_frontier_digest: String,
    #[diesel(select_expression = principal_did_bindings::principal_authority)]
    principal_authority: serde_json::Value,
    #[diesel(select_expression = principal_did_bindings::principal_control_realm_id)]
    principal_control_realm_id: String,
    #[diesel(select_expression = principal_did_bindings::created_at)]
    created_at: DateTime<Utc>,
    #[diesel(select_expression = principal_did_bindings::updated_at)]
    updated_at: DateTime<Utc>,
}

fn binding_from_row(row: PrincipalDidJoinedRow) -> Result<PrincipalDidBinding, DatabaseError> {
    let id = Ulid::from(row.id);
    let key_log_head = arkret_identifiers::Hash::new(row.key_log_head).map_err(|error| {
        DatabaseInconsistencyError::on("principal_did_owners")
            .column("key_log_head")
            .row(id)
            .source(error)
    })?;
    let principal_authority: arkret_wire::PrincipalAuthorityKey =
        serde_json::from_value(row.principal_authority).map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("principal_authority")
                .row(id)
                .source(error)
        })?;
    principal_authority.validate().map_err(|error| {
        DatabaseInconsistencyError::on("principal_did_bindings")
            .column("principal_authority")
            .row(id)
            .source(error)
    })?;
    let binding_receipt: arkret_models_identity::AccountBindingReceipt =
        serde_json::from_value(row.binding_receipt).map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("binding_receipt")
                .row(id)
                .source(error)
        })?;
    binding_receipt.validate_shape().map_err(|error| {
        DatabaseInconsistencyError::on("principal_did_bindings")
            .column("binding_receipt")
            .row(id)
            .source(error)
    })?;
    Ok(PrincipalDidBinding {
        id,
        user_id: Ulid::from(row.user_id),
        audience: row.audience,
        principal_id: row.principal_id,
        key_log_head,
        verified_did: arkret_identifiers::Did::new(row.verified_did).map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("verified_did")
                .row(id)
                .source(error)
        })?,
        verified_version_id: row.verified_version_id,
        binding_receipt,
        accepted_service_id: row.accepted_service_id,
        binding_version: u64::try_from(row.binding_version).map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("binding_version")
                .row(id)
                .source(error)
        })?,
        binding_frontier_digest: arkret_identifiers::Hash::new(row.binding_frontier_digest)
            .map_err(|error| {
                DatabaseInconsistencyError::on("principal_did_bindings")
                    .column("binding_frontier_digest")
                    .row(id)
                    .source(error)
            })?,
        principal_authority,
        principal_control_realm_id: arkret_identifiers::RealmId::new(
            row.principal_control_realm_id,
        )
        .map_err(|error| {
            DatabaseInconsistencyError::on("principal_did_bindings")
                .column("principal_control_realm_id")
                .row(id)
                .source(error)
        })?,
        created_at: row.created_at,
        updated_at: row.updated_at,
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
    principal_id: arkret_identifiers::DidCoreId,
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
    audience: arkret_identifiers::DidCoreId,
    verified_did: String,
    verified_version_id: String,
    binding_receipt: serde_json::Value,
    accepted_service_id: arkret_identifiers::DidCoreId,
    binding_version: i64,
    binding_frontier_digest: String,
    principal_authority: serde_json::Value,
    principal_control_realm_id: String,
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
            .select(PrincipalDidJoinedRow::as_select())
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
            .select(PrincipalDidJoinedRow::as_select())
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
            verified_did,
            verified_version_id,
            binding_receipt,
            accepted_service_id,
            binding_version,
            binding_frontier_digest,
            principal_authority,
            principal_control_realm_id,
        } = input;
        principal_authority
            .validate()
            .map_err(|_| DatabaseError::invalid_operation())?;
        let projected = arkret_identifiers::project_did_to_core_id(&verified_did);
        let resolution_snapshot_is_valid = projected
            .is_ok_and(|projected| projected == principal_id)
            && !verified_version_id.trim().is_empty()
            && binding_receipt.validate_shape().is_ok()
            && binding_receipt.principal_id == principal_id
            && binding_receipt.did == verified_did
            && binding_receipt.did_version_id == verified_version_id
            && binding_receipt.head_event_digest == key_log_head;
        if !resolution_snapshot_is_valid
            || binding_version < 1
            || accepted_service_id != audience
            || principal_authority.principal_id != principal_id
            || principal_authority.principal_server_id != accepted_service_id
        {
            return Err(DatabaseError::invalid_operation());
        }

        if let Some(binding) = self
            .binding_query_for_user_and_audience(Uuid::from(user.id), audience.as_str())
            .await?
            && (binding.principal_id != principal_id
                || binding.principal_authority != principal_authority)
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
            verified_did: verified_did.to_string(),
            verified_version_id: verified_version_id.clone(),
            binding_receipt: serde_json::to_value(&binding_receipt)
                .map_err(|_| DatabaseError::invalid_operation())?,
            accepted_service_id: accepted_service_id.clone(),
            binding_version: i64::try_from(binding_version)
                .map_err(|_| DatabaseError::invalid_operation())?,
            binding_frontier_digest: binding_frontier_digest.to_string(),
            principal_authority: serde_json::to_value(&principal_authority)
                .map_err(|_| DatabaseError::invalid_operation())?,
            principal_control_realm_id: principal_control_realm_id.to_string(),
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
                principal_did_bindings::verified_did.eq(verified_did.to_string()),
                principal_did_bindings::verified_version_id.eq(verified_version_id),
                principal_did_bindings::binding_receipt.eq(serde_json::to_value(&binding_receipt)
                    .map_err(|_| DatabaseError::invalid_operation())?),
                principal_did_bindings::accepted_service_id.eq(&accepted_service_id),
                principal_did_bindings::binding_version.eq(i64::try_from(binding_version)
                    .map_err(|_| DatabaseError::invalid_operation())?),
                principal_did_bindings::binding_frontier_digest
                    .eq(binding_frontier_digest.to_string()),
                principal_did_bindings::principal_authority
                    .eq(serde_json::to_value(&principal_authority)
                        .map_err(|_| DatabaseError::invalid_operation())?),
                principal_did_bindings::principal_control_realm_id
                    .eq(principal_control_realm_id.to_string()),
                principal_did_bindings::updated_at.eq(now),
            ))
            .execute(self.conn)
            .await?;

        let binding = self
            .binding_query_for_user_and_audience(Uuid::from(user.id), audience.as_str())
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
