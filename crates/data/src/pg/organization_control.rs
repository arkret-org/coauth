//! PostgreSQL implementation of the organization principal control +
//! organization delegation repository.

use arkret_core::models::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::organization_control::{
    NewOrganizationDelegation, NewOrganizationPrincipalControl, OrganizationBootstrapAuthorization,
    OrganizationControlRepository, OrganizationDelegation, OrganizationDelegationStatus,
    OrganizationPrincipalControl,
};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{organization_delegations, organization_principal_controls};
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`OrganizationControlRepository`].
pub struct PgOrganizationControlRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOrganizationControlRepository<'c> {
    /// Construct from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

// ── organization_principal_controls ──────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = organization_principal_controls)]
struct ControlRow {
    id: Uuid,
    organization_did: String,
    principal_control_realm_id: String,
    control_stream_ref: Option<String>,
    pcr_frontier_digest: Option<String>,
    bootstrap_authorization: String,
    bootstrap_delegation_ref: Option<String>,
    executed_by: Option<String>,
    bootstrap_proof_digest: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<ControlRow> for OrganizationPrincipalControl {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: ControlRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let bootstrap_authorization = OrganizationBootstrapAuthorization::parse(
            &value.bootstrap_authorization,
        )
        .ok_or_else(|| {
            DatabaseInconsistencyError::on("organization_principal_controls")
                .column("bootstrap_authorization")
                .row(id)
        })?;
        Ok(Self {
            id: id.to_string(),
            organization_did: value.organization_did,
            principal_control_realm_id: value.principal_control_realm_id,
            control_stream_ref: value.control_stream_ref,
            pcr_frontier_digest: value.pcr_frontier_digest,
            bootstrap_authorization,
            bootstrap_delegation_ref: value.bootstrap_delegation_ref,
            executed_by: value.executed_by,
            bootstrap_proof_digest: value.bootstrap_proof_digest,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = organization_principal_controls)]
struct InsertableControl {
    id: Uuid,
    organization_did: String,
    principal_control_realm_id: String,
    control_stream_ref: Option<String>,
    pcr_frontier_digest: Option<String>,
    bootstrap_authorization: String,
    bootstrap_delegation_ref: Option<String>,
    executed_by: Option<String>,
    bootstrap_proof_digest: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// ── organization_delegations ─────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = organization_delegations)]
struct DelegationRow {
    id: Uuid,
    delegation_ref: String,
    organization_did: String,
    delegate_did: String,
    issuer_role: String,
    purposes: Vec<String>,
    covered_relationships: Vec<String>,
    covered_control_scopes: Vec<String>,
    status: String,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
    created_by: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<DelegationRow> for OrganizationDelegation {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: DelegationRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let on_err = |column: &'static str| {
            DatabaseInconsistencyError::on("organization_delegations")
                .column(column)
                .row(id)
        };
        let issuer_role =
            parse_issuer_role(&value.issuer_role).ok_or_else(|| on_err("issuer_role"))?;
        let status =
            OrganizationDelegationStatus::parse(&value.status).ok_or_else(|| on_err("status"))?;
        let covered_relationships = value
            .covered_relationships
            .iter()
            .map(|raw| parse_relationship(raw).ok_or_else(|| on_err("covered_relationships")))
            .collect::<Result<Vec<_>, _>>()?;
        let covered_control_scopes = value
            .covered_control_scopes
            .iter()
            .map(|raw| parse_control_scope(raw).ok_or_else(|| on_err("covered_control_scopes")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            id: id.to_string(),
            delegation_ref: value.delegation_ref,
            organization_did: value.organization_did,
            delegate_did: value.delegate_did,
            issuer_role,
            purposes: value.purposes,
            covered_relationships,
            covered_control_scopes,
            status,
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            created_by: value.created_by,
            created_at: value.created_at,
            updated_at: value.updated_at,
            revoked_at: value.revoked_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = organization_delegations)]
struct InsertableDelegation {
    id: Uuid,
    delegation_ref: String,
    organization_did: String,
    delegate_did: String,
    issuer_role: String,
    purposes: Vec<String>,
    covered_relationships: Vec<String>,
    covered_control_scopes: Vec<String>,
    status: String,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
    created_by: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// ── SDK enum <-> wire-string helpers ─────────────────────────────
//
// `RealmOrganization*` enums serialize snake_case via serde; we store the same
// snake_case strings in TEXT[] columns. We round-trip through serde_json so the
// stored strings stay byte-identical to the on-wire `ak.realm.organization`
// values and cannot drift from the SDK definition.

fn issuer_role_str(role: RealmOrganizationIssuerRole) -> String {
    serde_json::to_value(role)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn parse_issuer_role(raw: &str) -> Option<RealmOrganizationIssuerRole> {
    serde_json::from_value(serde_json::Value::String(raw.to_owned())).ok()
}

fn relationship_str(relationship: RealmOrganizationRelationship) -> String {
    serde_json::to_value(relationship)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn parse_relationship(raw: &str) -> Option<RealmOrganizationRelationship> {
    serde_json::from_value(serde_json::Value::String(raw.to_owned())).ok()
}

fn control_scope_str(scope: RealmOrganizationControlScope) -> String {
    serde_json::to_value(scope)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn parse_control_scope(raw: &str) -> Option<RealmOrganizationControlScope> {
    serde_json::from_value(serde_json::Value::String(raw.to_owned())).ok()
}

#[async_trait]
impl OrganizationControlRepository for PgOrganizationControlRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.organization_control.bootstrap", skip_all, err)]
    async fn bootstrap(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewOrganizationPrincipalControl,
    ) -> Result<OrganizationPrincipalControl, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);
        let row = InsertableControl {
            id: Uuid::from(id),
            organization_did: params.organization_did,
            principal_control_realm_id: params.principal_control_realm_id,
            control_stream_ref: params.control_stream_ref,
            pcr_frontier_digest: params.pcr_frontier_digest,
            bootstrap_authorization: params.bootstrap_authorization.as_str().to_owned(),
            bootstrap_delegation_ref: params.bootstrap_delegation_ref,
            executed_by: params.executed_by,
            bootstrap_proof_digest: params.bootstrap_proof_digest,
            created_at: now,
            updated_at: now,
        };

        diesel::insert_into(organization_principal_controls::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(OrganizationPrincipalControl {
            id: id.to_string(),
            organization_did: row.organization_did,
            principal_control_realm_id: row.principal_control_realm_id,
            control_stream_ref: row.control_stream_ref,
            pcr_frontier_digest: row.pcr_frontier_digest,
            bootstrap_authorization: params.bootstrap_authorization,
            bootstrap_delegation_ref: row.bootstrap_delegation_ref,
            executed_by: row.executed_by,
            bootstrap_proof_digest: row.bootstrap_proof_digest,
            created_at: now,
            updated_at: now,
        })
    }

    #[tracing::instrument(name = "db.organization_control.get_control_by_did", skip_all, err)]
    async fn get_control_by_did(
        &mut self,
        organization_did: &str,
    ) -> Result<Option<OrganizationPrincipalControl>, Self::Error> {
        organization_principal_controls::table
            .filter(organization_principal_controls::organization_did.eq(organization_did))
            .select(ControlRow::as_select())
            .first::<ControlRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.organization_control.update_control", skip_all, err)]
    async fn update_control(
        &mut self,
        clock: &dyn Clock,
        organization_did: &str,
        control_stream_ref: Option<String>,
        pcr_frontier_digest: Option<String>,
    ) -> Result<Option<OrganizationPrincipalControl>, Self::Error> {
        let now = clock.now();
        diesel::update(
            organization_principal_controls::table
                .filter(organization_principal_controls::organization_did.eq(organization_did)),
        )
        .set((
            organization_principal_controls::control_stream_ref.eq(control_stream_ref),
            organization_principal_controls::pcr_frontier_digest.eq(pcr_frontier_digest),
            organization_principal_controls::updated_at.eq(now),
        ))
        .returning(ControlRow::as_returning())
        .get_result::<ControlRow>(self.conn)
        .await
        .optional()?
        .map(TryInto::try_into)
        .transpose()
        .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.organization_control.add_delegation", skip_all, err)]
    async fn add_delegation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewOrganizationDelegation,
    ) -> Result<OrganizationDelegation, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);
        let row = InsertableDelegation {
            id: Uuid::from(id),
            delegation_ref: params.delegation_ref,
            organization_did: params.organization_did,
            delegate_did: params.delegate_did,
            issuer_role: issuer_role_str(params.issuer_role),
            purposes: params.purposes,
            covered_relationships: params
                .covered_relationships
                .iter()
                .copied()
                .map(relationship_str)
                .collect(),
            covered_control_scopes: params
                .covered_control_scopes
                .iter()
                .copied()
                .map(control_scope_str)
                .collect(),
            status: OrganizationDelegationStatus::Active.as_str().to_owned(),
            valid_from: params.valid_from,
            valid_until: params.valid_until,
            created_by: params.created_by,
            created_at: now,
            updated_at: now,
        };

        diesel::insert_into(organization_delegations::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(OrganizationDelegation {
            id: id.to_string(),
            delegation_ref: row.delegation_ref,
            organization_did: row.organization_did,
            delegate_did: row.delegate_did,
            issuer_role: params.issuer_role,
            purposes: row.purposes,
            covered_relationships: params.covered_relationships,
            covered_control_scopes: params.covered_control_scopes,
            status: OrganizationDelegationStatus::Active,
            valid_from: row.valid_from,
            valid_until: row.valid_until,
            created_by: row.created_by,
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
    }

    #[tracing::instrument(name = "db.organization_control.get_delegation_by_ref", skip_all, err)]
    async fn get_delegation_by_ref(
        &mut self,
        delegation_ref: &str,
    ) -> Result<Option<OrganizationDelegation>, Self::Error> {
        organization_delegations::table
            .filter(organization_delegations::delegation_ref.eq(delegation_ref))
            .select(DelegationRow::as_select())
            .first::<DelegationRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.organization_control.list_delegations_for_org",
        skip_all,
        err
    )]
    async fn list_delegations_for_org(
        &mut self,
        organization_did: &str,
    ) -> Result<Vec<OrganizationDelegation>, Self::Error> {
        organization_delegations::table
            .filter(organization_delegations::organization_did.eq(organization_did))
            .order(organization_delegations::created_at.desc())
            .select(DelegationRow::as_select())
            .load::<DelegationRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.organization_control.revoke_delegation", skip_all, err)]
    async fn revoke_delegation(
        &mut self,
        clock: &dyn Clock,
        delegation_ref: &str,
    ) -> Result<Option<OrganizationDelegation>, Self::Error> {
        let now = clock.now();
        diesel::update(
            organization_delegations::table
                .filter(organization_delegations::delegation_ref.eq(delegation_ref))
                .filter(organization_delegations::revoked_at.is_null()),
        )
        .set((
            organization_delegations::status.eq(OrganizationDelegationStatus::Revoked.as_str()),
            organization_delegations::revoked_at.eq(Some(now)),
            organization_delegations::updated_at.eq(now),
        ))
        .returning(DelegationRow::as_returning())
        .get_result::<DelegationRow>(self.conn)
        .await
        .optional()?
        .map(TryInto::try_into)
        .transpose()
        .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.organization_control.renew_delegation", skip_all, err)]
    async fn renew_delegation(
        &mut self,
        clock: &dyn Clock,
        delegation_ref: &str,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Option<OrganizationDelegation>, Self::Error> {
        let now = clock.now();
        diesel::update(
            organization_delegations::table
                .filter(organization_delegations::delegation_ref.eq(delegation_ref))
                .filter(organization_delegations::revoked_at.is_null()),
        )
        .set((
            organization_delegations::valid_until.eq(valid_until),
            organization_delegations::updated_at.eq(now),
        ))
        .returning(DelegationRow::as_returning())
        .get_result::<DelegationRow>(self.conn)
        .await
        .optional()?
        .map(TryInto::try_into)
        .transpose()
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use coauth_data::clock::MockClock;
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::PgRepositoryFactory;

    fn control(did: &str) -> NewOrganizationPrincipalControl {
        NewOrganizationPrincipalControl {
            organization_did: did.to_owned(),
            principal_control_realm_id: format!("ak:realm:{did}"),
            control_stream_ref: Some("ak:event:01904100-0000-7000-8000-000000000aaa".to_owned()),
            pcr_frontier_digest: None,
            bootstrap_authorization: OrganizationBootstrapAuthorization::DidControllerProof,
            bootstrap_delegation_ref: None,
            executed_by: Some("did:web:admin.example".to_owned()),
            bootstrap_proof_digest: Some("sha256:deadbeef".to_owned()),
        }
    }

    fn delegation(org: &str, reference: &str) -> NewOrganizationDelegation {
        NewOrganizationDelegation {
            delegation_ref: reference.to_owned(),
            organization_did: org.to_owned(),
            delegate_did: "did:web:server.acme.example".to_owned(),
            issuer_role: RealmOrganizationIssuerRole::GovernanceService,
            purposes: vec!["principal_control_realm_bootstrap".to_owned()],
            covered_relationships: vec![RealmOrganizationRelationship::Owner],
            covered_control_scopes: vec![RealmOrganizationControlScope::RealmAdmin],
            valid_from: Utc::now(),
            valid_until: None,
            created_by: "did:web:admin.example".to_owned(),
        }
    }

    #[tokio::test]
    async fn control_and_delegation_roundtrip() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let factory = PgRepositoryFactory::new(pool);
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(73);
        let did = format!("did:web:{}.example", uuid::Uuid::now_v7());
        let reference = format!("ak:grant:{}", uuid::Uuid::now_v7());

        let mut repo = factory.create().await.unwrap();
        repo.organization_control()
            .bootstrap(&mut rng, &clock, control(&did))
            .await
            .unwrap();
        repo.organization_control()
            .add_delegation(&mut rng, &clock, delegation(&did, &reference))
            .await
            .unwrap();
        repo.save().await.unwrap();

        let mut repo = factory.create().await.unwrap();
        let fetched = repo
            .organization_control()
            .get_control_by_did(&did)
            .await
            .unwrap()
            .expect("control persisted");
        assert_eq!(fetched.organization_did, did);
        assert_eq!(
            fetched.executed_by.as_deref(),
            Some("did:web:admin.example")
        );

        let resolved = repo
            .organization_control()
            .get_delegation_by_ref(&reference)
            .await
            .unwrap()
            .expect("delegation persisted");
        assert!(resolved.is_live(Utc::now()));
        assert!(resolved.covers_pcr_bootstrap());

        let revoked = repo
            .organization_control()
            .revoke_delegation(&clock, &reference)
            .await
            .unwrap()
            .expect("active delegation revocable");
        assert!(!revoked.is_live(Utc::now()));
        repo.save().await.unwrap();
    }
}
