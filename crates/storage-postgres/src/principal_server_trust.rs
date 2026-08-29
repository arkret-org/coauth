//! PostgreSQL implementation of the Principal Server trust enrollment
//! storage.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::storage::principal_server_trust::{
    NewPrincipalServerTrustAudit, NewPrincipalServerTrustEnrollment, PrincipalServerTrustAudit,
    PrincipalServerTrustAuditAction, PrincipalServerTrustEnrollment,
    PrincipalServerTrustRepository, PrincipalServerTrustSource,
};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use uuid::Uuid;

use crate::schema::{principal_server_trust_audits, principal_server_trust_enrollments};
use crate::{DatabaseError, DatabaseInconsistencyError};

/// An implementation of [`PrincipalServerTrustRepository`] for a PostgreSQL
/// connection.
pub struct PgPrincipalServerTrustRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgPrincipalServerTrustRepository<'c> {
    /// Create a new [`PgPrincipalServerTrustRepository`] from an active
    /// PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = principal_server_trust_enrollments)]
struct EnrollmentRow {
    name: String,
    canonical_endpoint: String,
    service_id: arkret_identifiers::DidCoreId,
    did: String,
    method_history_head: String,
    version_id: String,
    resolution_record_digest: String,
    source: String,
    enrolled_at: DateTime<Utc>,
    last_verified_at: DateTime<Utc>,
}

impl TryFrom<EnrollmentRow> for PrincipalServerTrustEnrollment {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: EnrollmentRow) -> Result<Self, Self::Error> {
        let did = arkret_identifiers::Did::new(value.did).map_err(|error| {
            DatabaseInconsistencyError::on("principal_server_trust_enrollments")
                .column("did")
                .source(error)
        })?;
        if arkret_identifiers::project_did_to_core_id(&did)
            .map_or(true, |projected| projected != value.service_id)
        {
            return Err(
                DatabaseInconsistencyError::on("principal_server_trust_enrollments")
                    .column("service_id"),
            );
        }
        let source = PrincipalServerTrustSource::from_stored(&value.source).ok_or_else(|| {
            DatabaseInconsistencyError::on("principal_server_trust_enrollments").column("source")
        })?;
        Ok(Self {
            name: value.name,
            canonical_endpoint: value.canonical_endpoint,
            service_id: value.service_id,
            did,
            method_history_head: value.method_history_head,
            version_id: value.version_id,
            resolution_record_digest: value.resolution_record_digest,
            source,
            enrolled_at: value.enrolled_at,
            last_verified_at: value.last_verified_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = principal_server_trust_enrollments)]
struct NewEnrollmentRow {
    name: String,
    canonical_endpoint: String,
    service_id: arkret_identifiers::DidCoreId,
    service_kind: String,
    did: String,
    method_history_head: String,
    version_id: String,
    resolution_record_digest: String,
    source: String,
    enrolled_at: DateTime<Utc>,
    last_verified_at: DateTime<Utc>,
}

#[derive(AsChangeset)]
#[diesel(table_name = principal_server_trust_enrollments)]
struct EnrollmentReplacement {
    canonical_endpoint: String,
    service_id: arkret_identifiers::DidCoreId,
    did: String,
    method_history_head: String,
    version_id: String,
    resolution_record_digest: String,
    source: String,
    last_verified_at: DateTime<Utc>,
}

impl NewEnrollmentRow {
    fn from_params(params: &NewPrincipalServerTrustEnrollment, now: DateTime<Utc>) -> Self {
        Self {
            name: params.name.clone(),
            canonical_endpoint: params.canonical_endpoint.clone(),
            service_id: params.service_id.clone(),
            service_kind: "principal_server".to_owned(),
            did: params.did.to_string(),
            method_history_head: params.method_history_head.clone(),
            version_id: params.version_id.clone(),
            resolution_record_digest: params.resolution_record_digest.clone(),
            source: params.source.as_str().to_owned(),
            enrolled_at: now,
            last_verified_at: now,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = principal_server_trust_audits)]
struct AuditRow {
    id: Uuid,
    enrollment_name: String,
    action: String,
    service_id: Option<arkret_identifiers::DidCoreId>,
    previous_service_id: Option<arkret_identifiers::DidCoreId>,
    detail: String,
    created_at: DateTime<Utc>,
}

impl TryFrom<AuditRow> for PrincipalServerTrustAudit {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: AuditRow) -> Result<Self, Self::Error> {
        let action =
            PrincipalServerTrustAuditAction::from_stored(&value.action).ok_or_else(|| {
                DatabaseInconsistencyError::on("principal_server_trust_audits")
                    .column("action")
                    .row(value.id.into())
            })?;
        Ok(Self {
            id: value.id.into(),
            enrollment_name: value.enrollment_name,
            action,
            service_id: value.service_id,
            previous_service_id: value.previous_service_id,
            detail: value.detail,
            created_at: value.created_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = principal_server_trust_audits)]
struct NewAuditRow {
    id: Uuid,
    enrollment_name: String,
    action: String,
    service_id: Option<arkret_identifiers::DidCoreId>,
    previous_service_id: Option<arkret_identifiers::DidCoreId>,
    detail: String,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl PrincipalServerTrustRepository for PgPrincipalServerTrustRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.principal_server_trust.find_by_endpoint", skip_all, err)]
    async fn find_by_endpoint(
        &mut self,
        canonical_endpoint: &str,
    ) -> Result<Option<PrincipalServerTrustEnrollment>, Self::Error> {
        principal_server_trust_enrollments::table
            .filter(principal_server_trust_enrollments::canonical_endpoint.eq(canonical_endpoint))
            .select(EnrollmentRow::as_select())
            .first::<EnrollmentRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.principal_server_trust.find_by_name", skip_all, err)]
    async fn find_by_name(
        &mut self,
        name: &str,
    ) -> Result<Option<PrincipalServerTrustEnrollment>, Self::Error> {
        principal_server_trust_enrollments::table
            .find(name)
            .select(EnrollmentRow::as_select())
            .first::<EnrollmentRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.principal_server_trust.enroll", skip_all, err)]
    async fn enroll(
        &mut self,
        clock: &dyn Clock,
        params: NewPrincipalServerTrustEnrollment,
    ) -> Result<PrincipalServerTrustEnrollment, Self::Error> {
        if arkret_identifiers::project_did_to_core_id(&params.did)
            .map_or(true, |projected| projected != params.service_id)
        {
            return Err(DatabaseError::invalid_operation());
        }
        let now = clock.now();
        let row = NewEnrollmentRow::from_params(&params, now);
        diesel::insert_into(principal_server_trust_enrollments::table)
            .values(&row)
            .execute(self.conn)
            .await?;
        Ok(PrincipalServerTrustEnrollment {
            name: params.name,
            canonical_endpoint: params.canonical_endpoint,
            service_id: params.service_id,
            did: params.did,
            method_history_head: params.method_history_head,
            version_id: params.version_id,
            resolution_record_digest: params.resolution_record_digest,
            source: params.source,
            enrolled_at: now,
            last_verified_at: now,
        })
    }

    #[tracing::instrument(name = "db.principal_server_trust.replace", skip_all, err)]
    async fn replace(
        &mut self,
        clock: &dyn Clock,
        name: &str,
        expected_old_service_id: &arkret_identifiers::DidCoreId,
        params: NewPrincipalServerTrustEnrollment,
    ) -> Result<bool, Self::Error> {
        if arkret_identifiers::project_did_to_core_id(&params.did)
            .map_or(true, |projected| projected != params.service_id)
        {
            return Err(DatabaseError::invalid_operation());
        }
        let changes = EnrollmentReplacement {
            canonical_endpoint: params.canonical_endpoint.clone(),
            service_id: params.service_id.clone(),
            did: params.did.to_string(),
            method_history_head: params.method_history_head.clone(),
            version_id: params.version_id.clone(),
            resolution_record_digest: params.resolution_record_digest.clone(),
            source: params.source.as_str().to_owned(),
            last_verified_at: clock.now(),
        };
        let rows_affected = diesel::update(
            principal_server_trust_enrollments::table
                .filter(principal_server_trust_enrollments::name.eq(name))
                .filter(principal_server_trust_enrollments::service_id.eq(expected_old_service_id)),
        )
        .set(&changes)
        .execute(self.conn)
        .await?;
        Ok(rows_affected == 1)
    }

    #[tracing::instrument(name = "db.principal_server_trust.record_verification", skip_all, err)]
    async fn record_verification(
        &mut self,
        clock: &dyn Clock,
        canonical_endpoint: &str,
        method_history_head: &str,
        version_id: &str,
        resolution_record_digest: &str,
    ) -> Result<bool, Self::Error> {
        let rows_affected =
            diesel::update(principal_server_trust_enrollments::table.filter(
                principal_server_trust_enrollments::canonical_endpoint.eq(canonical_endpoint),
            ))
            .set((
                principal_server_trust_enrollments::last_verified_at.eq(clock.now()),
                principal_server_trust_enrollments::method_history_head.eq(method_history_head),
                principal_server_trust_enrollments::version_id.eq(version_id),
                principal_server_trust_enrollments::resolution_record_digest
                    .eq(resolution_record_digest),
            ))
            .execute(self.conn)
            .await?;
        Ok(rows_affected == 1)
    }

    #[tracing::instrument(name = "db.principal_server_trust.revoke", skip_all, err)]
    async fn revoke(&mut self, name: &str) -> Result<bool, Self::Error> {
        let rows_affected = diesel::delete(
            principal_server_trust_enrollments::table
                .filter(principal_server_trust_enrollments::name.eq(name)),
        )
        .execute(self.conn)
        .await?;
        Ok(rows_affected == 1)
    }

    #[tracing::instrument(name = "db.principal_server_trust.record_audit", skip_all, err)]
    async fn record_audit(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewPrincipalServerTrustAudit,
    ) -> Result<PrincipalServerTrustAudit, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        let row = NewAuditRow {
            id: Uuid::from(id),
            enrollment_name: params.enrollment_name.clone(),
            action: params.action.as_str().to_owned(),
            service_id: params.service_id.clone(),
            previous_service_id: params.previous_service_id.clone(),
            detail: params.detail.clone(),
            created_at,
        };
        diesel::insert_into(principal_server_trust_audits::table)
            .values(&row)
            .execute(self.conn)
            .await?;
        Ok(PrincipalServerTrustAudit {
            id,
            enrollment_name: params.enrollment_name,
            action: params.action,
            service_id: params.service_id,
            previous_service_id: params.previous_service_id,
            detail: params.detail,
            created_at,
        })
    }

    #[tracing::instrument(name = "db.principal_server_trust.list_audits", skip_all, err)]
    async fn list_audits(
        &mut self,
        enrollment_name: &str,
        limit: usize,
    ) -> Result<Vec<PrincipalServerTrustAudit>, Self::Error> {
        let limit = i64::try_from(limit).map_err(DatabaseError::to_invalid_operation)?;
        principal_server_trust_audits::table
            .filter(principal_server_trust_audits::enrollment_name.eq(enrollment_name))
            .order(principal_server_trust_audits::created_at.desc())
            .limit(limit)
            .select(AuditRow::as_select())
            .load::<AuditRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use coauth_data::clock::MockClock;
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::PgRepositoryFactory;

    fn enrollment_params(name: &str, service_id: &str) -> NewPrincipalServerTrustEnrollment {
        let scid = service_id
            .strip_prefix("ak:did_core:webvh:")
            .expect("fixture uses a webvh service id");
        NewPrincipalServerTrustEnrollment {
            name: name.to_owned(),
            canonical_endpoint: format!("https://{name}.example/"),
            service_id: arkret_identifiers::DidCoreId::new(service_id.to_owned())
                .expect("valid service core id"),
            did: arkret_identifiers::Did::new(format!("did:webvh:{scid}:soland.example"))
                .expect("valid DID"),
            method_history_head: "sha256:aa".to_owned(),
            version_id: "1-bb".to_owned(),
            resolution_record_digest: "sha256:cc".to_owned(),
            source: PrincipalServerTrustSource::OperatorCli,
        }
    }

    #[tokio::test]
    async fn enroll_find_replace_revoke_roundtrip() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        assert!(
            repo.principal_server_trust()
                .find_by_endpoint("https://soland.example/")
                .await
                .unwrap()
                .is_none()
        );

        let enrolled = repo
            .principal_server_trust()
            .enroll(&clock, enrollment_params("soland", "ak:did_core:webvh:old"))
            .await
            .unwrap();
        assert_eq!(enrolled.source, PrincipalServerTrustSource::OperatorCli);

        let fetched = repo
            .principal_server_trust()
            .find_by_endpoint("https://soland.example/")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.service_id.as_str(), "ak:did_core:webvh:old");
        assert_eq!(
            repo.principal_server_trust()
                .find_by_name("soland")
                .await
                .unwrap()
                .unwrap()
                .canonical_endpoint,
            "https://soland.example/"
        );

        // CAS replace with a stale expectation must not apply.
        let mut new_params = enrollment_params("soland", "ak:did_core:webvh:new");
        new_params.version_id = "2-dd".to_owned();
        let replaced = repo
            .principal_server_trust()
            .replace(
                &clock,
                "soland",
                &arkret_identifiers::DidCoreId::new("ak:did_core:webvh:stale".to_owned()).unwrap(),
                new_params.clone(),
            )
            .await
            .unwrap();
        assert!(!replaced);
        assert_eq!(
            repo.principal_server_trust()
                .find_by_name("soland")
                .await
                .unwrap()
                .unwrap()
                .service_id
                .as_str(),
            "ak:did_core:webvh:old"
        );

        // CAS replace with the current expectation applies.
        let replaced = repo
            .principal_server_trust()
            .replace(
                &clock,
                "soland",
                &arkret_identifiers::DidCoreId::new("ak:did_core:webvh:old".to_owned()).unwrap(),
                new_params,
            )
            .await
            .unwrap();
        assert!(replaced);
        assert_eq!(
            repo.principal_server_trust()
                .find_by_name("soland")
                .await
                .unwrap()
                .unwrap()
                .version_id,
            "2-dd"
        );

        // Verification advance + audit trail.
        assert!(
            repo.principal_server_trust()
                .record_verification(
                    &clock,
                    "https://soland.example/",
                    "sha256:ee",
                    "3-ff",
                    "sha256:00"
                )
                .await
                .unwrap()
        );
        repo.principal_server_trust()
            .record_audit(
                &mut rng,
                &clock,
                NewPrincipalServerTrustAudit {
                    enrollment_name: "soland".to_owned(),
                    action: PrincipalServerTrustAuditAction::Replaced,
                    service_id: Some(
                        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:new".to_owned())
                            .unwrap(),
                    ),
                    previous_service_id: Some(
                        arkret_identifiers::DidCoreId::new("ak:did_core:webvh:old".to_owned())
                            .unwrap(),
                    ),
                    detail: "explicit replace".to_owned(),
                },
            )
            .await
            .unwrap();
        let audits = repo
            .principal_server_trust()
            .list_audits("soland", 10)
            .await
            .unwrap();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].action, PrincipalServerTrustAuditAction::Replaced);

        assert!(
            repo.principal_server_trust()
                .revoke("soland")
                .await
                .unwrap()
        );
        assert!(
            repo.principal_server_trust()
                .find_by_name("soland")
                .await
                .unwrap()
                .is_none()
        );

        repo.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn enrollment_rejects_mismatched_service_id_and_did_on_create_replace_and_read() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let clock = MockClock::default();
        let name = format!("binding-{}", Uuid::now_v7().simple());
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        let mut mismatched = enrollment_params(&name, "ak:did_core:webvh:expected");
        mismatched.did =
            arkret_identifiers::Did::new("did:webvh:other:principal-server.example".to_owned())
                .unwrap();
        assert!(
            repo.principal_server_trust()
                .enroll(&clock, mismatched)
                .await
                .is_err()
        );

        let valid = enrollment_params(&name, "ak:did_core:webvh:expected");
        repo.principal_server_trust()
            .enroll(&clock, valid.clone())
            .await
            .unwrap();

        let mut replacement = valid;
        replacement.service_id =
            arkret_identifiers::DidCoreId::new("ak:did_core:webvh:other".to_owned()).unwrap();
        assert!(
            repo.principal_server_trust()
                .replace(
                    &clock,
                    &name,
                    &arkret_identifiers::DidCoreId::new("ak:did_core:webvh:expected".to_owned(),)
                        .unwrap(),
                    replacement,
                )
                .await
                .is_err()
        );
        repo.save().await.unwrap();

        let mut conn = pool.get().await.unwrap();
        diesel::update(
            principal_server_trust_enrollments::table
                .filter(principal_server_trust_enrollments::name.eq(&name)),
        )
        .set(
            principal_server_trust_enrollments::did
                .eq("did:webvh:corrupt:principal-server.example"),
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        drop(conn);

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();
        assert!(
            repo.principal_server_trust()
                .find_by_name(&name)
                .await
                .is_err(),
            "a syntactically valid but cross-bound corrupt row must fail closed"
        );
        repo.cancel().await.unwrap();
    }
}
