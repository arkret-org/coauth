use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    Clock, UpstreamOAuthAuthorizationSession, UserEmailAuthentication, UserPhoneAuthentication,
    UserRegistration, UserRegistrationPassword, UserRegistrationToken, new_id,
    user::UserRegistrationRepository,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ipnetwork::IpNetwork;
use rand_core::RngCore;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseInconsistencyError, schema::user_registrations};

/// An implementation of [`UserRegistrationRepository`] for a PostgreSQL
/// connection
pub struct PgUserRegistrationRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserRegistrationRepository<'c> {
    /// Create a new [`PgUserRegistrationRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_registrations)]
struct UserRegistrationRow {
    id: Uuid,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
    post_auth_action: Option<serde_json::Value>,
    username: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    terms_url: Option<String>,
    email_authentication_id: Option<Uuid>,
    phone_authentication_id: Option<Uuid>,
    user_registration_token_id: Option<Uuid>,
    hashed_password: Option<String>,
    hashed_password_version: Option<i32>,
    upstream_oauth_authorization_session_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl TryFrom<UserRegistrationRow> for UserRegistration {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: UserRegistrationRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);

        let password = match (value.hashed_password, value.hashed_password_version) {
            (Some(hashed_password), Some(version)) => {
                let version = version.try_into().map_err(|e| {
                    DatabaseInconsistencyError::on("user_registrations")
                        .column("hashed_password_version")
                        .row(id)
                        .source(e)
                })?;

                Some(UserRegistrationPassword {
                    hashed_password,
                    version,
                })
            }
            (None, None) => None,
            _ => {
                return Err(DatabaseInconsistencyError::on("user_registrations")
                    .column("hashed_password")
                    .row(id));
            }
        };

        let terms_url = value
            .terms_url
            .map(|u| u.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("user_registrations")
                    .column("terms_url")
                    .row(id)
                    .source(e)
            })?;

        Ok(UserRegistration {
            id,
            ip_address: value.ip_address.map(|network| network.ip()),
            user_agent: value.user_agent,
            post_auth_action: value.post_auth_action,
            username: value.username,
            display_name: value.display_name,
            avatar_url: value.avatar_url,
            terms_url,
            email_authentication_id: value.email_authentication_id.map(Ulid::from),
            phone_authentication_id: value.phone_authentication_id.map(Ulid::from),
            user_registration_token_id: value.user_registration_token_id.map(Ulid::from),
            password,
            upstream_oauth_authorization_session_id: value
                .upstream_oauth_authorization_session_id
                .map(Ulid::from),
            created_at: value.created_at,
            completed_at: value.completed_at,
        })
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = user_registrations)]
struct NewUserRegistration {
    id: Uuid,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
    post_auth_action: Option<serde_json::Value>,
    username: String,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl UserRegistrationRepository for PgUserRegistrationRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_registration.lookup",
        skip_all,
        fields(
            user_registration.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserRegistration>, Self::Error> {
        let res = user_registrations::table
            .find(Uuid::from(id))
            .select(UserRegistrationRow::as_select())
            .first::<UserRegistrationRow>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_registration.add",
        skip_all,
        fields(
            user_registration.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        post_auth_action: Option<serde_json::Value>,
    ) -> Result<UserRegistration, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user_registration.id", tracing::field::display(id));

        let new_registration = NewUserRegistration {
            id: Uuid::from(id),
            ip_address: ip_address.map(IpNetwork::from),
            user_agent: user_agent.clone(),
            post_auth_action: post_auth_action.clone(),
            username: username.clone(),
            created_at,
        };

        diesel::insert_into(user_registrations::table)
            .values(&new_registration)
            .execute(self.conn)
            .await?;

        Ok(UserRegistration {
            id,
            ip_address,
            user_agent,
            post_auth_action,
            created_at,
            completed_at: None,
            username,
            display_name: None,
            avatar_url: None,
            terms_url: None,
            email_authentication_id: None,
            phone_authentication_id: None,
            user_registration_token_id: None,
            password: None,
            upstream_oauth_authorization_session_id: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_registration.set_display_name",
        skip_all,
        fields(
            user_registration.id = %user_registration.id,
            user_registration.display_name = display_name,
        ),
        err,
    )]
    async fn set_display_name(
        &mut self,
        mut user_registration: UserRegistration,
        display_name: String,
    ) -> Result<UserRegistration, Self::Error> {
        let rows_affected = diesel::update(
            user_registrations::table
                .find(Uuid::from(user_registration.id))
                .filter(user_registrations::completed_at.is_null()),
        )
        .set(user_registrations::display_name.eq(Some(&display_name)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_registration.display_name = Some(display_name);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_avatar_url",
        skip_all,
        fields(
            user_registration.id = %user_registration.id,
        ),
        err,
    )]
    async fn set_avatar_url(
        &mut self,
        mut user_registration: UserRegistration,
        avatar_url: String,
    ) -> Result<UserRegistration, Self::Error> {
        let rows_affected = diesel::update(
            user_registrations::table
                .find(Uuid::from(user_registration.id))
                .filter(user_registrations::completed_at.is_null()),
        )
        .set(user_registrations::avatar_url.eq(Some(&avatar_url)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_registration.avatar_url = Some(avatar_url);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_terms_url",
        skip_all,
        fields(
            user_registration.id = %user_registration.id,
            user_registration.terms_url = %terms_url,
        ),
        err,
    )]
    async fn set_terms_url(
        &mut self,
        mut user_registration: UserRegistration,
        terms_url: Url,
    ) -> Result<UserRegistration, Self::Error> {
        let rows_affected = diesel::update(
            user_registrations::table
                .find(Uuid::from(user_registration.id))
                .filter(user_registrations::completed_at.is_null()),
        )
        .set(user_registrations::terms_url.eq(Some(terms_url.as_str())))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_registration.terms_url = Some(terms_url);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_email_authentication",
        skip_all,
        fields(
            %user_registration.id,
            %user_email_authentication.id,
            %user_email_authentication.email,
        ),
        err,
    )]
    async fn set_email_authentication(
        &mut self,
        mut user_registration: UserRegistration,
        user_email_authentication: &UserEmailAuthentication,
    ) -> Result<UserRegistration, Self::Error> {
        let rows_affected = diesel::update(
            user_registrations::table
                .find(Uuid::from(user_registration.id))
                .filter(user_registrations::completed_at.is_null()),
        )
        .set(
            user_registrations::email_authentication_id
                .eq(Some(Uuid::from(user_email_authentication.id))),
        )
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_registration.email_authentication_id = Some(user_email_authentication.id);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_phone_authentication",
        skip_all,
        fields(
            %user_registration.id,
            %user_phone_authentication.id,
            %user_phone_authentication.phone,
        ),
        err,
    )]
    async fn set_phone_authentication(
        &mut self,
        mut user_registration: UserRegistration,
        user_phone_authentication: &UserPhoneAuthentication,
    ) -> Result<UserRegistration, Self::Error> {
        let rows_affected = diesel::update(
            user_registrations::table
                .find(Uuid::from(user_registration.id))
                .filter(user_registrations::completed_at.is_null()),
        )
        .set(
            user_registrations::phone_authentication_id
                .eq(Some(Uuid::from(user_phone_authentication.id))),
        )
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_registration.phone_authentication_id = Some(user_phone_authentication.id);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_password",
        skip_all,
        fields(
            user_registration.id = %user_registration.id,
            user_registration.hashed_password = hashed_password,
            user_registration.hashed_password_version = version,
        ),
        err,
    )]
    async fn set_password(
        &mut self,
        mut user_registration: UserRegistration,
        hashed_password: String,
        version: u16,
    ) -> Result<UserRegistration, Self::Error> {
        let rows_affected = diesel::update(
            user_registrations::table
                .find(Uuid::from(user_registration.id))
                .filter(user_registrations::completed_at.is_null()),
        )
        .set((
            user_registrations::hashed_password.eq(Some(&hashed_password)),
            user_registrations::hashed_password_version.eq(Some(i32::from(version))),
        ))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_registration.password = Some(UserRegistrationPassword {
            hashed_password,
            version,
        });

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_registration_token",
        skip_all,
        fields(
            %user_registration.id,
            %user_registration_token.id,
        ),
        err,
    )]
    async fn set_registration_token(
        &mut self,
        mut user_registration: UserRegistration,
        user_registration_token: &UserRegistrationToken,
    ) -> Result<UserRegistration, Self::Error> {
        let rows_affected = diesel::update(
            user_registrations::table
                .find(Uuid::from(user_registration.id))
                .filter(user_registrations::completed_at.is_null()),
        )
        .set(
            user_registrations::user_registration_token_id
                .eq(Some(Uuid::from(user_registration_token.id))),
        )
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_registration.user_registration_token_id = Some(user_registration_token.id);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_upstream_oauth_authorization_session",
        skip_all,
        fields(
            %user_registration.id,
            %upstream_oauth_authorization_session.id,
        ),
        err,
    )]
    async fn set_upstream_oauth_authorization_session(
        &mut self,
        mut user_registration: UserRegistration,
        upstream_oauth_authorization_session: &UpstreamOAuthAuthorizationSession,
    ) -> Result<UserRegistration, Self::Error> {
        let rows_affected = diesel::update(
            user_registrations::table
                .find(Uuid::from(user_registration.id))
                .filter(user_registrations::completed_at.is_null()),
        )
        .set(
            user_registrations::upstream_oauth_authorization_session_id
                .eq(Some(Uuid::from(upstream_oauth_authorization_session.id))),
        )
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_registration.upstream_oauth_authorization_session_id =
            Some(upstream_oauth_authorization_session.id);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.complete",
        skip_all,
        fields(
            user_registration.id = %user_registration.id,
        ),
        err,
    )]
    async fn complete(
        &mut self,
        clock: &dyn Clock,
        mut user_registration: UserRegistration,
    ) -> Result<UserRegistration, Self::Error> {
        let completed_at = clock.now();
        let rows_affected = diesel::update(
            user_registrations::table
                .find(Uuid::from(user_registration.id))
                .filter(user_registrations::completed_at.is_null()),
        )
        .set(user_registrations::completed_at.eq(Some(completed_at)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_registration.completed_at = Some(completed_at);

        Ok(user_registration)
    }

    #[tracing::instrument(name = "db.user_registration.cleanup", skip_all, err)]
    async fn cleanup(
        &mut self,
        since: Option<Ulid>,
        until: Ulid,
        limit: usize,
    ) -> Result<(usize, Option<Ulid>), Self::Error> {
        // Use raw SQL for the complex CTE-based DELETE.
        // `MAX(uuid)` isn't a thing in Postgres, so we can't just re-select the
        // deleted rows and do a MAX on the `user_registration_id`.
        // Instead, we do the aggregation on the client side, which is a little
        // less efficient, but good enough.
        let res: Vec<UuidRow> = diesel::sql_query(
            "WITH to_delete AS ( \
                 SELECT id \
                 FROM user_registrations \
                 WHERE ($1::uuid IS NULL OR id > $1) \
                 AND id <= $2 \
                 ORDER BY id \
                 LIMIT $3 \
             ) \
             DELETE FROM user_registrations \
             USING to_delete \
             WHERE user_registrations.id = to_delete.id \
             RETURNING user_registrations.id",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(since.map(Uuid::from))
        .bind::<diesel::sql_types::Uuid, _>(Uuid::from(until))
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .load(self.conn)
        .await?;

        let count = res.len();
        let max_id = res.into_iter().map(|r| r.id).max();

        Ok((count, max_id.map(Ulid::from)))
    }
}

/// Helper row type for extracting a single UUID from raw SQL queries.
#[derive(Debug, Clone, QueryableByName)]
struct UuidRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use coauth_data::{
        Clock, RepositoryAccess as _, RepositoryFactory as _, RepositoryTransaction as _,
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
        UpstreamOAuthProviderTokenAuthMethod, UserRegistration, UserRegistrationPassword,
        clock::MockClock, upstream_oauth2::UpstreamOAuthProviderParams,
    };
    use coauth_iana::jose::JsonWebSignatureAlg;
    use ipnetwork::IpNetwork;
    use oauth2_types::scope::Scope;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use uuid::Uuid;

    use super::UserRegistrationRow;
    use crate::PgRepositoryFactory;

    #[tokio::test]
    async fn test_create_lookup_complete() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else { return; };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.created_at, clock.now());
        assert_eq!(registration.completed_at, None);
        assert_eq!(registration.username, "alice");
        assert_eq!(registration.display_name, None);
        assert_eq!(registration.terms_url, None);
        assert_eq!(registration.email_authentication_id, None);
        assert_eq!(registration.password, None);
        assert_eq!(registration.user_agent, None);
        assert_eq!(registration.ip_address, None);
        assert_eq!(registration.post_auth_action, None);

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.id, registration.id);
        assert_eq!(lookup.created_at, registration.created_at);
        assert_eq!(lookup.completed_at, registration.completed_at);
        assert_eq!(lookup.username, registration.username);
        assert_eq!(lookup.display_name, registration.display_name);
        assert_eq!(lookup.terms_url, registration.terms_url);
        assert_eq!(
            lookup.email_authentication_id,
            registration.email_authentication_id
        );
        assert_eq!(lookup.password, registration.password);
        assert_eq!(lookup.user_agent, registration.user_agent);
        assert_eq!(lookup.ip_address, registration.ip_address);
        assert_eq!(lookup.post_auth_action, registration.post_auth_action);

        // Mark the registration as completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();
        assert_eq!(registration.completed_at, Some(clock.now()));

        // Lookup the registration again
        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lookup.completed_at, registration.completed_at);

        // Do it again, it should fail
        let res = repo
            .user_registration()
            .complete(&clock, registration)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_create_useragent_ipaddress() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else { return; };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .add(
                &mut rng,
                &clock,
                "alice".to_owned(),
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some("Mozilla/5.0".to_owned()),
                Some(serde_json::json!({"kind": "change_password"})),
            )
            .await
            .unwrap();

        assert_eq!(registration.user_agent, Some("Mozilla/5.0".to_owned()));
        assert_eq!(
            registration.ip_address,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            registration.post_auth_action,
            Some(serde_json::json!({"kind": "change_password"}))
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.user_agent, registration.user_agent);
        assert_eq!(lookup.ip_address, registration.ip_address);
        assert_eq!(lookup.post_auth_action, registration.post_auth_action);
    }

    #[test]
    fn test_row_maps_inet_to_ipaddr() {
        let row = UserRegistrationRow {
            id: Uuid::now_v7(),
            ip_address: Some("103.151.173.203/32".parse::<IpNetwork>().unwrap()),
            user_agent: Some("Mozilla/5.0".to_owned()),
            post_auth_action: None,
            username: "alice".to_owned(),
            display_name: None,
            avatar_url: None,
            terms_url: None,
            email_authentication_id: None,
            phone_authentication_id: None,
            user_registration_token_id: None,
            hashed_password: None,
            hashed_password_version: None,
            upstream_oauth_authorization_session_id: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };

        let registration = UserRegistration::try_from(row).expect("row should convert");

        assert_eq!(
            registration.ip_address,
            Some(IpAddr::V4(Ipv4Addr::new(103, 151, 173, 203)))
        );
    }

    #[tokio::test]
    async fn test_set_display_name() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else { return; };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.display_name, None);

        let registration = repo
            .user_registration()
            .set_display_name(registration, "Alice".to_owned())
            .await
            .unwrap();

        assert_eq!(registration.display_name, Some("Alice".to_owned()));

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.display_name, registration.display_name);

        // Setting it again should work
        let registration = repo
            .user_registration()
            .set_display_name(registration, "Bob".to_owned())
            .await
            .unwrap();

        assert_eq!(registration.display_name, Some("Bob".to_owned()));

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.display_name, registration.display_name);

        // Can't set it once completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();

        let res = repo
            .user_registration()
            .set_display_name(registration, "Charlie".to_owned())
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_set_terms_url() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else { return; };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.terms_url, None);

        let registration = repo
            .user_registration()
            .set_terms_url(registration, "https://example.com/terms".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(
            registration.terms_url,
            Some("https://example.com/terms".parse().unwrap())
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.terms_url, registration.terms_url);

        // Setting it again should work
        let registration = repo
            .user_registration()
            .set_terms_url(registration, "https://example.com/terms2".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(
            registration.terms_url,
            Some("https://example.com/terms2".parse().unwrap())
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.terms_url, registration.terms_url);

        // Can't set it once completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();

        let res = repo
            .user_registration()
            .set_terms_url(registration, "https://example.com/terms3".parse().unwrap())
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_set_email_authentication() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else { return; };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.email_authentication_id, None);

        let authentication = repo
            .user_email()
            .add_authentication_for_registration(
                &mut rng,
                &clock,
                "alice@example.com".to_owned(),
                &registration,
            )
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await
            .unwrap();

        assert_eq!(
            registration.email_authentication_id,
            Some(authentication.id)
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            lookup.email_authentication_id,
            registration.email_authentication_id
        );

        // Setting it again should work
        let registration = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await
            .unwrap();

        assert_eq!(
            registration.email_authentication_id,
            Some(authentication.id)
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            lookup.email_authentication_id,
            registration.email_authentication_id
        );

        // Can't set it once completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();

        let res = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_set_password() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else { return; };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.password, None);

        let registration = repo
            .user_registration()
            .set_password(registration, "fakehashedpassword".to_owned(), 1)
            .await
            .unwrap();

        assert_eq!(
            registration.password,
            Some(UserRegistrationPassword {
                hashed_password: "fakehashedpassword".to_owned(),
                version: 1,
            })
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.password, registration.password);

        // Setting it again should work
        let registration = repo
            .user_registration()
            .set_password(registration, "fakehashedpassword2".to_owned(), 2)
            .await
            .unwrap();

        assert_eq!(
            registration.password,
            Some(UserRegistrationPassword {
                hashed_password: "fakehashedpassword2".to_owned(),
                version: 2,
            })
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.password, registration.password);

        // Can't set it once completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();

        let res = repo
            .user_registration()
            .set_password(registration, "fakehashedpassword3".to_owned(), 3)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_set_upstream_oauth_session() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else { return; };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.upstream_oauth_authorization_session_id, None);

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([oauth2_types::scope::OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .add(&mut rng, &clock, &provider, "state".to_owned(), None, None)
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .set_upstream_oauth_authorization_session(registration, &session)
            .await
            .unwrap();

        assert_eq!(
            registration.upstream_oauth_authorization_session_id,
            Some(session.id)
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            lookup.upstream_oauth_authorization_session_id,
            registration.upstream_oauth_authorization_session_id
        );

        // Setting it again should work
        let registration = repo
            .user_registration()
            .set_upstream_oauth_authorization_session(registration, &session)
            .await
            .unwrap();

        assert_eq!(
            registration.upstream_oauth_authorization_session_id,
            Some(session.id)
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            lookup.upstream_oauth_authorization_session_id,
            registration.upstream_oauth_authorization_session_id
        );

        // Can't set it once completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();

        let res = repo
            .user_registration()
            .set_upstream_oauth_authorization_session(registration, &session)
            .await;
        assert!(res.is_err());
    }
}
