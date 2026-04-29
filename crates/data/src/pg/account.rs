//! PostgreSQL implementation of [`AccountRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    AccountContactPoint, AccountIdentityBinding, ContactChannel, IdentityProviderType,
    account::{AccountRepository, AccountSecuritySummary},
    audit::AccountSecurityEvent,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    schema::{
        account_security_events, upstream_oauth_links, upstream_oauth_providers, user_emails,
        user_passwords, user_phones, user_sessions,
    },
};

/// PostgreSQL-backed [`AccountRepository`].
pub struct PgAccountRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgAccountRepository<'c> {
    /// Create a new [`PgAccountRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_emails)]
struct UserEmailRow {
    id: Uuid,
    user_id: Uuid,
    email: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_phones)]
struct UserPhoneRow {
    id: Uuid,
    user_id: Uuid,
    phone: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = account_security_events)]
struct AccountSecurityEventRow {
    id: Uuid,
    user_id: Uuid,
    event_type: String,
    metadata: serde_json::Value,
    ip_address: Option<ipnetwork::IpNetwork>,
    user_agent: Option<String>,
    created_at: DateTime<Utc>,
}

impl TryFrom<AccountSecurityEventRow> for AccountSecurityEvent {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: AccountSecurityEventRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        let event_type: coauth_data::SecurityEventType = serde_json::from_str(&value.event_type)
            .map_err(|e| {
                DatabaseInconsistencyError::on("account_security_events")
                    .column("event_type")
                    .row(id)
                    .source(e)
            })?;

        Ok(AccountSecurityEvent {
            id,
            user_id: value.user_id.into(),
            event_type,
            metadata: value.metadata,
            ip_address: value.ip_address.map(|ip| ip.ip()),
            user_agent: value.user_agent,
            created_at: value.created_at,
        })
    }
}

#[async_trait]
impl AccountRepository for PgAccountRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.account.list_contact_points",
        skip_all,
        fields(user_id = %user_id),
        err,
    )]
    async fn list_contact_points(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountContactPoint>, Self::Error> {
        let user_uuid = Uuid::from(user_id);

        // Query emails
        let email_rows = user_emails::table
            .filter(user_emails::user_id.eq(user_uuid))
            .order(user_emails::created_at.asc())
            .select(UserEmailRow::as_select())
            .load::<UserEmailRow>(self.conn)
            .await?;

        // Query phones
        let phone_rows = user_phones::table
            .filter(user_phones::user_id.eq(user_uuid))
            .order(user_phones::created_at.asc())
            .select(UserPhoneRow::as_select())
            .load::<UserPhoneRow>(self.conn)
            .await?;

        let mut contact_points = Vec::with_capacity(email_rows.len() + phone_rows.len());

        // Map emails — the first email is treated as the primary
        for (i, row) in email_rows.into_iter().enumerate() {
            contact_points.push(AccountContactPoint {
                id: row.id.into(),
                user_id: row.user_id.into(),
                channel: ContactChannel::Email,
                value: row.email,
                verified: true,
                verified_at: Some(row.created_at),
                is_primary: i == 0,
                created_at: row.created_at,
            });
        }

        // Map phones — the first phone is treated as the primary
        for (i, row) in phone_rows.into_iter().enumerate() {
            contact_points.push(AccountContactPoint {
                id: row.id.into(),
                user_id: row.user_id.into(),
                channel: ContactChannel::Phone,
                value: row.phone,
                verified: true,
                verified_at: Some(row.created_at),
                is_primary: i == 0,
                created_at: row.created_at,
            });
        }

        // Sort: primary contacts first within each channel, then by created_at
        contact_points.sort_by(|a, b| {
            let channel_ord = |ch: &ContactChannel| match ch {
                ContactChannel::Email => 0u8,
                ContactChannel::Phone => 1u8,
            };
            channel_ord(&a.channel)
                .cmp(&channel_ord(&b.channel))
                .then(b.is_primary.cmp(&a.is_primary))
                .then(a.created_at.cmp(&b.created_at))
        });

        Ok(contact_points)
    }

    #[tracing::instrument(
        name = "db.account.list_identity_bindings",
        skip_all,
        fields(user_id = %user_id),
        err,
    )]
    async fn list_identity_bindings(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountIdentityBinding>, Self::Error> {
        let user_uuid = Uuid::from(user_id);

        let rows: Vec<(Uuid, Uuid, String, DateTime<Utc>, Option<String>, Uuid)> =
            upstream_oauth_links::table
                .inner_join(
                    upstream_oauth_providers::table
                        .on(upstream_oauth_links::upstream_oauth_provider_id
                            .eq(upstream_oauth_providers::id)),
                )
                .filter(upstream_oauth_links::user_id.eq(user_uuid))
                .filter(upstream_oauth_links::unlinked_at.is_null())
                .order(upstream_oauth_links::created_at.asc())
                .select((
                    upstream_oauth_links::id,
                    upstream_oauth_links::user_id.assume_not_null(),
                    upstream_oauth_links::subject,
                    upstream_oauth_links::created_at,
                    upstream_oauth_links::human_account_name,
                    upstream_oauth_providers::id,
                ))
                .load(self.conn)
                .await?;

        let bindings = rows
            .into_iter()
            .map(
                |(link_id, link_user_id, subject, created_at, human_name, provider_id)| {
                    AccountIdentityBinding {
                        id: link_id.into(),
                        user_id: link_user_id.into(),
                        provider_type: IdentityProviderType::UpstreamOAuth2,
                        provider_id: Ulid::from(provider_id).to_string(),
                        external_subject: subject,
                        external_display_name: human_name,
                        metadata: serde_json::Value::Object(serde_json::Map::new()),
                        created_at,
                        last_used_at: None,
                    }
                },
            )
            .collect();

        Ok(bindings)
    }

    #[tracing::instrument(
        name = "db.account.security_summary",
        skip_all,
        fields(user_id = %user_id),
        err,
    )]
    async fn security_summary(
        &mut self,
        user_id: Ulid,
    ) -> Result<AccountSecuritySummary, Self::Error> {
        let user_uuid = Uuid::from(user_id);

        // Count active sessions (finished_at IS NULL)
        let active_sessions_count: i64 = user_sessions::table
            .filter(user_sessions::user_id.eq(user_uuid))
            .filter(user_sessions::finished_at.is_null())
            .count()
            .get_result(self.conn)
            .await?;

        // Count verified emails
        let verified_emails_count: i64 = user_emails::table
            .filter(user_emails::user_id.eq(user_uuid))
            .count()
            .get_result(self.conn)
            .await?;

        // Count verified phones
        let verified_phones_count: i64 = user_phones::table
            .filter(user_phones::user_id.eq(user_uuid))
            .count()
            .get_result(self.conn)
            .await?;

        // Check password existence
        let has_password: bool = diesel::select(diesel::dsl::exists(
            user_passwords::table.filter(user_passwords::user_id.eq(user_uuid)),
        ))
        .get_result(self.conn)
        .await?;

        // Count linked upstream providers (not unlinked)
        let linked_providers_count: i64 = upstream_oauth_links::table
            .filter(upstream_oauth_links::user_id.eq(user_uuid))
            .filter(upstream_oauth_links::unlinked_at.is_null())
            .count()
            .get_result(self.conn)
            .await?;

        // Recent security events (last 10, most recent first)
        let event_rows = account_security_events::table
            .filter(account_security_events::user_id.eq(user_uuid))
            .order(account_security_events::created_at.desc())
            .limit(10)
            .select(AccountSecurityEventRow::as_select())
            .load::<AccountSecurityEventRow>(self.conn)
            .await?;

        let recent_security_events: Vec<AccountSecurityEvent> = event_rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, DatabaseInconsistencyError>>()?;

        Ok(AccountSecuritySummary {
            has_password,
            active_sessions_count: active_sessions_count as usize,
            verified_emails_count: verified_emails_count as usize,
            verified_phones_count: verified_phones_count as usize,
            linked_providers_count: linked_providers_count as usize,
            recent_security_events,
        })
    }
}
