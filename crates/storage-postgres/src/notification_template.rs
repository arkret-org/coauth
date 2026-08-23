//! PostgreSQL implementation of the notification template version repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::notification::{
    NotificationChannel, NotificationTemplateRepository, NotificationTemplateVersion,
};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::notification_template_versions;

/// PostgreSQL-backed notification template version repository.
pub struct PgNotificationTemplateRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgNotificationTemplateRepository<'c> {
    /// Create a new [`PgNotificationTemplateRepository`] from an active
    /// PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = notification_template_versions)]
struct TemplateVersionRow {
    id: Uuid,
    template_key: String,
    version: i32,
    channel: String,
    subject_template: Option<String>,
    body_template: String,
    published_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

fn channel_from_str(s: &str) -> NotificationChannel {
    match s {
        "sms" => NotificationChannel::Sms,
        "webhook" => NotificationChannel::Webhook,
        "in_app" => NotificationChannel::InApp,
        _ => NotificationChannel::Email,
    }
}

impl From<TemplateVersionRow> for NotificationTemplateVersion {
    fn from(row: TemplateVersionRow) -> Self {
        let channel = channel_from_str(&row.channel);
        NotificationTemplateVersion {
            id: row.id.into(),
            template_key: row.template_key,
            version: row.version as u32,
            channel,
            subject_template: row.subject_template,
            body_template: row.body_template,
            created_at: row.created_at,
            published_at: row.published_at,
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = notification_template_versions)]
struct NewTemplateVersion {
    id: Uuid,
    template_key: String,
    version: i32,
    channel: String,
    locale: String,
    subject_template: Option<String>,
    body_template: String,
    published_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl NotificationTemplateRepository for PgNotificationTemplateRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.notification_template.list", skip_all, err)]
    async fn list(
        &mut self,
        template_key: Option<&str>,
    ) -> Result<Vec<NotificationTemplateVersion>, Self::Error> {
        let mut query = notification_template_versions::table
            .select(TemplateVersionRow::as_select())
            .order(notification_template_versions::created_at.desc())
            .into_boxed();

        if let Some(key) = template_key {
            query = query.filter(notification_template_versions::template_key.eq(key));
        }

        let rows = query.load::<TemplateVersionRow>(self.conn).await?;
        Ok(rows
            .into_iter()
            .map(NotificationTemplateVersion::from)
            .collect())
    }

    #[tracing::instrument(name = "db.notification_template.get_latest", skip_all, err)]
    async fn get_latest(
        &mut self,
        template_key: &str,
        channel: &str,
    ) -> Result<Option<NotificationTemplateVersion>, Self::Error> {
        let row = notification_template_versions::table
            .select(TemplateVersionRow::as_select())
            .filter(notification_template_versions::template_key.eq(template_key))
            .filter(notification_template_versions::channel.eq(channel))
            .filter(notification_template_versions::published_at.is_not_null())
            .order(notification_template_versions::version.desc())
            .first::<TemplateVersionRow>(self.conn)
            .await
            .optional()?;
        Ok(row.map(NotificationTemplateVersion::from))
    }

    #[tracing::instrument(name = "db.notification_template.publish", skip_all, err)]
    async fn publish(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        template_key: String,
        channel: String,
        locale: String,
        subject_template: Option<String>,
        body_template: String,
    ) -> Result<NotificationTemplateVersion, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);

        // Get the next version number for this key+channel
        let max_version: Option<i32> = notification_template_versions::table
            .select(diesel::dsl::max(notification_template_versions::version))
            .filter(notification_template_versions::template_key.eq(&template_key))
            .filter(notification_template_versions::channel.eq(&channel))
            .first(self.conn)
            .await?;
        let next_version = max_version.unwrap_or(0) + 1;

        let new_row = NewTemplateVersion {
            id: Uuid::from(id),
            template_key: template_key.clone(),
            version: next_version,
            channel: channel.clone(),
            locale: locale.clone(),
            subject_template: subject_template.clone(),
            body_template: body_template.clone(),
            created_at: now,
            published_at: Some(now),
        };

        diesel::insert_into(notification_template_versions::table)
            .values(&new_row)
            .execute(self.conn)
            .await?;

        let ch = channel_from_str(&channel);

        Ok(NotificationTemplateVersion {
            id,
            template_key,
            version: next_version as u32,
            channel: ch,
            subject_template,
            body_template,
            created_at: now,
            published_at: Some(now),
        })
    }
}
