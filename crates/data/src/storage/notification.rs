use chrono::{DateTime, Utc};
use coauth_data::{
    Clock, NotificationDelivery, NotificationDeliveryFailure, NotificationDestination,
    NotificationEventActor, NotificationEventKind, NotificationEventLog, NotificationPreference,
    NotificationRequest, NotificationRequestSource, NotificationRequestStatus, User,
};
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;

use crate::repository_impl;

/// Parameters used when creating a new logical notification request.
#[derive(Debug, Clone)]
pub struct NewNotificationRequest {
    template_key: String,
    locale: String,
    source: NotificationRequestSource,
    payload: Value,
    dedupe_key: Option<String>,
    correlation_key: Option<String>,
    scheduled_at: Option<DateTime<Utc>>,
}

impl NewNotificationRequest {
    /// Create a new notification request draft.
    #[must_use]
    pub fn new(
        template_key: impl Into<String>,
        locale: impl Into<String>,
        source: NotificationRequestSource,
        payload: Value,
    ) -> Self {
        Self {
            template_key: template_key.into(),
            locale: locale.into(),
            source,
            payload,
            dedupe_key: None,
            correlation_key: None,
            scheduled_at: None,
        }
    }

    /// The template key for this request.
    #[must_use]
    pub fn template_key(&self) -> &str {
        &self.template_key
    }

    /// The locale for this request.
    #[must_use]
    pub fn locale(&self) -> &str {
        &self.locale
    }

    /// The workflow or domain source for this request.
    #[must_use]
    pub fn source(&self) -> &NotificationRequestSource {
        &self.source
    }

    /// The structured payload for this request.
    #[must_use]
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// The deduplication key for this request, if any.
    #[must_use]
    pub fn dedupe_key(&self) -> Option<&str> {
        self.dedupe_key.as_deref()
    }

    /// The tracing correlation key for this request, if any.
    #[must_use]
    pub fn correlation_key(&self) -> Option<&str> {
        self.correlation_key.as_deref()
    }

    /// The explicit scheduled time for this request, if any.
    #[must_use]
    pub fn scheduled_at(&self) -> Option<DateTime<Utc>> {
        self.scheduled_at
    }
}

/// Parameters used when creating a channel-specific notification delivery.
#[derive(Debug, Clone)]
pub struct NewNotificationDelivery {
    channel: coauth_data::NotificationChannel,
    destination: NotificationDestination,
    provider_binding_key: Option<String>,
}

impl NewNotificationDelivery {
    /// Create a new notification delivery draft.
    #[must_use]
    pub fn new(
        channel: coauth_data::NotificationChannel,
        destination: NotificationDestination,
    ) -> Self {
        Self {
            channel,
            destination,
            provider_binding_key: None,
        }
    }

    /// Attach a provider binding key to the delivery.
    #[must_use]
    pub fn with_provider_binding_key(mut self, provider_binding_key: impl Into<String>) -> Self {
        self.provider_binding_key = Some(provider_binding_key.into());
        self
    }

    /// The channel for this delivery.
    #[must_use]
    pub fn channel(&self) -> coauth_data::NotificationChannel {
        self.channel
    }

    /// The destination for this delivery.
    #[must_use]
    pub fn destination(&self) -> &NotificationDestination {
        &self.destination
    }

    /// The provider binding key for this delivery, if any.
    #[must_use]
    pub fn provider_binding_key(&self) -> Option<&str> {
        self.provider_binding_key.as_deref()
    }
}

/// Parameters used when appending a notification audit event.
#[derive(Debug, Clone)]
pub struct NewNotificationEventLog {
    kind: NotificationEventKind,
    actor: NotificationEventActor,
    summary: Option<String>,
    audit_context: Value,
}

impl NewNotificationEventLog {
    /// Create a new notification event draft.
    #[must_use]
    pub fn new(
        kind: NotificationEventKind,
        actor: NotificationEventActor,
        audit_context: Value,
    ) -> Self {
        Self {
            kind,
            actor,
            summary: None,
            audit_context,
        }
    }

    /// Attach a human-readable summary to the event.
    #[must_use]
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// The event kind.
    #[must_use]
    pub fn kind(&self) -> NotificationEventKind {
        self.kind
    }

    /// The actor who caused the event.
    #[must_use]
    pub fn actor(&self) -> &NotificationEventActor {
        &self.actor
    }

    /// The optional summary for the event.
    #[must_use]
    pub fn summary(&self) -> Option<&str> {
        self.summary.as_deref()
    }

    /// Supplementary audit context independent of the event kind.
    #[must_use]
    pub fn audit_context(&self) -> &Value {
        &self.audit_context
    }
}

repository_impl! {
    /// Repository for persisted notification requests, deliveries, and audit logs.
    pub trait NotificationRepository {
        /// The error type returned by the repository.
        type Error;

        /// Look up a logical notification request.
        async fn lookup_request(
            &mut self,
            id: Ulid,
        ) -> Result<Option<NotificationRequest>, Self::Error>;

        /// Create a new logical notification request.
        async fn add_request(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            params: NewNotificationRequest,
        ) -> Result<NotificationRequest, Self::Error>;

        /// Update the lifecycle status of an existing request.
        async fn set_request_status(
            &mut self,
            clock: &dyn Clock,
            notification_request: NotificationRequest,
            status: NotificationRequestStatus,
        ) -> Result<NotificationRequest, Self::Error>;

        /// Look up a concrete delivery.
        async fn lookup_delivery(
            &mut self,
            id: Ulid,
        ) -> Result<Option<NotificationDelivery>, Self::Error>;

        /// Look up a delivery using the provider binding key and provider-side
        /// message identifier.
        async fn lookup_delivery_by_provider_message_id(
            &mut self,
            provider_binding_key: &str,
            provider_message_id: &str,
        ) -> Result<Option<NotificationDelivery>, Self::Error>;

        /// List deliveries belonging to a request.
        async fn list_deliveries(
            &mut self,
            notification_request: &NotificationRequest,
        ) -> Result<Vec<NotificationDelivery>, Self::Error>;

        /// Create a new delivery belonging to a request.
        async fn add_delivery(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            notification_request: &NotificationRequest,
            params: NewNotificationDelivery,
        ) -> Result<NotificationDelivery, Self::Error>;

        /// Reserve a batch of due deliveries for processing.
        async fn reserve_deliveries(
            &mut self,
            clock: &dyn Clock,
            limit: usize,
        ) -> Result<Vec<NotificationDelivery>, Self::Error>;

        /// Mark a reserved delivery as actively sending.
        async fn mark_delivery_sending(
            &mut self,
            clock: &dyn Clock,
            notification_delivery: NotificationDelivery,
            provider_message_id: Option<String>,
        ) -> Result<NotificationDelivery, Self::Error>;

        /// Mark a delivery as successfully delivered.
        async fn mark_delivery_delivered(
            &mut self,
            clock: &dyn Clock,
            notification_delivery: NotificationDelivery,
            provider_message_id: Option<String>,
        ) -> Result<NotificationDelivery, Self::Error>;

        /// Mark a delivery as failed, optionally scheduling a retry.
        async fn mark_delivery_failed(
            &mut self,
            clock: &dyn Clock,
            notification_delivery: NotificationDelivery,
            failure: NotificationDeliveryFailure,
            provider_message_id: Option<String>,
            next_retry_at: Option<DateTime<Utc>>,
        ) -> Result<NotificationDelivery, Self::Error>;

        /// Cancel a delivery so it is not attempted anymore.
        async fn cancel_delivery(
            &mut self,
            clock: &dyn Clock,
            notification_delivery: NotificationDelivery,
        ) -> Result<NotificationDelivery, Self::Error>;

        /// Append an immutable notification audit event.
        async fn append_event(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            notification_request: &NotificationRequest,
            notification_delivery: Option<&NotificationDelivery>,
            params: NewNotificationEventLog,
        ) -> Result<NotificationEventLog, Self::Error>;

        /// List audit events for a logical notification request.
        async fn list_events(
            &mut self,
            notification_request: &NotificationRequest,
        ) -> Result<Vec<NotificationEventLog>, Self::Error>;

        /// List persisted per-channel preferences for a user.
        async fn list_preferences(
            &mut self,
            user: &User,
        ) -> Result<Vec<NotificationPreference>, Self::Error>;

        /// Replace the persisted preferences for the given user.
        async fn replace_preferences(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            user: &User,
            preferences: Vec<(coauth_data::NotificationChannel, bool)>,
        ) -> Result<Vec<NotificationPreference>, Self::Error>;
    }
}
