use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::Ulid;
pub use crate::{
    pg::{
        notification::PgNotificationRepository,
        notification_template::PgNotificationTemplateRepository,
    },
    storage::{notification::*, notification_template::NotificationTemplateRepository},
};

/// A persisted logical notification request.
///
/// A request represents the user-visible intent to notify someone. One request
/// may fan out into multiple channel-specific [`NotificationDelivery`] records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRequest {
    /// Stable unique identifier for the logical notification request.
    pub id: Ulid,
    /// Application-defined template or message key.
    pub template_key: String,
    /// IETF language tag used to localize the notification.
    pub locale: String,
    /// Correlates the request to the business workflow or domain object that
    /// created it.
    pub source: NotificationRequestSource,
    /// Free-form template payload stored as structured JSON.
    pub payload: Value,
    /// Current lifecycle status for the request.
    pub status: NotificationRequestStatus,
    /// Optional deduplication key to suppress duplicate requests.
    pub dedupe_key: Option<String>,
    /// Optional cross-system correlation key for tracing and audit.
    pub correlation_key: Option<String>,
    /// When the request was recorded.
    pub created_at: DateTime<Utc>,
    /// When the request becomes eligible for delivery.
    pub scheduled_at: DateTime<Utc>,
    /// When delivery processing first started.
    pub started_at: Option<DateTime<Utc>>,
    /// When the request reached a terminal successful state.
    pub completed_at: Option<DateTime<Utc>>,
    /// When the request was explicitly cancelled.
    pub cancelled_at: Option<DateTime<Utc>>,
}

/// The business origin of a persisted notification request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotificationRequestSource {
    /// Triggered by an email-authentication flow.
    UserEmailAuthentication {
        /// The originating email-authentication session.
        user_email_authentication_id: Ulid,
    },
    /// Triggered by a phone-authentication flow.
    UserPhoneAuthentication {
        /// The originating phone-authentication session.
        user_phone_authentication_id: Ulid,
    },
    /// Triggered by an account-recovery flow.
    UserRecoverySession {
        /// The originating recovery session.
        user_recovery_session_id: Ulid,
    },
    /// Triggered by a workflow instance outside the legacy auth flows.
    WorkflowInstance {
        /// The originating workflow instance.
        workflow_instance_id: Ulid,
    },
    /// Triggered by an administrator-initiated operation.
    AdminOperation {
        /// The administrative operation that scheduled the notification.
        admin_operation_id: Ulid,
    },
    /// Triggered by an internal system process identified by a stable key.
    System {
        /// Stable source key, for example `cleanup_alert` or `tenant_rollout`.
        source_key: String,
    },
}

/// Lifecycle state for a logical notification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationRequestStatus {
    /// The request has been persisted but processing has not started yet.
    Pending,
    /// The request is being expanded into deliveries or currently processed.
    Processing,
    /// At least one delivery succeeded and no further work remains.
    Succeeded,
    /// All deliveries ended in terminal failure.
    Failed,
    /// Processing was intentionally cancelled before completion.
    Cancelled,
}

impl NotificationRequestStatus {
    /// Returns `true` when the request cannot make forward progress anymore.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

/// A channel-specific delivery attempt group for a notification request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationDelivery {
    /// Stable unique identifier for the delivery record.
    pub id: Ulid,
    /// Parent logical notification request.
    pub notification_request_id: Ulid,
    /// Delivery channel used by this attempt group.
    pub channel: NotificationChannel,
    /// Channel-specific destination for the notification.
    pub destination: NotificationDestination,
    /// Optional provider binding key used to resolve the transport adapter.
    pub provider_binding_key: Option<String>,
    /// Optional provider-side message identifier returned after submit.
    pub provider_message_id: Option<String>,
    /// Number of send attempts already made for this delivery.
    pub attempt_count: u32,
    /// Current lifecycle status for the delivery.
    pub status: NotificationDeliveryStatus,
    /// Last terminal or most recent failure captured for this delivery.
    pub last_failure: Option<NotificationDeliveryFailure>,
    /// When the delivery record was created.
    pub created_at: DateTime<Utc>,
    /// When a worker reserved this delivery for processing.
    pub reserved_at: Option<DateTime<Utc>>,
    /// When the provider accepted the outbound payload.
    pub sent_at: Option<DateTime<Utc>>,
    /// When the platform observed terminal success.
    pub delivered_at: Option<DateTime<Utc>>,
    /// When the most recent terminal failure occurred.
    pub failed_at: Option<DateTime<Utc>>,
    /// When this delivery should be retried next.
    pub next_retry_at: Option<DateTime<Utc>>,
}

impl NotificationDelivery {
    /// Returns `true` if the delivery should be retried by background workers.
    #[must_use]
    pub fn should_retry(&self) -> bool {
        matches!(self.status, NotificationDeliveryStatus::Failed)
            && self
                .last_failure
                .as_ref()
                .is_some_and(|failure| failure.retryable)
            && self.next_retry_at.is_some()
    }
}

/// Supported outbound delivery channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    /// Traditional email delivery.
    Email,
    /// SMS or similar phone-number-based delivery.
    Sms,
    /// Callback-based machine delivery.
    Webhook,
    /// First-party in-product inbox delivery.
    InApp,
}

/// Channel-specific destination details for a delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotificationDestination {
    /// Deliver to an email inbox.
    Email {
        /// RFC 5322 mailbox as a normalized string.
        email: String,
    },
    /// Deliver to a phone number.
    Sms {
        /// Phone number in normalized dialing format.
        phone_number: String,
    },
    /// Deliver via webhook callback.
    Webhook {
        /// Destination callback URL.
        url: Url,
    },
    /// Deliver into a first-party user inbox.
    InApp {
        /// Owning user for the in-product inbox item.
        user_id: Ulid,
    },
}

/// Lifecycle state for a concrete delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeliveryStatus {
    /// Delivery exists but has not been claimed by a worker.
    Pending,
    /// Delivery has been claimed by a worker.
    Reserved,
    /// Delivery is in the process of being sent to a provider.
    Sending,
    /// Delivery finished successfully.
    Delivered,
    /// Delivery finished unsuccessfully.
    Failed,
    /// Delivery will not be attempted anymore.
    Cancelled,
}

impl NotificationDeliveryStatus {
    /// Returns `true` when the delivery cannot progress without an explicit
    /// state reset or a new record.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Failed | Self::Cancelled)
    }
}

/// Failure details retained on a delivery record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationDeliveryFailure {
    /// Optional provider or platform error code.
    pub code: Option<String>,
    /// Human-readable failure summary.
    pub message: Option<String>,
    /// Whether the failure is eligible for retry.
    pub retryable: bool,
}

/// Immutable audit events emitted by the notification subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationEventLog {
    /// Stable unique identifier for the event.
    pub id: Ulid,
    /// Parent logical notification request.
    pub notification_request_id: Ulid,
    /// Related delivery record when the event is delivery-specific.
    pub notification_delivery_id: Option<Ulid>,
    /// Event kind.
    pub kind: NotificationEventKind,
    /// Actor responsible for the event.
    pub actor: NotificationEventActor,
    /// Optional human-readable summary.
    pub summary: Option<String>,
    /// Structured event metadata for audits and debugging.
    pub metadata: Value,
    /// When the event occurred.
    pub occurred_at: DateTime<Utc>,
}

/// Immutable notification lifecycle event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEventKind {
    /// Request was created.
    RequestCreated,
    /// Request was scheduled for later processing.
    RequestScheduled,
    /// Delivery record was created.
    DeliveryQueued,
    /// Delivery was claimed by a worker.
    DeliveryReserved,
    /// Delivery began sending.
    DeliverySendStarted,
    /// Provider accepted the outbound payload.
    DeliveryAccepted,
    /// Delivery completed successfully.
    DeliveryDelivered,
    /// Delivery completed unsuccessfully.
    DeliveryFailed,
    /// Delivery was explicitly rescheduled.
    DeliveryRetried,
    /// Request completed successfully.
    RequestCompleted,
    /// Request reached terminal failure.
    RequestFailed,
    /// Request was cancelled.
    RequestCancelled,
}

/// The actor recorded against a notification audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotificationEventActor {
    /// Internal platform actor.
    System,
    /// Background worker process.
    Worker {
        /// Stable worker name or queue identifier.
        worker: String,
    },
    /// Administrative user action.
    Admin {
        /// User that performed the admin operation.
        user_id: Ulid,
    },
    /// End-user initiated action.
    User {
        /// User that triggered the event.
        user_id: Ulid,
    },
}

/// A versioned notification template.
///
/// Templates are keyed by `template_key` and versioned independently per
/// channel.  Only published versions (`published_at.is_some()`) should be
/// resolved at send time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationTemplateVersion {
    /// Stable unique identifier for this template version.
    pub id: Ulid,
    /// Application-defined template key, for example `verification_email`.
    pub template_key: String,
    /// Monotonically increasing version number within the template key.
    pub version: u32,
    /// Delivery channel this version targets.
    pub channel: NotificationChannel,
    /// Optional subject line template (relevant for email).
    pub subject_template: Option<String>,
    /// Body template content.
    pub body_template: String,
    /// When this version was created.
    pub created_at: DateTime<Utc>,
    /// When this version was published for delivery use.
    pub published_at: Option<DateTime<Utc>>,
}

/// A user's notification channel preference.
///
/// Preferences express per-user opt-in / opt-out for each delivery channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationPreference {
    /// Stable unique identifier for the preference record.
    pub id: Ulid,
    /// The user this preference belongs to.
    pub user_id: Ulid,
    /// Delivery channel this preference controls.
    pub channel: NotificationChannel,
    /// Whether the channel is enabled for the user.
    pub enabled: bool,
    /// When this preference was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Binding between a notification channel and a provider.
///
/// Provider bindings map a logical channel to a concrete transport adapter
/// (e.g., SES for email, Twilio for SMS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationProviderBinding {
    /// Stable unique identifier for the binding.
    pub id: Ulid,
    /// Delivery channel this binding serves.
    pub channel: NotificationChannel,
    /// Stable provider key used to resolve the transport adapter at runtime.
    pub provider_key: String,
    /// Provider-specific configuration stored as structured JSON.
    pub config: Value,
    /// Whether this binding is currently active.
    pub enabled: bool,
    /// When this binding was created.
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::{
        NotificationDelivery, NotificationDeliveryFailure, NotificationDeliveryStatus,
        NotificationRequestStatus,
    };

    #[test]
    fn request_status_terminal_states_are_explicit() {
        assert!(!NotificationRequestStatus::Pending.is_terminal());
        assert!(!NotificationRequestStatus::Processing.is_terminal());
        assert!(NotificationRequestStatus::Succeeded.is_terminal());
        assert!(NotificationRequestStatus::Failed.is_terminal());
        assert!(NotificationRequestStatus::Cancelled.is_terminal());
    }

    #[test]
    fn delivery_retries_only_when_failure_is_retryable() {
        let delivery = NotificationDelivery {
            id: ulid::Ulid::nil(),
            notification_request_id: ulid::Ulid::nil(),
            channel: super::NotificationChannel::Email,
            destination: super::NotificationDestination::Email {
                email: "user@example.com".to_owned(),
            },
            provider_binding_key: None,
            provider_message_id: None,
            attempt_count: 1,
            status: NotificationDeliveryStatus::Failed,
            last_failure: Some(NotificationDeliveryFailure {
                code: Some("timeout".to_owned()),
                message: Some("gateway timeout".to_owned()),
                retryable: true,
            }),
            created_at: chrono::Utc::now(),
            reserved_at: None,
            sent_at: None,
            delivered_at: None,
            failed_at: Some(chrono::Utc::now()),
            next_retry_at: Some(chrono::Utc::now()),
        };

        assert!(delivery.should_retry());
    }
}
