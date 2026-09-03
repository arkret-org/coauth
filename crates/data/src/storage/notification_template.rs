//! Repository for notification template versions.

use coauth_data::Clock;
use coauth_data::notification::NotificationTemplateVersion;
use rand_core::RngCore;

use crate::repository_impl;

repository_impl! {
    /// A repository for managing notification template versions.
    pub trait NotificationTemplateRepository {
        /// The error type returned by the repository
        type Error;

        /// List all template versions, optionally filtered by `template_key`
        async fn list(
            &mut self,
            template_key: Option<&str>,
        ) -> Result<Vec<NotificationTemplateVersion>, Self::Error>;

        /// Get the latest published version for a given template key and channel
        async fn get_latest(
            &mut self,
            template_key: &str,
            channel: &str,
        ) -> Result<Option<NotificationTemplateVersion>, Self::Error>;

        /// Publish a new template version
        #[allow(clippy::too_many_arguments)]
        async fn publish(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            template_key: String,
            channel: String,
            locale: String,
            subject_template: Option<String>,
            body_template: String,
        ) -> Result<NotificationTemplateVersion, Self::Error>;
    }
}
