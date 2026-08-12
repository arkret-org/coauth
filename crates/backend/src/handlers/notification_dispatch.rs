use coauth_data::queue::{
    ContactVerificationTarget, DispatchNotificationJob, QueueJobRepositoryExt as _,
};
use coauth_data::{
    BoxRepository, Clock, RepositoryError, UserEmailAuthentication, UserPhoneAuthentication,
    UserRecoverySession,
};
use rand_core::RngCore;

/// User-facing notification intent expressed by the business layer.
pub enum NotificationIntent<'a> {
    /// Verify a contact point without binding the caller to a concrete channel.
    ContactVerification {
        /// The verification target.
        target: ContactVerificationIntentTarget<'a>,
        /// The language to use for the notification.
        language: String,
    },
    /// Send account recovery notifications for a recovery session.
    AccountRecovery {
        /// The recovery session for which to notify.
        session: &'a UserRecoverySession,
    },
}

/// Supported contact verification targets.
pub enum ContactVerificationIntentTarget<'a> {
    /// Email verification.
    Email(&'a UserEmailAuthentication),
    /// Phone verification.
    Phone(&'a UserPhoneAuthentication),
}

impl<'a> NotificationIntent<'a> {
    /// Create a contact verification intent for email.
    #[must_use]
    pub fn verify_email(authentication: &'a UserEmailAuthentication, language: String) -> Self {
        Self::ContactVerification {
            target: ContactVerificationIntentTarget::Email(authentication),
            language,
        }
    }

    /// Create a contact verification intent for phone.
    #[must_use]
    pub fn verify_phone(authentication: &'a UserPhoneAuthentication, language: String) -> Self {
        Self::ContactVerification {
            target: ContactVerificationIntentTarget::Phone(authentication),
            language,
        }
    }

    /// Create an account recovery notification intent.
    #[must_use]
    pub fn account_recovery(session: &'a UserRecoverySession) -> Self {
        Self::AccountRecovery { session }
    }
}

/// Schedule a notification intent for background processing.
pub async fn schedule_notification(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    intent: NotificationIntent<'_>,
) -> Result<(), RepositoryError> {
    let job = match intent {
        NotificationIntent::ContactVerification { target, language } => {
            let target = match target {
                ContactVerificationIntentTarget::Email(authentication) => {
                    ContactVerificationTarget::Email {
                        user_email_authentication_id: authentication.id,
                    }
                }
                ContactVerificationIntentTarget::Phone(authentication) => {
                    ContactVerificationTarget::Phone {
                        user_phone_authentication_id: authentication.id,
                    }
                }
            };

            DispatchNotificationJob::contact_verification(target, language)
        }
        NotificationIntent::AccountRecovery { session } => {
            DispatchNotificationJob::account_recovery(session)
        }
    };

    repo.queue_job().schedule_job(rng, clock, job).await
}
