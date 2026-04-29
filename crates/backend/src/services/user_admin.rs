use std::str::FromStr as _;

use anyhow::Error as AnyhowError;
use coauth_data::{
    AdminUserPatch, BoxRepository, Clock, RepositoryAccess, RepositoryError, UpstreamOAuthLink,
    UpstreamOAuthLinkPatch, User, UserEmail, UserEmailPatch,
    audit::AdminOperation,
    queue::{DeactivateUserJob, QueueJobRepositoryExt as _},
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
    user::{UserEmailRepository, UserRepository},
};
use coauth_matrix::HomeserverAdmin;
use lettre::address::AddressError;
use rand_core::RngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::{
    handlers::admin::audit_helper::record_admin_operation,
    services::user_profile::{sync_display_name_patch, validate_display_name_patch},
};

#[derive(Debug, Error)]
pub enum UserAdminServiceError {
    #[error("user {0} not found")]
    UserNotFound(Ulid),

    #[error("user email {0} not found")]
    UserEmailNotFound(Ulid),

    #[error("upstream oauth link {0} not found")]
    UpstreamOAuthLinkNotFound(Ulid),

    #[error("provider {0} not found")]
    ProviderNotFound(Ulid),

    #[error("referenced user {0} not found")]
    ReferencedUserNotFound(Ulid),

    #[error("display name is invalid")]
    InvalidDisplayName,

    #[error("email \"{email}\" is not valid")]
    InvalidEmail {
        email: String,
        #[source]
        source: AddressError,
    },

    #[error("user email \"{0}\" already in use")]
    EmailAlreadyInUse(String),

    #[error("upstream provider {provider_id} already has subject {subject}")]
    UpstreamSubjectAlreadyLinked { provider_id: Ulid, subject: String },

    #[error(transparent)]
    Homeserver(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn patch_user(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    homeserver: &dyn HomeserverAdmin,
    admin_user: Option<&User>,
    user_id: Ulid,
    patch: AdminUserPatch,
    hs_erase: bool,
) -> Result<User, UserAdminServiceError> {
    validate_admin_patch(&patch)?;

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(UserAdminServiceError::UserNotFound(user_id))?;

    if patch.is_empty() {
        return Ok(user);
    }

    let display_name_patch = patch.display_name.clone();
    let should_reactivate = user.deactivated_at.is_some() && patch.deactivated == Some(false);
    let should_schedule_deactivation =
        user.deactivated_at.is_none() && patch.deactivated == Some(true);

    let updated = repo
        .user()
        .patch(clock, user.clone(), patch.clone().into())
        .await?;

    if should_reactivate {
        homeserver
            .reactivate_user(&updated.username)
            .await
            .map_err(UserAdminServiceError::Homeserver)?;
    }

    if updated.deactivated_at.is_none() {
        sync_display_name_patch(homeserver, &updated, display_name_patch)
            .await
            .map_err(|error| match error {
                crate::services::user_profile::UserProfileServiceError::Homeserver(error) => {
                    UserAdminServiceError::Homeserver(error)
                }
                crate::services::user_profile::UserProfileServiceError::InvalidDisplayName => {
                    UserAdminServiceError::InvalidDisplayName
                }
                crate::services::user_profile::UserProfileServiceError::Repository(error) => {
                    UserAdminServiceError::Repository(error)
                }
                crate::services::user_profile::UserProfileServiceError::NotFound => {
                    UserAdminServiceError::UserNotFound(user_id)
                }
                crate::services::user_profile::UserProfileServiceError::Unauthorized => {
                    UserAdminServiceError::UserNotFound(user_id)
                }
                crate::services::user_profile::UserProfileServiceError::UnsupportedNotificationChannel(_) => {
                    UserAdminServiceError::UserNotFound(user_id)
                }
                crate::services::user_profile::UserProfileServiceError::DuplicateNotificationChannel(_) => {
                    UserAdminServiceError::UserNotFound(user_id)
                }
            })?;
    }

    if should_schedule_deactivation {
        repo.queue_job()
            .schedule_job(rng, clock, DeactivateUserJob::new(&updated, hs_erase))
            .await?;
    }

    record_admin_operation(
        repo,
        rng,
        clock,
        admin_user,
        AdminOperation::UserUpdated,
        "user",
        Some(updated.id),
        serde_json::json!({
            "patch": patch,
            "hs_erase": hs_erase,
        }),
    )
    .await?;

    Ok(updated)
}

pub async fn patch_user_email(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    admin_user: Option<&User>,
    user_email_id: Ulid,
    patch: UserEmailPatch,
) -> Result<UserEmail, UserAdminServiceError> {
    let user_email = repo
        .user_email()
        .lookup(user_email_id)
        .await?
        .ok_or(UserAdminServiceError::UserEmailNotFound(user_email_id))?;

    if patch.is_empty() {
        return Ok(user_email);
    }

    if let Some(email) = patch.email.as_ref() {
        if let Err(source) = lettre::Address::from_str(email) {
            return Err(UserAdminServiceError::InvalidEmail {
                email: email.clone(),
                source,
            });
        }

        if let Some(existing) = repo.user_email().find_by_email(email).await?
            && existing.id != user_email_id
        {
            return Err(UserAdminServiceError::EmailAlreadyInUse(email.clone()));
        }
    }

    let updated = repo
        .user_email()
        .patch(clock, user_email, patch.clone())
        .await?;

    record_admin_operation(
        repo,
        rng,
        clock,
        admin_user,
        AdminOperation::UserEmailUpdated,
        "user_email",
        Some(updated.id),
        serde_json::json!({
            "patch": patch,
        }),
    )
    .await?;

    Ok(updated)
}

pub async fn patch_upstream_oauth_link(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    admin_user: Option<&User>,
    link_id: Ulid,
    patch: UpstreamOAuthLinkPatch,
) -> Result<UpstreamOAuthLink, UserAdminServiceError> {
    let link = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or(UserAdminServiceError::UpstreamOAuthLinkNotFound(link_id))?;

    if patch.is_empty() {
        return Ok(link);
    }

    if let Some(Some(user_id)) = patch.user_id {
        repo.user()
            .lookup(user_id)
            .await?
            .ok_or(UserAdminServiceError::ReferencedUserNotFound(user_id))?;
    }

    if let Some(subject) = patch.subject.as_ref() {
        let provider = repo
            .upstream_oauth_provider()
            .lookup(link.provider_id)
            .await?
            .ok_or(UserAdminServiceError::ProviderNotFound(link.provider_id))?;

        if let Some(existing) = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, subject)
            .await?
            && existing.id != link.id
        {
            return Err(UserAdminServiceError::UpstreamSubjectAlreadyLinked {
                provider_id: link.provider_id,
                subject: subject.clone(),
            });
        }
    }

    let updated = repo
        .upstream_oauth_link()
        .patch(clock, link, patch.clone())
        .await?;

    record_admin_operation(
        repo,
        rng,
        clock,
        admin_user,
        AdminOperation::UpstreamLinkUpdated,
        "upstream_oauth_link",
        Some(updated.id),
        serde_json::json!({
            "patch": patch,
        }),
    )
    .await?;

    Ok(updated)
}

fn validate_admin_patch(patch: &AdminUserPatch) -> Result<(), UserAdminServiceError> {
    validate_display_name_patch(&coauth_data::UserProfilePatch {
        display_name: patch.display_name.clone(),
        avatar_url: patch.avatar_url.clone(),
        preferred_locale: patch.preferred_locale.clone(),
    })
    .map_err(|_| UserAdminServiceError::InvalidDisplayName)
}
