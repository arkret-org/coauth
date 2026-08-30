use std::str::FromStr as _;

use anyhow::Error as AnyhowError;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use coauth_data::audit::AdminOperation;
use coauth_data::queue::{
    AccountProjectionRewriteJob, DeactivateUserJob, QueueJobRepositoryExt as _,
};
use coauth_data::upstream_oauth::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository};
use coauth_data::user::{UserEmailRepository, UserRepository};
use coauth_data::{
    AdminUserPatch, BoxRepository, Clock, RepositoryAccess, RepositoryError, UpstreamOAuthLink,
    UpstreamOAuthLinkPatch, User, UserEmail, UserEmailPatch,
};
use coauth_email_types::Address;
use coauth_principal::ConnectorAdmin;
use rand_core::RngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::admin::audit_helper::{
    AdminAuditSigning, record_admin_operation, record_admin_operation_signed,
};
use crate::services::account_status_publication::{
    AccountStatusPublicationPlan, author_transition_plan, enqueue_exact_publication,
    validate_transition_plan,
};
use crate::services::user_profile::{sync_display_name_patch, validate_display_name_patch};

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

    #[error("account status transition from {from:?} to {to:?} is invalid")]
    InvalidStatusTransition {
        from: AccountStatus,
        to: AccountStatus,
    },

    #[error("account status publication plan is required for a durable status transition")]
    MissingAccountStatusPublication,

    #[error("account status publication plan is invalid: {0}")]
    InvalidAccountStatusPublication(String),

    #[error("email \"{email}\" is not valid")]
    InvalidEmail {
        email: String,
        #[source]
        source: email_address::Error,
    },

    #[error("user email \"{0}\" already in use")]
    EmailAlreadyInUse(String),

    #[error("upstream provider {provider_id} already has subject {subject}")]
    UpstreamSubjectAlreadyLinked { provider_id: Ulid, subject: String },

    #[error(transparent)]
    Station(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[allow(clippy::too_many_arguments)]
pub async fn patch_user(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    station: &dyn ConnectorAdmin,
    admin_user: Option<&User>,
    user_id: Ulid,
    patch: AdminUserPatch,
    principal_erase: bool,
    audit_signing: Option<AdminAuditSigning<'_>>,
    account_status_publication: Option<AccountStatusPublicationPlan>,
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
    let next_status = account_status_from_admin_patch(user.status, &patch);
    validate_admin_status_transition(user.status, next_status)?;
    let status_changes = user.status != next_status;
    let mut account_status_publication = account_status_publication;
    let publication_binding = if status_changes {
        let (destination_name, audience) = station
            .account_status_destination()
            .map_err(UserAdminServiceError::Station)?;
        let binding = repo
            .principal_did()
            .get_for_user_and_audience(&user, audience.as_str())
            .await?
            .ok_or(UserAdminServiceError::MissingAccountStatusPublication)?;
        if account_status_publication.is_none() {
            let signing = audit_signing
                .as_ref()
                .ok_or(UserAdminServiceError::MissingAccountStatusPublication)?;
            account_status_publication = Some(
                author_transition_plan(
                    repo,
                    station,
                    signing.keystore,
                    signing.service_id.as_str(),
                    &user,
                    &binding,
                    next_status,
                    None,
                    clock.now(),
                    rng,
                )
                .await
                .map_err(|error| {
                    UserAdminServiceError::InvalidAccountStatusPublication(error.to_string())
                })?,
            );
        }
        let plan = account_status_publication
            .as_ref()
            .ok_or(UserAdminServiceError::MissingAccountStatusPublication)?;
        if plan.destination_name != destination_name || plan.audience_id != audience {
            return Err(UserAdminServiceError::InvalidAccountStatusPublication(
                "publication destination does not match the configured Station".to_owned(),
            ));
        }
        validate_transition_plan(&user, &binding, next_status, plan).map_err(|error| {
            UserAdminServiceError::InvalidAccountStatusPublication(error.to_string())
        })?;
        Some(binding)
    } else {
        None
    };
    let should_schedule_deactivation = !account_status_needs_deactivation_fanout(user.status)
        && account_status_needs_deactivation_fanout(next_status);
    let should_schedule_erasure = user.status != AccountStatus::ErasurePending
        && next_status == AccountStatus::ErasurePending;

    let updated = repo
        .user()
        .patch(clock, user.clone(), patch.clone().into())
        .await?;

    if let (Some(plan), Some(_binding)) = (account_status_publication, publication_binding) {
        enqueue_exact_publication(
            repo,
            rng,
            clock,
            &plan.destination_name,
            plan.local_account_id,
            &plan.idempotency_key,
            plan.body,
        )
        .await
        .map_err(|error| {
            UserAdminServiceError::InvalidAccountStatusPublication(error.to_string())
        })?;
    }

    if !account_status_needs_deactivation_fanout(updated.status) {
        sync_display_name_patch(station, &updated, display_name_patch)
            .await
            .map_err(|error| match error {
                crate::services::user_profile::UserProfileServiceError::Station(error) => {
                    UserAdminServiceError::Station(error)
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
            .schedule_job(
                rng,
                clock,
                DeactivateUserJob::new(&updated, principal_erase),
            )
            .await?;
    }
    if should_schedule_erasure || (should_schedule_deactivation && principal_erase) {
        repo.queue_job()
            .schedule_job(
                rng,
                clock,
                AccountProjectionRewriteJob::new(
                    &updated,
                    principal_erase || should_schedule_erasure,
                ),
            )
            .await?;
    }

    let details = serde_json::json!({
        "patch": patch,
        "principal_erase": principal_erase,
    });
    if let Some(signing) = audit_signing {
        record_admin_operation_signed(
            repo,
            rng,
            clock,
            signing.keystore,
            signing.service_did,
            signing.fail_closed,
            admin_user,
            AdminOperation::UserUpdated,
            "user",
            Some(updated.id),
            details,
        )
        .await?;
    } else {
        record_admin_operation(
            repo,
            rng,
            clock,
            admin_user,
            AdminOperation::UserUpdated,
            "user",
            Some(updated.id),
            details,
        )
        .await?;
    }

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
        if let Err(source) = Address::from_str(email) {
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
        preferred_locale: patch.preferred_locale,
    })
    .map_err(|_| UserAdminServiceError::InvalidDisplayName)
}

fn account_status_from_admin_patch(
    current: AccountStatus,
    patch: &AdminUserPatch,
) -> AccountStatus {
    let mut status = patch.status.unwrap_or(current);

    if let Some(locked) = patch.locked {
        if locked {
            if AccountStatus::Locked.is_stricter_than(status) {
                status = AccountStatus::Locked;
            }
        } else if status == AccountStatus::Locked {
            status = AccountStatus::Active;
        }
    }

    if let Some(deactivated) = patch.deactivated {
        if deactivated {
            if AccountStatus::Deactivated.is_stricter_than(status) {
                status = AccountStatus::Deactivated;
            }
        } else if status == AccountStatus::Deactivated {
            status = AccountStatus::Active;
        }
    }

    status
}

fn account_status_needs_deactivation_fanout(status: AccountStatus) -> bool {
    matches!(
        status,
        AccountStatus::Deactivated | AccountStatus::ErasurePending
    )
}

fn validate_admin_status_transition(
    current: AccountStatus,
    next: AccountStatus,
) -> Result<(), UserAdminServiceError> {
    // `deactivated -> active` is a protocol-level transition, but it is
    // reserved for the recovery-completion authority path. A generic admin
    // patch carries neither a terminal PCR recovery receipt nor the
    // replacement-device generation fence, so it must never author it.
    if current == AccountStatus::Deactivated && next == AccountStatus::Active {
        return Err(UserAdminServiceError::InvalidStatusTransition {
            from: current,
            to: next,
        });
    }
    if current == next || current.validate_transition_to(next).is_ok() {
        return Ok(());
    }
    Err(UserAdminServiceError::InvalidStatusTransition {
        from: current,
        to: next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_legal_erasure_source_requires_fanout() {
        for source in [
            AccountStatus::Active,
            AccountStatus::SoftLoggedOut,
            AccountStatus::Locked,
            AccountStatus::Suspended,
            AccountStatus::Deactivated,
        ] {
            assert!(source.can_transition_to(AccountStatus::ErasurePending));
            assert_ne!(source, AccountStatus::ErasurePending);
        }
    }

    #[test]
    fn deactivated_account_cannot_be_reactivated() {
        assert!(AccountStatus::Deactivated.can_transition_to(AccountStatus::Active));
        assert!(matches!(
            validate_admin_status_transition(AccountStatus::Deactivated, AccountStatus::Active),
            Err(UserAdminServiceError::InvalidStatusTransition {
                from: AccountStatus::Deactivated,
                to: AccountStatus::Active,
            })
        ));
        validate_admin_status_transition(AccountStatus::Deactivated, AccountStatus::ErasurePending)
            .unwrap();
    }
}
