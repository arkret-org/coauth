use coauth_data::user::{UserEmailRepository, UserPhoneRepository};
use coauth_data::{BoxRepository, RepositoryAccess};
use ulid::Ulid;

use super::*;

pub async fn load_registration_progress(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationProgress, LoadRegistrationProgressError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(LoadRegistrationProgressError::NotFound)?;

    let email_authentication =
        if let Some(email_authentication_id) = registration.email_authentication_id {
            repo.user_email()
                .lookup_authentication(email_authentication_id)
                .await?
        } else {
            None
        };

    let phone_authentication =
        if let Some(phone_authentication_id) = registration.phone_authentication_id {
            repo.user_phone()
                .lookup_authentication(phone_authentication_id)
                .await?
        } else {
            None
        };

    Ok(RegistrationProgress {
        registration,
        email_authentication,
        phone_authentication,
    })
}

pub async fn load_registration_status(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationStatusSummary, LoadRegistrationProgressError> {
    let progress = load_registration_progress(repo, registration_id).await?;
    let workflow = progress.workflow_snapshot();

    let email_pending =
        progress.registration.email_authentication_id.is_some() && !progress.email_verified();
    let pending_email = progress
        .email_authentication
        .as_ref()
        .filter(|auth| auth.completed_at.is_none())
        .map(|auth| auth.email.clone());
    let phone_pending =
        progress.registration.phone_authentication_id.is_some() && !progress.phone_verified();
    let steps_completed = workflow.completed_steps.clone();
    let next_step = workflow.next_step.unwrap_or_else(|| progress.next_step());

    Ok(RegistrationStatusSummary {
        registration: progress.registration,
        email_pending,
        pending_email,
        phone_pending,
        steps_completed,
        next_step,
    })
}
