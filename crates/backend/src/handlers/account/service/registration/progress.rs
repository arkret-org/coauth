use coauth_data::user::{
    UserEmailRepository, UserPhoneRepository, UserRegistrationTokenRepository,
};
use coauth_data::{BoxRepository, Clock, RepositoryAccess, UserRegistration};
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
        workflow,
    })
}

pub async fn load_registration_email_step(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationEmailStepContext, LoadRegistrationEmailStepError> {
    let progress = load_registration_progress(repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => LoadRegistrationEmailStepError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                LoadRegistrationEmailStepError::Repository(error)
            }
        })?;

    let registration = progress.registration;

    if registration.completed_at.is_some() {
        return Err(LoadRegistrationEmailStepError::RegistrationCompleted(
            registration,
        ));
    }

    if registration.email_authentication_id.is_none() {
        return Err(LoadRegistrationEmailStepError::NoEmailAuthentication);
    }

    let email_authentication = progress
        .email_authentication
        .ok_or(LoadRegistrationEmailStepError::EmailAuthenticationMissing)?;

    if email_authentication.completed_at.is_some() {
        return Err(LoadRegistrationEmailStepError::EmailAlreadyVerified);
    }

    Ok(RegistrationEmailStepContext {
        registration,
        email_authentication,
    })
}

pub async fn load_registration_display_name_step(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationDisplayNameStepContext, LoadRegistrationDisplayNameStepError> {
    let progress = load_registration_progress(repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => {
                LoadRegistrationDisplayNameStepError::NotFound
            }
            LoadRegistrationProgressError::Repository(error) => {
                LoadRegistrationDisplayNameStepError::Repository(error)
            }
        })?;

    let registration = progress.registration;

    if registration.completed_at.is_some() {
        return Err(LoadRegistrationDisplayNameStepError::RegistrationCompleted(
            registration,
        ));
    }

    Ok(RegistrationDisplayNameStepContext { registration })
}

pub async fn load_registration_token_step(
    repo: &mut BoxRepository,
    registration_id: Ulid,
) -> Result<RegistrationTokenStepContext, LoadRegistrationTokenStepError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(LoadRegistrationTokenStepError::NotFound)?;

    if registration.completed_at.is_some() {
        return Err(LoadRegistrationTokenStepError::RegistrationCompleted(
            registration,
        ));
    }

    if registration.user_registration_token_id.is_some() {
        return Err(LoadRegistrationTokenStepError::TokenAlreadyAttached(
            registration,
        ));
    }

    Ok(RegistrationTokenStepContext { registration })
}

pub async fn attach_registration_token(
    mut repo: BoxRepository,
    clock: &dyn Clock,
    registration_id: Ulid,
    token: &str,
) -> Result<UserRegistration, AttachRegistrationTokenError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(AttachRegistrationTokenError::NotFound)?;

    if registration.completed_at.is_some() {
        return Err(AttachRegistrationTokenError::RegistrationCompleted(
            registration,
        ));
    }

    if registration.user_registration_token_id.is_some() {
        return Err(AttachRegistrationTokenError::TokenAlreadyAttached(
            registration,
        ));
    }

    let Some(registration_token) = repo.user_registration_token().find_by_token(token).await?
    else {
        return Err(AttachRegistrationTokenError::InvalidToken);
    };

    if !registration_token.is_valid(clock.now()) {
        return Err(AttachRegistrationTokenError::InvalidToken);
    }

    let registration = repo
        .user_registration()
        .set_registration_token(registration, &registration_token)
        .await?;

    repo.save().await?;

    Ok(registration)
}
