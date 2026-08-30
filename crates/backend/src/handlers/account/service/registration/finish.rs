use anyhow::Error as AnyhowError;
use chrono::Duration;
use coauth_data::queue::{ProvisionUserJob, QueueJobRepositoryExt as _};
use coauth_data::upstream_oauth::{UpstreamOAuthLinkRepository, UpstreamOAuthSessionRepository};
use coauth_data::user::{
    BrowserSessionRepository, UserEmailFilter, UserEmailRepository, UserPasswordRepository,
    UserPhoneRepository, UserRegistrationTokenRepository, UserRepository, UserTermsRepository,
};
use coauth_data::{BoxRepository, Clock, RepositoryAccess, RepositoryError, UserRegistration};
use coauth_principal::ConnectorAdmin;
use rand_chacha::rand_core::CryptoRngCore;
use ulid::Ulid;

use super::*;

pub async fn check_registration_finish_eligibility(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    station: &dyn ConnectorAdmin,
    registration: &UserRegistration,
    browser_session_present: Option<bool>,
) -> Result<(), CheckRegistrationFinishEligibilityError> {
    if clock.now() - registration.created_at > Duration::hours(1) {
        return Err(CheckRegistrationFinishEligibilityError::RegistrationExpired);
    }

    if let Some(false) = browser_session_present {
        return Err(CheckRegistrationFinishEligibilityError::BrowserSessionMissing);
    }

    if repo.user().exists(&registration.localpart).await? {
        return Err(CheckRegistrationFinishEligibilityError::HandleTaken);
    }

    match station.is_handle_available(&registration.localpart).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(CheckRegistrationFinishEligibilityError::HandleNotAvailable),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "Failed to check username availability during finish, skipping Station check"
            );
            Ok(())
        }
    }
}

pub async fn load_registration_finish_preparation(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    station: &dyn ConnectorAdmin,
    registration_id: Ulid,
    browser_session_present: Option<bool>,
    registration_token_required: bool,
) -> Result<PreparedRegistrationCompletion, LoadRegistrationFinishPreparationError> {
    let progress = load_registration_progress(repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => {
                LoadRegistrationFinishPreparationError::NotFound
            }
            LoadRegistrationProgressError::Repository(error) => {
                LoadRegistrationFinishPreparationError::Repository(error)
            }
        })?;

    let registration = progress.registration.clone();

    if registration.completed_at.is_some() {
        return Err(LoadRegistrationFinishPreparationError::AlreadyCompleted);
    }

    check_registration_finish_eligibility(
        repo,
        clock,
        station,
        &registration,
        browser_session_present,
    )
    .await
    .map_err(LoadRegistrationFinishPreparationError::Eligibility)?;

    prepare_registration_completion(repo, clock, progress, registration_token_required)
        .await
        .map_err(LoadRegistrationFinishPreparationError::Prepare)
}

pub async fn prepare_registration_completion(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    progress: RegistrationProgress,
    registration_token_required: bool,
) -> Result<PreparedRegistrationCompletion, PrepareRegistrationCompletionError> {
    let registration = progress.registration;

    let registration_token = if registration_token_required {
        if let Some(registration_token_id) = registration.user_registration_token_id {
            let registration_token = repo
                .user_registration_token()
                .lookup(registration_token_id)
                .await?
                .ok_or(PrepareRegistrationCompletionError::RegistrationTokenMissing)?;

            if !registration_token.is_valid(clock.now()) {
                return Err(PrepareRegistrationCompletionError::RegistrationTokenInvalid);
            }

            Some(registration_token)
        } else {
            return Err(PrepareRegistrationCompletionError::RegistrationTokenRequired);
        }
    } else {
        None
    };

    let email_authentication = if registration.email_authentication_id.is_some() {
        let email_authentication = progress
            .email_authentication
            .ok_or(PrepareRegistrationCompletionError::EmailAuthenticationMissing)?;

        if email_authentication.completed_at.is_none() {
            return Err(PrepareRegistrationCompletionError::EmailNotVerified);
        }

        if repo
            .user_email()
            .count(UserEmailFilter::new().for_email(&email_authentication.email))
            .await?
            > 0
        {
            return Err(PrepareRegistrationCompletionError::EmailInUse(
                email_authentication.email.clone(),
            ));
        }

        Some(email_authentication)
    } else {
        None
    };

    let phone_authentication = if registration.phone_authentication_id.is_some() {
        let phone_authentication = progress
            .phone_authentication
            .ok_or(PrepareRegistrationCompletionError::PhoneAuthenticationMissing)?;

        if phone_authentication.completed_at.is_none() {
            return Err(PrepareRegistrationCompletionError::PhoneNotVerified);
        }

        if repo
            .user_phone()
            .find_by_phone(&phone_authentication.phone)
            .await?
            .is_some()
        {
            return Err(PrepareRegistrationCompletionError::PhoneInUse);
        }

        Some(phone_authentication)
    } else {
        None
    };

    let upstream_oauth = if let Some(upstream_oauth_authorization_session_id) =
        registration.upstream_oauth_authorization_session_id
    {
        let upstream_oauth_authorization_session = repo
            .upstream_oauth_session()
            .lookup(upstream_oauth_authorization_session_id)
            .await?
            .ok_or(PrepareRegistrationCompletionError::UpstreamOAuthSessionMissing)?;

        let link_id = upstream_oauth_authorization_session
            .link_id()
            .ok_or(PrepareRegistrationCompletionError::UpstreamOAuthLinkMissing)?;

        let upstream_oauth_link = repo
            .upstream_oauth_link()
            .lookup(link_id)
            .await?
            .ok_or(PrepareRegistrationCompletionError::UpstreamOAuthLinkMissing)?;

        if upstream_oauth_link.user_id.is_some() {
            return Err(PrepareRegistrationCompletionError::UpstreamOAuthLinkAlreadyUsed);
        }

        Some((upstream_oauth_authorization_session, upstream_oauth_link))
    } else {
        None
    };

    if registration.display_name.is_none() {
        return Err(PrepareRegistrationCompletionError::DisplayNameRequired);
    }

    Ok(PreparedRegistrationCompletion {
        registration,
        registration_token,
        email_authentication,
        phone_authentication,
        upstream_oauth,
    })
}

pub async fn complete_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    request: CompleteRegistrationRequestBody,
    grant_admin: bool,
) -> Result<CompletedRegistration, RepositoryError> {
    let registration = repo
        .user_registration()
        .complete(clock, request.registration)
        .await?;

    if let Some(registration_token) = request.registration_token {
        repo.user_registration_token()
            .use_token(clock, registration_token)
            .await?;
    }

    let mut user = repo
        .user()
        .add(rng, clock, registration.localpart.clone())
        .await?;

    if grant_admin {
        user = repo.user().set_can_request_admin(user, true).await?;
    }

    // Mirror the registration's display_name / avatar_url onto coauth's
    // local user record so the account UI ("Edit profile") shows them
    // immediately, before the async Station-provision job runs.
    if registration.display_name.is_some() || registration.avatar_url.is_some() {
        let profile_patch = coauth_data::UserProfilePatch {
            display_name: registration.display_name.clone().map(Some),
            avatar_url: registration.avatar_url.clone().map(Some),
            preferred_locale: None,
        };
        user = repo
            .user()
            .update_profile(clock, user, profile_patch)
            .await?;
    }

    let user_session = repo
        .browser_session()
        .add(rng, clock, &user, request.user_agent)
        .await?;

    if let Some(email_authentication) = request.email_authentication {
        repo.user_email()
            .add(rng, clock, &user, email_authentication.email)
            .await?;
    }

    if let Some(phone_authentication) = request.phone_authentication {
        repo.user_phone()
            .add(rng, clock, &user, phone_authentication.phone)
            .await?;
    }

    if let Some(password) = registration.password.clone() {
        let user_password = repo
            .user_password()
            .add(
                rng,
                clock,
                &user,
                password.version,
                password.hashed_password,
                None,
            )
            .await?;

        repo.browser_session()
            .authenticate_with_password(rng, clock, &user_session, &user_password)
            .await?;
    }

    if let Some((upstream_session, upstream_link)) = request.upstream_oauth {
        let upstream_session = repo
            .upstream_oauth_session()
            .consume(clock, upstream_session, &user_session)
            .await?;

        repo.upstream_oauth_link()
            .associate_to_user(&upstream_link, &user)
            .await?;

        repo.browser_session()
            .authenticate_with_upstream(rng, clock, &user_session, &upstream_session)
            .await?;
    }

    if let Some(terms_url) = registration.terms_url.clone() {
        repo.user_terms()
            .accept_terms(rng, clock, &user, terms_url)
            .await?;
    }

    let mut job = ProvisionUserJob::new(&user);
    if let Some(display_name) = registration.display_name.clone() {
        job = job.set_display_name(display_name);
    }
    if let Some(avatar_url) = registration.avatar_url.clone() {
        job = job.set_avatar_url(avatar_url);
    }
    if user.can_request_admin {
        job = job.set_admin();
    }
    repo.queue_job().schedule_job(rng, clock, job).await?;

    repo.save().await?;

    Ok(CompletedRegistration {
        registration,
        user_session,
    })
}

pub async fn finish_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    station: &dyn ConnectorAdmin,
    registration_id: Ulid,
    browser_session_present: Option<bool>,
    registration_token_required: bool,
    configured_bootstrap_admin_token: Option<&str>,
    requested_bootstrap_admin_token: Option<String>,
    user_agent: Option<String>,
) -> Result<RegistrationFinishOutcome, RegistrationFinishError> {
    let prepared = match load_registration_finish_preparation(
        &mut repo,
        clock,
        station,
        registration_id,
        browser_session_present,
        registration_token_required,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(LoadRegistrationFinishPreparationError::NotFound) => {
            return Err(RegistrationFinishError::NotFound);
        }
        Err(LoadRegistrationFinishPreparationError::AlreadyCompleted) => {
            return Ok(RegistrationFinishOutcome::Rejected {
                error: "registration_already_completed",
            });
        }
        Err(LoadRegistrationFinishPreparationError::Eligibility(source)) => match source {
            CheckRegistrationFinishEligibilityError::RegistrationExpired => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "registration_expired",
                });
            }
            CheckRegistrationFinishEligibilityError::HandleTaken => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "handle_taken",
                });
            }
            CheckRegistrationFinishEligibilityError::HandleNotAvailable => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "handle_not_available",
                });
            }
            CheckRegistrationFinishEligibilityError::BrowserSessionMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Registration browser session is required",
                )));
            }
            CheckRegistrationFinishEligibilityError::Repository(error) => {
                return Err(RegistrationFinishError::Repository(error));
            }
        },
        Err(LoadRegistrationFinishPreparationError::Prepare(source)) => match source {
            PrepareRegistrationCompletionError::RegistrationTokenRequired => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "registration_token_required",
                });
            }
            PrepareRegistrationCompletionError::RegistrationTokenInvalid => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "registration_token_invalid",
                });
            }
            PrepareRegistrationCompletionError::EmailNotVerified => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "email_not_verified",
                });
            }
            PrepareRegistrationCompletionError::EmailInUse(_) => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "email_in_use",
                });
            }
            PrepareRegistrationCompletionError::PhoneNotVerified => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "phone_not_verified",
                });
            }
            PrepareRegistrationCompletionError::PhoneInUse => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "phone_in_use",
                });
            }
            PrepareRegistrationCompletionError::DisplayNameRequired => {
                return Ok(RegistrationFinishOutcome::Rejected {
                    error: "display_name_required",
                });
            }
            PrepareRegistrationCompletionError::RegistrationTokenMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the registration token",
                )));
            }
            PrepareRegistrationCompletionError::EmailAuthenticationMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the email authentication",
                )));
            }
            PrepareRegistrationCompletionError::PhoneAuthenticationMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the phone authentication",
                )));
            }
            PrepareRegistrationCompletionError::UpstreamOAuthSessionMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the upstream OAuth authorization session",
                )));
            }
            PrepareRegistrationCompletionError::UpstreamOAuthLinkMissing => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "Could not load the upstream OAuth link",
                )));
            }
            PrepareRegistrationCompletionError::UpstreamOAuthLinkAlreadyUsed => {
                return Err(RegistrationFinishError::Internal(AnyhowError::msg(
                    "The upstream identity was already linked to a user",
                )));
            }
            PrepareRegistrationCompletionError::Repository(error) => {
                return Err(RegistrationFinishError::Repository(error));
            }
        },
        Err(LoadRegistrationFinishPreparationError::Repository(error)) => {
            return Err(RegistrationFinishError::Repository(error));
        }
    };

    let grant_admin = match prepare_admin_bootstrap(
        &mut repo,
        configured_bootstrap_admin_token,
        requested_bootstrap_admin_token.as_deref(),
    )
    .await
    {
        Ok(grant_admin) => grant_admin,
        Err(PrepareAdminBootstrapError::InvalidToken) => {
            return Ok(RegistrationFinishOutcome::Rejected {
                error: "bootstrap_admin_token_invalid",
            });
        }
        Err(PrepareAdminBootstrapError::Repository(error)) => {
            return Err(RegistrationFinishError::Repository(error));
        }
    };

    let completed = match complete_registration(
        repo,
        rng,
        clock,
        prepared.into_request(user_agent),
        grant_admin,
    )
    .await
    {
        Ok(completed) => completed,
        // A concurrent finish claimed the same handle between the eligibility
        // check and the user insert. The unique constraint on the localpart
        // rejects the loser; report it as a clean `handle_taken` instead of a
        // generic repository 500.
        Err(error) if error.is_unique_violation() => {
            return Ok(RegistrationFinishOutcome::Rejected {
                error: "handle_taken",
            });
        }
        Err(error) => return Err(RegistrationFinishError::Repository(error)),
    };

    Ok(RegistrationFinishOutcome::Completed(completed))
}
