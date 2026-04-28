use std::sync::LazyLock;

use opentelemetry::metrics::Counter;
use coauth_data::PostAuthAction;
use crate::salvo_utils::{
    InternalError, SessionInfoExt as _,
    cookies::TimedCookie,
};
use coauth_templates::{RegisterStepsEmailInUseContext, TemplateContext as _, Templates};
use salvo::{prelude::*, writing::Text};
use ulid::Ulid;

use super::super::cookie::UserRegistrationSessions;
use crate::handlers::account::DepotExt;
use crate::handlers::{
    METER,
    account::service::registration::{
        LoadRegistrationFinishPreparationError, complete_registration,
        load_registration_finish_preparation,
    },
    rest,
    views::context::ViewContext,
    views::shared::OptionalPostAuthAction,
};

static PASSWORD_REGISTER_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.user.password_registration")
        .with_description("Number of password registrations")
        .with_unit("{registration}")
        .build()
});

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let ViewContext {
        mut rng,
        clock,
        locale: lang,
        site_config,
        templates,
        url_builder,
        mut repo,
        cookie_jar,
    } = ViewContext::extract(req, depot).await?;
    let homeserver = depot.homeserver()?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());
    let id: Ulid = req.param("id").unwrap_or_default();
    let registrations = UserRegistrationSessions::load(&cookie_jar);
    let prepared = match load_registration_finish_preparation(
        &mut repo,
        &clock,
        homeserver.as_ref(),
        id,
        Some(registrations.contains_id(id)),
        crate::handlers::account::service::registration::HomeserverCheckMode::Strict,
        site_config.registration_token_required,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(LoadRegistrationFinishPreparationError::NotFound) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "User registration not found"
            )));
        }
        Err(LoadRegistrationFinishPreparationError::AlreadyCompleted(registration)) => {
            let post_auth_action: Option<PostAuthAction> = registration
                .post_auth_action
                .map(serde_json::from_value)
                .transpose()?;

            cookie_jar.finalize(
                res,
                OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder),
            );
            return Ok(());
        }
        Err(LoadRegistrationFinishPreparationError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
        Err(LoadRegistrationFinishPreparationError::Eligibility { source, .. }) => match source {
            crate::handlers::account::service::registration::CheckRegistrationFinishEligibilityError::RegistrationExpired => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Registration session has expired"
                )));
            }
            crate::handlers::account::service::registration::CheckRegistrationFinishEligibilityError::BrowserSessionMissing => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Could not find the registration in the browser cookies"
                )));
            }
            crate::handlers::account::service::registration::CheckRegistrationFinishEligibilityError::UsernameTaken => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Username is already taken"
                )));
            }
            crate::handlers::account::service::registration::CheckRegistrationFinishEligibilityError::UsernameNotAvailable => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Username is not available"
                )));
            }
            crate::handlers::account::service::registration::CheckRegistrationFinishEligibilityError::HomeserverUnavailable(error) => {
                return Err(InternalError::from_anyhow(error));
            }
            crate::handlers::account::service::registration::CheckRegistrationFinishEligibilityError::Repository(error) => {
                return Err(InternalError::from_anyhow(error.into()));
            }
        },
        Err(LoadRegistrationFinishPreparationError::Prepare {
            registration,
            source,
        }) => match source {
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::RegistrationTokenRequired => {
                cookie_jar.finalize(
                    res,
                    salvo::writing::Redirect::other(
                        &url_builder.relative_url(&format!("/register/steps/{}/token", registration.id)),
                    ),
                );
                return Ok(());
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::EmailNotVerified => {
                cookie_jar.finalize(
                    res,
                    salvo::writing::Redirect::other(
                        &url_builder.relative_url(&format!("/register/steps/{}/verify-email", registration.id)),
                    ),
                );
                return Ok(());
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::EmailInUse(email) => {
                let action = registration
                    .post_auth_action
                    .clone()
                    .map(serde_json::from_value)
                    .transpose()?;

                let ctx = RegisterStepsEmailInUseContext::new(email, action).with_language(lang);

                cookie_jar.finalize(
                    res,
                    Text::Html(templates.render_register_steps_email_in_use(&ctx)?),
                );
                return Ok(());
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::DisplayNameRequired => {
                cookie_jar.finalize(
                    res,
                    salvo::writing::Redirect::other(
                        &url_builder.relative_url(&format!("/register/steps/{}/display-name", registration.id)),
                    ),
                );
                return Ok(());
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::RegistrationTokenMissing => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Could not load the registration token"
                )));
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::RegistrationTokenInvalid => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Registration token used is no longer valid"
                )));
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::EmailAuthenticationMissing => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Could not load the email authentication"
                )));
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::PhoneAuthenticationMissing => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Could not load the phone authentication"
                )));
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::PhoneNotVerified => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Phone verification is not complete"
                )));
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::PhoneInUse => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Phone number is already in use"
                )));
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::UpstreamOAuthSessionMissing => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Could not load the upstream OAuth authorization session"
                )));
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::UpstreamOAuthLinkMissing => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Could not load the upstream OAuth link"
                )));
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::UpstreamOAuthLinkAlreadyUsed => {
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "The upstream identity was already linked to a user. Try logging in again"
                )));
            }
            crate::handlers::account::service::registration::PrepareRegistrationCompletionError::Repository(error) => {
                return Err(InternalError::from_anyhow(error.into()));
            }
        },
    };

    // Consume the registration session
    let cookie_jar = registrations
        .consume_session(&prepared.registration)?
        .save(cookie_jar, &clock);

    let completed = complete_registration(
        repo,
        &mut rng,
        &clock,
        prepared.into_request(user_agent),
        false,
    )
    .await?;

    if completed.password_authenticated {
        PASSWORD_REGISTER_COUNTER.add(1, &[]);
    }

    activity_tracker
        .record_browser_session(&clock, &completed.user_session)
        .await;

    let post_auth_action: Option<PostAuthAction> = completed
        .registration
        .post_auth_action
        .map(serde_json::from_value)
        .transpose()?;

    // Login the user with the session we just created
    let cookie_jar = cookie_jar.set_session(&completed.user_session);

    cookie_jar.finalize(
        res,
        OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder),
    );
    Ok(())
}
