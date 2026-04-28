use anyhow::Context as _;
use coauth_data::PostAuthAction;
use crate::salvo_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt as _, ProtectedForm},
};
use coauth_templates::{
    FieldError, RegisterStepsRegistrationTokenContext, RegisterStepsRegistrationTokenFormField,
    TemplateContext as _, Templates, ToFormState,
};
use salvo::{prelude::*, writing::Text};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::handlers::{
    account::service::registration::{
        AttachRegistrationTokenError, LoadRegistrationTokenStepError, attach_registration_token,
        load_registration_token_step,
    },
    rest,
    views::context::ViewContext,
    views::shared::OptionalPostAuthAction,
};

#[derive(Deserialize, Serialize)]
pub(crate) struct RegistrationTokenForm {
    #[serde(default)]
    token: String,
}

impl ToFormState for RegistrationTokenForm {
    type Field = coauth_templates::RegisterStepsRegistrationTokenFormField;
}

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let ViewContext {
        mut rng,
        clock,
        locale,
        site_config: _,
        templates,
        url_builder,
        mut repo,
        cookie_jar,
    } = ViewContext::extract(req, depot).await?;
    let id: Ulid = req.param("id").unwrap_or_default();

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    match load_registration_token_step(&mut repo, id).await {
        Ok(_) => {}
        Err(LoadRegistrationTokenStepError::NotFound) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find user registration"
            )));
        }
        Err(LoadRegistrationTokenStepError::RegistrationCompleted(registration)) => {
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
        Err(LoadRegistrationTokenStepError::TokenAlreadyAttached(registration)) => {
            cookie_jar.finalize(
                res,
                salvo::writing::Redirect::other(
                    &url_builder
                        .relative_url(&format!("/register/steps/{}/display-name", registration.id)),
                ),
            );
            return Ok(());
        }
        Err(LoadRegistrationTokenStepError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    }

    let ctx = RegisterStepsRegistrationTokenContext::new()
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register_steps_registration_token(&ctx)?;

    cookie_jar.finalize(res, Text::Html(content));
    Ok(())
}

#[handler]
pub async fn post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let ViewContext {
        mut rng,
        clock,
        locale,
        site_config: _,
        templates,
        url_builder,
        repo,
        cookie_jar,
    } = ViewContext::extract(req, depot).await?;
    let mut repo = repo;
    let id: Ulid = req.param("id").unwrap_or_default();
    let form: ProtectedForm<RegistrationTokenForm> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    match load_registration_token_step(&mut repo, id).await {
        Ok(_) => {}
        Err(LoadRegistrationTokenStepError::NotFound) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find user registration"
            )));
        }
        Err(LoadRegistrationTokenStepError::RegistrationCompleted(registration)) => {
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
        Err(LoadRegistrationTokenStepError::TokenAlreadyAttached(registration)) => {
            cookie_jar.finalize(
                res,
                salvo::writing::Redirect::other(
                    &url_builder
                        .relative_url(&format!("/register/steps/{}/display-name", registration.id)),
                ),
            );
            return Ok(());
        }
        Err(LoadRegistrationTokenStepError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    // Validate the token
    let token = form.token.trim();
    if token.is_empty() {
        let ctx = RegisterStepsRegistrationTokenContext::new()
            .with_form_state(form.to_form_state().with_error_on_field(
                RegisterStepsRegistrationTokenFormField::Token,
                FieldError::Required,
            ))
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        cookie_jar.finalize(
            res,
            Text::Html(templates.render_register_steps_registration_token(&ctx)?),
        );
        return Ok(());
    }

    let registration = match attach_registration_token(repo, &clock, id, token).await {
        Ok(registration) => registration,
        Err(AttachRegistrationTokenError::InvalidToken) => {
            let ctx = RegisterStepsRegistrationTokenContext::new()
                .with_form_state(form.to_form_state().with_error_on_field(
                    RegisterStepsRegistrationTokenFormField::Token,
                    FieldError::Invalid,
                ))
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            cookie_jar.finalize(
                res,
                Text::Html(templates.render_register_steps_registration_token(&ctx)?),
            );
            return Ok(());
        }
        Err(AttachRegistrationTokenError::RegistrationCompleted(registration)) => {
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
        Err(AttachRegistrationTokenError::TokenAlreadyAttached(registration)) => {
            cookie_jar.finalize(
                res,
                salvo::writing::Redirect::other(
                    &url_builder
                        .relative_url(&format!("/register/steps/{}/display-name", registration.id)),
                ),
            );
            return Ok(());
        }
        Err(AttachRegistrationTokenError::NotFound) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find user registration"
            )));
        }
        Err(AttachRegistrationTokenError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    // Continue to the next step
    cookie_jar.finalize(
        res,
        salvo::writing::Redirect::other(
            &url_builder.relative_url(&format!("/register/steps/{}/finish", registration.id)),
        ),
    );
    Ok(())
}
