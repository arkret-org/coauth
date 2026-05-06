use coauth_data::PostAuthAction;
use crate::salvo_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use coauth_templates::{
    FieldError, RegisterStepsVerifyEmailContext, RegisterStepsVerifyEmailFormField,
    TemplateContext, Templates, ToFormState,
};
use salvo::{prelude::*, writing::Text};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::routing::account::DepotExt;
use crate::routing::{
    account::service::registration::{
        LoadRegistrationEmailStepError, VerifyRegistrationEmailCodeError,
        load_registration_email_step, verify_registration_email_code,
    },
    rest,
    views::context::ViewContext,
    views::shared::OptionalPostAuthAction,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct CodeForm {
    code: String,
}

impl ToFormState for CodeForm {
    type Field = coauth_templates::RegisterStepsVerifyEmailFormField;
}

#[endpoint]
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

    let step = match load_registration_email_step(&mut repo, id).await {
        Ok(step) => step,
        Err(LoadRegistrationEmailStepError::NotFound) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find user registration"
            )));
        }
        Err(LoadRegistrationEmailStepError::RegistrationCompleted(registration)) => {
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
        Err(LoadRegistrationEmailStepError::NoEmailAuthentication)
        | Err(LoadRegistrationEmailStepError::EmailAuthenticationMissing) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "No email authentication started for this registration"
            )));
        }
        Err(LoadRegistrationEmailStepError::EmailAlreadyVerified) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Email authentication already completed"
            )));
        }
        Err(LoadRegistrationEmailStepError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    let ctx = RegisterStepsVerifyEmailContext::new(step.email_authentication)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register_steps_verify_email(&ctx)?;

    cookie_jar.finalize(res, Text::Html(content));
    Ok(())
}

#[endpoint]
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
        mut repo,
        cookie_jar,
    } = ViewContext::extract(req, depot).await?;
    let limiter = depot.limiter()?;
    let id: Ulid = req.param("id").unwrap_or_default();
    let form: ProtectedForm<CodeForm> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    let form = cookie_jar.verify_form(&clock, form)?;

    let step = match load_registration_email_step(&mut repo, id).await {
        Ok(step) => step,
        Err(LoadRegistrationEmailStepError::NotFound) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find user registration"
            )));
        }
        Err(LoadRegistrationEmailStepError::RegistrationCompleted(registration)) => {
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
        Err(LoadRegistrationEmailStepError::NoEmailAuthentication)
        | Err(LoadRegistrationEmailStepError::EmailAuthenticationMissing) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find email authentication"
            )));
        }
        Err(LoadRegistrationEmailStepError::EmailAlreadyVerified) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Email authentication already completed"
            )));
        }
        Err(LoadRegistrationEmailStepError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    let registration = step.registration.clone();
    let email_authentication = step.email_authentication;

    match verify_registration_email_code(repo, &limiter, &clock, id, &form.code).await {
        Ok(_) => {}
        Err(VerifyRegistrationEmailCodeError::RateLimited) => {
            let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
            let ctx = RegisterStepsVerifyEmailContext::new(email_authentication)
                .with_form_state(
                    form.to_form_state()
                        .with_error_on_form(coauth_templates::FormError::RateLimitExceeded),
                )
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            let content = templates.render_register_steps_verify_email(&ctx)?;

            cookie_jar.finalize(res, Text::Html(content));
            return Ok(());
        }
        Err(VerifyRegistrationEmailCodeError::InvalidCode) => {
            let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
            let ctx = RegisterStepsVerifyEmailContext::new(email_authentication)
                .with_form_state(form.to_form_state().with_error_on_field(
                    RegisterStepsVerifyEmailFormField::Code,
                    FieldError::Invalid,
                ))
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            let content = templates.render_register_steps_verify_email(&ctx)?;

            cookie_jar.finalize(res, Text::Html(content));
            return Ok(());
        }
        Err(VerifyRegistrationEmailCodeError::RegistrationCompleted) => {
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
        Err(VerifyRegistrationEmailCodeError::NotFound)
        | Err(VerifyRegistrationEmailCodeError::NoEmailAuthentication)
        | Err(VerifyRegistrationEmailCodeError::EmailAuthenticationMissing) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find email authentication"
            )));
        }
        Err(VerifyRegistrationEmailCodeError::EmailAlreadyVerified) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Email authentication already completed"
            )));
        }
        Err(VerifyRegistrationEmailCodeError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    }

    cookie_jar.finalize(
        res,
        salvo::writing::Redirect::other(
            &url_builder.relative_url(&format!("/register/steps/{}/finish", registration.id)),
        ),
    );
    Ok(())
}
