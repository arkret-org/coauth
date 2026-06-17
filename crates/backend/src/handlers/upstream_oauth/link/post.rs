use opentelemetry::KeyValue;
use crate::salvo_utils::{
    SessionInfoExt,
    cookies::TimedCookie,
    csrf::{CsrfExt, ProtectedForm},
};
use coauth_data::{
    RepositoryAccess,
    upstream_oauth::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
};
use coauth_templates::{
    FieldError, FormError, TemplateContext, ToFormState, UpstreamRegister,
};
use salvo::prelude::*;
use ulid::Ulid;

use super::{FormData, PROVIDER, REGISTRATION_COUNTER, RouteError, UpstreamSessionsCookie};
use crate::handlers::{
    common::DepotExt,
    upstream_oauth::link_workflow::{
        SubmitUpstreamLinkError, SubmitUpstreamLinkOutcome, UpstreamLinkAction,
        UpstreamLinkRegistrationAction, load_upstream_link_context, submit_upstream_link_action,
    },
    account::registration_cookie::UserRegistrationSessions as UserRegistrationSessionsCookie,
};

#[handler]
#[tracing::instrument(name = "handlers.upstream_oauth.link.post", skip_all)]
pub async fn post(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let link_id: Ulid = req.param("link_id").ok_or(RouteError::LinkNotFound)?;
    let mut rng = crate::handlers::account::make_rng();
    let clock = crate::handlers::account::make_clock();
    let mut repo = depot.repo().await?;
    let cookie_jar = depot.cookie_jar(req)?;
    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let policy_factory = depot.policy_factory()?;
    let mut policy = policy_factory.instantiate().await?;
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let principal_server = depot.principal_server()?;
    let url_builder = depot.url_builder()?;
    let site_config = depot.site_config()?;
    let ip_address = crate::handlers::account::extract_bound_activity_tracker(req, depot).ip();

    let form: ProtectedForm<FormData> = req.parse_form().await?;
    let form = cookie_jar.verify_form(&clock, form)?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let form_state = form.to_form_state();

    let context =
        load_upstream_link_context(&mut repo, &session_info, &sessions_cookie, link_id).await?;

    let action = match form {
        FormData::Link => UpstreamLinkAction::LinkCurrentSession,
        FormData::Register {
            username,
            import_email,
            import_display_name,
            accept_terms,
        } => UpstreamLinkAction::Register(UpstreamLinkRegistrationAction {
            username,
            import_email: import_email.is_some(),
            import_display_name: import_display_name.is_some(),
            accept_terms: accept_terms.is_some(),
        }),
    };

    let outcome = submit_upstream_link_action(
        &mut repo,
        &mut *rng,
        &*clock,
        &url_builder,
        &*principal_server,
        &mut policy,
        &site_config,
        user_agent,
        ip_address,
        context,
        action,
    )
    .await;

    match outcome {
        Ok(SubmitUpstreamLinkOutcome::Linked {
            session,
            redirect_url,
        }) => {
            let cookie_jar = sessions_cookie
                .consume_link(link_id)?
                .save(cookie_jar, &clock)
                .set_session(&session);

            repo.save().await?;

            cookie_jar.finalize(res, Redirect::other(&redirect_url));
            Ok(())
        }

        Ok(SubmitUpstreamLinkOutcome::Registered {
            registration,
            redirect_url: _,
            provider_id,
        }) => {
            let registrations = UserRegistrationSessionsCookie::load(&cookie_jar);
            let cookie_jar = sessions_cookie
                .consume_link(link_id)?
                .save(cookie_jar, &clock);
            let cookie_jar = registrations.add(&registration).save(cookie_jar, &clock);

            repo.save().await?;

            REGISTRATION_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider_id.to_string())]);

            cookie_jar.finalize(
                res,
                salvo::writing::Redirect::other(
                    &url_builder.relative_url(&format!("/register/steps/{}/finish", registration.id)),
                ),
            );
            Ok(())
        }

        Err(SubmitUpstreamLinkError::InvalidAction) => Err(RouteError::InvalidFormAction),

        Err(SubmitUpstreamLinkError::Validation { field_errors }) => {
            // Re-render the registration form with validation errors.
            // We need to re-load the link and provider to rebuild the template context.
            let link = repo
                .upstream_oauth_link()
                .lookup(link_id)
                .await?
                .ok_or(RouteError::LinkNotFound)?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or_else(|| {
                    RouteError::Internal(
                        format!("Provider {} not found for validation re-render", link.provider_id)
                            .into(),
                    )
                })?;

            let mut form_state = form_state;
            if let Some(errors) = field_errors.as_object() {
                for (field, code) in errors {
                    let code_str = code.as_str().unwrap_or("unknown");
                    match field.as_str() {
                        "username" => {
                            let error = match code_str {
                                "required" => FieldError::Required,
                                "exists" => FieldError::Exists,
                                _ => FieldError::Policy {
                                    code: None,
                                    message: code_str.to_owned(),
                                },
                            };
                            form_state.add_error_on_field(
                                coauth_templates::UpstreamRegisterFormField::Username,
                                error,
                            );
                        }
                        "accept_terms" => {
                            form_state.add_error_on_field(
                                coauth_templates::UpstreamRegisterFormField::AcceptTerms,
                                FieldError::Required,
                            );
                        }
                        _ => {
                            form_state.add_error_on_form(FormError::Policy {
                                code: None,
                                message: code_str.to_owned(),
                            });
                        }
                    }
                }
            }

            let ctx = UpstreamRegister::new(link, provider)
                .with_form_state(form_state)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            cookie_jar.finalize(
                res,
                Text::Html(templates.render_upstream_oauth_do_register(&ctx)?),
            );
            Ok(())
        }

        Err(SubmitUpstreamLinkError::Workflow(e)) => Err(e.into()),
    }
}
