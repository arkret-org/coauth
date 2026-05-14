use crate::handlers::account::DepotExt;
use coauth_data::Clock;
use crate::salvo_utils::InternalError;
use coauth_templates::{
    DeviceLinkContext, DeviceLinkFormField, FieldError, FormState, TemplateContext,
};
use salvo::{prelude::*, writing::Text};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
pub struct Params {
    #[serde(default)]
    code: Option<String>,
}

#[handler]
#[tracing::instrument(name = "handlers.oauth.device.link.get", skip_all)]
pub async fn get(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_get(req, depot, res).await {
        Ok(()) => {}
        Err(e) => e.render(res),
    }
}

async fn handle_get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let clock = crate::handlers::account::make_clock();
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let mut repo = depot.repo().await?;
    let cookie_jar = depot.cookie_jar(req)?;
    let locale = crate::handlers::preferred_language(req, depot);

    let query: Params = req.parse_queries().unwrap_or_default();

    let mut form_state = FormState::from_form(&query);

    // If we have a code in query, find it in the database
    if let Some(code) = &query.code {
        // Find the code in the database
        let code = code.to_uppercase();
        let grant = repo
            .oauth_device_code_grant()
            .find_by_user_code(&code)
            .await?
            // XXX: We should have different error messages for already exchanged and expired
            .filter(|grant| grant.is_pending())
            .filter(|grant| grant.expires_at > clock.now());

        if let Some(grant) = grant {
            // This is a valid code, redirect to the consent page
            // This will in turn redirect to the login page if the user is not logged in
            let redirect = salvo::writing::Redirect::other(&url_builder.relative_url(
                &format!("/device/{}", grant.id),
            ));

            cookie_jar.finalize(res, redirect);
            return Ok(());
        }

        // The code isn't valid, set an error on the form
        form_state = form_state.with_error_on_field(DeviceLinkFormField::Code, FieldError::Invalid);
    }

    // Render the form
    let ctx = DeviceLinkContext::new()
        .with_form_state(form_state)
        .with_language(locale);

    let content = templates.render_device_link(&ctx)?;

    cookie_jar.finalize(res, Text::Html(content));
    Ok(())
}
