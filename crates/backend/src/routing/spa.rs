//! SPA shell handler — serves the Dioxus frontend HTML wrapper.
//!
//! This handler renders the `app.html` template, which loads the Dioxus WASM
//! frontend. The client-side router then handles all page routing.

use coauth_templates::{AppContext, TemplateContext};
use salvo::{prelude::*, writing::Text};

use crate::{routing::account::DepotExt, salvo_utils::InternalError};

/// Serve the SPA shell for anonymous (public) pages.
///
/// Used for login, registration, recovery, consent, and all other user-facing
/// pages that are handled by the Dioxus frontend.
#[endpoint]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let locale = crate::routing::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let script_src = depot.frontend_script_src()?;

    let ctx = AppContext::new(&url_builder, &script_src).with_language(locale);
    let content = templates.render_app(&ctx)?;

    res.render(Text::Html(content));
    Ok(())
}
