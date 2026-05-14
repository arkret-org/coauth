//! Shared render helper for both `GET /login` and `POST /login`, plus the
//! `login_hint` interpretation logic that turns an inbound username/email
//! login hint into a pre-filled form value.

use coauth_data::{
    Clock, RepositoryAccess, SiteConfig,
    oauth::LoginHint,
};
use coauth_i18n::DataLocale;
use coauth_principal::PrincipalServerAdmin;
use coauth_templates::{
    FormState, LoginContext, LoginFormField, PostAuthContext, PostAuthContextInner,
    TemplateContext, Templates,
};
use rand_core::RngCore as Rng;
use salvo::{prelude::*, writing::Text};

use crate::handlers::account::service::access::load_enabled_upstream_providers;
use crate::handlers::views::shared::OptionalPostAuthAction;
use crate::salvo_utils::{InternalError, csrf::CsrfExt};
use crate::salvo_utils::cookies::CookieJar;

/// Apply a login hint coming from an in-flight authorization grant to the
/// `LoginContext`. The hint pre-fills the username field unless the user
/// has already typed something on a previous failed attempt.
pub(super) fn handle_login_hint(
    mut ctx: LoginContext,
    next: &PostAuthContext,
    _principal_server: &dyn PrincipalServerAdmin,
    site_config: &SiteConfig,
) -> LoginContext {
    let form_state = ctx.form_state_mut();

    // Do not override username if coming from a failed login attempt
    if form_state.has_value(LoginFormField::Username) {
        return ctx;
    }

    if let PostAuthContextInner::ContinueAuthorizationGrant { ref grant } = next.ctx {
        let value = match grant.parse_login_hint() {
            LoginHint::Username(username) => Some(username.to_owned()),
            LoginHint::Email(email) if site_config.login_with_email_allowed => {
                Some(email.to_string())
            }
            _ => None,
        };
        form_state.set_value(LoginFormField::Username, value);
    }

    ctx
}

/// Render the login template, mounting the supplied form state and any
/// upstream-provider list. Used by both the GET path (initial render +
/// validation errors) and the POST path (re-render after a failed login).
#[allow(clippy::too_many_arguments)]
pub(super) async fn render(
    locale: DataLocale,
    cookie_jar: CookieJar,
    form_state: FormState<LoginFormField>,
    action: OptionalPostAuthAction,
    repo: &mut impl RepositoryAccess,
    clock: &impl Clock,
    rng: impl Rng,
    templates: &Templates,
    principal_server: &dyn PrincipalServerAdmin,
    site_config: &SiteConfig,
    res: &mut Response,
) -> Result<(), InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
    let providers = load_enabled_upstream_providers(repo).await?;

    let ctx = LoginContext::default()
        .with_form_state(form_state)
        .with_upstream_providers(providers);

    let next = action
        .load_context(repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    let ctx = if let Some(next) = next {
        let ctx = handle_login_hint(ctx, &next, principal_server, site_config);
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_login(&ctx)?;
    cookie_jar.finalize(res, Text::Html(content));
    Ok(())
}
