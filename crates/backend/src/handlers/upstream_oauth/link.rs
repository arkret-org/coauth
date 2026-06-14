use std::sync::LazyLock;

use opentelemetry::{Key, KeyValue, metrics::Counter};
use crate::salvo_utils::{
    GenericError, SessionInfoExt,
    cookies::TimedCookie,
    csrf::{CsrfExt, ProtectedForm},
    record_error,
};
use coauth_data::{
    RepositoryAccess,
    upstream_oauth::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
    user::UserRepository,
};
use coauth_templates::{
    AppContext, AppErrorState, FieldError, FormError, TemplateContext, Templates,
    ToFormState, UpstreamExistingLinkContext, UpstreamRegister, UpstreamSuggestLink,
};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use super::UpstreamSessionsCookie;
use crate::handlers::{
    METER, common::DepotExt,
    upstream_oauth::link_workflow::{
        LoadUpstreamLinkOutcome, SubmitUpstreamLinkError, SubmitUpstreamLinkOutcome,
        UpstreamLinkAction, UpstreamLinkRegistrationAction, UpstreamLinkWorkflowError,
        load_upstream_link_context, load_upstream_link_state, submit_upstream_link_action,
    },
    account::registration_cookie::UserRegistrationSessions as UserRegistrationSessionsCookie,
};

static LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.upstream_oauth.login")
        .with_description("Successful upstream OAuth login to existing accounts")
        .with_unit("{login}")
        .build()
});
static REGISTRATION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.upstream_oauth.registration")
        .with_description("Successful upstream OAuth registration")
        .with_unit("{registration}")
        .build()
});
const PROVIDER: Key = Key::from_static_str("provider");

#[derive(Debug, Error)]
pub enum RouteError {
    /// Couldn't find the link specified in the URL
    #[error("Link not found")]
    LinkNotFound,

    #[error("Invalid form action")]
    InvalidFormAction,

    #[error("Upstream link workflow error")]
    Workflow(#[source] UpstreamLinkWorkflowError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(coauth_templates::TemplateError);
impl_from_error_for_route!(crate::salvo_utils::csrf::CsrfError);
impl_from_error_for_route!(super::cookie::UpstreamSessionNotFound);
impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::account::RouteError);
impl_from_error_for_route!(coauth_policy::InstantiateError);
impl_from_error_for_route!(salvo::http::ParseError);

impl From<UpstreamLinkWorkflowError> for RouteError {
    fn from(error: UpstreamLinkWorkflowError) -> Self {
        Self::Workflow(error)
    }
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let sentry_event_id = record_error!(
            self,
            Self::Internal(_)
                | Self::Workflow(_)
        );

        let status_code = match self {
            Self::LinkNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        GenericError::new(status_code, self).render(res);

        if let Some(event_id) = sentry_event_id {
            event_id.write_to_response(res);
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase", tag = "action")]
pub enum FormData {
    Register {
        #[serde(default)]
        handle: Option<String>,
        #[serde(default)]
        import_email: Option<String>,
        #[serde(default)]
        import_display_name: Option<String>,
        #[serde(default)]
        accept_terms: Option<String>,
    },
    Link,
}

impl ToFormState for FormData {
    type Field = coauth_templates::UpstreamRegisterFormField;
}

#[handler]
#[tracing::instrument(name = "handlers.upstream_oauth.link.get", skip_all)]
pub async fn get(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let link_id: Ulid = req.param("link_id").ok_or(RouteError::LinkNotFound)?;
    let mut rng = crate::handlers::account::make_rng();
    let clock = crate::handlers::account::make_clock();
    let mut repo = depot.repo().await?;
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let principal_server = depot.principal_server()?;
    let cookie_jar = depot.cookie_jar(req)?;
    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    let policy_factory = depot.policy_factory()?;
    let mut policy = policy_factory.instantiate().await?;
    let site_config = depot.site_config()?;
    let ip_address = crate::handlers::account::extract_bound_activity_tracker(req, depot).ip();

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let context = load_upstream_link_context(&mut repo, &session_info, &sessions_cookie, link_id)
        .await?;

    // We need to stash the browser session before it's consumed by
    // load_upstream_link_state, so we can use it for template rendering.
    let browser_session_for_template = context.browser_session.clone();

    let outcome = match load_upstream_link_state(
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
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(
            UpstreamLinkWorkflowError::ConflictFail { handle: ref username }
            | UpstreamLinkWorkflowError::ConflictSetBlocked { handle: ref username },
        ) => {
            let err_state = AppErrorState {
                kind: "generic".to_owned(),
                handle: None,
                description: Some(format!(
                    "Upstream account provider returned {username:?} as username, \
                     which could not be linked automatically."
                )),
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.write_to_response(&mut *res);
            res.render(Text::Html(content));
            return Ok(());
        }
        Err(UpstreamLinkWorkflowError::PolicyDeniedHandle {
            handle: ref username,
            ref detail,
        }) => {
            let err_state = AppErrorState {
                kind: "generic".to_owned(),
                handle: None,
                description: Some(format!(
                    "Upstream account provider returned {username:?} as username, \
                     which does not pass the policy check: {detail}"
                )),
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.write_to_response(&mut *res);
            res.render(Text::Html(content));
            return Ok(());
        }
        Err(UpstreamLinkWorkflowError::HandleUnavailable { handle: ref username }) => {
            let err_state = AppErrorState {
                kind: "generic".to_owned(),
                handle: None,
                description: Some(format!(
                    "Username {username:?} is not available on this PrincipalServer"
                )),
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.write_to_response(&mut *res);
            res.render(Text::Html(content));
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    match outcome {
        LoadUpstreamLinkOutcome::Authenticated {
            session,
            redirect_url,
        } => {
            let cookie_jar = cookie_jar.set_session(&session);
            repo.save().await?;

            cookie_jar.finalize(res, Redirect::other(&redirect_url));
        }

        LoadUpstreamLinkOutcome::LoggedIn {
            session,
            redirect_url,
            provider_id,
        } => {
            let cookie_jar = sessions_cookie
                .consume_link(link_id)?
                .save(cookie_jar, &clock)
                .set_session(&session);

            repo.save().await?;

            LOGIN_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider_id.to_string())]);

            cookie_jar.finalize(res, Redirect::other(&redirect_url));
        }

        LoadUpstreamLinkOutcome::LinkMismatch { existing_handle: existing_username } => {
            // Look up the user again for the template context (needs the full User object)
            let user = repo
                .user()
                .find_by_handle(&existing_username)
                .await?
                .ok_or_else(|| {
                    RouteError::Internal(
                        format!("User {existing_username:?} not found for link mismatch template")
                            .into(),
                    )
                })?;

            // LinkMismatch only occurs when there's a logged-in user session
            let user_session = browser_session_for_template.ok_or_else(|| {
                RouteError::Internal("LinkMismatch without a browser session".into())
            })?;

            let ctx = UpstreamExistingLinkContext::new(user)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            cookie_jar.finalize(
                res,
                Text::Html(templates.render_upstream_oauth_link_mismatch(&ctx)?),
            );
        }

        LoadUpstreamLinkOutcome::SuggestLink {
            provider_name: _,
            upstream_subject: _,
        } => {
            // Re-load the link to construct the template context.
            let link = repo
                .upstream_oauth_link()
                .lookup(link_id)
                .await?
                .ok_or(RouteError::LinkNotFound)?;

            // SuggestLink only occurs when there's a logged-in user session
            let user_session = browser_session_for_template.ok_or_else(|| {
                RouteError::Internal("SuggestLink without a browser session".into())
            })?;

            let ctx = UpstreamSuggestLink::new(&link)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            cookie_jar.finalize(
                res,
                Text::Html(templates.render_upstream_oauth_suggest_link(&ctx)?),
            );
        }

        LoadUpstreamLinkOutcome::Register { screen } => {
            let mut ctx = UpstreamRegister::new(screen.link, screen.provider);

            if let Some(username) = screen.suggested_handle {
                ctx = ctx.with_handle(username, screen.handle_forced);
            }

            if let Some(display_name) = screen.suggested_display_name {
                ctx = ctx.with_display_name(display_name, screen.display_name_forced);
            }

            if let Some(email) = screen.suggested_email {
                ctx = ctx.with_email(email, screen.email_forced);
            }

            let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

            cookie_jar.finalize(
                res,
                Text::Html(templates.render_upstream_oauth_do_register(&ctx)?),
            );
        }

        LoadUpstreamLinkOutcome::Registered {
            registration,
            redirect_url: _,
            provider_id,
        } => {
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
        }

        LoadUpstreamLinkOutcome::AccountDeactivated { handle: username } => {
            let err_state = AppErrorState {
                kind: "account_deactivated".to_owned(),
                handle: Some(username),
                description: None,
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.finalize(res, Text::Html(content));
        }

        LoadUpstreamLinkOutcome::AccountLocked { handle: username } => {
            let err_state = AppErrorState {
                kind: "account_locked".to_owned(),
                handle: Some(username),
                description: None,
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.finalize(res, Text::Html(content));
        }
    }

    Ok(())
}

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

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode, header::CONTENT_TYPE};
    use oauth_types::scope::{OPENID, Scope};
    use coauth_data::{
        UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderImportPreference, UpstreamOAuthProviderHandlePreference,
        UpstreamOAuthProviderTokenAuthMethod, UserEmailAuthentication, UserRegistration,
    };
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
    use coauth_keystore::Keystore;
    use coauth_data::{
        Repository, RepositoryError, upstream_oauth::UpstreamOAuthProviderParams,
    };
    use rand_chacha::ChaChaRng;
    use serde_json::Value;
    use ulid::Ulid;

    use super::UpstreamSessionsCookie;
    use crate::handlers::account::DepotExt;
    #[cfg(test)]
    use crate::handlers::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_register() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            handle: UpstreamOAuthProviderHandlePreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Force,
                template: None,
                on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::default(),
            },
            email: UpstreamOAuthProviderImportPreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Force,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": "john",
            "email": "john@example.com",
            "email_verified": true,
        });

        // Grab a key to sign the id_token
        // We could generate a key on the fly, but because we have one available here,
        // why not use it?
        let signer = state
            .key_store
            .signer_for_algorithm(&JsonWebSignatureAlg::Rs256)
            .unwrap();
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);
        let id_token =
            Jwt::sign_with_rng(&mut rng, header, id_token_claims.clone(), &*signer).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout:
                        coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "state".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();

        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "subject".to_owned(),
                None,
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(
                &state.clock,
                session,
                &link,
                Some(id_token.into_string()),
                Some(id_token_claims),
                None,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request =
            Request::get(&format!("/upstream/link/{}", link.id)).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        let request = Request::post(&format!("/upstream/link/{}", link.id)).form(
            serde_json::json!({
                "csrf": csrf_token,
                "action": "register",
                "import_email": "on",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(hyper::header::LOCATION).unwrap();
        // Grab the registration ID from the redirected URL:
        //   /register/steps/{id}/finish
        let registration_id: Ulid = str::from_utf8(location.as_bytes())
            .unwrap()
            .rsplit('/')
            .nth(1)
            .expect("Location to have two slashes")
            .parse()
            .expect("last segment of location to be a ULID");

        // Check that we have a registered user, with the email imported
        let mut repo = state.repository().await.unwrap();
        let registration: UserRegistration = repo
            .user_registration()
            .lookup(registration_id)
            .await
            .unwrap()
            .expect("user registration exists");

        assert_eq!(registration.password, None);
        assert_eq!(registration.completed_at, None);
        assert_eq!(registration.handle, "john");

        let email_auth_id = registration
            .email_authentication_id
            .expect("registration should have an email authentication");
        let email_auth: UserEmailAuthentication = repo
            .user_email()
            .lookup_authentication(email_auth_id)
            .await
            .unwrap()
            .expect("email authentication should exist");
        assert_eq!(email_auth.email, "john@example.com");
        assert!(email_auth.completed_at.is_some());
    }

    #[tokio::test]
    async fn test_register_skip_confirmation() {
        // Same test as test_register, but checks that we get straight to the
        // registration strand skipping the confirmation
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            skip_confirmation: true,
            handle: UpstreamOAuthProviderHandlePreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
                on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::default(),
            },
            email: UpstreamOAuthProviderImportPreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Force,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": "john",
            "email": "john@example.com",
            "email_verified": true,
        });

        // Grab a key to sign the id_token
        // We could generate a key on the fly, but because we have one available here,
        // why not use it?
        let signer = state
            .key_store
            .signer_for_algorithm(&JsonWebSignatureAlg::Rs256)
            .unwrap();
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);
        let id_token =
            Jwt::sign_with_rng(&mut rng, header, id_token_claims.clone(), &*signer).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout:
                        coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "state".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();

        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "subject".to_owned(),
                None,
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(
                &state.clock,
                session,
                &link,
                Some(id_token.into_string()),
                Some(id_token_claims),
                None,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request =
            Request::get(&format!("/upstream/link/{}", link.id)).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        let location = response.headers().get(hyper::header::LOCATION).unwrap();
        // Grab the registration ID from the redirected URL:
        //   /register/steps/{id}/finish
        let registration_id: Ulid = str::from_utf8(location.as_bytes())
            .unwrap()
            .rsplit('/')
            .nth(1)
            .expect("Location to have two slashes")
            .parse()
            .expect("last segment of location to be a ULID");

        // Check that we have a registered user, with the email imported
        let mut repo = state.repository().await.unwrap();
        let registration: UserRegistration = repo
            .user_registration()
            .lookup(registration_id)
            .await
            .unwrap()
            .expect("user registration exists");

        assert_eq!(registration.password, None);
        assert_eq!(registration.completed_at, None);
        assert_eq!(registration.handle, "john");

        let email_auth_id = registration
            .email_authentication_id
            .expect("registration should have an email authentication");
        let email_auth: UserEmailAuthentication = repo
            .user_email()
            .lookup_authentication(email_auth_id)
            .await
            .unwrap()
            .expect("email authentication should exist");
        assert_eq!(email_auth.email, "john@example.com");
        assert!(email_auth.completed_at.is_some());
    }

    #[tokio::test]
    async fn test_link_existing_account() {
        let existing_username = "john";
        let subject = "subject";

        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            handle: UpstreamOAuthProviderHandlePreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
                // This is the important bit: this will automatically link
                // existing accounts if the username matches
                on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::Add,
            },
            email: UpstreamOAuthProviderImportPreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        //`preferred_username` matches an existing user's username
        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();

        //provision upstream authorization session to setup cookies
        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            subject,
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let user = repo
            .user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request =
            Request::get(&format!("/upstream/link/{}", link.id)).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Check that the existing user has the oidc link
        let mut repo = state.repository().await.unwrap();

        let link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, subject)
            .await
            .unwrap()
            .expect("link exists");

        assert_eq!(link.user_id, Some(user.id));
    }

    #[tokio::test]
    async fn test_link_existing_account_when_not_allowed_by_default() {
        let existing_username = "john";

        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            handle: UpstreamOAuthProviderHandlePreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
                on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::default(),
            },
            email: UpstreamOAuthProviderImportPreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        // `preferred_username` matches an existing user's username
        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();

        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            "subject",
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        // Provision an user
        repo.user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request =
            Request::get(&format!("/upstream/link/{}", link.id)).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        assert!(response.body().contains("Unexpected error"));
    }

    fn sign_token(
        rng: &mut ChaChaRng,
        keystore: &Keystore,
        payload: Value,
    ) -> Result<Jwt<'static, Value>, coauth_jose::jwt::JwtSignatureError> {
        let signer = keystore
            .signer_for_algorithm(&JsonWebSignatureAlg::Rs256)
            .unwrap();

        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);

        Jwt::sign_with_rng(rng, header, payload, &*signer)
    }

    async fn add_linked_upstream_session(
        rng: &mut ChaChaRng,
        clock: &impl coauth_data::Clock,
        repo: &mut Box<dyn Repository<RepositoryError> + Send + Sync + 'static>,
        provider: &coauth_data::UpstreamOAuthProvider,
        subject: &str,
        id_token: &str,
        id_token_claims: Value,
    ) -> Result<(UpstreamOAuthLink, UpstreamOAuthAuthorizationSession), anyhow::Error> {
        let session = repo
            .upstream_oauth_session()
            .add(
                rng,
                clock,
                provider,
                "state".to_owned(),
                None,
                Some("nonce".to_owned()),
            )
            .await?;

        let link = repo
            .upstream_oauth_link()
            .add(rng, clock, provider, subject.to_owned(), None)
            .await?;

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(
                clock,
                session,
                &link,
                Some(id_token.to_owned()),
                Some(id_token_claims),
                None,
                None,
            )
            .await?;

        Ok((link, session))
    }

    #[tokio::test]
    async fn test_link_existing_account_replace_conflict() {
        let existing_username = "john";
        let subject = "subject";
        let old_subject = "old_subject";

        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            handle: UpstreamOAuthProviderHandlePreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
                // This will replace any existing links for this provider and user
                on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::Replace,
            },
            email: UpstreamOAuthProviderImportPreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();

        // Create an existing user
        let user = repo
            .user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        // Create an existing link for this user and provider with a different subject
        let old_link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                old_subject.to_owned(),
                None,
            )
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&old_link, &user)
            .await
            .unwrap();

        // Provision upstream authorization session to setup cookies
        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            subject,
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request =
            Request::get(&format!("/upstream/link/{}", link.id)).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Check that the new link is associated with the existing user
        let mut repo = state.repository().await.unwrap();

        let new_link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, subject)
            .await
            .unwrap()
            .expect("new link exists");

        assert_eq!(new_link.user_id, Some(user.id));

        // Check that the old link was removed
        let old_link_result = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, old_subject)
            .await
            .unwrap();

        assert!(
            old_link_result.is_none(),
            "Old link should have been removed"
        );
    }

    #[tokio::test]
    async fn test_link_existing_account_set_conflict_success() {
        let existing_username = "john";
        let subject = "subject";

        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            handle: UpstreamOAuthProviderHandlePreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
                // This will only link if there are no existing links for this provider and user
                on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::Set,
            },
            email: UpstreamOAuthProviderImportPreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();

        // Create an existing user (with no existing links for this provider)
        let user = repo
            .user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        // Provision upstream authorization session to setup cookies
        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            subject,
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request =
            Request::get(&format!("/upstream/link/{}", link.id)).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Check that the new link is associated with the existing user
        let mut repo = state.repository().await.unwrap();

        let new_link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, subject)
            .await
            .unwrap()
            .expect("new link exists");

        assert_eq!(new_link.user_id, Some(user.id));
    }

    #[tokio::test]
    async fn test_link_existing_account_set_conflict_failure() {
        let existing_username = "john";
        let subject = "subject";
        let old_subject = "old_subject";

        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let claims_imports = UpstreamOAuthProviderClaimsImports {
            handle: UpstreamOAuthProviderHandlePreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
                // This will only link if there are no existing links for this provider and user
                on_conflict: coauth_data::UpstreamOAuthProviderOnConflict::Set,
            },
            email: UpstreamOAuthProviderImportPreference {
                action: coauth_data::UpstreamOAuthProviderImportAction::Require,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        };

        let id_token_claims = serde_json::json!({
            "preferred_username": existing_username,
            "email": "any@example.com",
            "email_verified": true,
        });

        let id_token = sign_token(&mut rng, &state.key_store, id_token_claims.clone()).unwrap();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports,
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    on_backchannel_logout:
                        coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    ui_order: 0,
                    source: coauth_data::UpstreamOAuthProviderSource::Config,
                },
            )
            .await
            .unwrap();

        // Create an existing user
        let user = repo
            .user()
            .add(&mut rng, &state.clock, existing_username.to_owned())
            .await
            .unwrap();

        // Create an existing link for this user and provider with a different subject
        let old_link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                old_subject.to_owned(),
                None,
            )
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&old_link, &user)
            .await
            .unwrap();

        // Provision upstream authorization session to setup cookies
        let (link, session) = add_linked_upstream_session(
            &mut rng,
            &state.clock,
            &mut repo,
            &provider,
            subject,
            &id_token.into_string(),
            id_token_claims,
        )
        .await
        .unwrap();

        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let upstream_sessions = UpstreamSessionsCookie::default()
            .add(session.id, provider.id, "state".to_owned(), None)
            .add_link_to_session(session.id, link.id)
            .unwrap();
        let cookie_jar = upstream_sessions.save(cookie_jar, &state.clock);
        cookies.import(cookie_jar);

        let request =
            Request::get(&format!("/upstream/link/{}", link.id)).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);

        // Should return an error page because the user already has a link for this
        // provider
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Verify the error message is displayed
        assert!(response.body().contains("User exists"));
        assert!(response.body().contains("replacing upstream account links"));

        // Check that the new link was NOT associated with the existing user
        let mut repo = state.repository().await.unwrap();

        let new_link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, subject)
            .await
            .unwrap()
            .expect("new link exists");

        // The new link should still not be associated with the user
        assert_eq!(new_link.user_id, None);

        // Check that the old link is still there
        let old_link_result = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, old_subject)
            .await
            .unwrap();

        assert!(old_link_result.is_some(), "Old link should still exist");
        assert_eq!(old_link_result.unwrap().user_id, Some(user.id));
    }
}
