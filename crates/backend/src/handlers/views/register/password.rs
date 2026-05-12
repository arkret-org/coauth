use std::sync::Arc;

use coauth_data::CaptchaConfig;
use coauth_i18n::DataLocale;
use crate::salvo_utils::{
    InternalError, SessionInfoExt,
    cookies::{CookieJar, TimedCookie},
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
};
use coauth_data::RepositoryAccess;
use coauth_templates::{
    FieldError, FormError, FormState, PasswordRegisterContext, RegisterFormField, TemplateContext,
    Templates, ToFormState,
};
use salvo::{prelude::*, writing::Text};
use serde::{Deserialize, Serialize};

use super::cookie::UserRegistrationSessions;
use coauth_data::SiteConfig;

use crate::handlers::{
    RequesterFingerprint,
    account::service::registration::{
        BeginPasswordRegistrationIssue, BeginPasswordRegistrationRequest,
        BeginPasswordRegistrationResult, EmailAvailabilityCheck, begin_password_registration,
    },
    captcha::Form as CaptchaForm,
    account::{self, DepotExt},
    views::shared::OptionalPostAuthAction,
};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RegisterForm {
    username: String,
    #[serde(default)]
    email: String,
    password: String,
    password_confirm: String,
    #[serde(default)]
    accept_terms: String,

    #[serde(flatten, skip_serializing)]
    captcha: CaptchaForm,
}

impl ToFormState for RegisterForm {
    type Field = RegisterFormField;
}

#[derive(Deserialize, Default)]
pub struct QueryParams {
    username: Option<String>,
    #[serde(flatten)]
    action: OptionalPostAuthAction,
}

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let crate::handlers::views::context::ViewContext {
        mut rng,
        clock,
        locale,
        site_config,
        templates,
        url_builder,
        mut repo,
        cookie_jar,
    } = crate::handlers::views::context::ViewContext::extract(req, depot).await?;
    let query: QueryParams = req.parse_queries().unwrap_or_default();

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if maybe_session.is_some() {
        let reply = query.action.go_next(&url_builder);
        cookie_jar.finalize(res, reply);
        return Ok(());
    }

    if !site_config.password_registration_enabled {
        // If password-based registration is disabled, redirect to the login page here
        let path = if let Some(action) = &query.action.post_auth_action {
            let query_str = serde_urlencoded::to_string(action).unwrap_or_default();
            if query_str.is_empty() {
                "/login".to_owned()
            } else {
                format!("/login?{query_str}")
            }
        } else {
            "/login".to_owned()
        };
        res.render(salvo::writing::Redirect::other(&url_builder.relative_url(&path)));
        return Ok(());
    }

    let mut ctx = PasswordRegisterContext::default();

    // If we got a username from the query string, use it to prefill the form
    if let Some(username) = query.username {
        let mut form_state = FormState::default();
        form_state.set_value(RegisterFormField::Username, Some(username));
        ctx = ctx.with_form_state(form_state);
    }

    let content = render(
        locale,
        ctx,
        query.action,
        csrf_token,
        &mut repo,
        &templates,
        site_config.captcha.clone(),
    )
    .await?;

    cookie_jar.finalize(res, Text::Html(content));
    Ok(())
}

#[handler]
pub async fn post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let crate::handlers::views::context::ViewContext {
        mut rng,
        clock,
        locale,
        site_config,
        templates,
        url_builder,
        mut repo,
        cookie_jar,
    } = crate::handlers::views::context::ViewContext::extract(req, depot).await?;
    let password_manager = depot.password_manager()?;
    let principal_server = depot.principal_server()?;
    let http_client = depot.http_client()?;
    let limiter = depot.limiter()?;
    let policy_factory = depot.policy_factory()?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());
    let query: OptionalPostAuthAction = req.parse_queries().unwrap_or_default();
    let form: ProtectedForm<RegisterForm> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    let ip_address = activity_tracker.ip();
    if !site_config.password_registration_enabled {
        res.status_code(StatusCode::METHOD_NOT_ALLOWED);
        return Ok(());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    // Validate the captcha
    // TODO: display a nice error message to the user
    let passed_captcha = form
        .captcha
        .verify(
            &activity_tracker,
            &http_client,
            url_builder.public_hostname(),
            site_config.captcha.as_ref(),
        )
        .await
        .is_ok();

    let state = form.to_form_state();

    // The email form is only shown if the server requires it
    let email = site_config
        .password_registration_contact_required
        .then_some(form.email);

    let state = {
        let mut state = state;

        if !passed_captcha {
            state.add_error_on_form(FormError::Captcha);
        }

        if site_config.tos_uri.is_some() && form.accept_terms != "on" {
            state.add_error_on_field(RegisterFormField::AcceptTerms, FieldError::Required);
        }

        state
    };

    if !state.is_valid() {
        let content = render(
            locale,
            PasswordRegisterContext::default().with_form_state(state),
            query,
            csrf_token,
            &mut repo,
            &templates,
            site_config.captcha.clone(),
        )
        .await?;

        cookie_jar.finalize(res, Text::Html(content));
        return Ok(());
    }

    let post_auth_action = query
        .post_auth_action
        .map(serde_json::to_value)
        .transpose()?;
    let started = match begin_password_registration(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        principal_server.as_ref(),
        policy_factory.as_ref(),
        &limiter,
        BeginPasswordRegistrationRequest {
            username: form.username,
            email,
            phone: None,
            password: form.password,
            password_confirm: form.password_confirm,
            user_agent,
            ip_address,
            requester,
            notification_language: locale.to_string(),
            post_auth_action,
            password_registration_enabled: site_config.password_registration_enabled,
            password_registration_contact_required: site_config
                .password_registration_contact_required,
            terms_url: site_config.tos_uri.clone(),
            email_availability: EmailAvailabilityCheck::Deferred,
        },
    )
    .await
    .map_err(InternalError::from_anyhow)?
    {
        BeginPasswordRegistrationResult::Started(started) => started,
        BeginPasswordRegistrationResult::Rejected { issues } => {
            let content = render(
                locale,
                PasswordRegisterContext::default()
                    .with_form_state(apply_begin_password_registration_issues(state, issues)),
                query,
                csrf_token,
                &mut repo,
                &templates,
                site_config.captcha.clone(),
            )
            .await?;

            cookie_jar.finalize(res, Text::Html(content));
            return Ok(());
        }
    };
    let registration = started.registration;

    let cookie_jar = UserRegistrationSessions::load(&cookie_jar)
        .add(&registration)
        .save(cookie_jar, &clock);

    cookie_jar.finalize(
        res,
        salvo::writing::Redirect::other(
            &url_builder.relative_url(&format!("/register/steps/{}/finish", registration.id)),
        ),
    );
    Ok(())
}

async fn render(
    locale: DataLocale,
    ctx: PasswordRegisterContext,
    action: OptionalPostAuthAction,
    csrf_token: CsrfToken,
    repo: &mut impl RepositoryAccess,
    templates: &Templates,
    captcha_config: Option<CaptchaConfig>,
) -> Result<String, InternalError> {
    let next = action
        .load_context(repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx
        .with_captcha(captcha_config)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_password_register(&ctx)?;
    Ok(content)
}

fn apply_begin_password_registration_issues(
    mut state: FormState<RegisterFormField>,
    issues: Vec<BeginPasswordRegistrationIssue>,
) -> FormState<RegisterFormField> {
    let has_username_policy_issue = issues.iter().any(|issue| {
        matches!(
            issue,
            BeginPasswordRegistrationIssue::Policy {
                field: Some(field),
                ..
            } if field == "username"
        )
    });

    for issue in issues {
        match issue {
            BeginPasswordRegistrationIssue::RegistrationDisabled => {
                state.add_error_on_form(FormError::Internal);
            }
            BeginPasswordRegistrationIssue::UsernameRequired => {
                state.add_error_on_field(RegisterFormField::Username, FieldError::Required);
            }
            BeginPasswordRegistrationIssue::UsernameExists => {
                if !has_username_policy_issue {
                    state.add_error_on_field(RegisterFormField::Username, FieldError::Exists);
                }
            }
            BeginPasswordRegistrationIssue::EmailOrPhoneRequired => {
                state.add_error_on_field(RegisterFormField::Email, FieldError::Required);
            }
            BeginPasswordRegistrationIssue::EmailInvalid => {
                state.add_error_on_field(RegisterFormField::Email, FieldError::Invalid);
            }
            BeginPasswordRegistrationIssue::EmailInUse => {
                state.add_error_on_field(RegisterFormField::Email, FieldError::Unspecified);
            }
            BeginPasswordRegistrationIssue::PhoneInUse => {
                state.add_error_on_form(FormError::Internal);
            }
            BeginPasswordRegistrationIssue::PasswordRequired => {
                state.add_error_on_field(RegisterFormField::Password, FieldError::Required);
            }
            BeginPasswordRegistrationIssue::PasswordConfirmRequired => {
                state.add_error_on_field(RegisterFormField::PasswordConfirm, FieldError::Required);
            }
            BeginPasswordRegistrationIssue::PasswordMismatch => {
                state.add_error_on_field(RegisterFormField::Password, FieldError::Unspecified);
                state.add_error_on_field(
                    RegisterFormField::PasswordConfirm,
                    FieldError::PasswordMismatch,
                );
            }
            BeginPasswordRegistrationIssue::PasswordTooWeak => {
                state.add_error_on_field(
                    RegisterFormField::Password,
                    FieldError::Policy {
                        code: None,
                        message: "Password is too weak".to_owned(),
                    },
                );
            }
            BeginPasswordRegistrationIssue::RateLimited => {
                state.add_error_on_form(FormError::RateLimitExceeded);
            }
            BeginPasswordRegistrationIssue::Policy {
                field,
                code,
                message,
            } => match field.as_deref() {
                Some("email") => state.add_error_on_field(
                    RegisterFormField::Email,
                    FieldError::Policy { code, message },
                ),
                Some("username") => state.add_error_on_field(
                    RegisterFormField::Username,
                    FieldError::Policy { code, message },
                ),
                Some("password") => state.add_error_on_field(
                    RegisterFormField::Password,
                    FieldError::Policy { code, message },
                ),
                _ => state.add_error_on_form(FormError::Policy { code, message }),
            },
        }
    }

    state
}

#[cfg(test)]
mod tests {
    use hyper::{
        Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };

    use coauth_data::SiteConfig;

    use crate::handlers::account::DepotExt;
    use crate::handlers::test_utils::{
        CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
    };

    #[tokio::test]
    async fn test_password_disabled() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool_with_site_config(
            pool.clone(),
            SiteConfig {
                password_login_enabled: false,
                password_registration_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let request =
            Request::get("/register/password").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/login");

        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": "abc",
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Test the registration happy path
    #[tokio::test]
    async fn test_register() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Submit the registration form
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(LOCATION).unwrap();

        // The handler redirects with the ID as the second to last portion of the path
        let id = location
            .to_str()
            .unwrap()
            .rsplit('/')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        // There should be a new registration in the database
        let mut repo = state.repository().await.unwrap();
        let registration = repo.user_registration().lookup(id).await.unwrap().unwrap();
        assert_eq!(registration.username, "john".to_owned());
        assert!(registration.password.is_some());

        let email_authentication = repo
            .user_email()
            .lookup_authentication(registration.email_authentication_id.unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(email_authentication.email, "john@example.com");
    }

    /// When the two password fields mismatch, it should give an error
    #[tokio::test]
    async fn test_register_password_mismatch() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Submit the registration form
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "mismatch",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Password fields don't match"));
    }

    #[tokio::test]
    async fn test_register_username_too_long() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Submit the registration form
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "a".repeat(256),
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(
            response.body().contains("Username is too long"),
            "response body: {}",
            response.body()
        );
    }

    /// When the user already exists in the database, it should give an error
    #[tokio::test]
    async fn test_register_user_exists() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        // Insert a user in the database first
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Submit the registration form
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("This username is already taken"));
    }

    /// When the username is already reserved on the principal_server, it should give
    /// an error
    #[tokio::test]
    async fn test_register_user_reserved() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Reserve "john" on the PrincipalServer
        state.principal_server_admin.reserve_username("john").await;

        // Submit the registration form
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("This username is already taken"));
    }

    /// Test registration without email when email is not required
    #[tokio::test]
    async fn test_register_without_email_when_not_required() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool_with_site_config(
            pool.clone(),
            SiteConfig {
                password_registration_contact_required: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Submit the registration form without email
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "alice",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(LOCATION).unwrap();

        // The handler redirects with the ID as the second to last portion of the path
        let id = location
            .to_str()
            .unwrap()
            .rsplit('/')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        // There should be a new registration in the database
        let mut repo = state.repository().await.unwrap();
        let registration = repo.user_registration().lookup(id).await.unwrap().unwrap();
        assert_eq!(registration.username, "alice".to_owned());
        assert!(registration.password.is_some());
        // Email authentication should be None when email is not required and not
        // provided
        assert!(registration.email_authentication_id.is_none());
    }

    /// Test registration with valid email when email is not required
    /// (email input is ignored completely when not required)
    #[tokio::test]
    async fn test_register_with_email_when_not_required() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool_with_site_config(
            pool.clone(),
            SiteConfig {
                password_registration_contact_required: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Submit the registration form with valid email
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "charlie",
                "email": "charlie@example.com",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(LOCATION).unwrap();

        // The handler redirects with the ID as the second to last portion of the path
        let id = location
            .to_str()
            .unwrap()
            .rsplit('/')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        // There should be a new registration in the database
        let mut repo = state.repository().await.unwrap();
        let registration = repo.user_registration().lookup(id).await.unwrap().unwrap();
        assert_eq!(registration.username, "charlie".to_owned());
        assert!(registration.password.is_some());

        // Email authentication should be None when email is not required
        // (email input is completely ignored in this case)
        assert!(registration.email_authentication_id.is_none());
    }

    /// Test registration fails when email is required but not provided
    #[tokio::test]
    async fn test_register_fails_without_email_when_required() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool_with_site_config(
            pool.clone(),
            SiteConfig {
                password_registration_contact_required: true,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Submit the registration form without email
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "david",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Check that the response contains an error about the email field
        let body = response.body();
        assert!(body.contains("email") || body.contains("Email"));

        // Ensure no registration was created
        let mut repo = state.repository().await.unwrap();
        let user_exists = repo.user().exists("david").await.unwrap();
        assert!(!user_exists);
    }

    /// Test registration fails when email is required but empty
    #[tokio::test]
    async fn test_register_fails_with_empty_email_when_required() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool_with_site_config(
            pool.clone(),
            SiteConfig {
                password_registration_contact_required: true,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Submit the registration form with empty email
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "eve",
                "email": "",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Check that the response contains an error about the email field
        let body = response.body();
        assert!(body.contains("email") || body.contains("Email"));

        // Ensure no registration was created
        let mut repo = state.repository().await.unwrap();
        let user_exists = repo.user().exists("eve").await.unwrap();
        assert!(!user_exists);
    }

    /// Test registration fails with invalid email when email is required
    #[tokio::test]
    async fn test_register_fails_with_invalid_email_when_required() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool_with_site_config(
            pool.clone(),
            SiteConfig {
                password_registration_contact_required: true,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get("/register/password").empty();
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

        // Submit the registration form with invalid email
        let request = Request::post("/register/password")
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "grace",
                "email": "not-an-email",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Check that the response contains an error about the email field
        let body = response.body();
        assert!(body.contains("email") || body.contains("Email"));

        // Ensure no registration was created
        let mut repo = state.repository().await.unwrap();
        let user_exists = repo.user().exists("grace").await.unwrap();
        assert!(!user_exists);
    }
}
