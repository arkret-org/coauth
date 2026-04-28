use dioxus::prelude::*;

use crate::{
    api::types::{
        ChangeRegistrationEmailResponse, ProvidersResponse, RegisterResponse,
        RegisterStatusResponse, ResendEmailAuthCodePayload, SiteConfig, StepResponse,
    },
    components::{
        layout::Layout, loading::LoadingSpinner, password_input::PasswordCreationDoubleInput,
    },
    pages::Route,
};

/// Registration entry page — shows password registration form and/or upstream
/// provider buttons.
#[component]
pub fn Register() -> Element {
    let providers_data = use_resource(|| async {
        crate::api::api_get::<ProvidersResponse>("/auth/providers").await
    });
    let binding = providers_data.read();

    match &*binding {
        Some(Ok(data)) => rsx! {
            Layout {
                RegisterPage { providers: data.clone() }
            }
        },
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! {
            Layout {
                RegisterPage {
                    providers: ProvidersResponse {
                        providers: vec![],
                        password_login_enabled: true,
                        password_registration_enabled: true,
                        account_recovery_allowed: true,
                    },
                }
            }
        },
    }
}

#[component]
fn RegisterPage(providers: ProvidersResponse) -> Element {
    let mut username = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut phone = use_signal(String::new);
    let new_password = use_signal(String::new);
    let new_password_again = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();
    let has_providers = !providers.providers.is_empty();
    let reg_enabled = providers.password_registration_enabled;

    rsx! {
        div { class: "login-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Create account" }

                if let Some(ref err) = *error.read() {
                    div { class: "alert alert-critical",
                        p { "{err}" }
                    }
                }

                if reg_enabled {
                    form {
                        class: "form-root",
                        onsubmit: move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let user = username.to_string();
                            let em = email.to_string();
                            let ph = phone.to_string();
                            let pw = new_password.to_string();
                            let pw2 = new_password_again.to_string();

                            if user.is_empty() {
                                error.set(Some("Username is required.".to_string()));
                                return;
                            }
                            if pw.is_empty() {
                                error.set(Some("Password is required.".to_string()));
                                return;
                            }
                            if pw != pw2 {
                                error.set(Some("Passwords do not match.".to_string()));
                                return;
                            }

                            submitting.set(true);
                            error.set(None);
                            let nav = nav.clone();

                            spawn(async move {
                                let result = crate::api::api_post::<RegisterResponse>(
                                    "/auth/register",
                                    serde_json::json!({
                                        "username": user,
                                        "email": if em.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(em) },
                                        "phone": if ph.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(ph) },
                                        "password": pw,
                                        "password_confirm": pw2,
                                    }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        if let Some(id) = resp.id {
                                            match resp.next_step.as_deref() {
                                                Some("verify_email") => {
                                                    nav.push(Route::RegisterVerifyEmail { id });
                                                }
                                                Some("verify_phone") => {
                                                    nav.push(Route::RegisterVerifyPhone { id });
                                                }
                                                Some("display_name") => {
                                                    nav.push(Route::RegisterDisplayName { id });
                                                }
                                                _ => {
                                                    nav.push(Route::RegisterFinish { id });
                                                }
                                            }
                                        }
                                    }
                                    Ok(resp) => {
                                        let msg = resp.error.unwrap_or_else(|| "Registration failed.".to_string());
                                        error.set(Some(msg));
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Username" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                autocomplete: "username",
                                required: true,
                                placeholder: "Choose a username",
                                value: "{username}",
                                oninput: move |e| username.set(e.value()),
                            }
                        }

                        div { class: "form-field",
                            label { class: "form-label", "Email (optional)" }
                            input {
                                class: "form-input",
                                r#type: "email",
                                autocomplete: "email",
                                placeholder: "your@email.com",
                                value: "{email}",
                                oninput: move |e| email.set(e.value()),
                            }
                        }

                        div { class: "form-field",
                            label { class: "form-label", "Phone (optional)" }
                            input {
                                class: "form-input",
                                r#type: "tel",
                                autocomplete: "tel",
                                placeholder: "+1234567890",
                                value: "{phone}",
                                oninput: move |e| phone.set(e.value()),
                            }
                        }

                        PasswordCreationDoubleInput {
                            new_password: new_password,
                            new_password_again: new_password_again,
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Create account"
                        }
                    }
                }

                if has_providers && reg_enabled {
                    div { class: "login-divider",
                        span { "or" }
                    }
                }

                if has_providers {
                    div { class: "login-providers",
                        for provider in providers.providers.iter() {
                            a {
                                class: "btn btn-secondary btn-block",
                                href: "{provider.authorize_url}",
                                {provider.human_name.clone().unwrap_or_else(|| format!("Sign up with {}", provider.id))}
                            }
                        }
                    }
                }

                div { class: "login-register",
                    span { "Already have an account? " }
                    Link { class: "link", to: Route::Login {},
                        "Sign in"
                    }
                }
            }
        }
    }
}

/// Email verification step during registration.
#[component]
pub fn RegisterVerifyEmail(id: String) -> Element {
    let mut code = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut editing_email = use_signal(|| false);
    let mut submitting = use_signal(|| false);
    let mut resending = use_signal(|| false);
    let mut changing_email = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut resend_message = use_signal(|| None::<String>);
    let nav = navigator();
    let reg_id = id.clone();
    let resend_id = id.clone();
    let change_id = id.clone();
    let status_id = id.clone();
    let mut status = use_resource(move || {
        let rid = status_id.clone();
        async move {
            crate::api::api_get::<RegisterStatusResponse>(&format!("/auth/register/{rid}")).await
        }
    });

    let status_binding = status.read();
    let pending_email = match &*status_binding {
        Some(Ok(data)) => data.pending_email.clone(),
        _ => None,
    };
    let masked_email = pending_email
        .as_deref()
        .map(mask_email_address)
        .unwrap_or_else(|| "your email address".to_string());
    let change_email_seed = pending_email.clone().unwrap_or_default();

    rsx! {
        Layout {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Verify your email" }
                    p { class: "text-secondary", "We sent a 6-digit verification code to {masked_email}. Please enter it below." }

                    button {
                        class: "btn btn-tertiary btn-block",
                        r#type: "button",
                        onclick: move |_| {
                            let next_open = !editing_email();
                            editing_email.set(next_open);
                            error.set(None);
                            resend_message.set(None);
                            if next_open {
                                email.set(change_email_seed.clone());
                            }
                        },
                        if editing_email() {
                            "Cancel email change"
                        } else {
                            "Wrong email? Change email"
                        }
                    }

                    if editing_email() {
                        form {
                            class: "form-root",
                            onsubmit: move |e| {
                                e.prevent_default();
                                e.stop_propagation();
                                let new_email = email.to_string();
                                if new_email.trim().is_empty() {
                                    error.set(Some("Please enter your email address.".to_string()));
                                    return;
                                }

                                changing_email.set(true);
                                error.set(None);
                                resend_message.set(None);
                                let rid = change_id.clone();

                                spawn(async move {
                                    let result = crate::api::api_post::<ChangeRegistrationEmailResponse>(
                                        &format!("/auth/register/{rid}/change-email"),
                                        serde_json::json!({ "email": new_email }),
                                    ).await;
                                    changing_email.set(false);
                                    match result {
                                        Ok(resp) if resp.status == "updated" => {
                                            code.set(String::new());
                                            editing_email.set(false);
                                            resend_message.set(Some("Your email has been updated and a new code has been sent.".to_string()));
                                            status.restart();
                                        }
                                        Ok(resp) => {
                                            let message = resp
                                                .error
                                                .as_deref()
                                                .map(registration_error_message)
                                                .unwrap_or_else(|| "Could not update your email address.".to_string());
                                            error.set(Some(message));
                                        }
                                        Err(e) => error.set(Some(e)),
                                    }
                                });
                            },

                            div { class: "form-field",
                                label { class: "form-label", "Email address" }
                                input {
                                    class: "form-input",
                                    r#type: "email",
                                    autocomplete: "email",
                                    required: true,
                                    placeholder: "your@email.com",
                                    value: "{email}",
                                    oninput: move |e| email.set(e.value()),
                                }
                                span { class: "form-help", "Saving a new email will send a fresh code and invalidate the current one." }
                            }

                            button {
                                class: "btn btn-primary btn-block",
                                r#type: "submit",
                                disabled: changing_email(),
                                if changing_email() {
                                    LoadingSpinner { inline: true }
                                }
                                "Save new email"
                            }
                        }
                    }

                    if let Some(ref err) = *error.read() {
                        div { class: "alert alert-critical",
                            p { "{err}" }
                        }
                    }

                    if let Some(ref msg) = *resend_message.read() {
                        div { class: "alert alert-info",
                            p { "{msg}" }
                        }
                    }

                    form {
                        class: "form-root",
                        onsubmit: move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let c = code.to_string();
                            if c.is_empty() {
                                error.set(Some("Please enter the verification code.".to_string()));
                                return;
                            }

                            submitting.set(true);
                            error.set(None);
                            resend_message.set(None);
                            let nav = nav.clone();
                            let rid = reg_id.clone();

                            spawn(async move {
                                let result = crate::api::api_post::<StepResponse>(
                                    &format!("/auth/register/{rid}/verify-email"),
                                    serde_json::json!({ "code": c }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        match resp.next_step.as_deref() {
                                            Some("display_name") => { nav.push(Route::RegisterDisplayName { id: rid }); }
                                            _ => { nav.push(Route::RegisterFinish { id: rid }); }
                                        }
                                    }
                                    Ok(resp) => {
                                        let message = resp
                                            .error
                                            .as_deref()
                                            .map(registration_error_message)
                                            .unwrap_or_else(|| "Incorrect code. Please try again.".to_string());
                                        error.set(Some(message));
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Verification code" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                autocomplete: "one-time-code",
                                required: true,
                                placeholder: "6-digit code",
                                value: "{code}",
                                oninput: move |e| code.set(e.value()),
                            }
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Verify"
                        }

                        button {
                            class: "btn btn-secondary btn-block",
                            r#type: "button",
                            disabled: resending(),
                            onclick: move |_| {
                                let rid = resend_id.clone();
                                resending.set(true);
                                resend_message.set(None);
                                error.set(None);
                                spawn(async move {
                                    let result = crate::api::api_post::<ResendEmailAuthCodePayload>(
                                        &format!("/auth/register/{rid}/resend-verification"),
                                        serde_json::json!({}),
                                    ).await;
                                    resending.set(false);
                                    match result {
                                        Ok(resp) if resp.status == "resent" => {
                                            resend_message.set(Some("A new verification code has been sent.".to_string()));
                                        }
                                        Ok(resp) => {
                                            let message = match resp.status.as_str() {
                                                "already_verified" => "This email has already been verified.".to_string(),
                                                "rate_limited" => "Please wait before requesting another code.".to_string(),
                                                _ => "Could not resend the verification code.".to_string(),
                                            };
                                            error.set(Some(message));
                                        }
                                        Err(err) => {
                                            error.set(Some(err));
                                        }
                                    }
                                });
                            },
                            if resending() {
                                LoadingSpinner { inline: true }
                            }
                            "Resend code"
                        }
                    }
                }
            }
        }
    }
}

fn mask_email_address(email: &str) -> String {
    let trimmed = email.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return trimmed.to_string();
    };

    if local.is_empty() || domain.is_empty() {
        return trimmed.to_string();
    }

    let visible = local.chars().take(2).collect::<String>();
    format!("{visible}***@{domain}")
}

fn registration_error_message(code: &str) -> String {
    match code {
        "invalid_code" => "Incorrect code. Please try again.".to_string(),
        "rate_limited" => "Please wait a moment and try again.".to_string(),
        "registration_already_completed" => {
            "This registration has already been completed.".to_string()
        }
        "email_already_verified" => "This email has already been verified.".to_string(),
        "email_invalid" => "Please enter a valid email address.".to_string(),
        "email_in_use" => "This email is already in use.".to_string(),
        "bootstrap_admin_token_invalid" => {
            "That admin bootstrap token is not valid. Clear the field to continue as a regular user, or enter the correct token to claim the first administrator account.".to_string()
        }
        other => other.to_string(),
    }
}

async fn submit_registration_finish(
    registration_id: &str,
    bootstrap_admin_token: Option<String>,
) -> Result<StepResponse, String> {
    crate::api::api_post::<StepResponse>(
        &format!("/auth/register/{registration_id}/finish"),
        serde_json::json!({
            "bootstrap_admin_token": bootstrap_admin_token,
        }),
    )
    .await
}

/// Phone verification step during registration.
#[component]
pub fn RegisterVerifyPhone(id: String) -> Element {
    let mut code = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut resending = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut resend_message = use_signal(|| None::<String>);
    let nav = navigator();
    let reg_id = id.clone();
    let resend_id = id.clone();

    rsx! {
        Layout {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Verify your phone" }
                    p { class: "text-secondary", "We sent a verification code to your phone number. Please enter it below." }

                    if let Some(ref err) = *error.read() {
                        div { class: "alert alert-critical",
                            p { "{err}" }
                        }
                    }

                    if let Some(ref msg) = *resend_message.read() {
                        div { class: "alert alert-info",
                            p { "{msg}" }
                        }
                    }

                    form {
                        class: "form-root",
                        onsubmit: move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let c = code.to_string();
                            if c.is_empty() {
                                error.set(Some("Please enter the verification code.".to_string()));
                                return;
                            }

                            submitting.set(true);
                            error.set(None);
                            resend_message.set(None);
                            let nav = nav.clone();
                            let rid = reg_id.clone();

                            spawn(async move {
                                let result = crate::api::api_post::<StepResponse>(
                                    &format!("/auth/register/{rid}/verify-phone"),
                                    serde_json::json!({ "code": c }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        match resp.next_step.as_deref() {
                                            Some("verify_email") => { nav.push(Route::RegisterVerifyEmail { id: rid }); }
                                            Some("display_name") => { nav.push(Route::RegisterDisplayName { id: rid }); }
                                            _ => { nav.push(Route::RegisterFinish { id: rid }); }
                                        }
                                    }
                                    Ok(resp) => {
                                        error.set(Some(resp.error.unwrap_or_else(|| "Invalid code.".to_string())));
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Verification code" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                autocomplete: "one-time-code",
                                required: true,
                                placeholder: "6-digit code",
                                value: "{code}",
                                oninput: move |e| code.set(e.value()),
                            }
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Verify"
                        }

                        button {
                            class: "btn btn-secondary btn-block",
                            r#type: "button",
                            disabled: resending(),
                            onclick: move |_| {
                                let rid = resend_id.clone();
                                resending.set(true);
                                resend_message.set(None);
                                error.set(None);
                                spawn(async move {
                                    let result = crate::api::api_post::<ResendEmailAuthCodePayload>(
                                        &format!("/auth/register/{rid}/resend-verification"),
                                        serde_json::json!({}),
                                    ).await;
                                    resending.set(false);
                                    match result {
                                        Ok(_) => {
                                            resend_message.set(Some("Verification code resent.".to_string()));
                                        }
                                        Err(err) => {
                                            error.set(Some(err));
                                        }
                                    }
                                });
                            },
                            if resending() {
                                LoadingSpinner { inline: true }
                            }
                            "Resend code"
                        }
                    }
                }
            }
        }
    }
}

/// Display name step during registration.
#[component]
pub fn RegisterDisplayName(id: String) -> Element {
    let mut display_name = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();
    let reg_id = id.clone();
    let reg_id2 = id.clone();

    rsx! {
        Layout {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Choose a display name" }
                    p { class: "text-secondary", "This is how others will see you. You can change it later." }

                    if let Some(ref err) = *error.read() {
                        div { class: "alert alert-critical",
                            p { "{err}" }
                        }
                    }

                    form {
                        class: "form-root",
                        onsubmit: move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let name = display_name.to_string();
                            submitting.set(true);
                            error.set(None);
                            let nav = nav.clone();
                            let rid = reg_id.clone();

                            spawn(async move {
                                let result = crate::api::api_post::<StepResponse>(
                                    &format!("/auth/register/{rid}/display-name"),
                                    serde_json::json!({ "display_name": name }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        nav.push(Route::RegisterFinish { id: rid });
                                    }
                                    Ok(resp) => {
                                        error.set(Some(resp.error.unwrap_or_else(|| "Failed.".to_string())));
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Display name" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                placeholder: "Your name",
                                value: "{display_name}",
                                oninput: move |e| display_name.set(e.value()),
                            }
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Continue"
                        }

                        button {
                            class: "btn btn-tertiary btn-block",
                            r#type: "button",
                            disabled: submitting(),
                            onclick: move |_| {
                                submitting.set(true);
                                error.set(None);
                                let nav = nav.clone();
                                let rid = reg_id2.clone();

                                spawn(async move {
                                    let result = crate::api::api_post::<StepResponse>(
                                        &format!("/auth/register/{rid}/display-name"),
                                        serde_json::json!({ "skip": true }),
                                    ).await;
                                    submitting.set(false);
                                    match result {
                                        Ok(_) => { nav.push(Route::RegisterFinish { id: rid }); }
                                        Err(e) => error.set(Some(e)),
                                    }
                                });
                            },
                            "Skip"
                        }
                    }
                }
            }
        }
    }
}

/// Final registration step — creates the user account.
#[component]
pub fn RegisterFinish(id: String) -> Element {
    let nav = navigator();
    let mut bootstrap_admin_token = use_signal(String::new);
    let mut finish_result = use_signal(|| None::<Result<StepResponse, String>>);
    let mut submitting = use_signal(|| false);
    let mut auto_submit_started = use_signal(|| false);

    let site_config =
        use_resource(|| async { crate::api::api_get::<SiteConfig>("/site-config").await });
    let site_config_binding = site_config.read();
    let bootstrap_admin_enabled = matches!(
        &*site_config_binding,
        Some(Ok(cfg)) if cfg.bootstrap_admin_token_enabled
    );
    let site_config_ready = site_config_binding.is_some();

    if site_config_ready
        && !bootstrap_admin_enabled
        && finish_result.read().is_none()
        && !auto_submit_started()
    {
        auto_submit_started.set(true);
        let registration_id = id.clone();
        spawn(async move {
            submitting.set(true);
            let result = submit_registration_finish(&registration_id, None).await;
            submitting.set(false);
            finish_result.set(Some(result));
        });
    }

    match finish_result.read().as_ref() {
        Some(Ok(resp)) if resp.status == "success" => {
            // Check if there is a pending OAuth authorization flow to resume.
            // The backend returns `post_auth_action` from the registration
            // record if registration was started from an OAuth grant; for
            // password registration we fall back to sessionStorage values
            // saved by the manual register flow.
            let mut redirected = false;

            // 1. API-returned post_auth_action (set during upstream OIDC registration
            //    flows)
            if let Some(action) = resp.post_auth_action.as_ref() {
                let kind = action.get("kind").and_then(|v| v.as_str());
                let id = action.get("id").and_then(|v| v.as_str()).map(String::from);
                if kind == Some("continue_authorization_grant")
                    && let Some(grant_id) = id
                {
                    nav.push(Route::Consent { grant_id });
                    redirected = true;
                }
            }

            #[cfg(target_arch = "wasm32")]
            if !redirected
                && let Some(storage) =
                    web_sys::window().and_then(|w| w.session_storage().ok().flatten())
            {
                let kind = storage.get_item("post_auth_kind").ok().flatten();
                let id = storage.get_item("post_auth_id").ok().flatten();
                // Clean up regardless
                let _ = storage.remove_item("post_auth_kind");
                let _ = storage.remove_item("post_auth_id");

                if kind.as_deref() == Some("continue_authorization_grant")
                    && let Some(grant_id) = id
                {
                    nav.push(Route::Consent { grant_id });
                    redirected = true;
                }
            }

            if !redirected {
                nav.push(Route::AccountOverview {});
            }
            rsx! {
                Layout {
                    div { class: "login-page",
                        div { class: "login-container",
                            h1 { class: "heading-md login-title", "Account created!" }
                            p { "Redirecting..." }
                        }
                    }
                }
            }
        }
        Some(Ok(resp)) if !bootstrap_admin_enabled => rsx! {
            Layout {
                div { class: "login-page",
                    div { class: "login-container",
                        h1 { class: "heading-md login-title", "Registration failed" }
                        div { class: "alert alert-critical",
                            p { {resp.error.clone().unwrap_or_else(|| "Could not complete registration.".to_string())} }
                        }
                        Link { class: "btn btn-primary", to: Route::Register {},
                            "Try again"
                        }
                    }
                }
            }
        },
        Some(Err(e)) if !bootstrap_admin_enabled => rsx! {
            Layout {
                div { class: "login-page",
                    div { class: "login-container",
                        div { class: "alert alert-critical", "{e}" }
                        Link { class: "btn btn-primary", to: Route::Register {},
                            "Try again"
                        }
                    }
                }
            }
        },
        _ if bootstrap_admin_enabled => {
            let error_message = match finish_result.read().as_ref() {
                Some(Ok(resp)) if resp.status != "success" => {
                    resp.error.as_deref().map(registration_error_message)
                }
                Some(Err(err)) => Some(err.clone()),
                _ => None,
            };

            rsx! {
                Layout {
                    div { class: "login-page",
                        div { class: "login-container",
                            h1 { class: "heading-md login-title", "Create your account" }
                            p { class: "text-secondary",
                                "If you are claiming the initial administrator account, enter the bootstrap token below. Leave it blank to continue as a regular user."
                            }

                            if let Some(err) = error_message {
                                div { class: "alert alert-critical",
                                    p { "{err}" }
                                }
                            }

                            form {
                                class: "form-root",
                                onsubmit: move |e| {
                                    e.prevent_default();
                                    e.stop_propagation();
                                    let registration_id = id.clone();
                                    let token = bootstrap_admin_token.to_string();

                                    spawn(async move {
                                        submitting.set(true);
                                        let result = submit_registration_finish(
                                            &registration_id,
                                            (!token.trim().is_empty()).then_some(token),
                                        )
                                        .await;
                                        submitting.set(false);
                                        finish_result.set(Some(result));
                                    });
                                },

                                div { class: "form-field",
                                    label { class: "form-label", "Admin bootstrap token (optional)" }
                                    input {
                                        class: "form-input",
                                        r#type: "text",
                                        autocomplete: "one-time-code",
                                        placeholder: "Enter token to claim the first admin account",
                                        value: "{bootstrap_admin_token}",
                                        oninput: move |e| bootstrap_admin_token.set(e.value()),
                                    }
                                    span { class: "form-help",
                                        "This token only has an effect while no administrator exists yet."
                                    }
                                }

                                button {
                                    class: "btn btn-primary btn-block",
                                    r#type: "submit",
                                    disabled: submitting(),
                                    if submitting() {
                                        LoadingSpinner { inline: true }
                                    }
                                    "Create account"
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => rsx! {
            Layout {
                div { class: "login-page",
                    div { class: "login-container",
                        h1 { class: "heading-md login-title", "Creating your account..." }
                        LoadingSpinner {}
                    }
                }
            }
        },
    }
}
