use dioxus::prelude::*;
use js_sys::Reflect;
use web_sys::wasm_bindgen::JsValue;

use crate::api::types::{LoginOutcome, ProvidersOutcome};
use crate::components::layout::Layout;
use crate::components::loading::LoadingSpinner;
use crate::components::password_input::PasswordVisibilityToggle;
use crate::pages::Route;

const PRESERVED_LOGIN_QUERY_PROPERTY: &str = "__coauth_login_query";
const LOGIN_ERROR_ID: &str = "login-error";
const LOGIN_HANDLE_ID: &str = "login-handle";
const LOGIN_PASSWORD_ID: &str = "login-password";

fn preserved_login_query() -> Option<String> {
    let window = web_sys::window()?;
    Reflect::get(
        window.as_ref(),
        &JsValue::from_str(PRESERVED_LOGIN_QUERY_PROPERTY),
    )
    .ok()?
    .as_string()
}

pub(crate) fn preserve_login_query() {
    let Some(window) = web_sys::window() else {
        return;
    };

    let Ok(pathname) = window.location().pathname() else {
        return;
    };
    let Ok(search) = window.location().search() else {
        return;
    };

    if pathname == "/login" && !search.is_empty() {
        let _ = Reflect::set(
            window.as_ref(),
            &JsValue::from_str(PRESERVED_LOGIN_QUERY_PROPERTY),
            &JsValue::from_str(&search),
        );
    }
}

/// Read a query parameter from the current URL.
fn get_query_param(name: &str) -> Option<String> {
    let window = web_sys::window()?;

    if let Ok(search) = window.location().search()
        && !search.is_empty()
        && let Ok(params) = web_sys::UrlSearchParams::new_with_str(&search)
        && let Some(value) = params.get(name)
    {
        return Some(value);
    }

    let search = preserved_login_query()?;
    let params = web_sys::UrlSearchParams::new_with_str(&search).ok()?;
    params.get(name)
}

/// Return the current page's query string (without leading `?`), falling
/// back to the preserved one if Dioxus has already rewritten the URL.
fn current_query_string() -> String {
    if let Some(window) = web_sys::window()
        && let Ok(search) = window.location().search()
        && !search.is_empty()
    {
        return search.trim_start_matches('?').to_owned();
    }

    preserved_login_query()
        .map(|s| s.trim_start_matches('?').to_owned())
        .unwrap_or_default()
}

fn clear_preserved_login_query() {
    if let Some(window) = web_sys::window() {
        let _ = Reflect::delete_property(
            window.as_ref(),
            &JsValue::from_str(PRESERVED_LOGIN_QUERY_PROPERTY),
        );
    }
}

fn store_post_auth_continuation(kind: &str, id: &str) {
    #[cfg(target_arch = "wasm32")]
    if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok().flatten()) {
        let _ = storage.set_item("post_auth_kind", kind);
        let _ = storage.set_item("post_auth_id", id);
    }

    #[cfg(not(target_arch = "wasm32"))]
    let _ = (kind, id);
}

#[component]
pub fn Login() -> Element {
    let providers_data = use_resource(|| async {
        crate::api::api_get::<ProvidersOutcome>("/account/auth/providers").await
    });
    let binding = providers_data.read();

    match &*binding {
        Some(Ok(data)) => rsx! {
            Layout {
                LoginForm {
                    providers: data.clone(),
                }
            }
        },
        Some(Err(e)) => rsx! {
            Layout {
                LoginFormBasic { error_msg: Some(e.clone()) }
            }
        },
        None => rsx! {
            Layout {
                LoginFormBasic { error_msg: None }
            }
        },
    }
}

#[component]
fn LoginFormBasic(error_msg: Option<String>) -> Element {
    rsx! {
        LoginForm {
            providers: ProvidersOutcome {
                providers: vec![],
                password_login_enabled: true,
                password_registration_enabled: false,
                account_recovery_allowed: true,
            },
        }
    }
}

#[component]
fn LoginForm(providers: ProvidersOutcome) -> Element {
    let mut handle = use_signal(String::new);
    let mut password = use_signal(String::new);
    let show_password = use_signal(|| false);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();
    let has_providers = !providers.providers.is_empty();
    let password_enabled = providers.password_login_enabled;
    let registration_enabled = providers.password_registration_enabled;
    let recovery_enabled = providers.account_recovery_allowed;
    let error_text = error.read().clone();
    let has_error = error_text.is_some();

    rsx! {
        div { class: "login-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Sign in" }

                if let Some(err) = error_text.as_ref() {
                    div {
                        class: "alert alert-critical",
                        id: LOGIN_ERROR_ID,
                        role: "alert",
                        "aria-live": "assertive",
                        p { "{err}" }
                    }
                }

                if password_enabled {
                    form {
                        class: "form-root",
                        "aria-describedby": if has_error { LOGIN_ERROR_ID } else { "" },
                        onsubmit: move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let user = handle.to_string();
                            let pass = password.to_string();

                            if user.is_empty() || pass.is_empty() {
                                error.set(Some("Please enter your username and password.".to_owned()));
                                return;
                            }

                            submitting.set(true);
                            error.set(None);

                            spawn(async move {
                                let result = crate::api::api_post::<LoginOutcome>(
                                    "/account/auth/login",
                                    serde_json::json!({
                                        "handle": user,
                                        "password": pass,
                                    }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        let continuation =
                                            get_query_param("kind").zip(get_query_param("id"));
                                        clear_preserved_login_query();

                                        // Check if this login is part of an OAuth authorization strand
                                        if let Some((kind, id)) = continuation {
                                            if kind == "continue_authorization_grant" {
                                                nav.push(Route::OAuthApproval { grant_id: id });
                                            } else {
                                                nav.push(Route::AccountOverview {});
                                            }
                                        } else {
                                            nav.push(Route::AccountOverview {});
                                        }
                                    }
                                    Ok(resp) => {
                                        let msg = match resp.error.as_deref() {
                                            Some("invalid_credentials") => "Invalid username or password.",
                                            Some("rate_limited") => "Too many attempts. Please try again later.",
                                            Some("account_deactivated") => "This account has been deactivated.",
                                            Some("account_locked") => "This account has been locked.",
                                            Some("password_login_disabled") => "Password login is not available.",
                                            Some(other) => other,
                                            None => "Login failed.",
                                        };
                                        error.set(Some(msg.to_owned()));
                                    }
                                    Err(e) => {
                                        error.set(Some(e));
                                    }
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", r#for: LOGIN_HANDLE_ID, "Username" }
                            input {
                                id: LOGIN_HANDLE_ID,
                                class: "form-input",
                                r#type: "text",
                                autocomplete: "username",
                                required: true,
                                "aria-invalid": if has_error { "true" } else { "false" },
                                "aria-describedby": if has_error { LOGIN_ERROR_ID } else { "" },
                                placeholder: "Username or email",
                                value: "{handle}",
                                oninput: move |e| handle.set(e.value()),
                            }
                        }

                        div { class: "form-field",
                            label { class: "form-label", r#for: LOGIN_PASSWORD_ID, "Password" }
                            div { class: "password-input-wrapper",
                                input {
                                    id: LOGIN_PASSWORD_ID,
                                    class: "form-input",
                                    r#type: if show_password() { "text" } else { "password" },
                                    autocomplete: "current-password",
                                    required: true,
                                    "aria-invalid": if has_error { "true" } else { "false" },
                                    "aria-describedby": if has_error { LOGIN_ERROR_ID } else { "" },
                                    placeholder: "Password",
                                    value: "{password}",
                                    oninput: move |e| password.set(e.value()),
                                }
                                PasswordVisibilityToggle { visible: show_password }
                            }
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            // Stable hook for e2e (cotest oidc-login-flow.spec.ts);
                            // the button carries no id otherwise.
                            "data-testid": "coauth-login-submit",
                            disabled: submitting(),
                            "aria-busy": if submitting() { "true" } else { "false" },
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Sign in"
                        }
                    }

                    if recovery_enabled {
                        div { class: "login-links",
                            Link { class: "link", to: Route::RecoveryStart {},
                                "Forgot password?"
                            }
                        }
                    }
                }

                if has_providers && password_enabled {
                    div { class: "login-divider",
                        span { "or" }
                    }
                }

                if has_providers {
                    div { class: "login-providers",
                        for provider in providers.providers.iter() {
                            {
                                // Propagate the current page's query string (e.g.
                                // ?kind=continue_authorization_grant&id=...) to the
                                // upstream authorize URL so that after the upstream
                                // strand completes, coauth can continue the original
                                // OAuth grant and redirect back to the originating
                                // client.
                                let query = current_query_string();
                                let href = if query.is_empty() {
                                    provider.authorize_url.clone()
                                } else {
                                    format!("{}?{}", provider.authorize_url, query)
                                };
                                let label = provider
                                    .human_name
                                    .clone()
                                    .unwrap_or_else(|| format!("Sign in with {}", provider.id));
                                rsx! {
                                    a {
                                        key: "{provider.id}",
                                        class: "btn btn-secondary btn-block",
                                        href: "{href}",
                                        "aria-label": "{label}",
                                        "{label}"
                                    }
                                }
                            }
                        }
                    }
                }

                if !password_enabled && !has_providers {
                    div { class: "alert alert-warning",
                        p { "No login methods are currently available." }
                    }
                }

                if registration_enabled {
                    div { class: "login-register",
                        span { "Don't have an account? " }
                        Link {
                            class: "link",
                            to: Route::Register {},
                            onclick: move |_| {
                                // Carry forward any OAuth continuation so the
                                // registration finish step can redirect to
                                // the OAuth approval page instead of the account
                                // overview.
                                let continuation =
                                    get_query_param("kind").zip(get_query_param("id"));
                                if let Some((kind, id)) = continuation {
                                    store_post_auth_continuation(&kind, &id);
                                }
                            },
                            "Create account"
                        }
                    }
                }
            }
        }
    }
}
