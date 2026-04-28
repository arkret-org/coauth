use dioxus::prelude::*;
use serde::Deserialize;

use crate::{
    api::{api_get, api_post},
    components::{layout::Layout, loading::LoadingSpinner},
};

// ── API types ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LinkState {
    Redirect {
        redirect_url: String,
    },
    SuggestLink {
        provider_name: Option<String>,
        upstream_subject: Option<String>,
    },
    LinkMismatch {
        existing_username: String,
    },
    Register {
        suggested_username: Option<String>,
        username_forced: bool,
        suggested_display_name: Option<String>,
        display_name_forced: bool,
        suggested_email: Option<String>,
        email_forced: bool,
        provider_name: Option<String>,
        has_tos: bool,
    },
    AccountDeactivated {
        username: String,
    },
    AccountLocked {
        username: String,
    },
    Error {
        code: String,
        description: String,
    },
}

#[derive(Debug, Deserialize, Clone)]
pub struct LinkActionResponse {
    pub status: String,
    pub redirect_url: Option<String>,
    pub error: Option<String>,
    pub field_errors: Option<serde_json::Value>,
}

// ── Component ───────────────────────────────────────────────────

#[component]
pub fn UpstreamLink(id: String) -> Element {
    let link_data = use_resource({
        let id = id.clone();
        move || {
            let id = id.clone();
            async move { api_get::<LinkState>(&format!("/upstream-oauth2/link/{id}")).await }
        }
    });

    let binding = link_data.read();

    match &*binding {
        Some(Ok(state)) => rsx! {
            Layout {
                LinkStateView { id: id.clone(), state: state.clone() }
            }
        },
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "login-page",
                    div { class: "login-container",
                        h1 { class: "heading-md login-title", "Error" }
                        div { class: "alert alert-critical",
                            p { "Failed to load link information: {e}" }
                        }
                    }
                }
            }
        },
        None => rsx! {
            Layout {
                LoadingSpinner {}
            }
        },
    }
}

#[component]
fn LinkStateView(id: String, state: LinkState) -> Element {
    match state {
        LinkState::Redirect { redirect_url } => {
            // Redirect immediately
            let nav = navigator();
            nav.push(redirect_url);
            rsx! { LoadingSpinner {} }
        }
        LinkState::SuggestLink {
            provider_name,
            upstream_subject,
        } => rsx! {
            SuggestLinkView {
                id,
                provider_name,
                upstream_subject,
            }
        },
        LinkState::LinkMismatch { existing_username } => rsx! {
            LinkMismatchView { existing_username }
        },
        LinkState::Register {
            suggested_username,
            username_forced,
            suggested_display_name,
            display_name_forced,
            suggested_email,
            email_forced,
            provider_name,
            has_tos,
        } => rsx! {
            RegisterView {
                id,
                suggested_username,
                username_forced,
                suggested_display_name,
                display_name_forced,
                suggested_email,
                email_forced,
                provider_name,
                has_tos,
            }
        },
        LinkState::AccountDeactivated { username } => rsx! {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Account Deactivated" }
                    p { class: "text-secondary", "The account " strong { "{username}" } " has been deactivated." }
                    p { class: "text-secondary", "Please contact your administrator for assistance." }
                }
            }
        },
        LinkState::AccountLocked { username } => rsx! {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Account Locked" }
                    p { class: "text-secondary", "The account " strong { "{username}" } " has been locked." }
                    p { class: "text-secondary", "Please contact your administrator for assistance." }
                }
            }
        },
        LinkState::Error { code, description } => rsx! {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Error: {code}" }
                    div { class: "alert alert-critical",
                        p { "{description}" }
                    }
                }
            }
        },
    }
}

// ── Suggest Link ────────────────────────────────────────────────

#[component]
fn SuggestLinkView(
    id: String,
    provider_name: Option<String>,
    upstream_subject: Option<String>,
) -> Element {
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();
    let provider = provider_name.unwrap_or_else(|| "the external provider".to_string());

    rsx! {
        div { class: "login-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Link Account" }
                p { class: "text-secondary",
                    "Would you like to link your account with "
                    strong { "{provider}" }
                    if let Some(ref subject) = upstream_subject {
                        " ({subject})"
                    }
                    "?"
                }

                if let Some(ref err) = *error.read() {
                    div { class: "alert alert-critical",
                        p { "{err}" }
                    }
                }

                button {
                    class: "btn btn-primary btn-block",
                    r#type: "button",
                    disabled: *submitting.read(),
                    onclick: {
                        let id = id.clone();
                        move |_| {
                            let id = id.clone();
                            submitting.set(true);
                            spawn(async move {
                                let body = serde_json::json!({ "action": "link" });
                                match api_post::<LinkActionResponse>(
                                    &format!("/upstream-oauth2/link/{id}"),
                                    body,
                                )
                                .await
                                {
                                    Ok(resp) if resp.status == "success" => {
                                        let url = resp.redirect_url.unwrap_or_else(|| "/".to_owned());
                                        nav.push(url);
                                    }
                                    Ok(resp) => {
                                        error.set(resp.error.or(Some("Failed to link account".to_owned())));
                                        submitting.set(false);
                                    }
                                    Err(e) => {
                                        error.set(Some(e));
                                        submitting.set(false);
                                    }
                                }
                            });
                        }
                    },
                    if *submitting.read() { "Linking..." } else { "Link Account" }
                }
            }
        }
    }
}

// ── Link Mismatch ───────────────────────────────────────────────

#[component]
fn LinkMismatchView(existing_username: String) -> Element {
    rsx! {
        div { class: "login-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Account Mismatch" }
                p { class: "text-secondary",
                    "This external account is already linked to another user: "
                    strong { "{existing_username}" }
                    "."
                }
                p { class: "text-secondary", "Please log out and sign in with the correct account, or contact your administrator." }
                a { href: "/", class: "btn btn-primary btn-block", "Go to Home" }
            }
        }
    }
}

// ── Register ────────────────────────────────────────────────────

#[component]
fn RegisterView(
    id: String,
    suggested_username: Option<String>,
    username_forced: bool,
    suggested_display_name: Option<String>,
    display_name_forced: bool,
    suggested_email: Option<String>,
    email_forced: bool,
    provider_name: Option<String>,
    has_tos: bool,
) -> Element {
    let mut username = use_signal(|| suggested_username.clone().unwrap_or_default());
    let mut import_email = use_signal(|| suggested_email.is_some());
    let mut import_display_name = use_signal(|| suggested_display_name.is_some());
    let mut accept_terms = use_signal(|| false);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut field_errors = use_signal(|| None::<serde_json::Value>);
    let nav = navigator();

    let provider = provider_name.unwrap_or_else(|| "external provider".to_string());

    rsx! {
        div { class: "login-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Create Account" }
                p { class: "text-secondary", "Complete your registration with {provider}." }

                if let Some(ref err) = *error.read() {
                    div { class: "alert alert-critical",
                        p { "{err}" }
                    }
                }

                form {
                    class: "form-root",
                    onsubmit: {
                        let id = id.clone();
                        move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let id = id.clone();
                            let user = username.to_string();
                            let ie = *import_email.read();
                            let idn = *import_display_name.read();
                            let at = *accept_terms.read();

                            submitting.set(true);
                            error.set(None);
                            field_errors.set(None);

                            spawn(async move {
                                let body = serde_json::json!({
                                    "action": "register",
                                    "username": user,
                                    "import_email": ie,
                                    "import_display_name": idn,
                                    "accept_terms": at,
                                });
                                match api_post::<LinkActionResponse>(
                                    &format!("/upstream-oauth2/link/{id}"),
                                    body,
                                )
                                .await
                                {
                                    Ok(resp) if resp.status == "success" => {
                                        let url = resp.redirect_url.unwrap_or_else(|| "/".to_owned());
                                        nav.push(url);
                                    }
                                    Ok(resp) => {
                                        if let Some(fe) = resp.field_errors {
                                            field_errors.set(Some(fe));
                                        }
                                        error.set(resp.error.or(Some("Registration failed".to_owned())));
                                        submitting.set(false);
                                    }
                                    Err(e) => {
                                        error.set(Some(e));
                                        submitting.set(false);
                                    }
                                }
                            });
                        }
                    },

                    // Username field
                    div { class: "form-field",
                        label { class: "form-label", r#for: "username", "Username" }
                        input {
                            id: "username",
                            name: "username",
                            r#type: "text",
                            class: "form-input",
                            required: true,
                            disabled: username_forced,
                            value: "{username}",
                            oninput: move |e| username.set(e.value()),
                        }
                        if let Some(ref fe) = *field_errors.read() {
                            if let Some(err) = fe.get("username") {
                                span { class: "form-error",
                                    "{err}"
                                }
                            }
                        }
                    }

                    // Display name import checkbox
                    if suggested_display_name.is_some() && !display_name_forced {
                        div { class: "form-field",
                            label { class: "checkbox-label",
                                input {
                                    r#type: "checkbox",
                                    checked: *import_display_name.read(),
                                    onchange: move |e| import_display_name.set(e.checked()),
                                }
                                "Import display name"
                            }
                        }
                    }

                    // Email import checkbox
                    if suggested_email.is_some() && !email_forced {
                        div { class: "form-field",
                            label { class: "checkbox-label",
                                input {
                                    r#type: "checkbox",
                                    checked: *import_email.read(),
                                    onchange: move |e| import_email.set(e.checked()),
                                }
                                "Import email address"
                            }
                        }
                    }

                    // Terms of service checkbox
                    if has_tos {
                        div { class: "form-field",
                            label { class: "checkbox-label",
                                input {
                                    r#type: "checkbox",
                                    checked: *accept_terms.read(),
                                    onchange: move |e| accept_terms.set(e.checked()),
                                }
                                "I accept the Terms of Service"
                            }
                            if let Some(ref fe) = *field_errors.read() {
                                if let Some(err) = fe.get("accept_terms") {
                                    span { class: "form-error",
                                        "{err}"
                                    }
                                }
                            }
                        }
                    }

                    button {
                        class: "btn btn-primary btn-block",
                        r#type: "submit",
                        disabled: *submitting.read(),
                        if *submitting.read() { "Registering..." } else { "Register" }
                    }
                }
            }
        }
    }
}
