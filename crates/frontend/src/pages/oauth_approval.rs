use dioxus::prelude::*;

use crate::api::types::{ApprovalDataOutcome, OAuthApprovalSubmitOutcome};
use crate::components::form_error::FormError;
use crate::components::layout::Layout;
use crate::components::loading::LoadingScreen;
use crate::pages::Route;

#[cfg(target_arch = "wasm32")]
fn submit_consent_form(grant: &str, action: &str, csrf: &str) -> Result<(), String> {
    use web_sys::wasm_bindgen::JsCast as _;
    let window = web_sys::window().ok_or("Browser window unavailable")?;
    let url = format!(
        "{}/self/oauth/authorization-grants/{grant}/decision",
        crate::config::api_base_url()
    );
    let document = window.document().ok_or("Browser document unavailable")?;
    let form = document
        .create_element("form")
        .map_err(|_| "Could not create callback form")?
        .dyn_into::<web_sys::HtmlFormElement>()
        .map_err(|_| "Invalid callback form")?;
    form.set_method("post");
    form.set_action(&url);
    for (name, value) in [("action", action), ("csrf_token", csrf)] {
        let input = document
            .create_element("input")
            .map_err(|_| "Could not create callback field")?
            .dyn_into::<web_sys::HtmlInputElement>()
            .map_err(|_| "Invalid callback field")?;
        input.set_type("hidden");
        input.set_name(name);
        input.set_value(value);
        form.append_child(&input)
            .map_err(|_| "Could not append callback field")?;
    }
    document
        .body()
        .ok_or("Browser body unavailable")?
        .append_child(&form)
        .map_err(|_| "Could not mount callback form")?;
    form.submit()
        .map_err(|_| "Could not submit callback form")?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn finish_authorization(outcome: &OAuthApprovalSubmitOutcome) -> Result<(), String> {
    let window = web_sys::window().ok_or("Browser window unavailable")?;
    let url = outcome
        .redirect_url
        .as_deref()
        .ok_or("Missing callback URL")?;
    if matches!(outcome.response_mode.as_deref(), Some("query" | "fragment")) {
        window
            .location()
            .assign(url)
            .map_err(|_| "Could not navigate to callback")?;
    } else {
        return Err("Unsupported callback mode".to_owned());
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn submit_consent_form(_grant: &str, _action: &str, _csrf: &str) -> Result<(), String> {
    Err("Consent form submission requires a browser".to_owned())
}

#[cfg(not(target_arch = "wasm32"))]
fn finish_authorization(_outcome: &OAuthApprovalSubmitOutcome) -> Result<(), String> {
    Ok(())
}

/// OAuth approval page — shows what permissions a client is requesting.
#[component]
pub fn OAuthApproval(grant_id: String) -> Element {
    let gid = grant_id.clone();
    let data = use_resource(move || {
        let id = gid.clone();
        async move {
            crate::api::api_get::<ApprovalDataOutcome>(&format!(
                "/self/oauth/authorization-grants/{id}/decision"
            ))
            .await
        }
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(resp)) => {
            if resp.error.as_deref() == Some("not_authenticated") {
                let nav = navigator();
                nav.push(Route::Login {});
                return rsx! { Layout { p { "Redirecting to login..." } } };
            }
            if resp.policy_violation {
                return rsx! {
                    Layout {
                        div { class: "login-page",
                            div { class: "login-container",
                                h1 { class: "heading-md login-title", "Access Denied" }
                                div { class: "alert alert-critical",
                                    p { "This authorization request was denied by policy." }
                                }
                            }
                        }
                    }
                };
            }
            rsx! {
                    Layout {
                    OAuthApprovalForm {
                        data: resp.clone(),
                        grant_id: grant_id.clone(),
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}

#[component]
fn OAuthApprovalForm(data: ApprovalDataOutcome, grant_id: String) -> Element {
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let decision_csrf = data.csrf_token.clone();
    let decision_grant = grant_id.clone();
    let decision_form_post = data.response_mode.as_deref() == Some("form_post");
    let navigation = navigator();
    let decide = use_callback(move |action: &'static str| {
        let Some(csrf_token) = decision_csrf.clone() else {
            error.set(Some(
                "Missing authorization continuation. Restart sign-in.".to_owned(),
            ));
            return;
        };
        submitting.set(true);
        error.set(None);
        let gid = decision_grant.clone();
        if decision_form_post {
            if let Err(message) = submit_consent_form(&gid, action, &csrf_token) {
                submitting.set(false);
                error.set(Some(message));
            }
            return;
        }
        spawn(async move {
            let result = crate::api::api_post::<OAuthApprovalSubmitOutcome>(
                &format!("/self/oauth/authorization-grants/{gid}/decision"),
                serde_json::json!({ "action": action, "csrf_token": csrf_token }),
            )
            .await;
            submitting.set(false);
            match result {
                Ok(resp) if resp.status == "success" => {
                    if let Err(message) = finish_authorization(&resp) {
                        error.set(Some(message));
                    }
                }
                Ok(resp) if resp.error.as_deref() == Some("not_authenticated") => {
                    navigation.push(Route::Login {});
                }
                Err(message) if message == "not_authenticated" => {
                    navigation.push(Route::Login {});
                }
                Ok(resp) => error.set(Some(
                    resp.error
                        .unwrap_or_else(|| "Authorization failed.".to_owned()),
                )),
                Err(message) => error.set(Some(message)),
            }
        });
    });

    let client_name = data
        .client
        .client_name
        .clone()
        .unwrap_or_else(|| data.client.client_id.clone());

    // Scope parsing + description lookup only depends on the (immutable) prop,
    // so memoize it instead of recomputing on every submitting/error rerender.
    let scope_descriptions = use_memo({
        let scope = data.scope.clone();
        move || {
            scope
                .split_whitespace()
                .map(scope_description)
                .collect::<Vec<String>>()
        }
    });

    rsx! {
        div { class: "login-page approval-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Authorize {client_name}" }

                if let Some(ref uri) = data.client.logo_uri {
                    div { class: "approval-logo",
                        img { src: "{uri}", alt: "{client_name}", width: "64", height: "64" }
                    }
                }

                p { class: "text-secondary",
                    strong { "{client_name}" }
                    " wants to access your account as "
                    strong { "{data.user.principal_address}" }
                }

                if !scope_descriptions.read().is_empty() {
                    div { class: "approval-scopes",
                        p { class: "form-label", "This will allow the application to:" }
                        ul {
                            for (i, description) in scope_descriptions.read().iter().enumerate() {
                                li { key: "{i}", "{description}" }
                            }
                        }
                    }
                }

                if let Some(ref err) = *error.read() {
                    FormError { message: err.clone() }
                }

                div { class: "approval-actions",
                    button {
                        class: "btn btn-primary btn-block",
                        // Stable hook for e2e (cotest oidc-login-flow.spec.ts).
                        "data-testid": "coauth-oauth-approve",
                        disabled: submitting(),
                        autofocus: true,
                        onmounted: move |event| async move {
                            let _ = event.set_focus(true).await;
                        },
                        onclick: move |_| decide.call("approve"),
                        "Allow"
                    }
                    button {
                        class: "btn btn-secondary btn-block",
                        "data-testid": "coauth-oauth-deny",
                        disabled: submitting(),
                        onclick: move |_| decide.call("deny"),
                        "Deny"
                    }
                }

                if let Some(ref uri) = data.client.client_uri {
                    div { class: "login-register",
                        a { class: "link", href: "{uri}", target: "_blank",
                            "About {client_name}"
                        }
                    }
                }
            }
        }
    }
}

fn scope_description(scope: &str) -> String {
    match scope {
        "openid" => "Verify your identity with coauth".to_owned(),
        "profile" => "View your basic account profile".to_owned(),
        "email" => "View your verified email address".to_owned(),
        "phone" => "View your phone number".to_owned(),
        "address" => "View your address".to_owned(),
        "urn:arkret:station:session.bind" => {
            "Receive a short-lived session grant bound to this login session".to_owned()
        }
        other if other.starts_with("urn:arkret:station:") => {
            "Act as a trusted Station integration".to_owned()
        }
        other if other.starts_with("urn:arkret:client:") => {
            "Use Arkret client capabilities on your behalf".to_owned()
        }
        other if other == "urn:coauth:admin" || other.starts_with("urn:arkret:admin:") => {
            "Administrative access to coauth management APIs".to_owned()
        }
        other => other.to_owned(),
    }
}
