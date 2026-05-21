use dioxus::prelude::*;

use crate::{
    api::types::{ConsentDataResponse, ConsentSubmitResponse},
    components::{layout::Layout, loading::LoadingScreen},
    pages::Route,
};

#[cfg(target_arch = "wasm32")]
fn navigate_to_redirect_url(url: &str) {
    if let Some(win) = web_sys::window() {
        let _ = win.location().assign(url);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn navigate_to_redirect_url(_url: &str) {}

/// OAuth consent page — shows what permissions a client is requesting.
#[component]
pub fn Consent(grant_id: String) -> Element {
    let gid = grant_id.clone();
    let data = use_resource(move || {
        let id = gid.clone();
        async move { crate::api::api_get::<ConsentDataResponse>(&format!("/oauth/consent/{id}")).await }
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
                    ConsentForm {
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
fn ConsentForm(data: ConsentDataResponse, grant_id: String) -> Element {
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let client_name = data
        .client
        .client_name
        .clone()
        .unwrap_or_else(|| data.client.client_id.clone());

    let scopes: Vec<&str> = data.scope.split_whitespace().collect();

    rsx! {
        div { class: "login-page consent-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Authorize {client_name}" }

                if let Some(ref uri) = data.client.logo_uri {
                    div { class: "consent-logo",
                        img { src: "{uri}", alt: "{client_name}", width: "64", height: "64" }
                    }
                }

                p { class: "text-secondary",
                    strong { "{client_name}" }
                    " wants to access your account as "
                    strong { "{data.user.principal_id}" }
                }

                if !scopes.is_empty() {
                    div { class: "consent-scopes",
                        p { class: "form-label", "This will allow the application to:" }
                        ul {
                            for scope in scopes.iter() {
                                li { {scope_description(scope)} }
                            }
                        }
                    }
                }

                if let Some(ref err) = *error.read() {
                    div { class: "alert alert-critical",
                        p { "{err}" }
                    }
                }

                div { class: "consent-actions",
                    button {
                        class: "btn btn-primary btn-block",
                        disabled: submitting(),
                        onclick: {
                            let gid = grant_id.clone();
                            move |_| {
                                submitting.set(true);
                                error.set(None);
                                let gid = gid.clone();

                                spawn(async move {
                                    let result = crate::api::api_post::<ConsentSubmitResponse>(
                                        &format!("/oauth/consent/{gid}"),
                                        serde_json::json!({ "action": "consent" }),
                                    ).await;
                                    submitting.set(false);
                                    match result {
                                        Ok(resp) if resp.status == "success" => {
                                            if let Some(url) = resp.redirect_url {
                                                // Navigate browser to the OAuth callback URL
                                                // with assign() for a full navigation.
                                                navigate_to_redirect_url(&url);
                                            } else {
                                                error.set(Some("No redirect URL in response.".to_owned()));
                                            }
                                        }
                                        Ok(resp) if resp.error.as_deref() == Some("not_authenticated") => {
                                            // Session expired — redirect to login so
                                            // the user can re-authenticate and retry.
                                            let nav = navigator();
                                            nav.push(Route::Login {});
                                        }
                                        Ok(resp) => {
                                            error.set(Some(resp.error.unwrap_or_else(|| "Authorization failed.".to_owned())));
                                        }
                                        Err(e) => error.set(Some(e)),
                                    }
                                });
                            }
                        },
                        "Allow"
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
        "urn:contrix:principal-server:session.bind" => {
            "Receive a short-lived session grant bound to this login session".to_owned()
        }
        other if other.starts_with("urn:contrix:principal-server:") => {
            "Act as a trusted Principal Server integration".to_owned()
        }
        other if other.starts_with("urn:contrix:client:") => {
            "Use Contrix client capabilities on your behalf".to_owned()
        }
        other if other == "urn:coauth:admin" || other.starts_with("urn:contrix:admin:") => {
            "Administrative access to coauth management APIs".to_owned()
        }
        other => other.to_owned(),
    }
}
