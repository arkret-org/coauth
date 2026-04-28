use dioxus::prelude::*;

use crate::{
    api::types::{ConsentDataResponse, DeviceConsentResponse},
    components::{layout::Layout, loading::LoadingScreen},
    pages::Route,
};

/// Device code consent page — user approves or rejects device authorization.
#[component]
pub fn DeviceConsent(id: String) -> Element {
    let grant_id = id.clone();
    let data = use_resource(move || {
        let gid = grant_id.clone();
        async move {
            crate::api::api_get::<ConsentDataResponse>(&format!("/device-consent/{gid}")).await
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
                    DeviceConsentForm { data: resp.clone(), id: id.clone() }
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
fn DeviceConsentForm(data: ConsentDataResponse, id: String) -> Element {
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut done = use_signal(|| None::<String>);

    let client_name = data
        .client
        .client_name
        .clone()
        .unwrap_or_else(|| data.client.client_id.clone());

    rsx! {
        div { class: "login-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Authorize device" }

                if let Some(ref msg) = *done.read() {
                    div { class: "alert alert-info",
                        p { "{msg}" }
                    }
                    Link { class: "btn btn-primary btn-block", to: Route::AccountSettings {},
                        "Go to account"
                    }
                } else {
                    p { class: "text-secondary",
                        strong { "{client_name}" }
                        " on a new device wants to access your account as "
                        strong { "{data.user.mxid}" }
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
                                let gid = id.clone();
                                move |_| {
                                    submitting.set(true);
                                    error.set(None);
                                    let gid = gid.clone();

                                    spawn(async move {
                                        let result = crate::api::api_post::<DeviceConsentResponse>(
                                            &format!("/device-consent/{gid}"),
                                            serde_json::json!({ "action": "consent" }),
                                        ).await;
                                        submitting.set(false);
                                        match result {
                                            Ok(resp) if resp.status == "fulfilled" => {
                                                done.set(Some("Device authorized successfully. You can now use the device.".to_string()));
                                            }
                                            Ok(resp) => {
                                                error.set(Some(format!("Unexpected status: {}", resp.status)));
                                            }
                                            Err(e) => error.set(Some(e)),
                                        }
                                    });
                                }
                            },
                            "Approve"
                        }

                        button {
                            class: "btn btn-secondary btn-block",
                            disabled: submitting(),
                            onclick: {
                                let gid = id.clone();
                                move |_| {
                                    submitting.set(true);
                                    error.set(None);
                                    let gid = gid.clone();

                                    spawn(async move {
                                        let result = crate::api::api_post::<DeviceConsentResponse>(
                                            &format!("/device-consent/{gid}"),
                                            serde_json::json!({ "action": "reject" }),
                                        ).await;
                                        submitting.set(false);
                                        match result {
                                            Ok(resp) if resp.status == "rejected" => {
                                                done.set(Some("Device authorization was rejected.".to_string()));
                                            }
                                            Ok(_) | Err(_) => {
                                                done.set(Some("Device authorization was rejected.".to_string()));
                                            }
                                        }
                                    });
                                }
                            },
                            "Deny"
                        }
                    }
                }
            }
        }
    }
}
