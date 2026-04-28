use dioxus::prelude::*;

use crate::{
    api::types::RecoveryStatusResponse,
    components::{
        layout::Layout,
        loading::{LoadingScreen, LoadingSpinner},
    },
    pages::Route,
};

/// Recovery progress page — shows status of recovery session.
#[component]
pub fn RecoveryProgress(id: String) -> Element {
    let recovery_id = id.clone();
    let status_data = use_resource(move || {
        let rid = recovery_id.clone();
        async move {
            crate::api::api_get::<RecoveryStatusResponse>(&format!("/auth/recovery/{rid}")).await
        }
    });
    let binding = status_data.read();

    match &*binding {
        Some(Ok(data)) => rsx! {
            Layout {
                RecoveryProgressContent { data: data.clone(), id: id.clone() }
            }
        },
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "login-page",
                    div { class: "login-container",
                        div { class: "alert alert-critical", "{e}" }
                        Link { class: "btn btn-primary", to: Route::RecoveryStart {},
                            "Try again"
                        }
                    }
                }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}

#[component]
fn RecoveryProgressContent(data: RecoveryStatusResponse, id: String) -> Element {
    let mut resending = use_signal(|| false);
    let mut resend_msg = use_signal(|| None::<String>);
    let recovery_id = id.clone();

    rsx! {
        div { class: "login-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Check your email" }

                match data.status.as_str() {
                    "consumed" => rsx! {
                        div { class: "alert alert-info",
                            p { "This recovery link has already been used." }
                        }
                        Link { class: "btn btn-primary", to: Route::Login {},
                            "Back to sign in"
                        }
                    },
                    "disabled" => rsx! {
                        div { class: "alert alert-warning",
                            p { "Account recovery is not available." }
                        }
                        Link { class: "btn btn-primary", to: Route::Login {},
                            "Back to sign in"
                        }
                    },
                    _ => rsx! {
                        p { class: "text-secondary",
                            "We sent a recovery email to "
                            strong { "{data.email}" }
                            ". Please check your inbox and follow the link."
                        }

                        if let Some(ref msg) = *resend_msg.read() {
                            div { class: "alert alert-info",
                                p { "{msg}" }
                            }
                        }

                        button {
                            class: "btn btn-secondary btn-block",
                            disabled: resending(),
                            onclick: move |_| {
                                resending.set(true);
                                resend_msg.set(None);
                                let rid = recovery_id.clone();

                                spawn(async move {
                                    let result = crate::api::api_post::<serde_json::Value>(
                                        &format!("/auth/recovery/{rid}/resend"),
                                        serde_json::json!({}),
                                    ).await;
                                    resending.set(false);
                                    match result {
                                        Ok(_) => resend_msg.set(Some("Recovery email resent.".to_string())),
                                        Err(e) => resend_msg.set(Some(e)),
                                    }
                                });
                            },
                            if resending() {
                                LoadingSpinner { inline: true }
                            }
                            "Resend email"
                        }

                        Link { class: "btn btn-tertiary btn-block", to: Route::Login {},
                            "Back to sign in"
                        }
                    },
                }
            }
        }
    }
}
