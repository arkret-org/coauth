use dioxus::prelude::*;

use crate::{
    api::types::RecoveryStartResponse,
    components::{layout::Layout, loading::LoadingSpinner},
    pages::Route,
};

/// Account recovery — enter email to receive recovery link.
#[component]
pub fn RecoveryStart() -> Element {
    let mut email = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();

    rsx! {
        Layout {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Account recovery" }
                    p { class: "text-secondary",
                        "Enter the email address associated with your account and we'll send you a recovery link."
                    }

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
                            let em = email.to_string();
                            if em.is_empty() {
                                error.set(Some("Please enter your email address.".to_string()));
                                return;
                            }

                            submitting.set(true);
                            error.set(None);
                            let nav = nav.clone();

                            spawn(async move {
                                let result = crate::api::api_post::<RecoveryStartResponse>(
                                    "/auth/recovery/start",
                                    serde_json::json!({ "email": em }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        if let Some(id) = resp.id {
                                            nav.push(Route::RecoveryProgress { id });
                                        }
                                    }
                                    Ok(resp) => {
                                        error.set(Some(resp.error.unwrap_or_else(|| "Recovery failed.".to_string())));
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
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Send recovery email"
                        }
                    }

                    div { class: "login-register",
                        Link { class: "link", to: Route::Login {},
                            "Back to sign in"
                        }
                    }
                }
            }
        }
    }
}
