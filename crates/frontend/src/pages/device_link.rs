use dioxus::prelude::*;

use crate::{
    api::types::DeviceLinkResponse,
    components::{layout::Layout, loading::LoadingSpinner},
    pages::Route,
};

/// Device code link page — user enters the code shown on their device.
#[component]
pub fn DeviceLink() -> Element {
    let mut code = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();

    rsx! {
        Layout {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Link a device" }
                    p { class: "text-secondary",
                        "Enter the code displayed on the device you want to link."
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
                            let c = code.to_string();
                            if c.is_empty() {
                                error.set(Some("Please enter the device code.".to_string()));
                                return;
                            }

                            submitting.set(true);
                            error.set(None);
                            let nav = nav.clone();

                            spawn(async move {
                                let result = crate::api::api_get::<DeviceLinkResponse>(
                                    &format!("/device-link?code={c}"),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "valid" => {
                                        if let Some(grant_id) = resp.grant_id {
                                            nav.push(Route::DeviceConsent { id: grant_id });
                                        }
                                    }
                                    Ok(_) => {
                                        error.set(Some("Invalid or expired code. Please try again.".to_string()));
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Device code" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                autocomplete: "off",
                                required: true,
                                placeholder: "ABCD-EFGH",
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
                            "Continue"
                        }
                    }
                }
            }
        }
    }
}
