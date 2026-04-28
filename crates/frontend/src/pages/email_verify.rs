use dioxus::prelude::*;

use crate::{
    api::types::{CompleteEmailAuthStatus, ResendEmailAuthCodePayload, UserEmailAuthentication},
    components::{
        layout::Layout,
        loading::{LoadingScreen, LoadingSpinner},
        page_heading::PageHeading,
    },
    pages::Route,
};

#[component]
pub fn EmailVerify(id: String) -> Element {
    let mut code = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut success = use_signal(|| false);
    let mut resending = use_signal(|| false);
    let mut resend_message = use_signal(|| None::<String>);
    let email_id = id.clone();

    // Preliminary query to check email authentication status
    let id_for_query = id.clone();
    let auth_data = use_resource(move || {
        let qid = id_for_query.clone();
        async move {
            crate::api::api_get::<UserEmailAuthentication>(&format!("/email-auth/{}", qid)).await
        }
    });

    if success() {
        return rsx! {
            Layout {
                div { class: "flex flex-col gap-10",
                    PageHeading {
                        icon: "✓".to_string(),
                        title: "Email verified".to_string(),
                        subtitle: "Your email address has been verified successfully.".to_string(),
                    }
                    Link { class: "btn btn-primary", to: Route::AccountSettings {},
                        "Back to settings"
                    }
                }
            }
        };
    }

    let auth_binding = auth_data.read();
    match &*auth_binding {
        Some(Ok(auth)) => {
            // Check if already completed
            {
                if auth.completed_at.is_some() {
                    return rsx! {
                        Layout {
                            div { class: "flex flex-col gap-10",
                                PageHeading {
                                    icon: "✓".to_string(),
                                    title: "Already verified".to_string(),
                                    subtitle: "This email address has already been verified.".to_string(),
                                }
                                Link { class: "btn btn-primary", to: Route::AccountSettings {},
                                    "Back to settings"
                                }
                            }
                        }
                    };
                }

                let email_address = auth.email.clone();
                let subtitle = format!("Enter the verification code sent to {email_address}.");

                rsx! {
                    Layout {
                        div { class: "flex flex-col gap-10",
                            PageHeading {
                                icon: "✉".to_string(),
                                title: "Verify your email".to_string(),
                                subtitle: subtitle,
                            }

                            form {
                                class: "form-root",
                                onsubmit: move |evt| {
                                    evt.prevent_default();
                                    evt.stop_propagation();
                                    let code_val = code.to_string();
                                    if code_val.is_empty() {
                                        return;
                                    }
                                    let eid = email_id.clone();
                                    submitting.set(true);
                                    error.set(None);

                                    spawn(async move {
                                        let result = crate::api::api_post::<crate::api::types::CompleteEmailAuthPayload>(
                                            &format!("/email-auth/{}/complete", eid),
                                            serde_json::json!({
                                                "code": code_val,
                                            }),
                                        ).await;
                                        submitting.set(false);
                                        match result {
                                            Ok(data) => match data.status {
                                                CompleteEmailAuthStatus::Completed => {
                                                    success.set(true);
                                                }
                                                CompleteEmailAuthStatus::InvalidCode => {
                                                    error.set(Some("Invalid verification code.".to_string()));
                                                }
                                                CompleteEmailAuthStatus::NotFound => {
                                                    error.set(Some("Verification not found.".to_string()));
                                                }
                                            },
                                            Err(err) => {
                                                error.set(Some(err));
                                            }
                                        }
                                    });
                                },

                                if let Some(ref err) = *error.read() {
                                    div { class: "alert alert-critical", "{err}" }
                                }

                                if let Some(ref msg) = *resend_message.read() {
                                    div { class: "alert alert-info", "{msg}" }
                                }

                                div { class: "form-field",
                                    label { class: "form-label", "Verification code" }
                                    input {
                                        class: "form-input",
                                        r#type: "text",
                                        autocomplete: "one-time-code",
                                        required: true,
                                        placeholder: "Enter code",
                                        value: "{code}",
                                        oninput: move |evt| code.set(evt.value()),
                                    }
                                }

                                button {
                                    class: "btn btn-primary",
                                    r#type: "submit",
                                    disabled: submitting(),
                                    if submitting() {
                                        LoadingSpinner { inline: true }
                                    }
                                    "Verify"
                                }

                                // Resend verification code button
                                button {
                                    class: "btn btn-secondary",
                                    r#type: "button",
                                    disabled: resending(),
                                    onclick: {
                                        let resend_id = id.clone();
                                        move |_| {
                                            let rid = resend_id.clone();
                                            resending.set(true);
                                            resend_message.set(None);
                                            spawn(async move {
                                                let result = crate::api::api_post::<ResendEmailAuthCodePayload>(
                                                    &format!("/email-auth/{}/resend", rid),
                                                    serde_json::json!({
                                                        "language": "en",
                                                    }),
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
                                        }
                                    },
                                    if resending() {
                                        LoadingSpinner { inline: true }
                                    }
                                    "Resend code"
                                }

                                Link { class: "btn btn-tertiary", to: Route::AccountSettings {},
                                    "Cancel"
                                }
                            }
                        }
                    }
                }
            }
        }
        Some(Err(err)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{err}" }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}
