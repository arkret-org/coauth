use dioxus::prelude::*;

use crate::{
    api::types::{SetPasswordStatus, ViewerResponse},
    components::{
        layout::Layout,
        loading::{LoadingScreen, LoadingSpinner},
        page_heading::PageHeading,
        password_input::PasswordCreationDoubleInput,
        separator::Separator,
    },
    pages::Route,
};

#[component]
pub fn PasswordChange() -> Element {
    let data = use_resource(|| async { crate::api::api_get::<ViewerResponse>("/viewer").await });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let user = match result.viewer.as_user() {
                Some(u) => u,
                None => return rsx! { Layout { p { "Not authenticated." } } },
            };
            let user_id = user.id.clone();

            rsx! {
                Layout {
                    PasswordChangeForm { user_id: user_id }
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
fn PasswordChangeForm(user_id: String) -> Element {
    let mut current_password = use_signal(String::new);
    let new_password = use_signal(String::new);
    let new_password_again = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut wrong_password = use_signal(|| false);
    let mut invalid_new = use_signal(|| false);
    let nav = navigator();
    let uid = user_id.clone();

    rsx! {
        div { class: "flex flex-col gap-10",
            PageHeading {
                icon: "🔒".to_string(),
                title: "Change password".to_string(),
                subtitle: "Choose a new password for your account.".to_string(),
            }

            form {
                class: "form-root",
                onsubmit: move |e| {
                    e.prevent_default();
                    e.stop_propagation();
                    let current = current_password.to_string();
                    let new_pw = new_password.to_string();
                    let new_pw2 = new_password_again.to_string();

                    if new_pw != new_pw2 {
                        error.set(Some("Passwords do not match.".to_string()));
                        return;
                    }

                    let uid = uid.clone();
                    submitting.set(true);
                    error.set(None);
                    wrong_password.set(false);
                    invalid_new.set(false);
                    let nav = nav.clone();

                    spawn(async move {
                        let result = crate::api::api_post::<crate::api::types::SetPasswordPayload>(
                            "/viewer/password",
                            serde_json::json!({
                                "user_id": uid,
                                "current_password": current,
                                "new_password": new_pw,
                            }),
                        ).await;
                        submitting.set(false);
                        match result {
                            Ok(data) => match data.status {
                                SetPasswordStatus::Allowed => {
                                    nav.push(Route::PasswordChangeSuccess {});
                                }
                                SetPasswordStatus::WrongPassword => {
                                    wrong_password.set(true);
                                    error.set(Some("Current password is incorrect.".to_string()));
                                }
                                SetPasswordStatus::InvalidNewPassword => {
                                    invalid_new.set(true);
                                    error.set(Some("New password does not meet the requirements.".to_string()));
                                }
                                _ => {
                                    error.set(Some("An error occurred while changing your password.".to_string()));
                                }
                            },
                            Err(e) => {
                                error.set(Some(e));
                            }
                        }
                    });
                },

                if let Some(ref err) = *error.read() {
                    div { class: "alert alert-critical",
                        p { class: "alert-title", "Error" }
                        p { "{err}" }
                    }
                }

                div { class: "form-field",
                    label { class: "form-label", "Current password" }
                    input {
                        class: if wrong_password() { "form-input invalid" } else { "form-input" },
                        r#type: "password",
                        autocomplete: "current-password",
                        required: true,
                        value: "{current_password}",
                        oninput: move |e| current_password.set(e.value()),
                    }
                    if wrong_password() {
                        span { class: "form-error", "Incorrect password." }
                    }
                }

                Separator {}

                PasswordCreationDoubleInput {
                    new_password: new_password,
                    new_password_again: new_password_again,
                    force_invalid: invalid_new(),
                }

                button {
                    class: "btn btn-primary",
                    r#type: "submit",
                    disabled: submitting(),
                    if submitting() {
                        LoadingSpinner { inline: true }
                    }
                    "Save"
                }

                Link { class: "btn btn-tertiary", to: Route::AccountSettings {},
                    "Cancel"
                }
            }
        }
    }
}
