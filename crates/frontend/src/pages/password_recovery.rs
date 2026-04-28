use dioxus::prelude::*;

use crate::{
    api::types::{
        RecoveryTicketStatusResponse, ResendRecoveryEmailPayload, SetPasswordPayload,
        SetPasswordStatus,
    },
    components::{
        layout::Layout,
        loading::{LoadingScreen, LoadingSpinner},
        page_heading::PageHeading,
        password_input::PasswordCreationDoubleInput,
    },
    pages::Route,
};

#[derive(Debug, Clone, PartialEq)]
enum RecoveryState {
    Loading,
    Valid,
    Expired,
    Consumed,
    Success,
    Error(String),
}

fn get_ticket_from_url() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(win) = web_sys::window() {
            if let Ok(href) = win.location().href() {
                if let Ok(url) = web_sys::Url::new(&href) {
                    if let Some(ticket) = url.search_params().get("ticket") {
                        return ticket;
                    }
                }
            }
        }
    }

    String::new()
}

#[cfg(target_arch = "wasm32")]
fn navigate_to_url(url: String) -> Result<(), String> {
    let Some(window) = web_sys::window() else {
        return Err("Browser window is not available.".to_string());
    };

    window
        .location()
        .set_href(&url)
        .map_err(|_| "Failed to navigate to the recovery progress page.".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn navigate_to_url(_url: String) -> Result<(), String> {
    Err("Navigation is only available in the browser.".to_string())
}

#[component]
pub fn PasswordRecovery() -> Element {
    let ticket = use_signal(get_ticket_from_url);
    let new_password = use_signal(String::new);
    let new_password_again = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut resending = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut invalid_new = use_signal(|| false);
    let mut ticket_email = use_signal(|| None::<String>);
    let mut recovery_state = use_signal(|| RecoveryState::Loading);

    let ticket_value = ticket.read().clone();

    let _ticket_status = use_resource({
        let ticket_value = ticket_value.clone();
        move || {
            let ticket_value = ticket_value.clone();
            async move {
                if ticket_value.is_empty() {
                    recovery_state.set(RecoveryState::Error(
                        "No recovery ticket found in the URL.".to_string(),
                    ));
                    return;
                }

                match crate::api::api_get::<RecoveryTicketStatusResponse>(&format!(
                    "/password-recovery/{ticket_value}"
                ))
                .await
                {
                    Ok(response) => {
                        ticket_email.set(response.email);
                        match response.status.as_str() {
                            "valid" => recovery_state.set(RecoveryState::Valid),
                            "expired" => recovery_state.set(RecoveryState::Expired),
                            "consumed" => recovery_state.set(RecoveryState::Consumed),
                            "disabled" => recovery_state.set(RecoveryState::Error(
                                "Account recovery is not available.".to_string(),
                            )),
                            "not_found" => recovery_state
                                .set(RecoveryState::Error("Invalid recovery ticket.".to_string())),
                            other => recovery_state.set(RecoveryState::Error(format!(
                                "Unexpected recovery ticket status: {other}",
                            ))),
                        }
                    }
                    Err(err) => recovery_state.set(RecoveryState::Error(err)),
                }
            }
        }
    });

    match recovery_state.read().clone() {
        RecoveryState::Loading => {
            return rsx! { LoadingScreen {} };
        }
        RecoveryState::Success => {
            return rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "✓".to_string(),
                            title: "Password reset".to_string(),
                            subtitle: "Your password has been reset successfully. You can now sign in with your new password.".to_string(),
                        }

                        div { class: "login-links",
                            Link { class: "link", to: Route::Login {},
                                "Back to sign in"
                            }
                        }
                    }
                }
            };
        }
        RecoveryState::Consumed => {
            return rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "✗".to_string(),
                            title: "Recovery link already used".to_string(),
                            subtitle: "This password recovery link has already been used. Request a new recovery email if you still need to reset your password.".to_string(),
                        }

                        div { class: "login-links",
                            Link { class: "link", to: Route::RecoveryStart {},
                                "Request a new recovery email"
                            }
                        }
                    }
                }
            };
        }
        RecoveryState::Expired => {
            let ticket_value = ticket_value.clone();
            let subtitle = ticket_email.read().clone().map_or_else(
                || {
                    "This password recovery link has expired. You can request a new recovery email."
                        .to_string()
                },
                |email| {
                    format!(
                        "This password recovery link for {email} has expired. You can request a new recovery email.",
                    )
                },
            );

            return rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "⏰".to_string(),
                            title: "Recovery link expired".to_string(),
                            subtitle: subtitle,
                        }

                        if let Some(ref err) = *error.read() {
                            div { class: "alert alert-critical",
                                p { class: "alert-title", "Error" }
                                p { "{err}" }
                            }
                        }

                        button {
                            class: "btn btn-primary",
                            disabled: resending(),
                            onclick: move |_| {
                                let ticket_value = ticket_value.clone();
                                resending.set(true);
                                error.set(None);

                                spawn(async move {
                                    let result = crate::api::api_post::<ResendRecoveryEmailPayload>(
                                        "/password-recovery/resend",
                                        serde_json::json!({ "ticket": ticket_value }),
                                    )
                                    .await;

                                    resending.set(false);
                                    match result {
                                        Ok(response) => match response.status.as_str() {
                                            "SENT" => {
                                                if let Some(progress_url) = response.progress_url {
                                                    if let Err(err) = navigate_to_url(progress_url) {
                                                        error.set(Some(err));
                                                    }
                                                } else {
                                                    error.set(Some(
                                                        "Recovery email sent, but no progress page was returned."
                                                            .to_string(),
                                                    ));
                                                }
                                            }
                                            "RATE_LIMITED" => error.set(Some(
                                                "Too many recovery emails were requested. Please try again later."
                                                    .to_string(),
                                            )),
                                            "RECOVERY_TICKET_ALREADY_USED" => {
                                                recovery_state.set(RecoveryState::Consumed);
                                            }
                                            "NO_SUCH_RECOVERY_TICKET" => recovery_state.set(
                                                RecoveryState::Error(
                                                    "Invalid recovery ticket.".to_string(),
                                                ),
                                            ),
                                            _ => error.set(Some(
                                                "Could not resend the recovery email.".to_string(),
                                            )),
                                        },
                                        Err(err) => error.set(Some(err)),
                                    }
                                });
                            },
                            if resending() {
                                LoadingSpinner { inline: true }
                            }
                            "Resend recovery email"
                        }

                        div { class: "login-links",
                            Link { class: "link", to: Route::RecoveryStart {},
                                "Start over"
                            }
                        }
                    }
                }
            };
        }
        RecoveryState::Error(message) => {
            return rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "⚠".to_string(),
                            title: "Password recovery".to_string(),
                            subtitle: message,
                        }

                        div { class: "login-links",
                            Link { class: "link", to: Route::RecoveryStart {},
                                "Start over"
                            }
                        }
                    }
                }
            };
        }
        RecoveryState::Valid => {}
    }

    let ticket_value = ticket_value.clone();

    rsx! {
        Layout {
            div { class: "flex flex-col gap-10",
                PageHeading {
                    icon: "🔒".to_string(),
                    title: "Reset your password".to_string(),
                    subtitle: "Enter a new password for your account.".to_string(),
                }

                form {
                    class: "form-root",
                    onsubmit: move |event: FormEvent| {
                        event.prevent_default();
                        event.stop_propagation();

                        let new_password_value = new_password.to_string();
                        let new_password_again_value = new_password_again.to_string();

                        if new_password_value != new_password_again_value {
                            error.set(Some("Passwords do not match.".to_string()));
                            return;
                        }

                        submitting.set(true);
                        error.set(None);
                        invalid_new.set(false);

                        let ticket_value = ticket_value.clone();
                        spawn(async move {
                            let result = crate::api::api_post::<SetPasswordPayload>(
                                "/password-recovery/set",
                                serde_json::json!({
                                    "ticket": ticket_value,
                                    "new_password": new_password_value,
                                }),
                            )
                            .await;

                            submitting.set(false);
                            match result {
                                Ok(response) => match response.status {
                                    SetPasswordStatus::Allowed => {
                                        recovery_state.set(RecoveryState::Success);
                                    }
                                    SetPasswordStatus::InvalidNewPassword => {
                                        invalid_new.set(true);
                                        error.set(Some(
                                            "New password does not meet the requirements."
                                                .to_string(),
                                        ));
                                    }
                                    SetPasswordStatus::ExpiredRecoveryTicket => {
                                        recovery_state.set(RecoveryState::Expired);
                                    }
                                    SetPasswordStatus::NoSuchRecoveryTicket => {
                                        recovery_state.set(RecoveryState::Error(
                                            "Invalid recovery ticket.".to_string(),
                                        ));
                                    }
                                    SetPasswordStatus::RecoveryTicketAlreadyUsed => {
                                        recovery_state.set(RecoveryState::Consumed);
                                    }
                                    SetPasswordStatus::AccountLocked => {
                                        error.set(Some(
                                            "This account is locked and cannot be recovered."
                                                .to_string(),
                                        ));
                                    }
                                    SetPasswordStatus::PasswordChangesDisabled => {
                                        error.set(Some(
                                            "Password recovery is not available.".to_string(),
                                        ));
                                    }
                                    _ => error.set(Some(
                                        "An error occurred while resetting your password."
                                            .to_string(),
                                    )),
                                },
                                Err(err) => error.set(Some(err)),
                            }
                        });
                    },

                    if let Some(ref err) = *error.read() {
                        div { class: "alert alert-critical",
                            p { class: "alert-title", "Error" }
                            p { "{err}" }
                        }
                    }

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
                        "Reset password"
                    }
                }
            }
        }
    }
}
